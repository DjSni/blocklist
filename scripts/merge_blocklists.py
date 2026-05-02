#!/usr/bin/env python3
from __future__ import annotations

import concurrent.futures
import datetime as dt
import gzip
import hashlib
import io
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, NamedTuple

ROOT = Path(__file__).resolve().parents[1]
URLS_FILE = ROOT / "src" / "blocklist-urls.txt"
ALLOWLIST_FILE = ROOT / "src" / "allowlist.txt"
MANUAL_BLOCKLIST_FILE = ROOT / "src" / "manual-blocklist.txt"
OUT_DIR = ROOT / os.getenv("OUTPUT_DIR", "public")
OUT_FILE = OUT_DIR / os.getenv("OUTPUT_FILE", "technitium-blocklist.txt")
META_FILE = OUT_DIR / "metadata.json"
CACHE_DIR = ROOT / os.getenv("HTTP_CACHE_DIR", ".cache/http")

TIMEOUT_SECONDS = int(os.getenv("FETCH_TIMEOUT_SECONDS", "25"))
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "24"))
MINIMIZE_COVERED_DOMAINS = os.getenv("MINIMIZE_COVERED_DOMAINS", "true").lower() in {"1", "true", "yes", "on"}
FAIL_ON_URL_ERROR = os.getenv("FAIL_ON_URL_ERROR", "false").lower() in {"1", "true", "yes", "on"}
USER_AGENT = os.getenv(
    "USER_AGENT",
    "technitium-blocklist-merge/2.0 (+https://github.com/DjSni/blocklist)",
)

DOMAIN_RE = re.compile(
    r"^(?:\*\.)?(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)
ADBLOCK_DOMAIN_RE = re.compile(r"^@@?\|\|([^\^/$:*]+)\^?")
HOSTS_IPS = {"0.0.0.0", "127.0.0.1", "::", "::1"}


class ParseResult(NamedTuple):
    blocked: set[str]
    allowed: set[str]
    ignored: int


@dataclass
class SourceResult:
    url: str
    ok: bool
    blocked: set[str]
    allowed: set[str]
    ignored: int
    bytes_read: int = 0
    from_cache: bool = False
    not_modified: bool = False
    elapsed_seconds: float = 0.0
    error: str | None = None


def url_cache_key(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def cache_paths(url: str) -> tuple[Path, Path]:
    key = url_cache_key(url)
    return CACHE_DIR / f"{key}.body", CACHE_DIR / f"{key}.headers.json"


def read_cached_headers(url: str) -> dict[str, str]:
    _, header_path = cache_paths(url)
    if not header_path.exists():
        return {}
    try:
        data = json.loads(header_path.read_text(encoding="utf-8"))
        return {str(k): str(v) for k, v in data.items() if v}
    except (OSError, json.JSONDecodeError):
        return {}


def write_cache(url: str, body: bytes, headers: dict[str, str]) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    body_path, header_path = cache_paths(url)
    body_path.write_bytes(body)
    header_path.write_text(json.dumps(headers, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def iter_cached_lines(url: str) -> Iterator[str] | None:
    body_path, header_path = cache_paths(url)
    if not body_path.exists() or not header_path.exists():
        return None
    headers = read_cached_headers(url)
    encoding = headers.get("content_encoding", "").lower()
    charset = headers.get("charset") or "utf-8"

    def _iter() -> Iterator[str]:
        with body_path.open("rb") as fh:
            stream: io.BufferedIOBase | gzip.GzipFile
            if encoding == "gzip":
                stream = gzip.GzipFile(fileobj=fh)
            else:
                stream = fh
            with io.TextIOWrapper(stream, encoding=charset, errors="replace") as text_stream:
                for line in text_stream:
                    yield line

    return _iter()


def strip_inline_comment(line: str) -> str:
    if "#" in line:
        return line.split("#", 1)[0].strip()
    return line.strip()


def is_ip(value: str) -> bool:
    # Avoid the expensive ipaddress parser for obvious domains.
    v = value.strip("[]")
    if not v or any(ch.isalpha() for ch in v.replace("a", "").replace("b", "").replace("c", "").replace("d", "").replace("e", "").replace("f", "")):
        return False
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def normalize_domain(raw: str) -> str | None:
    d = raw.strip().lower().strip('"\'`').rstrip(".")
    d = d.split("/", 1)[0]
    d = d.split("^", 1)[0]

    if not d or d in {"localhost", "local", "broadcasthost"}:
        return None
    if "://" in d or ":" in d or "@" in d or " " in d or "\t" in d:
        return None
    if is_ip(d):
        return None

    wildcard = d.startswith("*.")
    if wildcard:
        d = d[2:]

    d = d.lstrip(".")
    if not d or ".." in d:
        return None

    try:
        ascii_labels = [label.encode("idna").decode("ascii") for label in d.split(".")]
        d = ".".join(ascii_labels)
    except UnicodeError:
        return None

    normalized = f"*.{d}" if wildcard else d
    if not DOMAIN_RE.match(normalized):
        return None
    return normalized


def parse_line(line: str) -> tuple[str | None, bool]:
    original = line.strip().replace("\ufeff", "")
    if not original:
        return None, False

    if original.startswith(("#", "!", "[", ";")) and not original.startswith("@@"):
        return None, False

    if original.startswith("@@"):
        match = ADBLOCK_DOMAIN_RE.match(original)
        if match:
            return normalize_domain(match.group(1)), True
        return None, False

    match = ADBLOCK_DOMAIN_RE.match(original)
    if match:
        return normalize_domain(match.group(1)), False

    line = strip_inline_comment(original)
    if not line:
        return None, False

    parts = line.split()
    if len(parts) >= 2 and (parts[0] in HOSTS_IPS or is_ip(parts[0])):
        return normalize_domain(parts[1]), False

    if line.startswith("address=/"):
        try:
            domain = line.split("/", 2)[1]
            return normalize_domain(domain), False
        except IndexError:
            return None, False

    if len(parts) >= 3 and parts[1].upper() == "CNAME" and parts[2] == ".":
        return normalize_domain(parts[0]), False

    return normalize_domain(parts[0]), False


def parse_lines(lines: Iterable[str]) -> ParseResult:
    blocked: set[str] = set()
    allowed: set[str] = set()
    ignored = 0

    for line in lines:
        domain, is_allow = parse_line(line)
        if not domain:
            ignored += 1
            continue
        if is_allow:
            allowed.add(domain)
        else:
            blocked.add(domain)

    return ParseResult(blocked=blocked, allowed=allowed, ignored=ignored)


def load_local_list(path: Path) -> ParseResult:
    if not path.exists():
        return ParseResult(set(), set(), 0)
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        return parse_lines(fh)


def load_urls(path: Path) -> list[str]:
    if not path.exists():
        raise FileNotFoundError(f"Missing URL file: {path}")
    urls: list[str] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        urls.append(line)
    return urls


def parse_cached(url: str, *, not_modified: bool, elapsed: float) -> SourceResult | None:
    cached_lines = iter_cached_lines(url)
    if cached_lines is None:
        return None
    parsed = parse_lines(cached_lines)
    body_path, _ = cache_paths(url)
    return SourceResult(
        url=url,
        ok=True,
        blocked=parsed.blocked,
        allowed=parsed.allowed,
        ignored=parsed.ignored,
        bytes_read=body_path.stat().st_size,
        from_cache=True,
        not_modified=not_modified,
        elapsed_seconds=elapsed,
    )


def fetch_and_parse_url(url: str) -> SourceResult:
    started = time.monotonic()
    cached_headers = read_cached_headers(url)
    headers = {
        "User-Agent": USER_AGENT,
        "Accept-Encoding": "gzip",
    }
    if cached_headers.get("etag"):
        headers["If-None-Match"] = cached_headers["etag"]
    if cached_headers.get("last_modified"):
        headers["If-Modified-Since"] = cached_headers["last_modified"]

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as response:
            charset = response.headers.get_content_charset() or "utf-8"
            content_encoding = response.headers.get("Content-Encoding", "").lower()
            body = response.read()
            cache_headers = {
                "etag": response.headers.get("ETag", ""),
                "last_modified": response.headers.get("Last-Modified", ""),
                "content_encoding": content_encoding,
                "charset": charset,
            }
            write_cache(url, body, cache_headers)

        cached = parse_cached(url, not_modified=False, elapsed=time.monotonic() - started)
        if cached is not None:
            return cached
        return SourceResult(url, False, set(), set(), 0, error="failed to read freshly written cache")

    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            cached = parse_cached(url, not_modified=True, elapsed=time.monotonic() - started)
            if cached is not None:
                return cached
        return SourceResult(url, False, set(), set(), 0, elapsed_seconds=time.monotonic() - started, error=f"HTTP {exc.code}: {exc.reason}")
    except (urllib.error.URLError, TimeoutError, OSError, gzip.BadGzipFile) as exc:
        cached = parse_cached(url, not_modified=False, elapsed=time.monotonic() - started)
        if cached is not None:
            # Stale cache is better than failing a whole hourly build due to one upstream timeout.
            return SourceResult(url, True, cached.blocked, cached.allowed, cached.ignored, cached.bytes_read, True, False, time.monotonic() - started, error=f"used stale cache after fetch error: {exc}")
        return SourceResult(url, False, set(), set(), 0, elapsed_seconds=time.monotonic() - started, error=str(exc))


def iter_suffixes(domain: str) -> Iterator[str]:
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        yield ".".join(labels[i:])


class AllowMatcher:
    def __init__(self, rules: set[str]):
        self.normal = {r for r in rules if not r.startswith("*.")}
        self.wildcard = {r[2:] for r in rules if r.startswith("*.")}

    def matches(self, domain: str) -> bool:
        is_wildcard_domain = domain.startswith("*.")
        bare = domain[2:] if is_wildcard_domain else domain

        for suffix in iter_suffixes(bare):
            if suffix in self.normal:
                return True

        for base in self.wildcard:
            if bare.endswith("." + base):
                return True
            if is_wildcard_domain and bare == base:
                return True
        return False


class CoverageMatcher:
    def __init__(self) -> None:
        self.normal: set[str] = set()
        self.wildcard: set[str] = set()

    def is_covered(self, domain: str) -> bool:
        is_wildcard_domain = domain.startswith("*.")
        bare = domain[2:] if is_wildcard_domain else domain

        # A normal Technitium entry covers the root domain and all subdomains.
        for suffix in iter_suffixes(bare):
            if suffix in self.normal:
                return True

        # A wildcard covers subdomains only, not the root domain itself.
        for base in self.wildcard:
            if bare.endswith("." + base):
                return True
            if is_wildcard_domain and bare == base:
                return True
        return False

    def add(self, domain: str) -> None:
        if domain.startswith("*."):
            self.wildcard.add(domain[2:])
        else:
            self.normal.add(domain)


def domain_sort_key(domain: str) -> tuple[int, str]:
    bare = domain[2:] if domain.startswith("*.") else domain
    return (bare.count("."), bare, domain)


def minimize_covered_domains(domains: Iterable[str]) -> set[str]:
    matcher = CoverageMatcher()
    minimized: set[str] = set()
    for domain in sorted(domains, key=domain_sort_key):
        if matcher.is_covered(domain):
            continue
        minimized.add(domain)
        matcher.add(domain)
    return minimized


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_output(domains: Iterable[str], metadata: dict) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    sorted_domains = sorted(domains)
    with OUT_FILE.open("w", encoding="utf-8", newline="\n") as fh:
        for domain in sorted_domains:
            fh.write(domain)
            fh.write("\n")

    metadata["output_file"] = OUT_FILE.name
    metadata["output_size_bytes"] = OUT_FILE.stat().st_size
    metadata["output_sha256"] = sha256_file(OUT_FILE)
    META_FILE.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    urls = load_urls(URLS_FILE)

    all_blocked: set[str] = set()
    all_allowed: set[str] = set()
    failed: list[dict[str, str]] = []
    source_stats: list[dict[str, object]] = []

    manual = load_local_list(MANUAL_BLOCKLIST_FILE)
    all_blocked.update(manual.blocked)
    all_allowed.update(manual.allowed)

    explicit_allow = load_local_list(ALLOWLIST_FILE)
    all_allowed.update(explicit_allow.blocked)
    all_allowed.update(explicit_allow.allowed)

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        for result in pool.map(fetch_and_parse_url, urls):
            if not result.ok:
                failed.append({"url": result.url, "error": result.error or "unknown error"})
                print(f"WARN: failed to fetch {result.url}: {result.error}", file=sys.stderr)
                continue

            all_blocked.update(result.blocked)
            all_allowed.update(result.allowed)
            source_stats.append({
                "url": result.url,
                "blocked_entries": len(result.blocked),
                "embedded_allow_entries": len(result.allowed),
                "ignored_lines": result.ignored,
                "bytes_read": result.bytes_read,
                "from_cache": result.from_cache,
                "not_modified": result.not_modified,
                "elapsed_seconds": round(result.elapsed_seconds, 3),
                "warning": result.error,
            })
            cache_note = " cache" if result.from_cache else " fetch"
            stale_note = " stale" if result.error else ""
            print(f"OK:{cache_note}{stale_note}: {result.url} -> {len(result.blocked)} block, {len(result.allowed)} allow")

    before_allow = len(all_blocked)
    allow_matcher = AllowMatcher(all_allowed)
    after_allow_set = {d for d in all_blocked if not allow_matcher.matches(d)}
    removed_by_allow = before_allow - len(after_allow_set)

    before_minimize = len(after_allow_set)
    if MINIMIZE_COVERED_DOMAINS:
        final_blocked = minimize_covered_domains(after_allow_set)
    else:
        final_blocked = after_allow_set
    removed_by_minimize = before_minimize - len(final_blocked)

    metadata = {
        "generated_at_utc": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "source_url_count": len(urls),
        "source_success_count": len(source_stats),
        "source_failed_count": len(failed),
        "manual_block_entries": len(manual.blocked),
        "allowlist_entries": len(all_allowed),
        "unique_block_entries_before_allowlist": before_allow,
        "removed_by_allowlist": removed_by_allow,
        "unique_block_entries_before_minimize": before_minimize,
        "removed_by_covered_parent_domain": removed_by_minimize,
        "final_block_entries": len(final_blocked),
        "minimize_covered_domains": MINIMIZE_COVERED_DOMAINS,
        "failed_sources": failed,
        "sources": source_stats,
    }

    write_output(final_blocked, metadata)

    print(json.dumps({
        "unique_before_allowlist": before_allow,
        "allowlist_entries": len(all_allowed),
        "removed_by_allowlist": removed_by_allow,
        "removed_by_covered_parent_domain": removed_by_minimize,
        "final_block_entries": len(final_blocked),
        "output_size_bytes": OUT_FILE.stat().st_size,
        "failed_sources": len(failed),
    }, indent=2))

    if FAIL_ON_URL_ERROR and failed:
        return 3
    if urls and len(source_stats) == 0 and len(manual.blocked) == 0:
        print("ERROR: no source list could be fetched and no manual block entries exist", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
