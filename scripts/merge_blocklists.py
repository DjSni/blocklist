#!/usr/bin/env python3
from __future__ import annotations

import concurrent.futures
import datetime as dt
import ipaddress
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterable, NamedTuple

ROOT = Path(__file__).resolve().parents[1]
URLS_FILE = ROOT / "src" / "blocklist-urls.txt"
ALLOWLIST_FILE = ROOT / "src" / "allowlist.txt"
MANUAL_BLOCKLIST_FILE = ROOT / "src" / "manual-blocklist.txt"
OUT_DIR = ROOT / "dist"
OUT_FILE = OUT_DIR / "technitium-blocklist.txt"
META_FILE = OUT_DIR / "metadata.json"

TIMEOUT_SECONDS = int(os.getenv("FETCH_TIMEOUT_SECONDS", "45"))
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "8"))
USER_AGENT = os.getenv(
    "USER_AGENT",
    "technitium-blocklist-merge/1.0 (+https://github.com/)"
)

# Accept common DNS names and a conservative wildcard prefix.
DOMAIN_RE = re.compile(
    r"^(?:\*\.)?(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)

ADBLOCK_DOMAIN_RE = re.compile(r"^@@?\|\|([^\^/$:*]+)\^?")
HOSTS_IPS = {"0.0.0.0", "127.0.0.1", "::", "::1"}


class FetchResult(NamedTuple):
    url: str
    ok: bool
    text: str
    error: str | None = None


class ParseResult(NamedTuple):
    blocked: set[str]
    allowed: set[str]
    ignored: int


def strip_inline_comment(line: str) -> str:
    """Strip safe inline comments for plain/hosts lists.

    We intentionally do not strip '!' because Adblock lists use it as a full-line comment,
    and URLs/domains can legitimately contain no '#'.
    """
    if "#" in line:
        return line.split("#", 1)[0].strip()
    return line.strip()


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def normalize_domain(raw: str) -> str | None:
    d = raw.strip().lower().strip('"\'`').rstrip(".")

    # Remove common ABP/path leftovers if a parser passes too much.
    d = d.split("/", 1)[0]
    d = d.split("^", 1)[0]

    # Ignore obvious non-domain inputs.
    if not d or d in {"localhost", "local", "broadcasthost"}:
        return None
    if "://" in d or ":" in d or "@" in d or " " in d or "\t" in d:
        return None
    if is_ip(d):
        return None

    wildcard = d.startswith("*.")
    if wildcard:
        d = d[2:]

    # Trim leading dot after wildcard/ABP cleanup.
    d = d.lstrip(".")
    if not d or ".." in d:
        return None

    # IDNA-normalize internationalized domains.
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
    """Return (domain, is_allow_rule)."""
    original = line.strip().replace("\ufeff", "")
    if not original:
        return None, False

    # Full-line comments used by common list formats.
    if original.startswith(("#", "!", "[", ";")) and not original.startswith("@@"):
        return None, False

    # Adblock exception rule -> local allow rule.
    if original.startswith("@@"):
        match = ADBLOCK_DOMAIN_RE.match(original)
        if match:
            return normalize_domain(match.group(1)), True
        return None, False

    # Adblock block rule: ||example.com^
    match = ADBLOCK_DOMAIN_RE.match(original)
    if match:
        return normalize_domain(match.group(1)), False

    line = strip_inline_comment(original)
    if not line:
        return None, False

    # hosts format: 0.0.0.0 example.com [aliases...]
    parts = line.split()
    if len(parts) >= 2 and (parts[0] in HOSTS_IPS or is_ip(parts[0])):
        return normalize_domain(parts[1]), False

    # dnsmasq style: address=/example.com/0.0.0.0
    if line.startswith("address=/"):
        try:
            domain = line.split("/", 2)[1]
            return normalize_domain(domain), False
        except IndexError:
            return None, False

    # RPZ-ish: example.com CNAME .
    if len(parts) >= 3 and parts[1].upper() == "CNAME" and parts[2] == ".":
        return normalize_domain(parts[0]), False

    # Plain domain format.
    return normalize_domain(parts[0]), False


def parse_text(text: str) -> ParseResult:
    blocked: set[str] = set()
    allowed: set[str] = set()
    ignored = 0

    for line in text.splitlines():
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
    return parse_text(path.read_text(encoding="utf-8", errors="replace"))


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


def fetch_url(url: str) -> FetchResult:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as response:
            charset = response.headers.get_content_charset() or "utf-8"
            raw = response.read()
            text = raw.decode(charset, errors="replace")
            return FetchResult(url=url, ok=True, text=text)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return FetchResult(url=url, ok=False, text="", error=str(exc))


def is_whitelisted(domain: str, allow_rules: set[str]) -> bool:
    for rule in allow_rules:
        if rule.startswith("*."):
            base = rule[2:]
            if domain.endswith("." + base):
                return True
            continue

        # A root allowlist entry protects the domain and all subdomains.
        if domain == rule or domain.endswith("." + rule):
            return True
    return False


def write_output(domains: Iterable[str], metadata: dict) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    sorted_domains = sorted(domains)
    OUT_FILE.write_text("\n".join(sorted_domains) + ("\n" if sorted_domains else ""), encoding="utf-8")
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
        for result in pool.map(fetch_url, urls):
            if not result.ok:
                failed.append({"url": result.url, "error": result.error or "unknown error"})
                print(f"WARN: failed to fetch {result.url}: {result.error}", file=sys.stderr)
                continue

            parsed = parse_text(result.text)
            all_blocked.update(parsed.blocked)
            all_allowed.update(parsed.allowed)
            source_stats.append({
                "url": result.url,
                "blocked_entries": len(parsed.blocked),
                "embedded_allow_entries": len(parsed.allowed),
                "ignored_lines": parsed.ignored,
            })
            print(f"OK: {result.url} -> {len(parsed.blocked)} block, {len(parsed.allowed)} allow")

    before_allow = len(all_blocked)
    final_blocked = {d for d in all_blocked if not is_whitelisted(d, all_allowed)}
    removed_by_allow = before_allow - len(final_blocked)

    metadata = {
        "generated_at_utc": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "source_url_count": len(urls),
        "source_success_count": len(source_stats),
        "source_failed_count": len(failed),
        "manual_block_entries": len(manual.blocked),
        "allowlist_entries": len(all_allowed),
        "unique_block_entries_before_allowlist": before_allow,
        "removed_by_allowlist": removed_by_allow,
        "final_block_entries": len(final_blocked),
        "failed_sources": failed,
        "sources": source_stats,
    }

    write_output(final_blocked, metadata)

    print(json.dumps({
        "unique_before_allowlist": before_allow,
        "allowlist_entries": len(all_allowed),
        "removed_by_allowlist": removed_by_allow,
        "final_block_entries": len(final_blocked),
        "failed_sources": len(failed),
    }, indent=2))

    # Fail only when nothing useful was generated. Individual URL failures are tolerated
    # so one dead upstream list does not break your complete blocklist.
    if urls and len(source_stats) == 0 and len(manual.blocked) == 0:
        print("ERROR: no source list could be fetched and no manual block entries exist", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
