# Technitium Blocklist Merge Repo

Dieses Repo erzeugt automatisch eine deduplizierte DNS-Blocklist für Technitium DNS Server.

## Dateien

```text
src/blocklist-urls.txt        # URLs zu externen Blocklisten, eine URL pro Zeile
src/allowlist.txt             # Whitelist/Allowlist, eine Domain pro Zeile
src/manual-blocklist.txt      # optionale eigene Blockeinträge
dist/technitium-blocklist.txt # generierte finale Liste für Technitium
dist/metadata.json            # Statistik zum letzten Build
```

## Unterstützte Eingabeformate

Das Script akzeptiert gängige DNS-Listenformate:

```text
example.com
*.example.com
0.0.0.0 example.com
127.0.0.1 example.com
||example.com^
@@||allowed.example.com^
address=/example.com/0.0.0.0
example.com CNAME .
```

## Whitelist-Verhalten

Eine normale Allowlist-Domain entfernt die Domain und alle Subdomains aus der finalen Blocklist:

```text
example.com
```

entfernt:

```text
example.com
a.example.com
b.a.example.com
```

Ein Wildcard-Eintrag entfernt nur Subdomains, nicht die Root-Domain:

```text
*.example.com
```

entfernt:

```text
a.example.com
b.a.example.com
```

aber nicht:

```text
example.com
```

## GitHub Actions

Der Workflow läuft stündlich auf Minute 17 UTC und kann zusätzlich manuell unter **Actions → Build Technitium Blocklist → Run workflow** gestartet werden.

Die generierte Datei wird nur committet, wenn sie sich geändert hat.

## Technitium einbinden

In Technitium DNS Server unter **Settings → Blocking → Allow / Block List URLs** die Raw-URL der generierten Datei eintragen:

```text
https://raw.githubusercontent.com/<USER>/<REPO>/main/dist/technitium-blocklist.txt
```

Für GitHub Pages oder einen eigenen CDN-Mirror kannst du dieselbe Datei ebenfalls verwenden.

## Lokal testen

```bash
python3 scripts/merge_blocklists.py
```

Danach liegt die finale Datei hier:

```text
dist/technitium-blocklist.txt
```
