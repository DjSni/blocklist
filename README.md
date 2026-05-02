# Technitium Blocklist Merge Repo

Dieses Repo erzeugt automatisch eine deduplizierte DNS-Blocklist für Technitium DNS Server.

Die finale Blockliste wird **nicht mehr ins Git-Repo committed**, weil große Listen schnell über GitHubs 100-MiB-Dateilimit laufen. Stattdessen wird die Datei als Asset in das GitHub Release `latest` hochgeladen.

## Dateien

```text
src/blocklist-urls.txt        # URLs zu externen Blocklisten, eine URL pro Zeile
src/allowlist.txt             # Whitelist/Allowlist, eine Domain pro Zeile
src/manual-blocklist.txt      # optionale eigene Blockeinträge
scripts/merge_blocklists.py   # Parser, Dedupe, Allowlist, Minimierung
.github/workflows/build-blocklist.yml
```

## Fertige Technitium-URL

Nach dem ersten erfolgreichen Workflow-Lauf ist die Datei hier erreichbar:

```text
https://github.com/<USER>/<REPO>/releases/download/latest/technitium-blocklist.txt
```

Für dein Repo also z. B.:

```text
https://github.com/DjSni/blocklist/releases/download/latest/technitium-blocklist.txt
```

Diese URL trägst du in Technitium unter **Settings → Blocking → Allow / Block List URLs** ein.

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

## Größenoptimierung

Das Script entfernt doppelte Einträge und zusätzlich Einträge, die bereits durch einen Parent-Domain-Eintrag abgedeckt sind. Beispiel:

```text
example.com
a.example.com
b.a.example.com
```

wird zu:

```text
example.com
```

Das passt zu Technitium, weil ein normaler Blockeintrag die Domain und ihre Subdomains abdeckt.

## Unterstützte Eingabeformate

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

## GitHub Actions

Der Workflow läuft stündlich auf Minute 17 UTC und kann zusätzlich manuell unter **Actions → Build Technitium Blocklist → Run workflow** gestartet werden.

Das Script nutzt einen GitHub-Actions-Cache für heruntergeladene Quellen und sendet bei unterstützten Servern `If-None-Match` / `If-Modified-Since` Header. Dadurch werden unveränderte Quellen nicht jedes Mal vollständig neu geladen.
