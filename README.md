# mullvad-exit-check

[![Check Mullvad Exits](https://github.com/Scanner771/mullvad-exit-check/actions/workflows/check.yml/badge.svg)](https://github.com/Scanner771/mullvad-exit-check/actions/workflows/check.yml)

Scans Mullvad VPN WireGuard exit servers against DNSBLs, threat intelligence feeds, and the AbuseIPDB abuse-confidence database. Generates an interactive HTML report showing which exits are clean and safe to use.

**[View live report](https://scanner771.github.io/mullvad-exit-check/)** — checks every 30 minutes, always up to date.

## Why?

Mullvad exit IPs get burned by Cloudflare and other services regularly. You'll hit CAPTCHAs, blocks, or degraded service depending on which server you land on. This tool checks every exit so you know which ones are clean before connecting.

## What it checks

| Source | Type | Impact on verdict |
|--------|------|-------------------|
| Spamhaus, SORBS, Barracuda, SpamCop, UCEPROTECT | DNSBL | Direct (RISKY/BURNED) |
| AbuseIPDB | Abuse confidence (0–100) | Direct (FAIR/ELEVATED) — requires `ABUSEIPDB_API_KEY` |
| Abusix, Project Honeypot, CBL, XBL | Threat intel | Informational only |

### Verdict scale

- **CLEAN** - No DNSBL listings, low confidence (<25)
- **FAIR** - No DNSBL listings, moderate confidence (25-49)
- **ELEVATED** - No DNSBL listings, high confidence (50+)
- **RISKY** - DNSBL listed
- **BURNED** - DNSBL listed + high confidence

> Without an AbuseIPDB key, the fraud column is empty and the verdict reduces to **CLEAN** (no DNSBL hits) or **RISKY** (one or more hits). The HTML header shows a "DISABLED" pill for AbuseIPDB so this is visible. When a data source starts failing the same pill flips to "DEGRADED" or "DOWN" — so silent regressions stop being silent.

## Quick start

```bash
# No dependencies beyond Python 3.7+ (stdlib only)
git clone https://github.com/Scanner771/mullvad-exit-check.git
cd mullvad-exit-check

# Optional: enable AbuseIPDB fraud lookups (free tier = 1000/day,
# results are cached 24h per IP so the script naturally fits the limit)
export ABUSEIPDB_API_KEY="your-key-from-abuseipdb.com"

# Check all cities (takes 2-5 minutes depending on server count)
python3 mullvad-check.py

# Check specific cities only
python3 mullvad-check.py --cities lon sto nyc

# Use a config file
python3 mullvad-check.py --config config.json

# Output to a specific directory
python3 mullvad-check.py --output-dir /var/www/mullvad
```

Open `mullvad-report.html` in a browser to see the results. The report auto-refreshes every 30 minutes if served over HTTP.

## Configuration

Create a `config.json` to customize behavior:

```json
{
    "cities": ["lon", "ams", "fra", "par", "sto", "cph"],
    "proximity": ["lon", "ams", "par", "fra", "cph", "sto"],
    "output_dir": "/var/www/mullvad",
    "max_workers": 10,
    "max_history": 336
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `cities` | all | City codes to check. Omit to check every Mullvad WG city |
| `proximity` | alphabetical | Order for "Recommended Exits" sorting (closest first) |
| `output_dir` | script dir | Where to write report.html, api.json, history.json |
| `max_workers` | 10 | Concurrent threads for IP checks |
| `max_history` | 336 | Snapshots to retain (336 = 7 days at 30min intervals) |

### City codes

Common codes (the script auto-discovers from Mullvad's API, these are just for filtering):

| Region | Cities |
|--------|--------|
| UK/Ireland | `lon` (London), `dub` (Dublin) |
| Nordics | `sto` (Stockholm), `got` (Gothenburg), `mma` (Malmo), `hel` (Helsinki), `osl` (Oslo), `svg` (Stavanger), `cph` (Copenhagen) |
| Western Europe | `ams` (Amsterdam), `fra` (Frankfurt), `par` (Paris), `bru` (Brussels), `zrh` (Zurich) |
| Southern Europe | `mad` (Madrid), `lis` (Lisbon), `mil` (Milan), `rom` (Rome), `ath` (Athens) |
| Eastern Europe | `war` (Warsaw), `prg` (Prague), `bud` (Budapest), `beg` (Belgrade), `vie` (Vienna) |
| US | `nyc`, `chi` (Chicago), `dal` (Dallas), `lax` (Los Angeles), `sea` (Seattle), `mia` (Miami), `den` (Denver), `sjc` (San Jose), `atl` (Atlanta) |
| Canada | `tor` (Toronto), `van` (Vancouver), `mtr` (Montreal) |
| Asia-Pacific | `tky` (Tokyo), `sin` (Singapore), `hkg` (Hong Kong), `syd` (Sydney), `mel` (Melbourne) |

## Running on a schedule

### systemd timer (Linux)

```bash
# Copy the service files
sudo cp systemd/mullvad-check.service /etc/systemd/system/
sudo cp systemd/mullvad-check.timer /etc/systemd/system/

# Edit the service file to set the correct path and user
sudo systemctl edit mullvad-check.service

# Enable and start
sudo systemctl enable --now mullvad-check.timer
```

### cron

```bash
# Run every 30 minutes
*/30 * * * * /usr/bin/python3 /path/to/mullvad-check.py --config /path/to/config.json
```

### Serving the report

Any static file server works. Quick option with Python:

```bash
cd /path/to/output-dir
python3 -m http.server 8099
```

Or with nginx, Caddy, etc. — just point at the directory containing `mullvad-report.html`.

## Output files

| File | Description |
|------|-------------|
| `mullvad-report.html` | Interactive HTML report with filters, sparklines, and health gauge |
| `mullvad-api.json` | JSON API with all servers, top 15 recommended, health stats, and per-source health |
| `feed.xml` | Atom feed with health status (subscribe in any RSS reader) |
| `mullvad-history.json` | Rolling history for trend computation (not human-readable) |
| `mullvad-fraud-cache.json` | Per-IP AbuseIPDB scores with 24h TTL (regenerated as needed) |

### JSON API format

The API includes summary stats, top 10 recommended servers, and the full server list:

```json
{
    "updated": "2026-04-10 12:00 UTC",
    "total_servers": 135,
    "clean": 64,
    "usable": 78,
    "health_pct": 57.8,
    "recommended": [
        {
            "hostname": "gb-lon-wg-001",
            "ip": "...",
            "city": "London",
            "country": "GB",
            "fraud": 3,
            "verdict": "CLEAN",
            "owned": true,
            "provider": "",
            "trend": "stable",
            "threats": 0,
            "dnsbl": [],
            "features": ["DAITA", "SOCKS5"]
        }
    ],
    "servers": [ ... ],
    "sources": {
        "groups": {
            "DNSBLs":       {"ok": 2660, "fail": 0, "cached": 0, "skipped": 0, "status": "ok"},
            "Threat intel": {"ok": 2128, "fail": 0, "cached": 0, "skipped": 0, "status": "ok"},
            "AbuseIPDB":    {"ok": 22,   "fail": 0, "cached": 511, "skipped": 0, "status": "ok"}
        },
        "sources": { "dnsbl:zen.spamhaus.org": {...}, "abuseipdb": {...} }
    }
}
```

The `sources` block surfaces silent regressions: status flips to `degraded` (≥50% failure) or `down` (≥90% failure), and the same status is rendered as a coloured pill in the HTML header. The workflow also emits a `::warning::` annotation when any group is degraded or down so it shows up in the Actions run summary.

## Report features

- Health gauge showing overall % of usable exits
- Per-source health pills (DNSBLs / Threat intel / AbuseIPDB) so a broken data source is visible at a glance
- Recommended exits sorted by proximity to you (auto-detected from timezone)
- Filter buttons: All / Clean only / Usable (clean + fair)
- Feature filters: SOCKS5, DAITA, Multihop, IPv6, Mullvad-owned (with AND/OR toggle)
- Collapsible country/city sections with mini progress bars
- Per-server: fraud score, DNSBL status (with tooltips), threat intel hits, owned/rented badge
- Sparkline history (last 24 checks)
- Trend arrows (improving/degrading/stable)
- Last-clean date for currently dirty servers
- Click-to-copy hostnames
- Permalink anchors: link directly to a country (`#gb`) or city (`#city-lon`)
- Export as `.txt` (hostnames) or `.csv` (full dataset)
- Dynamic favicon with health %
- Mobile responsive, dark theme
- OpenGraph meta tags for social sharing previews

## Docker

```bash
# Build
docker build -t mullvad-check .

# Run once, output to ./public
docker run --rm -v ./public:/data mullvad-check

# Check specific cities
docker run --rm -v ./public:/data mullvad-check --cities lon sto nyc

# Run on a schedule with cron or systemd timer
*/30 * * * * docker run --rm -v /var/www/mullvad:/data mullvad-check
```

## Requirements

- Python 3.7+
- No external dependencies (stdlib only)
- DNS resolution must work (for DNSBL lookups)
- Outbound HTTPS to `api.mullvad.net` and (optionally) `api.abuseipdb.com`

### Running in CI

The repo's GitHub Action runs every 30 min and publishes to GitHub Pages. To enable the AbuseIPDB lookups when forking, add `ABUSEIPDB_API_KEY` under **Settings → Secrets and variables → Actions → New repository secret**. Without it the workflow still runs but the fraud column stays empty — the source-health pill will read DISABLED so consumers know.

## License

MIT
