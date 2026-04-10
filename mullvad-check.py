#!/usr/bin/env python3
"""
Mullvad Exit Reputation Checker

Scans Mullvad WireGuard exit servers against DNSBLs, threat intel feeds,
and fraud scoring to find which exits are clean and usable.

Generates an HTML report + JSON API file. Tracks history with sparklines.

Usage:
    python3 mullvad-check.py                  # Check all cities
    python3 mullvad-check.py --config config.json  # Use custom config

Config file (optional JSON):
    {
        "cities": ["lon", "sto", "nyc"],       // filter to these city codes only
        "proximity": ["lon", "sto", "cph"],    // sort recommended by proximity
        "output_dir": "/var/www/mullvad",       // where to write report files
        "max_workers": 10,                      // concurrent check threads
        "max_history": 336                      // history snapshots to keep (7 days @ 30min)
    }
"""

import json, socket, re, ssl, os, sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict

# ── Config defaults ──────────────────────────────────────────────────────────

DEFAULT_MAX_WORKERS = 10
DEFAULT_MAX_HISTORY = 336  # 7 days at 30min intervals

DNSBLS = [
    ("zen.spamhaus.org", "Spamhaus"),
    ("dnsbl.sorbs.net", "SORBS"),
    ("b.barracudacentral.org", "Barracuda"),
    ("bl.spamcop.net", "SpamCop"),
    ("dnsbl-1.uceprotect.net", "UCEPROTECT"),
]

# All known Mullvad WG city codes → (display name, country code, flag code)
# The script auto-discovers cities from the API; this map provides display names.
# If a city isn't listed here, it still gets checked — just with the raw code as name.
KNOWN_CITIES = {
    "ams": ("Amsterdam", "NL", "nl"),
    "ath": ("Athens", "GR", "gr"),
    "atl": ("Atlanta", "US", "us"),
    "beg": ("Belgrade", "RS", "rs"),
    "ber": ("Berlin", "DE", "de"),
    "bkk": ("Bangkok", "TH", "th"),
    "bma": ("Stockholm", "SE", "se"),
    "bog": ("Bogota", "CO", "co"),
    "bru": ("Brussels", "BE", "be"),
    "bts": ("Bratislava", "SK", "sk"),
    "bud": ("Budapest", "HU", "hu"),
    "chi": ("Chicago", "US", "us"),
    "cph": ("Copenhagen", "DK", "dk"),
    "dal": ("Dallas", "US", "us"),
    "den": ("Denver", "US", "us"),
    "dub": ("Dublin", "IE", "ie"),
    "dus": ("Dusseldorf", "DE", "de"),
    "fra": ("Frankfurt", "DE", "de"),
    "got": ("Gothenburg", "SE", "se"),
    "hel": ("Helsinki", "FI", "fi"),
    "hkg": ("Hong Kong", "HK", "hk"),
    "jnb": ("Johannesburg", "ZA", "za"),
    "lax": ("Los Angeles", "US", "us"),
    "lis": ("Lisbon", "PT", "pt"),
    "lon": ("London", "GB", "gb"),
    "mad": ("Madrid", "ES", "es"),
    "mel": ("Melbourne", "AU", "au"),
    "mia": ("Miami", "US", "us"),
    "mil": ("Milan", "IT", "it"),
    "mma": ("Malmo", "SE", "se"),
    "mrs": ("Marseille", "FR", "fr"),
    "mtr": ("Montreal", "CA", "ca"),
    "nyc": ("New York", "US", "us"),
    "osl": ("Oslo", "NO", "no"),
    "par": ("Paris", "FR", "fr"),
    "prg": ("Prague", "CZ", "cz"),
    "qas": ("Ashburn", "US", "us"),
    "rag": ("Raleigh", "US", "us"),
    "rix": ("Riga", "LV", "lv"),
    "rom": ("Rome", "IT", "it"),
    "sea": ("Seattle", "US", "us"),
    "sin": ("Singapore", "SG", "sg"),
    "sjc": ("San Jose", "US", "us"),
    "slc": ("Salt Lake City", "US", "us"),
    "sof": ("Sofia", "BG", "bg"),
    "sto": ("Stockholm", "SE", "se"),
    "svg": ("Stavanger", "NO", "no"),
    "syd": ("Sydney", "AU", "au"),
    "tia": ("Tirana", "AL", "al"),
    "tky": ("Tokyo", "JP", "jp"),
    "tor": ("Toronto", "CA", "ca"),
    "van": ("Vancouver", "CA", "ca"),
    "vie": ("Vienna", "AT", "at"),
    "war": ("Warsaw", "PL", "pl"),
    "zag": ("Zagreb", "HR", "hr"),
    "zrh": ("Zurich", "CH", "ch"),
}

FLAG_EMOJI = {
    "al": "\U0001f1e6\U0001f1f1", "at": "\U0001f1e6\U0001f1f9",
    "au": "\U0001f1e6\U0001f1fa", "be": "\U0001f1e7\U0001f1ea",
    "bg": "\U0001f1e7\U0001f1ec", "br": "\U0001f1e7\U0001f1f7",
    "ca": "\U0001f1e8\U0001f1e6", "ch": "\U0001f1e8\U0001f1ed",
    "co": "\U0001f1e8\U0001f1f4", "cz": "\U0001f1e8\U0001f1ff",
    "de": "\U0001f1e9\U0001f1ea", "dk": "\U0001f1e9\U0001f1f0",
    "es": "\U0001f1ea\U0001f1f8", "fi": "\U0001f1eb\U0001f1ee",
    "fr": "\U0001f1eb\U0001f1f7", "gb": "\U0001f1ec\U0001f1e7",
    "gr": "\U0001f1ec\U0001f1f7", "hk": "\U0001f1ed\U0001f1f0",
    "hr": "\U0001f1ed\U0001f1f7", "hu": "\U0001f1ed\U0001f1fa",
    "ie": "\U0001f1ee\U0001f1ea", "it": "\U0001f1ee\U0001f1f9",
    "jp": "\U0001f1ef\U0001f1f5", "lv": "\U0001f1f1\U0001f1fb",
    "nl": "\U0001f1f3\U0001f1f1", "no": "\U0001f1f3\U0001f1f4",
    "pl": "\U0001f1f5\U0001f1f1", "pt": "\U0001f1f5\U0001f1f9",
    "ro": "\U0001f1f7\U0001f1f4", "rs": "\U0001f1f7\U0001f1f8",
    "se": "\U0001f1f8\U0001f1ea", "sg": "\U0001f1f8\U0001f1ec",
    "sk": "\U0001f1f8\U0001f1f0", "th": "\U0001f1f9\U0001f1ed",
    "us": "\U0001f1fa\U0001f1f8", "za": "\U0001f1ff\U0001f1e6",
}


def load_config(config_path=None):
    """Load optional config file. Returns dict with defaults filled in."""
    cfg = {
        "cities": None,  # None = all cities
        "proximity": None,  # None = alphabetical
        "output_dir": None,  # None = script directory
        "max_workers": DEFAULT_MAX_WORKERS,
        "max_history": DEFAULT_MAX_HISTORY,
    }
    if config_path and Path(config_path).exists():
        try:
            with open(config_path) as f:
                user_cfg = json.load(f)
            cfg.update({k: v for k, v in user_cfg.items() if k in cfg})
        except (json.JSONDecodeError, OSError) as e:
            print(f"Warning: couldn't load config: {e}", file=sys.stderr)
    return cfg


# ── Data collection ─────────────────────────────────────────────────────────

def fetch_servers(city_filter=None):
    """Fetch active WireGuard servers from Mullvad API.

    Args:
        city_filter: optional list of city codes to include. None = all cities.
    """
    req = urllib.request.Request(
        "https://api.mullvad.net/www/relays/wireguard/",
        headers={"User-Agent": "mullvad-exit-check/1.0"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.load(resp)
    servers = {}
    for s in data:
        city = s.get("city_code", "")
        if not s.get("active"):
            continue
        if city_filter and city not in city_filter:
            continue
        servers.setdefault(city, []).append({
            "hostname": s["hostname"],
            "ip": s["ipv4_addr_in"],
            "owned": s.get("owned", False),
            "provider": s.get("provider", ""),
        })
    return servers


def city_info(city_code):
    """Return (name, country, flag_code) for a city code."""
    if city_code in KNOWN_CITIES:
        return KNOWN_CITIES[city_code]
    return (city_code.upper(), "??", "")


def check_dnsbl(ip, bl_host):
    rev = ".".join(reversed(ip.split(".")))
    try:
        socket.getaddrinfo(f"{rev}.{bl_host}", None, socket.AF_INET, socket.SOCK_STREAM, 0, socket.AI_NUMERICSERV)
        return True
    except socket.gaierror:
        return False


def check_honeypot(ip):
    """Check threat intel DNSBLs (informational)."""
    rev = ".".join(reversed(ip.split(".")))
    results = {}
    for bl, name in [
        ("combined.mail.abusix.zone", "Abusix"),
        ("dnsbl.httpbl.org", "Honeypot"),
        ("cbl.abuseat.org", "CBL"),
        ("xbl.spamhaus.org", "XBL"),
    ]:
        try:
            socket.getaddrinfo(f"{rev}.{bl}", None, socket.AF_INET, socket.SOCK_STREAM, 0, socket.AI_NUMERICSERV)
            results[name] = True
        except socket.gaierror:
            results[name] = False
    return results


def check_mullvad_blacklist(ip):
    """Check Mullvad's own blacklist API for an IP."""
    try:
        req = urllib.request.Request(
            f"https://am.i.mullvad.net/ip/{ip}",
            headers={"User-Agent": "mullvad-exit-check/1.0"},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            text = resp.read().decode()
            return "blacklisted" in text.lower()
    except Exception:
        return None


def check_fraud(ip):
    """Check IP fraud score via Scamalytics (free, no API key needed)."""
    try:
        req = urllib.request.Request(
            f"https://scamalytics.com/ip/{ip}",
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
        )
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=12, context=ctx) as resp:
            html = resp.read().decode()
            m = re.search(r"Fraud Score:\s*(\d+)", html)
            return int(m.group(1)) if m else -1
    except Exception:
        return -1


def check_server(server_info):
    ip = server_info["ip"]
    hostname = server_info["hostname"]
    listed_on = []
    for bl_host, bl_name in DNSBLS:
        if check_dnsbl(ip, bl_host):
            listed_on.append(bl_name)
    fraud = check_fraud(ip)
    threat_intel = check_honeypot(ip)
    extra_lists = [name for name, hit in threat_intel.items() if hit]
    return {
        "hostname": hostname,
        "ip": ip,
        "owned": server_info.get("owned", False),
        "provider": server_info.get("provider", ""),
        "dnsbl": listed_on,
        "threat": extra_lists,
        "fraud": fraud,
        "verdict": get_verdict(listed_on, fraud),
    }


def get_verdict(listed, fraud):
    effective_fraud = fraud if fraud >= 0 else 0
    if listed and effective_fraud >= 50:
        return "BURNED"
    if listed:
        return "RISKY"
    if fraud >= 50:
        return "ELEVATED"
    if fraud >= 25:
        return "FAIR"
    if fraud >= 0 or fraud == -1:
        return "CLEAN" if not listed else "RISKY"
    return "UNKNOWN"


# ── History ─────────────────────────────────────────────────────────────────

def load_history(history_file):
    if history_file.exists():
        try:
            return json.loads(history_file.read_text())
        except (json.JSONDecodeError, OSError):
            return []
    return []


def save_history(history, history_file):
    history_file.write_text(json.dumps(history, separators=(",", ":")))


def append_to_history(results, timestamp, history_file, max_history):
    history = load_history(history_file)
    snapshot = {"ts": timestamp, "servers": {}}
    for city_code, entries in results.items():
        for s in entries:
            snapshot["servers"][s["hostname"]] = s["verdict"]
    history.append(snapshot)
    if len(history) > max_history:
        history = history[-max_history:]
    save_history(history, history_file)
    return history


def compute_trends(history, current_results):
    if len(history) < 2:
        return {}
    SCORE = {"CLEAN": 0, "FAIR": 1, "ELEVATED": 2, "RISKY": 3, "BURNED": 4, "UNKNOWN": 5}
    trends = {}
    recent = history[-7:-1]
    if not recent:
        return {}
    for city_entries in current_results.values():
        for s in city_entries:
            h = s["hostname"]
            now_score = SCORE.get(s["verdict"], 5)
            past_scores = [SCORE.get(snap["servers"].get(h, "UNKNOWN"), 5) for snap in recent]
            if not past_scores:
                continue
            avg_past = sum(past_scores) / len(past_scores)
            diff = now_score - avg_past
            if diff <= -1.0:
                trends[h] = "improving"
            elif diff >= 1.0:
                trends[h] = "degrading"
            else:
                trends[h] = "stable"
    return trends


def compute_last_clean(history):
    last_clean = {}
    for snap in history:
        ts = snap["ts"]
        for hostname, verdict in snap["servers"].items():
            if verdict == "CLEAN":
                last_clean[hostname] = ts
    return last_clean


def compute_history_sparkline(history, hostname):
    points = []
    for snap in history[-24:]:
        v = snap["servers"].get(hostname)
        if v == "CLEAN":
            points.append("G")
        elif v == "FAIR":
            points.append("Y")
        elif v in ("RISKY", "ELEVATED"):
            points.append("O")
        elif v == "BURNED":
            points.append("R")
        else:
            points.append("X")
    return points


# ── HTML generation ─────────────────────────────────────────────────────────

VERDICT_COLORS = {
    "CLEAN": "#22c55e",
    "FAIR": "#a3e635",
    "ELEVATED": "#f97316",
    "RISKY": "#f59e0b",
    "BURNED": "#dc2626",
    "UNKNOWN": "#6b7280",
}


def sparkline_html(points):
    if not points:
        return ""
    cells = ""
    colors = {"G": "#22c55e", "Y": "#a3e635", "O": "#f59e0b", "R": "#dc2626", "X": "#333"}
    for p in points:
        c = colors.get(p, "#333")
        cells += f'<span class="spark-dot" style="background:{c}"></span>'
    return f'<span class="sparkline">{cells}</span>'


def health_gauge(clean_pct):
    import math
    angle = -135 + (clean_pct / 100) * 270
    rad = math.radians(angle)
    cx, cy, r = 60, 60, 45
    sx = cx + r * math.cos(math.radians(-135))
    sy = cy + r * math.sin(math.radians(-135))
    ex = cx + r * math.cos(rad)
    ey = cy + r * math.sin(rad)
    large_arc = 1 if (angle - (-135)) > 180 else 0

    if clean_pct >= 50:
        color = "#22c55e"
    elif clean_pct >= 25:
        color = "#f59e0b"
    else:
        color = "#dc2626"

    return f"""<svg width="120" height="80" viewBox="0 0 120 80">
      <path d="M {sx:.1f} {sy:.1f} A {r} {r} 0 1 1 {cx + r * math.cos(math.radians(135)):.1f} {cy + r * math.sin(math.radians(135)):.1f}"
            fill="none" stroke="#262626" stroke-width="8" stroke-linecap="round"/>
      <path d="M {sx:.1f} {sy:.1f} A {r} {r} 0 {large_arc} 1 {ex:.1f} {ey:.1f}"
            fill="none" stroke="{color}" stroke-width="8" stroke-linecap="round"/>
      <text x="60" y="58" text-anchor="middle" fill="{color}" font-size="22" font-weight="700">{clean_pct:.0f}%</text>
      <text x="60" y="74" text-anchor="middle" fill="#737373" font-size="9">usable</text>
    </svg>"""


def generate_html(results, timestamp, history, trends, last_clean, proximity_order):
    VERDICT_ORDER = {"CLEAN": 0, "FAIR": 1, "ELEVATED": 2, "RISKY": 3, "BURNED": 4, "UNKNOWN": 5}

    total_servers = 0
    total_clean = 0
    total_fair = 0
    all_servers = []

    city_data = []
    for city_code, entries in results.items():
        name, country, flag_code = city_info(city_code)
        flag = FLAG_EMOJI.get(flag_code, "")
        prox = proximity_order.index(city_code) if city_code in proximity_order else 99
        counts = defaultdict(int)
        rows = []

        for s in entries:
            v = s["verdict"]
            color = VERDICT_COLORS.get(v, "#6b7280")
            dnsbl_str = ", ".join(s["dnsbl"]) if s["dnsbl"] else "None"
            threat_list = s.get("threat", [])
            threat_str = ", ".join(threat_list) if threat_list else "None"
            threat_count = len(threat_list)
            fraud = s["fraud"]
            hostname = s["hostname"]
            owned = s.get("owned", False)
            provider = s.get("provider", "")
            trend = trends.get(hostname, "")
            lc = last_clean.get(hostname, "")
            spark = sparkline_html(compute_history_sparkline(history, hostname))
            counts[v] += 1
            total_servers += 1
            if v == "CLEAN":
                total_clean += 1
            if v == "FAIR":
                total_fair += 1

            trend_html = ""
            if trend == "improving":
                trend_html = '<span class="trend up" title="Improving">&#9650;</span>'
            elif trend == "degrading":
                trend_html = '<span class="trend down" title="Degrading">&#9660;</span>'

            lc_html = ""
            if lc and v != "CLEAN":
                lc_html = f'<span class="last-clean" title="Last clean: {lc}">{lc[:10]}</span>'

            owned_html = '<span class="owned-badge" title="Mullvad-owned">MV</span>' if owned else f'<span class="rented-badge" title="{provider}">{provider[:8] if provider else "3P"}</span>'

            threat_color = f'color:var(--orange);' if threat_count >= 3 else f'color:var(--yellow);' if threat_count >= 1 else 'color:var(--muted);'
            rows.append((
                VERDICT_ORDER.get(v, 5), fraud, hostname,
                f'<tr class="verdict-{v.lower()}">'
                f'<td>{hostname} {trend_html}</td>'
                f'<td><code>{s["ip"]}</code></td>'
                f'<td class="mono">{fraud if fraud >= 0 else "?"}</td>'
                f'<td class="owner-cell">{owned_html}</td>'
                f'<td class="dnsbl-cell">{dnsbl_str}</td>'
                f'<td class="threat-cell" style="{threat_color}">{threat_str}</td>'
                f'<td style="color:{color};font-weight:700">{v}</td>'
                f'<td>{spark}</td>'
                f'<td class="lc-cell">{lc_html}</td>'
                f'</tr>'
            ))

            if v in ("CLEAN", "FAIR"):
                all_servers.append((prox, VERDICT_ORDER.get(v, 5), fraud, threat_count, hostname, s["ip"], name, flag, v, color, trend_html, spark, owned, provider))

        rows.sort(key=lambda r: (r[0], r[1], r[2]))
        html_rows = [r[3] for r in rows]

        city_data.append({
            "code": city_code,
            "name": name,
            "flag": flag,
            "prox": prox,
            "rows": html_rows,
            "counts": dict(counts),
            "total": len(entries),
            "clean": counts.get("CLEAN", 0),
            "usable": counts.get("CLEAN", 0) + counts.get("FAIR", 0),
        })

    city_data.sort(key=lambda c: (-c["clean"], -c["usable"], c["prox"]))

    clean_pct = ((total_clean + total_fair) / total_servers * 100) if total_servers else 0
    gauge_svg = health_gauge(clean_pct)

    # Recommended box
    all_servers.sort(key=lambda s: (s[0], s[1], s[2]))
    rec_rows = ""
    for prox, vo, fraud, tc, hostname, ip, city_name, flag, v, color, trend_html, spark, owned, provider in all_servers[:15]:
        threat_indicator = f'<span style="color:var(--orange)">{tc}</span>' if tc else '<span style="color:var(--muted)">0</span>'
        owner_badge = '<span class="owned-badge">MV</span>' if owned else f'<span class="rented-badge">{provider[:6] if provider else "3P"}</span>'
        rec_rows += (
            f'<tr>'
            f'<td style="color:{color};font-weight:600">{hostname} {trend_html}</td>'
            f'<td><code>{ip}</code></td>'
            f'<td>{flag} {city_name}</td>'
            f'<td>{owner_badge}</td>'
            f'<td class="mono">{fraud}</td>'
            f'<td class="mono">{threat_indicator}</td>'
            f'<td style="color:{color};font-weight:700">{v}</td>'
            f'<td>{spark}</td>'
            f'</tr>'
        )
    if rec_rows:
        rec_box = f"""
        <div class="recommended">
            <div class="rec-header">
                <div>
                    <h2>Recommended Exits</h2>
                    <p class="rec-sub">Top {min(len(all_servers), 15)} usable servers sorted by proximity &mdash; {total_clean} clean, {total_fair} fair out of {total_servers}</p>
                </div>
            </div>
            <table>
                <tr><th>Server</th><th>IP</th><th>City</th><th>Owner</th><th>Fraud</th><th>Threats</th><th>Verdict</th><th>History</th></tr>
                {rec_rows}
            </table>
        </div>"""
    else:
        rec_box = f"""
        <div class="recommended warn">
            <h2>No Clean Exits Available</h2>
            <p class="rec-sub">All {total_servers} servers are DNSBL-listed or have elevated fraud scores. Consider trying different cities.</p>
        </div>"""

    # City sections
    sections = ""
    for c in city_data:
        badges = ""
        for vname in ["CLEAN", "FAIR", "ELEVATED", "RISKY", "BURNED"]:
            cnt = c["counts"].get(vname, 0)
            if cnt:
                badges += f' <span class="badge {vname.lower()}">{cnt} {vname.lower()}</span>'
        pct = (c["usable"] / c["total"] * 100) if c["total"] else 0
        bar_color = "#22c55e" if pct >= 50 else "#f59e0b" if pct >= 20 else "#dc2626" if pct > 0 else "#333"

        sections += f"""
        <details class="city">
            <summary>
                <span class="city-name">{c['flag']} {c['name']}</span>
                <span class="count">{c['total']} servers</span>
                <span class="mini-bar"><span class="mini-fill" style="width:{pct:.0f}%;background:{bar_color}"></span></span>
                {badges}
            </summary>
            <table>
                <tr><th>Server</th><th>IP</th><th>Fraud</th><th>Owner</th><th>DNSBL</th><th>Threat Intel</th><th>Verdict</th><th>History</th><th>Last Clean</th></tr>
                {"".join(c['rows'])}
            </table>
        </details>"""

    history_note = ""
    if len(history) > 1:
        first_ts = history[0]["ts"]
        history_note = f' &mdash; Tracking since {first_ts[:10]} ({len(history)} snapshots)'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="1800">
<title>Mullvad Exit Reputation</title>
<style>
  :root {{
    --bg: #09090b; --card: #111113; --card-hover: #18181b;
    --border: #27272a; --text: #e4e4e7; --muted: #71717a;
    --green: #22c55e; --green-dim: #052e16;
    --yellow: #f59e0b; --yellow-dim: #451a03;
    --orange: #f97316; --orange-dim: #431407;
    --red: #dc2626; --red-dim: #450a0a;
    --lime: #a3e635;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    background: var(--bg); color: var(--text);
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    padding: 1.2rem; max-width: 1100px; margin: 0 auto;
  }}
  .header {{ display: flex; align-items: center; gap: 1.2rem; margin-bottom: 1rem; flex-wrap: wrap; }}
  .header-text h1 {{ font-size: 1.5rem; font-weight: 700; letter-spacing: -0.02em; }}
  .header-text .sub {{ color: var(--muted); font-size: .82rem; margin-top: .15rem; }}
  .gauge {{ flex-shrink: 0; }}
  .filters {{
    display: flex; gap: .4rem; margin-bottom: 1rem; flex-wrap: wrap;
    padding: .5rem .7rem; background: var(--card); border: 1px solid var(--border);
    border-radius: 8px; align-items: center;
  }}
  .filters label {{ color: var(--muted); font-size: .78rem; margin-right: .3rem; }}
  .filter-btn {{
    background: transparent; border: 1px solid var(--border); color: var(--text);
    padding: .25rem .65rem; border-radius: 6px; font-size: .78rem; cursor: pointer;
    transition: all .15s;
  }}
  .filter-btn:hover {{ background: var(--card-hover); }}
  .filter-btn.active {{ background: var(--green-dim); border-color: var(--green); color: var(--green); }}
  .recommended {{
    background: linear-gradient(135deg, #0a1a0a 0%, #0d1f0d 100%);
    border: 1px solid #166534; border-radius: 10px;
    padding: 1rem 1.2rem; margin-bottom: 1rem;
  }}
  .recommended h2 {{ font-size: 1.05rem; color: var(--green); margin-bottom: .1rem; }}
  .recommended.warn {{
    background: linear-gradient(135deg, #1a0a0a 0%, #1f0d0d 100%);
    border-color: var(--red);
  }}
  .recommended.warn h2 {{ color: var(--red); }}
  .rec-header {{ display: flex; justify-content: space-between; align-items: flex-start; }}
  .rec-sub {{ color: var(--muted); font-size: .8rem; margin-bottom: .7rem; }}
  .city {{
    background: var(--card); border: 1px solid var(--border);
    border-radius: 8px; margin-bottom: .4rem;
    transition: border-color .15s;
  }}
  .city:hover {{ border-color: #3f3f46; }}
  .city summary {{
    font-size: .95rem; font-weight: 600; padding: .65rem 1rem;
    cursor: pointer; display: flex; align-items: center; gap: .5rem;
    flex-wrap: wrap; list-style: none; user-select: none;
  }}
  .city summary::-webkit-details-marker {{ display: none; }}
  .city summary::before {{
    content: "\\25b6"; font-size: .6rem; color: var(--muted);
    transition: transform .15s; flex-shrink: 0;
  }}
  .city[open] summary::before {{ transform: rotate(90deg); }}
  .city[open] {{ border-color: #3f3f46; }}
  .city table {{ margin: 0 .8rem .8rem; width: calc(100% - 1.6rem); }}
  .city-name {{ min-width: 120px; }}
  .count {{ color: var(--muted); font-weight: 400; font-size: .82rem; }}
  .mini-bar {{
    width: 50px; height: 4px; background: #27272a; border-radius: 2px;
    overflow: hidden; flex-shrink: 0;
  }}
  .mini-fill {{ height: 100%; border-radius: 2px; transition: width .3s; }}
  table {{ width: 100%; border-collapse: collapse; font-size: .82rem; }}
  th {{
    text-align: left; padding: .35rem .5rem;
    border-bottom: 1px solid var(--border); color: var(--muted);
    font-weight: 500; font-size: .75rem; text-transform: uppercase; letter-spacing: .04em;
  }}
  td {{ padding: .3rem .5rem; border-bottom: 1px solid #1e1e1e; }}
  tr:last-child td {{ border-bottom: none; }}
  code {{
    background: #1a1a1e; padding: .1rem .4rem; border-radius: 3px;
    font-size: .78rem; font-family: 'JetBrains Mono', 'Fira Code', monospace;
  }}
  .mono {{ font-family: 'JetBrains Mono', monospace; text-align: center; }}
  .dnsbl-cell {{ max-width: 140px; font-size: .75rem; }}
  .threat-cell {{ max-width: 130px; font-size: .75rem; }}
  .owner-cell {{ white-space: nowrap; }}
  .owned-badge {{
    background: #1e3a5f; color: #60a5fa; font-size: .68rem; font-weight: 700;
    padding: .1rem .4rem; border-radius: 3px; letter-spacing: .03em;
  }}
  .rented-badge {{
    background: #27272a; color: var(--muted); font-size: .68rem; font-weight: 500;
    padding: .1rem .4rem; border-radius: 3px;
  }}
  .lc-cell {{ font-size: .72rem; color: var(--muted); }}
  .last-clean {{ opacity: .7; }}
  .badge {{
    font-size: .65rem; padding: .12rem .45rem; border-radius: 99px;
    font-weight: 600; letter-spacing: .02em;
  }}
  .badge.clean {{ background: var(--green-dim); color: var(--green); }}
  .badge.fair {{ background: #1a2e05; color: var(--lime); }}
  .badge.risky {{ background: var(--yellow-dim); color: var(--yellow); }}
  .badge.elevated {{ background: var(--orange-dim); color: var(--orange); }}
  .badge.burned {{ background: var(--red-dim); color: var(--red); }}
  .legend {{
    display: flex; gap: .8rem; margin-bottom: 1rem; flex-wrap: wrap;
    font-size: .78rem; color: var(--muted);
  }}
  .legend span {{ display: flex; align-items: center; gap: .25rem; }}
  .dot {{ width: 8px; height: 8px; border-radius: 50%; display: inline-block; }}
  .sparkline {{ display: inline-flex; gap: 1px; align-items: center; }}
  .spark-dot {{ width: 4px; height: 12px; border-radius: 1px; display: inline-block; }}
  .trend {{ font-size: .65rem; margin-left: .3rem; }}
  .trend.up {{ color: var(--green); }}
  .trend.down {{ color: var(--red); }}
  .footer {{ color: var(--muted); font-size: .72rem; margin-top: 1.2rem; padding-top: .8rem; border-top: 1px solid var(--border); }}
  tbody tr:hover, table tr:hover {{ background: rgba(255,255,255,.02); }}
  body.filter-clean .verdict-risky,
  body.filter-clean .verdict-burned,
  body.filter-clean .verdict-elevated,
  body.filter-clean .verdict-fair,
  body.filter-clean .verdict-unknown {{ display: none; }}
  body.filter-usable .verdict-burned,
  body.filter-usable .verdict-risky,
  body.filter-usable .verdict-elevated,
  body.filter-usable .verdict-unknown {{ display: none; }}
  @media (max-width: 640px) {{
    body {{ padding: .8rem; }}
    .header {{ flex-direction: column; align-items: flex-start; }}
    .city summary {{ font-size: .85rem; padding: .5rem .7rem; }}
    .lc-cell, th:last-child {{ display: none; }}
    td:last-child {{ display: none; }}
  }}
</style>
</head>
<body>

<div class="header">
    <div class="gauge">{gauge_svg}</div>
    <div class="header-text">
        <h1>Mullvad Exit Reputation</h1>
        <div class="sub">Updated {timestamp}{history_note}</div>
        <div class="sub">{total_servers} servers across {len(city_data)} cities &mdash; {total_clean} clean, {total_fair} fair</div>
    </div>
</div>

<div class="filters">
    <label>Filter:</label>
    <button class="filter-btn active" onclick="setFilter('',this)">All ({total_servers})</button>
    <button class="filter-btn" onclick="setFilter('clean',this)">Clean only ({total_clean})</button>
    <button class="filter-btn" onclick="setFilter('usable',this)">Usable ({total_clean + total_fair})</button>
</div>

<div class="legend">
  <span><span class="dot" style="background:var(--green)"></span> Clean</span>
  <span><span class="dot" style="background:var(--lime)"></span> Fair</span>
  <span><span class="dot" style="background:var(--orange)"></span> Elevated</span>
  <span><span class="dot" style="background:var(--yellow)"></span> Risky</span>
  <span><span class="dot" style="background:var(--red)"></span> Burned</span>
  <span style="margin-left:.5rem">|</span>
  <span>Sparkline = last {min(len(history), 24)} checks</span>
</div>

{rec_box}
{sections}

<div class="footer">
    DNSBLs: {', '.join(n for _, n in DNSBLS)} | Fraud scoring: Scamalytics | Threat intel: Abusix, Honeypot, CBL, XBL<br>
    Auto-refreshes every 30 minutes | <a href="https://github.com/Scanner771/mullvad-exit-check" style="color:var(--muted)">mullvad-exit-check</a>
</div>

<script>
function setFilter(mode, el) {{
    document.body.className = mode ? 'filter-' + mode : '';
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    el.classList.add('active');
    document.querySelectorAll('details.city').forEach(d => {{
        const allRows = d.querySelectorAll('tr[class^="verdict-"]');
        let shown = 0;
        allRows.forEach(r => {{ if (getComputedStyle(r).display !== 'none') shown++; }});
        d.style.display = shown === 0 ? 'none' : '';
    }});
}}
</script>
</body>
</html>"""


# ── JSON API ────────────────────────────────────────────────────────────────

def generate_api_json(results, timestamp, trends, proximity_order):
    """Generate a compact JSON summary."""
    VERDICT_ORDER = {"CLEAN": 0, "FAIR": 1, "ELEVATED": 2, "RISKY": 3, "BURNED": 4, "UNKNOWN": 5}

    total = 0
    total_clean = 0
    total_usable = 0
    recommended = []

    for city_code, entries in results.items():
        name, country, flag_code = city_info(city_code)
        prox = proximity_order.index(city_code) if city_code in proximity_order else 99

        for s in entries:
            total += 1
            v = s["verdict"]
            if v == "CLEAN":
                total_clean += 1
            if v in ("CLEAN", "FAIR"):
                total_usable += 1
                trend = trends.get(s["hostname"], "stable")
                recommended.append({
                    "rank": prox,
                    "vo": VERDICT_ORDER.get(v, 5),
                    "hostname": s["hostname"],
                    "ip": s["ip"],
                    "city": name,
                    "country": flag_code.upper(),
                    "fraud": s["fraud"],
                    "verdict": v,
                    "owned": s.get("owned", False),
                    "provider": s.get("provider", ""),
                    "trend": trend,
                    "threats": len(s.get("threat", [])),
                })

    recommended.sort(key=lambda s: (s["rank"], s["vo"], s["fraud"]))
    health_pct = round((total_usable / total * 100), 1) if total else 0

    return {
        "updated": timestamp,
        "total_servers": total,
        "clean": total_clean,
        "usable": total_usable,
        "health_pct": health_pct,
        "recommended": recommended[:10],
    }


# ── Main ────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Mullvad Exit IP Reputation Checker")
    parser.add_argument("--config", help="Path to config.json", default=None)
    parser.add_argument("--output-dir", help="Directory for output files", default=None)
    parser.add_argument("--cities", nargs="+", help="City codes to check (e.g. lon sto nyc)", default=None)
    args = parser.parse_args()

    cfg = load_config(args.config)

    # CLI args override config file
    city_filter = args.cities or cfg["cities"]
    output_dir = Path(args.output_dir) if args.output_dir else (Path(cfg["output_dir"]) if cfg["output_dir"] else Path(__file__).parent)
    max_workers = cfg["max_workers"]
    max_history = cfg["max_history"]

    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "mullvad-report.html"
    api_file = output_dir / "mullvad-api.json"
    history_file = output_dir / "mullvad-history.json"

    # Build proximity order from config or auto-detect
    if cfg["proximity"]:
        proximity_order = cfg["proximity"]
    else:
        # Default: alphabetical by city code
        proximity_order = sorted(KNOWN_CITIES.keys())

    print("Fetching Mullvad server list...", flush=True)
    servers = fetch_servers(city_filter)
    total = sum(len(v) for v in servers.values())
    if total == 0:
        print("No servers found. Check your city filter or network connection.")
        sys.exit(1)
    print(f"Checking {total} servers across {len(servers)} cities...", flush=True)

    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {}
        for city, svrs in servers.items():
            for s in svrs:
                f = ex.submit(check_server, s)
                futures[f] = city

        done = 0
        for f in as_completed(futures):
            city = futures[f]
            result = f.result()
            results.setdefault(city, []).append(result)
            done += 1
            if done % 10 == 0:
                print(f"  {done}/{total}...", flush=True)

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # History
    history = append_to_history(results, ts, history_file, max_history)
    trends = compute_trends(history, results)
    last_clean = compute_last_clean(history)

    # Generate HTML
    html = generate_html(results, ts, history, trends, last_clean, proximity_order)
    output_file.write_text(html)

    # Generate JSON API
    api_data = generate_api_json(results, ts, trends, proximity_order)
    api_file.write_text(json.dumps(api_data, indent=2))

    print(f"\nReport: {output_file}")
    print(f"API:    {api_file}")
    print(f"History: {len(history)} snapshots in {history_file}")

    for city_code, entries in sorted(results.items()):
        name = city_info(city_code)[0]
        clean = sum(1 for s in entries if s["verdict"] == "CLEAN")
        usable = sum(1 for s in entries if s["verdict"] in ("CLEAN", "FAIR"))
        print(f"  {name}: {clean} clean, {usable} usable / {len(entries)}")


if __name__ == "__main__":
    main()
