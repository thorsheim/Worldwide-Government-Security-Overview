# CLAUDE.md — govmap developer guide

## What this project does

Interactive world map showing DNS/email security scores for every country's government domain (~210 entries). Country polygons are colored red→green by score (0–100). Clicking a country opens a per-check results sidebar. A burger (☰) menu shows global stats and top/bottom 10 rankings.

## File roles

| File | Role |
|------|------|
| `index.html` | Single-page app shell; Leaflet CSS + JS from CDN |
| `app.js` | All frontend logic (map init, data loading, rendering, sidebar) |
| `style.css` | Dark theme; CSS variables; toolbar, panels, legend, check cards |
| `countries.json` | Static dataset: ~210 entries with iso2, gov_domain, gov_url, status |
| `data.json` | Scanner output (gitignored when stale); loaded by app.js at runtime |
| `scanner.py` | Async Python scanner — 9 DNS/email security checks per domain |
| `fetch_world.py` | One-shot utility to download + fix Natural Earth 110m GeoJSON |
| `world.geojson` | Country polygons (176 features; committed to repo) |
| `requirements.txt` | Python deps: httpx, aiolimiter, tqdm |

## Scanner

```bash
# Install deps (Kali/Debian system Python)
pip install -r requirements.txt --break-system-packages

# Full scan (~210 domains, ~5–15 min depending on network)
python scanner.py

# Re-scan specific countries only
python scanner.py --country NO,SE,DK

# Tune concurrency and timeout
python scanner.py --concurrency 8 --timeout 10

# Skip DKIM probing (faster but incomplete)
python scanner.py --no-dkim
```

Scanner writes `data.json` in-place. Re-running with `--country` merges results rather than overwriting the whole file.

### Domain source priority

For every country, before running any DNS checks, the scanner queries Wikidata P856 ("official website" property) via the Wikipedia and Wikidata APIs. The domain resolution order is:

1. **Wikidata P856** — preferred authoritative source
2. **countries.json** — used if Wikidata has no entry, or as fallback if the Wikidata domain is also unresolvable

The result records `gov_domain_source: "wikidata"` or `"countries.json"`. The info sidebar shows a blue provenance note when Wikidata was the source.

### Unresolvable domain console output

When a domain cannot be resolved (NXDOMAIN or no A/AAAA records), the scanner prints a highlighted entry to the console outside the progress bar:

```
[UNRESOLVABLE] govt.af — Afghanistan (AF) [un_member]
    Reason: NXDOMAIN – domain does not exist in DNS
    Source: Wikidata P856
```

If both the Wikidata domain and the countries.json domain are unresolvable, both are tried before giving up. The source shown reflects which one was actually attempted when the error occurred.

## Serving

```bash
python3 -m http.server 8080
# Open http://localhost:8080
```

No build step. All frontend assets are static files + CDN Leaflet.

## Architecture decisions

**DNS via Cloudflare DoH** — all checks use `https://cloudflare-dns.com/dns-query` (JSON API). No system resolver dependency, works consistently across environments.

**Wikidata as primary domain source** — the scanner queries Wikidata P856 ("official website") for every country before running DNS checks. This is preferred over countries.json because Wikidata is community-maintained and often more current. countries.json acts as a fallback when Wikidata has no P856 entry, or as a secondary fallback if the Wikidata domain itself is unresolvable.

**Pre-computed data** — scanner runs offline and writes `data.json`; frontend loads it once at page load. The map renders immediately from the pre-computed scores. No live DNS queries from the browser.

**DOM-safe JS** — `app.js` uses zero `innerHTML` with external data. All dynamic content is built with `document.createElement`, `textContent`, and `appendChild`. This is a hard requirement enforced by a pre-commit hook.

**Polygon source** — Natural Earth 110m admin boundaries. 38 countries in `countries.json` are too small to appear in NE 110m (Vatican, Singapore, Malta, Marshall Islands, etc.) — they are still scanned and appear in rankings. Clicking a ranking entry with no polygon opens the info sidebar without map navigation.

**ISO_A2 overrides** — Natural Earth uses `-99` for Norway and some other territories. `fetch_world.py` patches these to correct ISO codes. `app.js` has a matching override map for any remaining cases.

## countries.json

Edit this file to update government domains or add missing entries. Schema:

```json
{
  "iso2": "NO",
  "iso3": "NOR",
  "name": "Norway",
  "flag": "🇳🇴",
  "region": "Europe",
  "status": "un_member",
  "gov_domain": "regjeringen.no",
  "gov_url": "https://www.regjeringen.no",
  "notes": ""
}
```

**Status values:** `un_member` | `observer` | `disputed` | `territory`

**`no_polygon: true`** — add this for entries that have no Natural Earth polygon (Abkhazia, South Ossetia, Somaliland, Northern Cyprus). They are scanned and shown in rankings but skipped during map rendering.

**`notes` field** — shown as an addendum to the "Source" line in the console output for unresolvable domains. Useful for recording where an unusual domain was found.

Note: since the scanner now prefers Wikidata P856, the `gov_domain` in countries.json is only used when Wikidata has no entry for that country, or as a secondary fallback. Keep it up to date regardless — it is the only source for countries/territories not in Wikidata.

## Checks and weights

| Check | Weight | Excellent | Good | Warning | Fail | Raw records stored |
|-------|--------|-----------|------|---------|------|--------------------|
| DKIM | 20% | Selector found (RSA-2048+/Ed25519) | — | — | No selector | — |
| SPF | 15% | `-all` | `~all` | Weak/missing | None | `record` string |
| DMARC | 15% | `p=reject` | `p=quarantine` | `p=none` | Missing | `record` string |
| MTA-STS | 15% | `mode=enforce` | `mode=testing` | — | Missing/fail | `record` string |
| DNSSEC | 10% | DNSKEY + DS | — | — | Missing | `records[]` DNSKEY + DS data |
| MX | 10% | MX + DNSSEC | MX found | Null MX | No MX | `records[]` raw MX strings |
| DANE | 10% | TLSA on all MX | — | — | No TLSA | `records[]` `_25._tcp.<host> TLSA <data>` |
| TLS-RPT | 3% | `rua=https:` | `rua=mailto:` | — | Missing | `record` string |
| CAA | 2% | issue + iodef | issue only | — | Missing | `records[]` CAA tags |

Rating scores: excellent=100, good=75, warning=40, fail=0. Grade: A≥85, B≥70, C≥50, F<50.

Raw records are shown in collapsible "Raw record" sections inside each check card in the info sidebar.

## data.json result fields

Each country entry in `data.json` includes:

```json
{
  "iso2": "NO",
  "gov_domain": "regjeringen.no",
  "gov_url": "https://www.regjeringen.no",
  "gov_domain_source": "wikidata",
  "score": 88.5,
  "grade": "A",
  "scanned_at": "2026-04-15T14:30:12Z",
  "domain_reachable": true,
  "blocked_by": null,
  "domain_notes": null,
  "checks": { ... },
  "error": null
}
```

`gov_domain_source` is `"wikidata"` when the scanned domain came from Wikidata P856, or `"countries.json"` when it came from the static dataset. The info sidebar shows a blue provenance note for Wikidata-sourced entries.

## website/ folder

The `website/` directory contains the six files needed to host the map on any static web server:

| File | Purpose |
|------|---------|
| `index.html` | App shell |
| `app.js` | All frontend logic |
| `style.css` | Dark theme styles |
| `countries.json` | Static country/domain dataset |
| `world.geojson` | Country polygons |
| `data.json` | Scanner output (scores + check results) |

After running the scanner, copy the updated `data.json` (and `countries.json` if edited) into `website/` before deploying. The Python scripts, `CLAUDE.md`, `README.md`, `fetch_world.py`, and `requirements.txt` are not needed for display.

## Toolbar note

A subtitle line (`#toolbar-note`) sits between `#status-summary` and the spacer in the header:

> "Official domain name for each country/territory collected primarily from Wikidata, but other sources may have been used as well."

Edit the text directly in `index.html` if it needs updating.

## Footer

The status bar shows:
- Left: polygon/country count and scan summary
- Right: "Last scan: YYYY-MM-DD HH:MM UTC" (from `data.json.generated`) · `v2026.04.15` (version hardcoded in `index.html`)
- Bottom row: credits and disclaimer

Update the version string in `index.html` (`#status-version`) when making significant changes.

## Adding a new burger panel section

1. Add an element to `index.html` inside `#burger-body`
2. Populate it in `populateBurger()` in `app.js`
3. Data source is `window._data.stats` (pre-computed by scanner) or iterate `window._data.countries`

## OSM tile Referer compliance

Two-layer approach required by osm.wiki/Blocked:
1. `<meta name="referrer" content="no-referrer-when-downgrade">` in `index.html` — document-level policy
2. `referrerPolicy: "no-referrer-when-downgrade"` in the Leaflet `tileLayer` options — sets `referrerpolicy` attribute on each tile `<img>` element

Both are in place. Do not remove either.
