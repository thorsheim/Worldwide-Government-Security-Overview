# GovMap — Government Domain Security

An interactive world map showing DNS and email security scores for the official government domains of ~210 countries and territories. Each domain is tested with the same checks as [mailcheck](../email-security/mailcheck/).

Both UN member states and disputed territories are included. The rankings reflect technical findings, not political positions.

## What it shows

- **Color-coded polygons** — red (0) to green (100) security score per country
- **Click any country** — per-check detail with raw DNS records: DKIM, SPF, DMARC, MTA-STS, DNSSEC, MX, DANE, TLS-RPT, CAA
- **Burger menu (☰)** — global stats, grade distribution, top 10 and bottom 10 rankings
- **Domain notes** — flags WAF/CDN blocking (Cloudflare, Akamai, etc.) and unreachable domains
- **Wikidata sourcing** — government domains are looked up from Wikidata P856 ("official website") before scanning; a blue note in the sidebar indicates when this source was used
- **Header note** — "Official domain name for each country/territory collected primarily from Wikidata, but other sources may have been used as well."
- **Footer** — version number, timestamp of last scan, and credits

## Prerequisites

- Python 3.10+
- pip

## Setup

```bash
# 1. Install Python dependencies
pip install -r requirements.txt --break-system-packages

# 2. Download country polygons (one-time, ~289 KB)
python fetch_world.py
```

## Running a scan

```bash
# Scan all ~210 government domains (takes 5–15 minutes)
python scanner.py

# Scan specific countries only (ISO 3166-1 alpha-2 codes)
python scanner.py --country NO,SE,DK,FI,IS

# Options
python scanner.py --concurrency 8    # parallel domains (default: 5)
python scanner.py --timeout 10       # DNS timeout in seconds (default: 8)
python scanner.py --no-dkim          # skip DKIM probing
```

Scan results are written to `data.json`. Re-running with `--country` merges into the existing file rather than overwriting it.

### Domain source priority

For every country the scanner first queries **Wikidata P856** (the "official website" property maintained by the Wikipedia community). If Wikidata has an entry it is preferred. The domain from `countries.json` is used only when:

- Wikidata has no P856 entry for that country, or
- The Wikidata domain is also unresolvable (countries.json is tried as a secondary fallback)

The result records where each domain came from (`gov_domain_source`). The info sidebar shows a blue provenance note for Wikidata-sourced entries.

### Unresolvable domains

When a domain cannot be resolved the scanner prints it to the console immediately:

```
[UNRESOLVABLE] govt.af — Afghanistan (AF) [un_member]
    Reason: NXDOMAIN – domain does not exist in DNS
    Source: Wikidata P856
```

If both sources are tried and both fail, the output shows which one was last attempted.

## Viewing the map

```bash
python3 -m http.server 8080
```

Open [http://localhost:8080](http://localhost:8080) in a browser. No build step required.

## Updating government domains

Edit `countries.json` to add missing entries or fix domains for countries not covered by Wikidata P856. Each entry:

```json
{
  "iso2": "NO",
  "name": "Norway",
  "flag": "🇳🇴",
  "status": "un_member",
  "gov_domain": "regjeringen.no",
  "gov_url": "https://www.regjeringen.no",
  "notes": ""
}
```

Because the scanner now prefers Wikidata P856, the `gov_domain` here is only used as a fallback. Keep it accurate for countries/territories that Wikidata doesn't cover.

After editing, re-run the scanner for affected countries:

```bash
python scanner.py --country NO
```

## Interpreting results

| Grade | Score | Meaning |
|-------|-------|---------|
| A | 85–100 | Strong security posture |
| B | 70–84 | Good, with some gaps |
| C | 50–69 | Partial implementation |
| F | 0–49 | Major gaps or no implementation |

Each check card in the sidebar shows a rating badge, a plain-English detail line, and a collapsible raw record section. DNSSEC, MX, DANE, and CAA include the actual DNS records found. SPF, DMARC, MTA-STS, and TLS-RPT include the raw TXT record.

**Notes in the sidebar:**
- Yellow warning — WAF/CDN blocking detected; some checks may be incomplete
- "NXDOMAIN" or similar — domain does not exist or does not resolve; all checks skipped
- Blue note below the link — URL was sourced from Wikidata (Wikipedia P856)

Countries with no map polygon (too small for Natural Earth 110m, or disputed territories without internationally recognised boundaries) still appear in rankings and have a full results sidebar.

## Data sources

- Country polygons: [Natural Earth](https://www.naturalearthdata.com/) 110m admin boundaries
- Tiles: © [OpenStreetMap](https://www.openstreetmap.org/copyright) contributors
- DNS checks: Cloudflare DNS-over-HTTPS (`cloudflare-dns.com/dns-query`)
- Official websites: [Wikidata](https://www.wikidata.org/) P856, with [countries.json](countries.json) as fallback

## Credits

Created by Per Thorsheim using Anthropic Claude. No guarantees for the correctness of found domains or their test results — there are too many factors out of my control for getting everything right. Free to use, copy, enhance and whatever. Credit is nice, not mandatory.

Checks mirror the [mailcheck](../email-security/mailcheck/) methodology.
