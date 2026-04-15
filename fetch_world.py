#!/usr/bin/env python3
"""
Download Natural Earth 110m world country GeoJSON and clean it up.

Usage:
    python fetch_world.py              # writes world.geojson
    python fetch_world.py --res 50m    # higher resolution (~4 MB)
"""

import argparse
import json
import sys
import urllib.request

URLS = {
    "110m": "https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_110m_admin_0_countries.geojson",
    "50m":  "https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_50m_admin_0_countries.geojson",
}

# Natural Earth ships some ISO_A2 values as "-99" for entries that don't have
# a clean ISO 3166-1 code.  Map them via ADM0_A3 or NAME to the correct code.
ISO_A2_OVERRIDES = {
    # ADM0_A3 → correct ISO_A2
    "NOR": "NO",  # Norway
    "FRA": "FR",  # France (main territory, not overseas)
    "CYN": "CY",  # Northern Cyprus — keep separate if desired, else skip
    "KAB": "AB",  # Abkhazia (custom)
    "OSE": "OS",  # South Ossetia (custom)
    "SOL": "XS",  # Somaliland (custom)
    "XKX": "XK",  # Kosovo
    "TWN": "TW",  # Taiwan
    "PSX": "PS",  # Palestine (West Bank / Gaza — NE may split or merge)
    "ESB": "CY",  # British Sovereign Base Areas on Cyprus → map to CY
    "SAH": "EH",  # Western Sahara
    "ESH": "EH",
}

# Properties to KEEP; all others are stripped to reduce file size.
KEEP_PROPS = {"ISO_A2", "ISO_A3", "ADM0_A3", "NAME", "NAME_EN"}


def fix_feature(f: dict) -> dict:
    """Normalise properties and apply ISO_A2 overrides."""
    p = f.get("properties") or {}

    # Strip to only the props we care about
    f["properties"] = {k: p.get(k, "") for k in KEEP_PROPS}

    iso2 = f["properties"]["ISO_A2"]
    adm3 = f["properties"]["ADM0_A3"]

    if iso2 == "-99" or not iso2:
        iso2 = ISO_A2_OVERRIDES.get(adm3, "")
        f["properties"]["ISO_A2"] = iso2

    return f


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--res", choices=["110m", "50m"], default="110m",
                    help="Resolution (default: 110m)")
    ap.add_argument("--out", default="world.geojson",
                    help="Output file (default: world.geojson)")
    args = ap.parse_args()

    url = URLS[args.res]
    print(f"Downloading Natural Earth {args.res} from:\n  {url}")

    try:
        with urllib.request.urlopen(url, timeout=60) as resp:
            raw = resp.read()
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    data = json.loads(raw)
    features = data.get("features", [])
    print(f"Downloaded {len(features)} features")

    fixed = [fix_feature(f) for f in features]

    # Remove features with no usable ISO_A2 (uninhabited/disputed without mapping)
    kept = [f for f in fixed if f["properties"]["ISO_A2"]]
    removed = len(fixed) - len(kept)
    if removed:
        print(f"Removed {removed} features with no ISO_A2 mapping")

    out = {"type": "FeatureCollection", "features": kept}
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, separators=(",", ":"))

    kb = len(json.dumps(out).encode()) // 1024
    print(f"Written {len(kept)} features → {args.out}  ({kb} KB)")


if __name__ == "__main__":
    main()
