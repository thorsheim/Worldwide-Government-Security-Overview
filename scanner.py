#!/usr/bin/env python3
"""
Government Domain Security Scanner
====================================
Runs mailcheck-equivalent DNS/email security checks against every government
domain in countries.json and writes results to data.json.

Checks (identical weights to mailcheck index.html):
  DKIM  20% | SPF    15% | DMARC 15% | MTA-STS 15% | DNSSEC 10%
  MX    10% | DANE   10% | TLS-RPT 3% | CAA      2%

Usage:
  python scanner.py                          # scan all countries
  python scanner.py --country NO,SE,DK       # re-scan specific ISO2 codes
  python scanner.py --concurrency 5          # parallel domains (default: 5)
  python scanner.py --timeout 8              # per-query timeout in seconds
  python scanner.py --no-dkim               # skip DKIM selector probing
  python scanner.py --output /tmp/out.json  # custom output path
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx
from aiolimiter import AsyncLimiter
from tqdm import tqdm

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.WARNING,
    format="%(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("scanner")

# ── Constants ──────────────────────────────────────────────────────────────────
DOH_URL = "https://cloudflare-dns.com/dns-query"
RTYPE_TXT    = "TXT"
RTYPE_MX     = "MX"
RTYPE_CAA    = "CAA"
RTYPE_DNSKEY = "DNSKEY"
RTYPE_DS     = "DS"
RTYPE_TLSA   = "TLSA"
RTYPE_A      = "A"
RTYPE_NS     = "NS"

WEIGHTS = {
    "dkim":   0.20,
    "spf":    0.15,
    "dmarc":  0.15,
    "mtasts": 0.15,
    "dnssec": 0.10,
    "mx":     0.10,
    "dane":   0.10,
    "tlsrpt": 0.03,
    "caa":    0.02,
}
RATING_SCORE = {"excellent": 100, "good": 75, "warning": 40, "fail": 0}

# Top 5 DKIM selectors — covers Google Workspace, Microsoft 365, Apple iCloud,
# SendGrid, and Mailchimp (the most common providers for government domains).
AUTO_SELECTORS = [
    "google",    # Google Workspace
    "selector1", # Microsoft 365
    "selector2", # Microsoft 365 (rotation)
    "sig1",      # Apple iCloud
    "s1",        # SendGrid
]

# ── Helpers ────────────────────────────────────────────────────────────────────

def compute_score(checks: dict[str, dict]) -> float | None:
    """Weighted score (0-100), handling MTA-STS skip like mailcheck."""
    mta_skipped = checks.get("mtasts", {}).get("skipped", False)
    total_w = sum(
        w for k, w in WEIGHTS.items()
        if not (k == "mtasts" and mta_skipped)
    )
    if total_w == 0:
        return None
    raw = sum(
        RATING_SCORE.get(checks.get(k, {}).get("rating", "fail"), 0) * w
        for k, w in WEIGHTS.items()
        if not (k == "mtasts" and mta_skipped)
    )
    return round(raw / total_w, 1)


def compute_grade(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 85:
        return "A"
    if score >= 70:
        return "B"
    if score >= 50:
        return "C"
    return "F"


def dkim_key_bits(p_value: str) -> int:
    """Rough RSA key size from DKIM p= value (base64 DER SubjectPublicKeyInfo)."""
    try:
        der = base64.b64decode(p_value + "==")  # add padding just in case
        # For SubjectPublicKeyInfo, the modulus is ~half the total DER length minus overhead
        # Rough heuristic: (total_bytes - 24) * 8
        # Ed25519 keys are 44 chars base64 → ~32 bytes → flag as excellent
        if len(der) < 50:
            return 256  # Ed25519 or similar — treat as excellent
        return max(0, (len(der) - 24) * 8)
    except Exception:
        return 0


# ── DoH client ─────────────────────────────────────────────────────────────────

class DoHClient:
    """Cloudflare DNS-over-HTTPS client (JSON format)."""

    def __init__(self, client: httpx.AsyncClient, limiter: AsyncLimiter, timeout: float):
        self._client = client
        self._limiter = limiter
        self._timeout = timeout

    async def query(self, name: str, rtype: str) -> dict:
        """Return parsed DNS response dict or empty dict on error."""
        async with self._limiter:
            try:
                r = await self._client.get(
                    DOH_URL,
                    params={"name": name, "type": rtype},
                    headers={"Accept": "application/dns-json"},
                    timeout=self._timeout,
                )
                r.raise_for_status()
                return r.json()
            except Exception as e:
                log.debug("DoH %s %s: %s", rtype, name, e)
                return {}

    def answers(self, resp: dict) -> list[str]:
        """Extract string data values from DNS response."""
        out = []
        for rec in resp.get("Answer") or []:
            d = rec.get("data", "")
            if d:
                # TXT records sometimes have quoted strings; strip quotes
                out.append(d.strip('"').strip())
        return out

    def ad_flag(self, resp: dict) -> bool:
        """True if the AD (Authenticated Data) bit is set."""
        return bool(resp.get("AD", False))

    def status(self, resp: dict) -> int:
        """RCODE: 0=NOERROR, 3=NXDOMAIN, etc."""
        return resp.get("Status", -1)


# ── Individual checks ──────────────────────────────────────────────────────────

async def check_dnssec(doh: DoHClient, domain: str) -> dict:
    """Check DNSSEC: query DNSKEY + DS.  Uses AD flag from validating resolver."""
    dnskey_resp = await doh.query(domain, RTYPE_DNSKEY)
    has_dnskey = bool(dnskey_resp.get("Answer"))
    ad = doh.ad_flag(dnskey_resp)
    raw_records = [rec.get("data", "") for rec in (dnskey_resp.get("Answer") or []) if rec.get("data")]

    if has_dnskey and ad:
        rating = "excellent"
        detail = "DNSKEY present, AD flag set (chain validated)"
    elif has_dnskey:
        # Try querying the parent for DS record as a secondary check
        # Peel one label to get parent zone
        parts = domain.split(".")
        if len(parts) >= 2:
            ds_resp = await doh.query(domain, RTYPE_DS)
            has_ds = bool(ds_resp.get("Answer"))
            if has_ds:
                raw_records += [rec.get("data", "") for rec in (ds_resp.get("Answer") or []) if rec.get("data")]
        else:
            has_ds = False
        if has_ds:
            rating = "good"
            detail = "DNSKEY + DS found (AD flag not set by this resolver)"
        else:
            rating = "warning"
            detail = "DNSKEY found but no DS in parent zone"
    else:
        rating = "fail"
        detail = "No DNSKEY records found"

    return {"rating": rating, "score": RATING_SCORE[rating],
            "has_dnskey": has_dnskey, "ad": ad, "detail": detail,
            "records": raw_records}


async def check_mx(doh: DoHClient, domain: str) -> dict:
    """Check MX records."""
    resp = await doh.query(domain, RTYPE_MX)
    answers = resp.get("Answer") or []
    raw_records = [rec.get("data", "") for rec in answers if rec.get("data")]

    if not answers:
        return {"rating": "fail", "score": 0, "hosts": [], "records": [],
                "detail": "No MX records found", "mx_dnssec": False}

    hosts = []
    null_mx = False
    for rec in answers:
        data = rec.get("data", "").strip()
        # Null MX: "0 ."
        if data in ("0 .", "0."):
            null_mx = True
        else:
            parts = data.split(None, 1)
            if len(parts) == 2:
                hosts.append(parts[1].rstrip("."))

    if null_mx and not hosts:
        return {"rating": "warning", "score": RATING_SCORE["warning"],
                "hosts": [], "records": raw_records,
                "detail": "Null MX (RFC 7505 — no email accepted)",
                "mx_dnssec": False}

    # Check DNSSEC on MX hosts
    mx_dnssec_count = 0
    for host in hosts[:5]:  # cap to avoid too many queries
        h_resp = await doh.query(host, RTYPE_A)
        if doh.ad_flag(h_resp):
            mx_dnssec_count += 1

    mx_dnssec = mx_dnssec_count == len(hosts[:5]) and len(hosts) > 0

    if mx_dnssec:
        rating = "excellent"
        detail = f"{len(hosts)} MX host(s), DNSSEC validated"
    else:
        rating = "good"
        detail = f"{len(hosts)} MX host(s)"

    return {"rating": rating, "score": RATING_SCORE[rating],
            "hosts": hosts, "records": raw_records,
            "mx_dnssec": mx_dnssec, "detail": detail}


async def check_spf(doh: DoHClient, domain: str) -> dict:
    """Check SPF TXT record."""
    resp = await doh.query(domain, RTYPE_TXT)
    spf = None
    for txt in doh.answers(resp):
        if txt.startswith("v=spf1"):
            spf = txt
            break

    if not spf:
        return {"rating": "fail", "score": 0, "record": None,
                "policy": None, "detail": "No SPF record found"}

    # Determine qualifier from 'all' mechanism
    m = re.search(r"([+\-~?])all", spf, re.IGNORECASE)
    qualifier = m.group(1) if m else None

    if qualifier == "-":
        rating, detail = "excellent", "Hard fail (-all)"
    elif qualifier == "~":
        rating, detail = "good", "Soft fail (~all)"
    elif qualifier in ("+", "?", None):
        rating, detail = "warning", f"Weak qualifier ('{qualifier or 'missing'}all')"
    else:
        rating, detail = "warning", "Unexpected SPF qualifier"

    return {"rating": rating, "score": RATING_SCORE[rating],
            "record": spf, "policy": qualifier, "detail": detail}


async def check_dmarc(doh: DoHClient, domain: str) -> dict:
    """Check DMARC at _dmarc.<domain>."""
    resp = await doh.query(f"_dmarc.{domain}", RTYPE_TXT)
    record = None
    for txt in doh.answers(resp):
        if txt.startswith("v=DMARC1"):
            record = txt
            break

    if not record:
        return {"rating": "fail", "score": 0, "record": None,
                "policy": None, "detail": "No DMARC record found"}

    # Parse policy
    m = re.search(r"p=(\w+)", record, re.IGNORECASE)
    policy = m.group(1).lower() if m else None

    if policy == "reject":
        rating, detail = "excellent", "Policy: reject"
    elif policy == "quarantine":
        rating, detail = "good", "Policy: quarantine"
    elif policy == "none":
        rating, detail = "warning", "Policy: none (monitoring only)"
    else:
        rating, detail = "warning", f"Unknown policy: {policy}"

    # Extract rua
    rua_m = re.search(r"rua=([^;]+)", record, re.IGNORECASE)
    rua = rua_m.group(1).strip() if rua_m else None

    return {"rating": rating, "score": RATING_SCORE[rating],
            "record": record, "policy": policy, "rua": rua, "detail": detail}


async def check_mtasts(doh: DoHClient, client: httpx.AsyncClient,
                       domain: str, timeout: float) -> dict:
    """Check MTA-STS: DNS record + policy file fetch."""
    # Step 1: DNS TXT _mta-sts.<domain>
    resp = await doh.query(f"_mta-sts.{domain}", RTYPE_TXT)
    dns_record = None
    for txt in doh.answers(resp):
        if txt.startswith("v=STSv1"):
            dns_record = txt
            break

    if not dns_record:
        return {"rating": "fail", "score": 0, "record": None,
                "mode": None, "skipped": False,
                "detail": "No MTA-STS DNS record found"}

    # Step 2: Fetch policy file
    policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        async with doh._limiter:
            r = await client.get(policy_url, timeout=timeout,
                                 follow_redirects=True)
        policy_text = r.text
        mode_m = re.search(r"mode:\s*(\w+)", policy_text, re.IGNORECASE)
        mode = mode_m.group(1).lower() if mode_m else None
        skipped = False
    except httpx.ConnectError:
        return {"rating": "fail", "score": 0, "record": dns_record,
                "mode": None, "skipped": True,
                "detail": "MTA-STS DNS record found but policy file unreachable"}
    except Exception:
        return {"rating": "warning", "score": RATING_SCORE["warning"],
                "record": dns_record, "mode": None, "skipped": True,
                "detail": "MTA-STS DNS record found but policy fetch failed"}

    if mode == "enforce":
        rating, detail = "excellent", "Mode: enforce"
    elif mode == "testing":
        rating, detail = "good", "Mode: testing"
    elif mode == "none":
        rating, detail = "warning", "Mode: none"
    else:
        rating, detail = "warning", f"Unknown mode: {mode}"

    return {"rating": rating, "score": RATING_SCORE[rating],
            "record": dns_record, "mode": mode, "skipped": skipped,
            "detail": detail}


async def check_dane(doh: DoHClient, domain: str, mx_hosts: list[str]) -> dict:
    """Check DANE TLSA records at _25._tcp.<mx_host>."""
    if not mx_hosts:
        return {"rating": "fail", "score": 0, "hosts_with_tlsa": 0,
                "hosts_total": 0, "records": [], "detail": "No MX hosts to check"}

    tlsa_found = 0
    tlsa_dnssec = 0
    raw_records: list[str] = []
    for host in mx_hosts[:5]:
        tlsa_name = f"_25._tcp.{host}"
        resp = await doh.query(tlsa_name, RTYPE_TLSA)
        if resp.get("Answer"):
            tlsa_found += 1
            if doh.ad_flag(resp):
                tlsa_dnssec += 1
            for rec in resp.get("Answer", []):
                data = rec.get("data", "")
                if data:
                    raw_records.append(f"{tlsa_name} TLSA {data}")

    total = min(len(mx_hosts), 5)

    if tlsa_dnssec == total and total > 0:
        rating = "excellent"
        detail = f"DNSSEC-validated TLSA on all {total} MX host(s)"
    elif tlsa_found == total and total > 0:
        rating = "good"
        detail = f"TLSA found on all {total} MX host(s) (no DNSSEC)"
    elif tlsa_found > 0:
        rating = "warning"
        detail = f"TLSA on {tlsa_found}/{total} MX host(s)"
    else:
        rating = "fail"
        detail = "No TLSA records found"

    return {"rating": rating, "score": RATING_SCORE[rating],
            "hosts_with_tlsa": tlsa_found, "hosts_with_dnssec_tlsa": tlsa_dnssec,
            "hosts_total": total, "records": raw_records, "detail": detail}


async def check_tlsrpt(doh: DoHClient, domain: str) -> dict:
    """Check TLS-RPT at _smtp._tls.<domain>."""
    resp = await doh.query(f"_smtp._tls.{domain}", RTYPE_TXT)
    record = None
    for txt in doh.answers(resp):
        if txt.startswith("v=TLSRPTv1"):
            record = txt
            break

    if not record:
        return {"rating": "fail", "score": 0, "record": None,
                "rua_type": None, "detail": "No TLS-RPT record found"}

    rua_m = re.search(r"rua=([^;]+)", record, re.IGNORECASE)
    rua = rua_m.group(1).strip() if rua_m else ""

    if "https:" in rua:
        rating, rua_type, detail = "excellent", "https", "Reports via HTTPS endpoint"
    elif "mailto:" in rua:
        rating, rua_type, detail = "good", "mailto", "Reports via mailto:"
    elif rua:
        rating, rua_type, detail = "warning", "unknown", f"rua={rua}"
    else:
        rating, rua_type, detail = "warning", None, "TLS-RPT record found but no rua="

    return {"rating": rating, "score": RATING_SCORE[rating],
            "record": record, "rua": rua, "rua_type": rua_type, "detail": detail}


async def check_caa(doh: DoHClient, domain: str) -> dict:
    """Check CAA records."""
    resp = await doh.query(domain, RTYPE_CAA)
    answers = resp.get("Answer") or []

    if not answers:
        return {"rating": "fail", "score": 0, "records": [],
                "detail": "No CAA records found"}

    records = []
    has_issue = False
    has_iodef = False
    for rec in answers:
        data = rec.get("data", "").strip()
        records.append(data)
        dl = data.lower()
        if "issue " in dl or "issuewild " in dl:
            has_issue = True
        if "iodef " in dl:
            has_iodef = True

    if has_issue and has_iodef:
        rating = "excellent"
        detail = "issue + iodef tags present"
    elif has_issue:
        rating = "good"
        detail = "issue tag present (no iodef)"
    else:
        rating = "warning"
        detail = "CAA records found but no issue/iodef tags"

    return {"rating": rating, "score": RATING_SCORE[rating],
            "records": records, "detail": detail}


async def check_dkim(doh: DoHClient, domain: str,
                     skip: bool = False) -> dict:
    """Probe AUTO_SELECTORS for DKIM TXT records (concurrency 10 per domain)."""
    if skip:
        return {"rating": "fail", "score": 0, "selectors_found": [],
                "selectors_tested": 0, "detail": "DKIM check skipped"}

    sem = asyncio.Semaphore(10)
    found: list[dict] = []

    async def probe(sel: str) -> None:
        async with sem:
            resp = await doh.query(f"{sel}._domainkey.{domain}", RTYPE_TXT)
            for txt in doh.answers(resp):
                if "v=DKIM1" in txt or "k=rsa" in txt or "k=ed25519" in txt or "p=" in txt:
                    # Parse key type
                    k_m = re.search(r"k=(\w+)", txt)
                    key_type = k_m.group(1).lower() if k_m else "rsa"
                    p_m = re.search(r"p=([A-Za-z0-9+/=]+)", txt)
                    p_val = p_m.group(1) if p_m else ""
                    key_bits = dkim_key_bits(p_val) if p_val else 0
                    found.append({
                        "selector": sel,
                        "key_type": key_type,
                        "key_bits": key_bits,
                        "record": txt[:200],
                    })
                    break

    await asyncio.gather(*[probe(s) for s in AUTO_SELECTORS])

    if not found:
        return {"rating": "fail", "score": 0,
                "selectors_found": [], "selectors_tested": len(AUTO_SELECTORS),
                "detail": f"No DKIM selectors found (tested {len(AUTO_SELECTORS)})"}

    # Rate best key
    best_bits = max((k.get("key_bits", 0) for k in found), default=0)
    has_ed25519 = any(k["key_type"] == "ed25519" for k in found)

    if has_ed25519 or best_bits >= 2048:
        rating = "excellent"
        detail = f"{len(found)} selector(s) found, strong key"
    elif best_bits >= 1024:
        rating = "good"
        detail = f"{len(found)} selector(s) found, key ≥1024 bits"
    else:
        rating = "warning"
        detail = f"{len(found)} selector(s) found, weak or unknown key size"

    return {
        "rating": rating, "score": RATING_SCORE[rating],
        "selectors_found": [k["selector"] for k in found],
        "selectors_tested": len(AUTO_SELECTORS),
        "keys": found,
        "detail": detail,
    }


# ── Domain pre-check & blocking detection ──────────────────────────────────────

# Known WAF/CDN server header patterns
_BLOCKING_SIGNATURES = [
    ("cloudflare", "Cloudflare"),
    ("akamai",     "Akamai"),
    ("fastly",     "Fastly"),
    ("sucuri",     "Sucuri"),
    ("imperva",    "Imperva"),
    ("incapsula",  "Imperva/Incapsula"),
    ("barracuda",  "Barracuda"),
    ("f5 big-ip",  "F5 BIG-IP"),
]


def detect_blocking(response: httpx.Response) -> str | None:
    """Return the name of any WAF/CDN that appears to be blocking the request."""
    server = response.headers.get("server", "").lower()
    via    = response.headers.get("via", "").lower()
    # cf-ray header is a definitive Cloudflare marker
    if response.headers.get("cf-ray") and response.status_code in (403, 429, 503):
        return "Cloudflare"
    combined = server + " " + via
    for signature, name in _BLOCKING_SIGNATURES:
        if signature in combined:
            if response.status_code in (403, 429, 503):
                return name
    return None


async def check_domain_reachable(
    doh: DoHClient,
    client: httpx.AsyncClient,
    domain: str,
    timeout: float,
) -> dict:
    """
    Quick pre-flight: can the domain be resolved, and does its web presence respond?
    Returns a dict with:
      reachable   – True if DNS resolves to at least one address
      dns_note    – human-readable DNS status note
      http_note   – human-readable HTTP note (if reachable)
      blocked_by  – name of detected WAF/CDN, or None
    """
    # DNS resolution check (A + AAAA)
    a_resp    = await doh.query(domain, RTYPE_A)
    aaaa_resp = await doh.query(domain, "AAAA")
    has_a     = bool(a_resp.get("Answer"))
    has_aaaa  = bool(aaaa_resp.get("Answer"))

    if doh.status(a_resp) == 3:  # NXDOMAIN
        return {
            "reachable":  False,
            "dns_note":   "NXDOMAIN – domain does not exist in DNS",
            "http_note":  None,
            "blocked_by": None,
        }

    if not has_a and not has_aaaa:
        # Check for NS to distinguish "no records" from "not delegated"
        ns_resp = await doh.query(domain, RTYPE_NS)
        has_ns  = bool(ns_resp.get("Answer"))
        return {
            "reachable":  has_ns,
            "dns_note":   (
                "Domain is delegated (NS records exist) but has no A/AAAA records"
                if has_ns
                else "Domain does not resolve (no A, AAAA, or NS records)"
            ),
            "http_note":  None,
            "blocked_by": None,
        }

    # Attempt HTTP GET to the gov_url to detect blocking
    url = f"https://{domain}"
    try:
        async with doh._limiter:
            resp = await client.get(
                url, timeout=timeout, follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; govmap-scanner/1.0)"},
            )
        blocked_by = detect_blocking(resp)
        if blocked_by:
            http_note = (
                f"HTTP {resp.status_code} – {blocked_by} appears to be blocking "
                f"automated requests (WAF/bot protection)"
            )
        elif resp.status_code >= 400:
            http_note = f"HTTP {resp.status_code} returned by web server"
        else:
            http_note = f"HTTP {resp.status_code} OK"
        return {
            "reachable":  True,
            "dns_note":   "Resolves to " + (
                ", ".join(r["data"] for r in (a_resp.get("Answer") or [])[:3])
            ),
            "http_note":  http_note,
            "blocked_by": blocked_by,
        }
    except (httpx.ConnectError, httpx.TimeoutException) as e:
        return {
            "reachable":  True,   # DNS resolved, but web server is unreachable/slow
            "dns_note":   "DNS resolves but web server is unreachable",
            "http_note":  f"Connection failed: {type(e).__name__}",
            "blocked_by": None,
        }
    except Exception as e:
        return {
            "reachable":  True,
            "dns_note":   "DNS resolves",
            "http_note":  f"HTTP check error: {e}",
            "blocked_by": None,
        }


# ── URL helpers ────────────────────────────────────────────────────────────────

def extract_domain(url: str) -> str | None:
    """Return the bare hostname from a URL, stripping www. and port."""
    try:
        netloc = urlparse(url).netloc
        if netloc.startswith("www."):
            netloc = netloc[4:]
        netloc = netloc.split(":")[0].strip()
        return netloc or None
    except Exception:
        return None


# ── Wikipedia / Wikidata official-website lookup ───────────────────────────────

async def find_wikipedia_gov_url(
    client: httpx.AsyncClient,
    country_name: str,
    timeout: float,
) -> str | None:
    """
    Look up a country's official government website via Wikidata P856
    ("official website" property).  Called for every country — Wikidata is the
    preferred authoritative source; countries.json is the fallback.

    Two-step:
      1. Wikipedia API: article title → Wikidata Q-ID (pageprops wikibase_item)
      2. Wikidata API: Q-ID → P856 claim value (official website URL)
    """
    if not country_name:
        return None
    t = min(timeout, 8.0)
    try:
        # Step 1 — Wikipedia → Q-ID
        wp = await client.get(
            "https://en.wikipedia.org/w/api.php",
            params={
                "action":      "query",
                "titles":      country_name,
                "prop":        "pageprops",
                "ppprop":      "wikibase_item",
                "format":      "json",
                "formatversion": "2",
            },
            timeout=t,
        )
        wp.raise_for_status()
        pages = wp.json().get("query", {}).get("pages", [])
        if not pages or pages[0].get("missing"):
            return None
        q_id = pages[0].get("pageprops", {}).get("wikibase_item")
        if not q_id:
            return None

        # Step 2 — Wikidata P856 (official website)
        wd = await client.get(
            "https://www.wikidata.org/w/api.php",
            params={
                "action":        "wbgetentities",
                "ids":           q_id,
                "props":         "claims",
                "format":        "json",
                "formatversion": "2",
            },
            timeout=t,
        )
        wd.raise_for_status()
        entity = wd.json().get("entities", {}).get(q_id, {})
        p856 = entity.get("claims", {}).get("P856", [])
        if p856:
            url = (
                p856[0]
                .get("mainsnak", {})
                .get("datavalue", {})
                .get("value")
            )
            if isinstance(url, str) and url.startswith("http"):
                return url
    except Exception as exc:
        log.debug("Wikipedia lookup %r: %s", country_name, exc)
    return None


# ── Domain scanner ─────────────────────────────────────────────────────────────

async def scan_domain(
    iso2: str,
    entry: dict,
    doh: DoHClient,
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    timeout: float,
    skip_dkim: bool,
) -> dict:
    """
    Run all 9 checks against a single government domain.

    Domain selection priority:
      1. Wikidata P856 (official website) — queried for every country.
      2. countries.json gov_domain — used if Wikidata has no entry, or if
         the Wikidata domain is also unresolvable.
    """
    orig_domain = entry["gov_domain"]
    orig_url    = entry.get("gov_url") or f"https://{orig_domain}"
    # domain / gov_url may be reassigned below; track separately from entry
    domain  = orig_domain
    gov_url = orig_url
    t0 = time.monotonic()

    async with sem:
        try:
            # ── 1. Prefer Wikidata P856 as the authoritative domain source ──
            wikidata_url    = await find_wikipedia_gov_url(client, entry.get("name", ""), timeout)
            wikidata_domain = extract_domain(wikidata_url) if wikidata_url else None

            if wikidata_domain and wikidata_domain != orig_domain:
                domain     = wikidata_domain
                gov_url    = wikidata_url
                gov_source = "wikidata"
            else:
                gov_source = "countries.json"

            # ── 2. Pre-flight reachability check ────────────────────────────
            reach = await check_domain_reachable(doh, client, domain, timeout)

            if not reach["reachable"]:
                if gov_source == "wikidata":
                    # Wikidata domain unresolvable — try countries.json as fallback
                    reach2 = await check_domain_reachable(doh, client, orig_domain, timeout)
                    if reach2["reachable"]:
                        domain     = orig_domain
                        gov_url    = orig_url
                        gov_source = "countries.json"
                        reach      = reach2
                        # Fall through to full scan below
                    else:
                        # Both sources unresolvable
                        return {
                            "iso2":             iso2,
                            "gov_domain":       domain,
                            "gov_url":          gov_url,
                            "gov_domain_source": gov_source,
                            "score":            None,
                            "grade":            None,
                            "scan_duration_ms": round((time.monotonic() - t0) * 1000),
                            "scanned_at":       datetime.now(timezone.utc).isoformat(),
                            "checks":           {},
                            "domain_reachable": False,
                            "blocked_by":       None,
                            "domain_notes":     reach["dns_note"],
                            "error":            reach["dns_note"],
                        }
                else:
                    # countries.json domain unresolvable, no Wikidata fallback
                    return {
                        "iso2":             iso2,
                        "gov_domain":       domain,
                        "gov_url":          gov_url,
                        "gov_domain_source": gov_source,
                        "score":            None,
                        "grade":            None,
                        "scan_duration_ms": round((time.monotonic() - t0) * 1000),
                        "scanned_at":       datetime.now(timezone.utc).isoformat(),
                        "checks":           {},
                        "domain_reachable": False,
                        "blocked_by":       None,
                        "domain_notes":     reach["dns_note"],
                        "error":            reach["dns_note"],
                    }

            # ── 3. Run MX first (DANE needs MX hosts), then all others ──────
            mx_result = await check_mx(doh, domain)
            mx_hosts  = mx_result.get("hosts", [])

            (
                dnssec_result,
                spf_result,
                dmarc_result,
                mtasts_result,
                dane_result,
                tlsrpt_result,
                caa_result,
                dkim_result,
            ) = await asyncio.gather(
                check_dnssec(doh, domain),
                check_spf(doh, domain),
                check_dmarc(doh, domain),
                check_mtasts(doh, client, domain, timeout),
                check_dane(doh, domain, mx_hosts),
                check_tlsrpt(doh, domain),
                check_caa(doh, domain),
                check_dkim(doh, domain, skip=skip_dkim),
            )

            checks = {
                "dnssec": dnssec_result,
                "mx":     mx_result,
                "spf":    spf_result,
                "dmarc":  dmarc_result,
                "mtasts": mtasts_result,
                "dane":   dane_result,
                "tlsrpt": tlsrpt_result,
                "caa":    caa_result,
                "dkim":   dkim_result,
            }

            # Annotate MTA-STS with blocking note if applicable
            if reach["blocked_by"] and mtasts_result.get("skipped"):
                mtasts_result["detail"] = (
                    f"{mtasts_result.get('detail','')} "
                    f"[{reach['blocked_by']} WAF may be blocking policy fetch]"
                ).strip()

            score = compute_score(checks)
            grade = compute_grade(score)

            # Compose domain notes — only for problems, not healthy domains
            notes_parts = []
            if reach["http_note"] and (
                "failed" in reach["http_note"].lower()
                or "blocked" in reach["http_note"].lower()
                or (reach["http_note"].startswith("HTTP ") and
                    not reach["http_note"].startswith("HTTP 2") and
                    not reach["http_note"].startswith("HTTP 3"))
            ):
                notes_parts.append(reach["http_note"])
            if reach["blocked_by"]:
                notes_parts.append(
                    f"{reach['blocked_by']} WAF/bot-protection detected — "
                    f"some HTTP-based checks may be incomplete"
                )

            return {
                "iso2":             iso2,
                "gov_domain":       domain,
                "gov_url":          gov_url,
                "gov_domain_source": gov_source,
                "score":            score,
                "grade":            grade,
                "scan_duration_ms": round((time.monotonic() - t0) * 1000),
                "scanned_at":       datetime.now(timezone.utc).isoformat(),
                "checks":           checks,
                "domain_reachable": reach["reachable"],
                "blocked_by":       reach["blocked_by"],
                "domain_notes":     "; ".join(notes_parts) if notes_parts else None,
                "error":            None,
            }

        except Exception as e:
            log.warning("scan_domain %s (%s): %s", iso2, domain, e)
            return {
                "iso2":             iso2,
                "gov_domain":       domain,
                "gov_url":          gov_url,
                "gov_domain_source": "unknown",
                "score":            None,
                "grade":            None,
                "scan_duration_ms": round((time.monotonic() - t0) * 1000),
                "scanned_at":       datetime.now(timezone.utc).isoformat(),
                "checks":           {},
                "domain_reachable": None,
                "blocked_by":       None,
                "domain_notes":     None,
                "error":            str(e),
            }


# ── Stats builder ──────────────────────────────────────────────────────────────

def build_stats(results: dict[str, dict], total_countries: int) -> dict:
    scanned = [r for r in results.values() if r["score"] is not None]
    errors  = [r for r in results.values() if r["error"]]
    avg_score = (
        round(sum(r["score"] for r in scanned) / len(scanned), 1)
        if scanned else None
    )
    grade_dist: dict[str, int] = {"A": 0, "B": 0, "C": 0, "F": 0}
    for r in scanned:
        g = r.get("grade")
        if g in grade_dist:
            grade_dist[g] += 1

    sorted_scanned = sorted(scanned, key=lambda r: r["score"], reverse=True)
    top10    = [r["iso2"] for r in sorted_scanned[:10]]
    bottom10 = [r["iso2"] for r in sorted_scanned[-10:][::-1]]

    return {
        "total_countries": total_countries,
        "scanned":  len(scanned),
        "errors":   len(errors),
        "avg_score": avg_score,
        "grade_distribution": grade_dist,
        "top10":    top10,
        "bottom10": bottom10,
    }


# ── Main ───────────────────────────────────────────────────────────────────────

def load_countries(path: Path) -> dict[str, dict]:
    """Return {iso2: entry} from countries.json."""
    data = json.loads(path.read_text(encoding="utf-8"))
    return {e["iso2"]: e for e in data["entries"]}


async def run(args: argparse.Namespace) -> None:
    countries = load_countries(Path(args.countries))

    # Filter if --country is specified
    if args.country:
        codes = [c.strip().upper() for c in args.country.split(",")]
        missing = [c for c in codes if c not in countries]
        if missing:
            print(f"Unknown ISO2 codes: {', '.join(missing)}", file=sys.stderr)
        countries = {k: v for k, v in countries.items() if k in codes}

    # Skip entities with no polygon and/or no real domain if desired
    # (we still scan them — results are just shown in sidebar)
    to_scan = {
        k: v for k, v in countries.items()
        if v.get("gov_domain")
    }

    print(f"Scanning {len(to_scan)} government domains …")

    # Load existing data.json to merge results
    output_path = Path(args.output)
    existing: dict[str, dict] = {}
    if output_path.exists():
        try:
            existing = json.loads(output_path.read_text())["countries"]
        except Exception:
            pass

    # Rate limiter: 50 DNS queries/second globally
    limiter = AsyncLimiter(max_rate=50, time_period=1.0)
    sem = asyncio.Semaphore(args.concurrency)

    timeout = float(args.timeout)

    results: dict[str, dict] = dict(existing)

    async with httpx.AsyncClient(
        headers={"User-Agent": "govmap-scanner/1.0"},
        verify=False,  # Some gov sites have incomplete chains
    ) as http_client:
        doh = DoHClient(http_client, limiter, timeout)

        tasks = {
            iso2: scan_domain(iso2, entry, doh, http_client,
                              sem, timeout, args.no_dkim)
            for iso2, entry in to_scan.items()
        }

        with tqdm(total=len(tasks), unit="domain") as bar:
            for iso2, coro in tasks.items():
                result = await coro
                results[iso2] = result

                score_str = (
                    f"{result['score']:.0f}/100 {result['grade']}"
                    if result["score"] is not None
                    else f"ERR: {result.get('error', '')[:40]}"
                )
                bar.set_postfix_str(f"{iso2} {result['gov_domain']} → {score_str}")
                bar.update(1)

                # Print unresolvable domains clearly outside the progress bar
                if result.get("domain_reachable") is False:
                    e2      = to_scan[iso2]
                    status  = e2.get("status", "?")
                    src     = result.get("gov_domain_source", "unknown")
                    notes   = e2.get("notes") or ""
                    source_line = f"Wikidata P856" if src == "wikidata" else f"countries.json"
                    if notes:
                        source_line += f" · {notes}"
                    tqdm.write(
                        f"\033[33m[UNRESOLVABLE]\033[0m "
                        f"{result['gov_domain']} — "
                        f"{e2.get('name', iso2)} ({iso2}) "
                        f"[{status}]"
                        f"\n    Reason: {result.get('domain_notes', 'unknown')}"
                        f"\n    Source: {source_line}"
                    )

    stats = build_stats(results, len(countries))

    output = {
        "generated":       datetime.now(timezone.utc).isoformat(),
        "scanner_version": "1.0",
        "countries":       results,
        "stats":           stats,
    }

    output_path.write_text(
        json.dumps(output, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"\nWritten {len(results)} results → {output_path}")
    print(f"Scanned: {stats['scanned']}  Errors: {stats['errors']}  "
          f"Avg score: {stats['avg_score']}")
    g = stats["grade_distribution"]
    print(f"Grades: A={g['A']}  B={g['B']}  C={g['C']}  F={g['F']}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Government domain security scanner")
    ap.add_argument("--countries", default="countries.json",
                    help="Path to countries.json (default: countries.json)")
    ap.add_argument("--country", default="",
                    help="Comma-separated ISO2 codes to re-scan (default: all)")
    ap.add_argument("--concurrency", type=int, default=5,
                    help="Parallel domains (default: 5)")
    ap.add_argument("--timeout", type=float, default=8.0,
                    help="Per-query timeout in seconds (default: 8)")
    ap.add_argument("--output", default="data.json",
                    help="Output file (default: data.json)")
    ap.add_argument("--no-dkim", action="store_true", dest="no_dkim",
                    help="Skip DKIM selector probing (much faster)")
    args = ap.parse_args()

    asyncio.run(run(args))


if __name__ == "__main__":
    main()
