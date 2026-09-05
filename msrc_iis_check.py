"""
msrc_iis_check.py
Supplementary source investigation -- checks whether Microsoft's OWN
vulnerability database (MSRC Security Update Guide) tags "Internet
Information Services" as a distinct product, separately from Windows
Server, for CVEs in the 2020-2025 study window.

Rationale: NVD's CPE dictionary was confirmed (Section 3.4/4.x) to carry
no IIS-specific field within windows_server CPE matches. MSRC is
Microsoft's own vendor-published source and, historically (pre-2016
bulletins), tagged IIS as its own product line separate from the OS.
This script tests whether that separation still exists in MSRC's modern
CVRF v3.0 API for the study window -- an empirical check, not an
assumption.

IMPORTANT: this could not be tested from the development sandbox used to
write it (msrc.microsoft.com is outside that environment's network
allowlist). It is built directly from Microsoft's documented CVRF v3.0
schema and public API examples, but has not been run against a live
response. Run it, and if the JSON structure differs from what's expected
below, share the first raw response and it can be adjusted quickly.

API reference: https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{YYYY-MMM}
No API key required (confirmed public, unauthenticated per Microsoft's
own documentation and third-party integration docs, e.g. Brinqa's MSRC
connector docs).

Usage:
    python msrc_iis_check.py
Produces:
    msrc_iis_candidates.csv   (any CVE where a product name matches "Internet
                                Information Services", month by month)
"""

import time
import calendar
import requests
import pandas as pd

BASE_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{month}"
HEADERS = {"Accept": "application/json"}
REQUEST_DELAY_SECONDS = 2  # be polite to a free, unauthenticated public API

STUDY_START_YEAR = 2020
STUDY_END_YEAR = 2025

IIS_PRODUCT_KEYWORDS = ("internet information services", "iis")


def month_labels(start_year, end_year):
    """MSRC's URL scheme uses e.g. '2023-Oct', not '2023-10'."""
    labels = []
    for year in range(start_year, end_year + 1):
        for month_num in range(1, 13):
            month_abbr = calendar.month_abbr[month_num]  # 'Jan', 'Feb', ...
            labels.append(f"{year}-{month_abbr}")
    return labels


def fetch_month(month_label):
    url = BASE_URL.format(month=month_label)
    try:
        resp = requests.get(url, headers=HEADERS, timeout=30)
        if resp.status_code == 404:
            return None  # no bulletin that month -- not an error
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        print(f"  [{month_label}] error: {e}")
        return None


def extract_iis_candidates(cvrf_json, month_label):
    """Given a parsed CVRF document, find every vulnerability associated
    with a product whose name mentions IIS. CVRF schema (per Microsoft's
    published structure): top-level 'ProductTree' -> 'FullProductName'
    (list of {'ProductID': ..., 'Value': ...}), and top-level
    'Vulnerability' (list), each with 'CVE' and 'ProductStatuses' listing
    affected ProductID(s)."""
    if not cvrf_json:
        return []

    product_tree = cvrf_json.get("ProductTree", {})
    full_products = product_tree.get("FullProductName", [])
    iis_product_ids = {
        p.get("ProductID")
        for p in full_products
        if any(kw in (p.get("Value") or "").lower() for kw in IIS_PRODUCT_KEYWORDS)
    }
    if not iis_product_ids:
        return []  # no IIS-named product this month -- expected if folded into OS

    hits = []
    for vuln in cvrf_json.get("Vulnerability", []):
        cve_id = vuln.get("CVE")
        affected_ids = set()
        for status_group in vuln.get("ProductStatuses", []):
            affected_ids.update(status_group.get("ProductID", []))
        matched = affected_ids & iis_product_ids
        if matched:
            matched_names = [
                p["Value"] for p in full_products if p.get("ProductID") in matched
            ]
            hits.append({
                "month": month_label,
                "cve_id": cve_id,
                "matched_iis_products": "; ".join(matched_names),
            })
    return hits


if __name__ == "__main__":
    all_hits = []
    months = month_labels(STUDY_START_YEAR, STUDY_END_YEAR)
    print(f"Checking {len(months)} monthly bulletins ({months[0]} to {months[-1]})...")

    for month_label in months:
        cvrf = fetch_month(month_label)
        hits = extract_iis_candidates(cvrf, month_label)
        if hits:
            print(f"  [{month_label}] {len(hits)} IIS-tagged CVE(s) found")
            all_hits.extend(hits)
        time.sleep(REQUEST_DELAY_SECONDS)

    df = pd.DataFrame(all_hits)
    df.to_csv("msrc_iis_candidates.csv", index=False)
    print(f"\nTotal IIS-tagged CVEs found across {STUDY_START_YEAR}-{STUDY_END_YEAR}: {len(df)}")
    if len(df) == 0:
        print("Zero hits: MSRC likely no longer tags IIS as a distinct product")
        print("separately from the Windows OS product line in this window --")
        print("this would CONFIRM the structural finding from Section 3.4/4.x")
        print("via a second, independent, vendor-authoritative source, which")
        print("is a stronger result than the NVD-only finding on its own.")
    else:
        print("Saved msrc_iis_candidates.csv -- review each CVE ID for genuine")
        print("relevance before citing (spot-check a few against msrc.microsoft.com")
        print("directly, e.g. https://msrc.microsoft.com/update-guide/vulnerability/<CVE-ID>)")