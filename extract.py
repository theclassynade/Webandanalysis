"""
extract.py
Section 3.4 — Data Collection Procedure.

Streams CVE records from the NVD API, filtered by CPE (product/OS identity)
and chunked into <=120-day date windows as required by the NVD API.

Usage:
    python extract.py
Produces:
    raw_records.pkl   (dict of {label: [CVE objects]})
"""

import time
import pickle
from datetime import datetime

import nvdlib
import pandas as pd

from config import (
    API_KEY, ALL_CPES, STUDY_START_DATE, STUDY_END_DATE,
    REQUEST_DELAY_SECONDS, MAX_WINDOW_DAYS
)


def fetch_by_cpe(cpe_name, start_date, end_date, api_key=API_KEY,
                  delay=REQUEST_DELAY_SECONDS, max_window_days=MAX_WINDOW_DAYS):
    """Fetch all CVE records matching a single CPE string within a date range,
    chunked into windows no larger than max_window_days (NVD API limit)."""
    all_records = []
    current_start = datetime.strptime(start_date, "%Y-%m-%d")
    final_end = datetime.strptime(end_date, "%Y-%m-%d")

    while current_start < final_end:
        window_end = min(current_start + pd.Timedelta(days=max_window_days), final_end)
        print(f"[{cpe_name}] {current_start.date()} -> {window_end.date()}")
        try:
            results = nvdlib.searchCVE(
                virtualMatchString=cpe_name,
                pubStartDate=current_start.strftime("%Y-%m-%d %H:%M"),
                pubEndDate=window_end.strftime("%Y-%m-%d %H:%M"),
                key=api_key,
                delay=delay,
            )
            all_records.extend(results)
        except Exception as e:
            print(f"  error fetching window: {e}")
        current_start = window_end
        time.sleep(delay)

    return all_records


def extract_all_platforms(start_date=STUDY_START_DATE, end_date=STUDY_END_DATE):
    """Fetch records for every configured web server and OS CPE target.
    Each platform may map to multiple CPE variants (see config.py) --
    results across variants are merged and deduplicated by CVE ID.

    Each individual CPE variant's yield is checked and reported separately
    (not just the merged per-platform total). This closes the exact gap
    that originally let IIS silently return zero records across an entire
    study window without raising an error: a per-variant zero used to blend
    invisibly into a multi-variant platform's merged count. It no longer can.
    """
    dataset = {}
    variant_zero_warnings = []
    for label, cpe_list in ALL_CPES.items():
        merged = {}
        for cpe in cpe_list:
            records = fetch_by_cpe(cpe, start_date, end_date)
            print(f"    [{label}] variant '{cpe}' -> {len(records)} records")
            if len(records) == 0:
                variant_zero_warnings.append((label, cpe))
            for r in records:
                merged[r.id] = r  # dedupe across CPE variants by CVE ID
        dataset[label] = list(merged.values())
        print(f"  -> {label}: {len(dataset[label])} records (from {len(cpe_list)} CPE variant(s))")

    if variant_zero_warnings:
        print("\n" + "=" * 60)
        print("WARNING: the following CPE variants returned ZERO records")
        print("for the full study window. This does not necessarily mean")
        print("the platform has zero vulnerabilities -- verify the CPE")
        print("string against https://nvd.nist.gov/products/cpe/search")
        print("before treating a platform's merged total as reliable.")
        print("=" * 60)
        for label, cpe in variant_zero_warnings:
            print(f"  [{label}] {cpe}")
        print()

    return dataset


if __name__ == "__main__":
    raw = extract_all_platforms()
    with open("raw_records.pkl", "wb") as f:
        pickle.dump(raw, f)
    print("\nSaved raw_records.pkl")
    for label, records in raw.items():
        print(f"  {label}: {len(records)} records")