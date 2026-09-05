"""
clean.py
Section 3.6 — Data Cleaning.

Applies the five cleaning steps described in the methodology:
deduplication, date type coercion, missing-value handling,
severity-label standardisation, and derived temporal fields.

Usage:
    python clean.py
Reads:
    parsed_records.csv
Produces:
    clean_records.csv
"""

import pandas as pd

# From patterns.py, not config.py: config.py requires NVD_API_KEY to be set
# (it raises on import otherwise), but clean.py should run offline on an
# already-fetched parsed_records.csv with no API key needed at all.
from patterns import IIS_COMPONENT_PATTERN


def clean_data(df):
    df = df.copy()

    # Type coercion — malformed dates would compromise time-series analysis (Section 3.6)
    df["published_date"] = pd.to_datetime(df["published_date"], errors="coerce")
    df["last_modified"] = pd.to_datetime(df["last_modified"], errors="coerce")

    # Deduplication — overlapping 120-day query windows can produce duplicate rows
    before = len(df)
    df = df.drop_duplicates(subset=["cve_id", "platform"], keep="last")
    print(f"Deduplication removed {before - len(df)} rows")

    # Drop records with no usable CVE ID or publication date
    before = len(df)
    df = df.dropna(subset=["cve_id", "published_date"])
    print(f"Dropped {before - len(df)} rows with missing cve_id/published_date")

    # Severity standardisation — missing scores kept as UNKNOWN, not imputed
    df["cvss_severity"] = df["cvss_severity"].fillna("UNKNOWN").str.upper()
    df["cvss_score"] = pd.to_numeric(df["cvss_score"], errors="coerce")

    # Derived fields for Chapter 4 time-series and CWE-presence analysis
    df["pub_year"] = df["published_date"].dt.year
    df["pub_month"] = df["published_date"].dt.to_period("M").astype(str)
    df["has_cwe"] = df["cwe_ids"].notna()

    # IIS reclassification (Sections 3.4/3.9/4.x).
    #
    # NVD's CPE dictionary and MSRC's own product taxonomy both have no
    # field separating IIS from the rest of the Windows OS (confirmed
    # empirically against both sources), which is why the "iis" CPE
    # target in config.py returns zero records on its own. To give IIS a
    # real, analysable bucket in Tables 2-6 and the cross-platform overlap
    # matrix, any windows_server record whose description matches
    # IIS_COMPONENT_PATTERN is reassigned here from platform
    # "windows_server" to platform "iis" -- merging into the same "iis"
    # bucket the CPE-based query already targets.
    #
    # This IS a reclassification, not just a flag: it reduces Table 2's
    # windows_server count by the number of matches and gives "iis" a
    # non-zero count for the first time. That's the intended effect.
    #
    # iis_component_mention is kept as an audit trail marking exactly
    # which rows were moved this way (True) vs. rows that were already
    # tagged "iis" directly via CPE match (False, if any exist) -- useful
    # for the methods section and for manually spot-checking the keyword
    # match before citing it, since it's precision-biased, not
    # recall-complete.
    iis_mask = (
        (df["platform"] == "windows_server") &
        df["description"].fillna("").apply(lambda d: bool(IIS_COMPONENT_PATTERN.search(d)))
    )
    df["iis_component_mention"] = iis_mask
    df.loc[iis_mask, "platform"] = "iis"

    return df.reset_index(drop=True)


if __name__ == "__main__":
    df = pd.read_csv("parsed_records.csv")
    df_clean = clean_data(df)
    df_clean.to_csv("clean_records.csv", index=False)
    print(f"\nClean records: {len(df_clean)} -> clean_records.csv")
    print(df_clean.groupby("platform")["cve_id"].count())

    n_reclassified = int(df_clean["iis_component_mention"].sum())
    print(f"Records reclassified windows_server -> iis (keyword match): {n_reclassified}")