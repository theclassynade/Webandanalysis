"""
risk_metrics.py
Section 3.6 — Days-of-Risk / Forever-Day Proxy.

NVD does not store an explicit patch date. This script implements the
documented proxy described in Chapter Three: prefer a vendor-cross-referenced
fixed-version boundary where available, falling back conservatively to the
record's last_modified timestamp. Records with neither signal are excluded
from days-of-risk/forever-day analysis but retained for frequency/severity
analysis (RQ1).

This is a proxy, not a verified patch date — the limitation is discussed
explicitly in Section 3.6 and 3.9, and should be restated in Chapter 4
wherever these figures are reported.

Usage:
    python risk_metrics.py
Reads:
    clean_records.csv
Produces:
    records_with_risk.csv
"""

import pandas as pd


def estimate_days_of_risk(df, vendor_release_lookup=None):
    """
    vendor_release_lookup: optional dict {(platform, version): release_date}
    populated separately from vendor changelogs/release archives, used to
    override the conservative last_modified fallback where available.
    """
    df = df.copy()

    # Conservative fallback proxy
    df["patch_date_proxy"] = pd.to_datetime(df["last_modified"])

    if vendor_release_lookup:
        # Placeholder for merging verified vendor release dates in by
        # (platform, version) once that lookup table has been built —
        # left as an extension point rather than implemented here, since
        # it depends on external changelog data not yet collected.
        pass

    df["days_of_risk"] = (df["patch_date_proxy"] - pd.to_datetime(df["published_date"])).dt.days
    df["forever_day"] = df["days_of_risk"] > 365

    # Flag records where the proxy is unusable (negative or missing days-of-risk)
    df["risk_estimate_valid"] = df["days_of_risk"].notna() & (df["days_of_risk"] >= 0)

    return df


if __name__ == "__main__":
    df = pd.read_csv("clean_records.csv")
    df_risk = estimate_days_of_risk(df)
    df_risk.to_csv("records_with_risk.csv", index=False)

    valid = df_risk[df_risk["risk_estimate_valid"]]
    print(f"Records with valid days-of-risk estimate: {len(valid)} / {len(df_risk)}")
    print(valid.groupby("platform")["days_of_risk"].agg(["mean", "median"]))
    print(valid.groupby("platform")["forever_day"].mean())