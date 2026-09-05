"""
separate_iis_component.py
Standalone convenience entry point for the IIS reclassification audit
trail (Table 7 / Section 4.x appendix).

The reclassification itself now happens automatically in clean.py: any
windows_server record matching config/patterns.IIS_COMPONENT_PATTERN is
moved to its own "iis" platform value there, which means Tables 2-6 and
the overlap matrix (Table 5) already include IIS as a real, non-zero
category with no extra step needed. This script just re-exposes
analysis.table7_iis_reclassification_audit() so you can list exactly
which CVEs were moved and why, for manual spot-checking before citing
them -- without duplicating that matching logic anywhere else.

Usage:
    python separate_iis_component.py
Reads:
    records_with_risk.csv
Produces (in ./analysis_output/):
    table7_iis_reclassification_audit.csv
"""

import os
import pandas as pd

from analysis import table7_iis_reclassification_audit, OUT_DIR

if __name__ == "__main__":
    os.makedirs(OUT_DIR, exist_ok=True)

    df = pd.read_csv("records_with_risk.csv", parse_dates=["published_date", "last_modified"])
    iis_count = int((df["platform"] == "iis").sum())

    audit = table7_iis_reclassification_audit(df)

    print(f"Records currently in the 'iis' platform bucket: {iis_count}")
    print(f"Of those, reclassified from windows_server via keyword match: {len(audit)}")
    print()
    print("Reclassified CVEs (verify each manually before citing as genuine IIS hits):")
    for _, row in audit.iterrows():
        snippet = str(row["description"])[:120]
        print(f"  {row['cve_id']}  |  {snippet}")

    audit.to_csv(f"{OUT_DIR}/table7_iis_reclassification_audit.csv", index=False)
    print(f"\nSaved {OUT_DIR}/table7_iis_reclassification_audit.csv ({len(audit)} rows)")