"""
main.py
Runs the full pipeline end to end: extract -> parse -> clean -> risk metrics
-> overlap -> (optional) PostgreSQL load.

Usage:
    export NVD_API_KEY="your-key-here"
    python main.py
"""

import pickle
import pandas as pd

from extract import extract_all_platforms
from parse import parse_all
from clean import clean_data
from risk_metrics import estimate_days_of_risk
from overlap import build_overlap_matrix
from analysis import run_analysis
from config import ALL_CPES

# Set to True once PostgreSQL is configured and reachable
LOAD_TO_DB = False


def run_pipeline():
    print("=== 1. Extraction ===")
    raw = extract_all_platforms()
    with open("raw_records.pkl", "wb") as f:
        pickle.dump(raw, f)

    print("\n=== 2. Parsing ===")
    df_parsed = parse_all(raw)
    df_parsed.to_csv("parsed_records.csv", index=False)

    print("\n=== 3. Cleaning ===")
    df_clean = clean_data(df_parsed)
    df_clean.to_csv("clean_records.csv", index=False)

    print("\n=== 4. Days-of-risk / forever-day ===")
    df_risk = estimate_days_of_risk(df_clean)
    df_risk.to_csv("records_with_risk.csv", index=False)

    print("\n=== 5. Cross-platform overlap ===")
    overlap_df = build_overlap_matrix(df_risk, list(ALL_CPES.keys()))
    overlap_df.to_csv("overlap_matrix.csv", index=False)

    print("\n=== Summary ===")
    print(df_risk.groupby("platform")["cve_id"].count())
    print(overlap_df.sort_values("jaccard_index").to_string(index=False))

    print("\n=== 6. Chapter Four tables (Tables 2-7, Figure 2) ===")
    # iis is now a real, reclassified platform category (see clean.py) --
    # it appears as its own row in Tables 2-6 and the overlap matrix
    # automatically. Table 7 is just the audit trail of which specific
    # windows_server records were moved there and why.
    run_analysis()

    if LOAD_TO_DB:
        print("\n=== 7. Loading to PostgreSQL ===")
        from db import load_all
        load_all(df_risk, overlap_df)

    print("\nPipeline complete. Outputs: clean_records.csv, records_with_risk.csv, "
          "overlap_matrix.csv, and ./analysis_output/ (Tables 2-7 + Figure 2 data, "
          "with iis reclassified out of windows_server into its own category).")


if __name__ == "__main__":
    run_pipeline()