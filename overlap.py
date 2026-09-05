"""
overlap.py
Section 3.7 — Cross-Platform Overlap (Jaccard similarity).

Computes CWE-level Jaccard overlap between every pairwise combination of
web server platforms, operating systems, and cross-stack pairs. CWE-level
(not CVE-ID-level) overlap is used because Apache, Nginx, and IIS are
independently developed and essentially never share a literal CVE ID —
this adaptation is documented in Section 3.2 and 3.7.

Usage:
    python overlap.py
Reads:
    records_with_risk.csv
Produces:
    overlap_matrix.csv
"""

import pandas as pd


def get_cwe_set(df, platform):
    subset = df[df["platform"] == platform]
    all_cwes = set()
    for cwe_str in subset["cwe_ids"].dropna():
        all_cwes.update(cwe_str.split(";"))
    return all_cwes


def jaccard_overlap(df, platform_a, platform_b):
    set_a = get_cwe_set(df, platform_a)
    set_b = get_cwe_set(df, platform_b)

    if not set_a or not set_b:
        return None

    intersection = set_a & set_b
    union = set_a | set_b

    return {
        "platform_a": platform_a,
        "platform_b": platform_b,
        "jaccard_index": len(intersection) / len(union),
        "diversity_score": 1 - (len(intersection) / len(union)),
        "shared_cwe_count": len(intersection),
        "cwe_a_only": len(set_a - set_b),
        "cwe_b_only": len(set_b - set_a),
    }


def build_overlap_matrix(df, platforms):
    results = []
    for i, a in enumerate(platforms):
        for b in platforms[i + 1:]:
            r = jaccard_overlap(df, a, b)
            if r:
                results.append(r)
    return pd.DataFrame(results)


if __name__ == "__main__":
    from config import ALL_CPES

    df = pd.read_csv("records_with_risk.csv")
    platforms = list(ALL_CPES.keys())

    overlap_df = build_overlap_matrix(df, platforms)
    overlap_df.to_csv("overlap_matrix.csv", index=False)

    print(overlap_df.sort_values("jaccard_index").to_string(index=False))
    print("\nSaved overlap_matrix.csv")