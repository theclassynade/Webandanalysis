"""
analyze.py
Chapter 4 analysis -- produces Tables 2, 3, 4, 6 and the Figure 2 trend data
directly from the pipeline's CSV outputs. Table 5 (overlap matrix) already
exists as overlap_matrix.csv from overlap.py -- this script doesn't
recompute it, just reports it alongside the others for a complete picture.

Usage:
    python analyze.py
Reads:
    records_with_risk.csv
    overlap_matrix.csv
Produces (in ./analysis_output/):
    table2_platform_counts.csv
    table3_severity_distribution.csv
    table3_cvss_stats.csv
    table4_days_of_risk.csv
    table6_top_cwe.csv
    figure2_annual_trend.csv
Also prints everything to console for a quick read.
"""

import os
import pandas as pd

OUT_DIR = "analysis_output"


def table2_platform_counts(df):
    """Table 2: Summary of Vulnerability Counts by Platform."""
    counts = df.groupby("platform")["cve_id"].nunique().rename("total_cves")
    total = counts.sum()
    pct = (counts / total * 100).round(2).rename("pct_of_dataset")

    date_range = df.groupby("platform")["published_date"].agg(
        earliest="min", latest="max"
    )

    result = pd.concat([counts, pct, date_range], axis=1).reset_index()
    result = result.sort_values("total_cves", ascending=False)
    return result


def table3_severity_distribution(df):
    """Table 3: CVSS Severity Distribution by Platform (counts + %)."""
    dist = pd.crosstab(df["platform"], df["cvss_severity"])
    dist_pct = dist.div(dist.sum(axis=1), axis=0).round(4) * 100
    dist_pct.columns = [f"{c}_pct" for c in dist_pct.columns]
    result = pd.concat([dist, dist_pct], axis=1).reset_index()
    return result


def table3_cvss_stats(df):
    """Supplementary to Table 3: mean/median/SD of CVSS score per platform."""
    stats = df.groupby("platform")["cvss_score"].agg(
        mean_score="mean", median_score="median", std_score="std", n_scored="count"
    ).round(2).reset_index()
    return stats


def table4_days_of_risk(df):
    """Table 4: Mean Days-of-Risk and Forever-Day Proportion by Platform."""
    valid = df[df.get("risk_estimate_valid", False) == True] if "risk_estimate_valid" in df.columns else df
    if valid.empty or "days_of_risk" not in df.columns:
        return pd.DataFrame({"note": ["No valid days-of-risk data available"]})

    stats = valid.groupby("platform")["days_of_risk"].agg(
        mean_days="mean", median_days="median", n_valid="count"
    ).round(1)

    forever_pct = valid.groupby("platform")["forever_day"].mean().mul(100).round(2).rename("pct_forever_day")

    total_per_platform = df.groupby("platform")["cve_id"].nunique().rename("total_cves")
    pct_excluded = (100 - (stats["n_valid"] / total_per_platform * 100)).round(2).rename("pct_excluded_insufficient_data")

    result = pd.concat([stats, forever_pct, pct_excluded], axis=1).reset_index()
    return result


def table6_top_cwe(df, top_n=10):
    """Table 6: Top CWE Types per Platform."""
    rows = []
    for platform, group in df.groupby("platform"):
        cwe_counts = {}
        for cwe_str in group["cwe_ids"].dropna():
            for cwe in str(cwe_str).split(";"):
                cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
        top = sorted(cwe_counts.items(), key=lambda x: -x[1])[:top_n]
        for rank, (cwe, count) in enumerate(top, start=1):
            rows.append({"platform": platform, "rank": rank, "cwe_id": cwe, "count": count})
    return pd.DataFrame(rows)


def table7_iis_reclassification_audit(df):
    """Table 7 / Section 4.x appendix: audit trail of which records were
    reclassified from windows_server to the "iis" platform via the
    keyword match in clean.py (Sections 3.4/3.9/4.x).

    This is deliberately NOT a duplicate of Table 2/3/4/6 for the "iis"
    platform -- those tables already include these records naturally,
    since "iis" is now a real value in the platform column rather than a
    permanently-empty CPE target. This table exists purely so the specific
    CVEs that moved can be listed and spot-checked before being cited,
    since a free-text keyword match is precision-biased, not
    recall-complete.
    """
    reclassified = df[
        (df["platform"] == "iis") & (df.get("iis_component_mention", False) == True)
    ].copy()

    cols = [c for c in ["cve_id", "published_date", "cvss_score", "cvss_severity", "description"]
            if c in reclassified.columns]
    if "published_date" in reclassified.columns:
        reclassified = reclassified.sort_values("published_date")

    return reclassified[cols]


def figure2_annual_trend(df):
    """Figure 2 data: CVE count per platform per year."""
    trend = df.groupby(["platform", "pub_year"])["cve_id"].nunique().reset_index()
    trend = trend.rename(columns={"cve_id": "cve_count"})
    return trend.sort_values(["platform", "pub_year"])


def run_analysis():
    os.makedirs(OUT_DIR, exist_ok=True)

    df = pd.read_csv("records_with_risk.csv", parse_dates=["published_date", "last_modified"])

    print("=" * 60)
    print("TABLE 2: Platform Counts")
    print("=" * 60)
    t2 = table2_platform_counts(df)
    print(t2.to_string(index=False))
    t2.to_csv(f"{OUT_DIR}/table2_platform_counts.csv", index=False)

    print("\n" + "=" * 60)
    print("TABLE 3: Severity Distribution")
    print("=" * 60)
    t3 = table3_severity_distribution(df)
    print(t3.to_string(index=False))
    t3.to_csv(f"{OUT_DIR}/table3_severity_distribution.csv", index=False)

    print("\n" + "=" * 60)
    print("TABLE 3 (supplementary): CVSS Score Stats")
    print("=" * 60)
    t3b = table3_cvss_stats(df)
    print(t3b.to_string(index=False))
    t3b.to_csv(f"{OUT_DIR}/table3_cvss_stats.csv", index=False)

    print("\n" + "=" * 60)
    print("TABLE 4: Days-of-Risk / Forever-Day")
    print("=" * 60)
    t4 = table4_days_of_risk(df)
    print(t4.to_string(index=False))
    t4.to_csv(f"{OUT_DIR}/table4_days_of_risk.csv", index=False)

    print("\n" + "=" * 60)
    print("TABLE 6: Top CWE Types per Platform")
    print("=" * 60)
    t6 = table6_top_cwe(df)
    print(t6.to_string(index=False))
    t6.to_csv(f"{OUT_DIR}/table6_top_cwe.csv", index=False)

    print("\n" + "=" * 60)
    print("TABLE 7 (appendix): IIS Reclassification Audit Trail")
    print("=" * 60)
    t7 = table7_iis_reclassification_audit(df)
    print(f"{len(t7)} records reclassified windows_server -> iis (keyword match)")
    print("(already included as the 'iis' row in Tables 2-6 and Table 5 above --")
    print(" this just lists which specific CVEs moved, for manual spot-checking)")
    t7.to_csv(f"{OUT_DIR}/table7_iis_reclassification_audit.csv", index=False)

    print("\n" + "=" * 60)
    print("FIGURE 2 data: Annual Trend")
    print("=" * 60)
    f2 = figure2_annual_trend(df)
    print(f2.to_string(index=False))
    f2.to_csv(f"{OUT_DIR}/figure2_annual_trend.csv", index=False)

    print("\n" + "=" * 60)
    print("TABLE 5: Overlap Matrix (from overlap.py -- shown for completeness)")
    print("=" * 60)
    try:
        t5 = pd.read_csv("overlap_matrix.csv")
        print(t5.sort_values("jaccard_index").to_string(index=False))
    except FileNotFoundError:
        print("overlap_matrix.csv not found -- run overlap.py first")

    print(f"\nAll tables saved to ./{OUT_DIR}/")


if __name__ == "__main__":
    run_analysis()