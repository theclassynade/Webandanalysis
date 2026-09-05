"""
Usage:
    python visualize.py
Reads:
    records_with_risk.csv
    overlap_matrix.csv
Produces (in ./analysis_output/figures/):
    figure2_annual_trend.png
    figure3_cvss_boxplot.png
    figure4_survival_curves.png
    figure5_overlap_heatmap.png

NOTE (supervisor feedback, Aug 2026): earlier versions of this script
plotted web servers *and* operating systems side by side on the same
axes. That comparison doesn't answer this dissertation's research
questions (which are about web-server diversity), so as of this
version PLATFORM_ORDER is restricted to the three web servers in
scope: apache_httpd, nginx, iis. If you need the OS figures again for
an appendix, restore the longer list, but keep the web-server-only
figures as the primary ones referenced in Chapter Four.
"""

import os
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

OUT_DIR = "analysis_output/figures"
sns.set_theme(style="whitegrid", context="paper", font_scale=1.05)

# Web servers only -- this is the single source of truth for which
# platforms appear in the comparison figures. Add/remove a platform
# here and every figure below picks it up automatically (this is what
# broke before: PALETTE was a fixed dict that fell out of sync with
# the data after IIS was split out of windows_server).
PLATFORM_ORDER = ["apache_httpd", "nginx", "iis"]
PALETTE = dict(zip(PLATFORM_ORDER, sns.color_palette("tab10", len(PLATFORM_ORDER))))


def _ordered(df, col="platform"):
    """Return only the platforms that are both in PLATFORM_ORDER and
    actually present in df, in PLATFORM_ORDER's sequence. Anything in
    df but NOT in PLATFORM_ORDER (e.g. leftover OS rows) is silently
    excluded from these figures rather than crashing."""
    present = [p for p in PLATFORM_ORDER if p in df[col].unique()]
    return present


def _filtered(df, col="platform"):
    """Restrict a dataframe to rows whose platform is one of the three
    web servers, dropping OS rows before any plotting happens. This is
    the actual fix: previously every figure plotted whatever unique
    platform values were in the CSV, so as soon as a new category
    (iis) appeared without a matching palette entry, seaborn raised
    ValueError. Filtering here means new/unexpected platform values
    (e.g. if an OS sneaks back into records_with_risk.csv) are dropped
    quietly instead of crashing the whole script."""
    return df[df[col].isin(PLATFORM_ORDER)].copy()


def figure2_annual_trend(df):
    """Figure 2: Annual CVE publication trend per web server (line chart)."""
    df = _filtered(df)
    trend = df.groupby(["platform", "pub_year"])["cve_id"].nunique().reset_index()
    trend = trend.rename(columns={"cve_id": "cve_count"})

    fig, ax = plt.subplots(figsize=(8, 5))
    for platform in _ordered(trend):
        sub = trend[trend["platform"] == platform].sort_values("pub_year")
        ax.plot(sub["pub_year"], sub["cve_count"], marker="o",
                label=platform, color=PALETTE[platform])

    ax.set_title("Figure 2: Annual CVE Publication Trends by Web Server")
    ax.set_xlabel("Publication Year")
    ax.set_ylabel("Number of CVEs Published")
    ax.legend(title="Web Server", bbox_to_anchor=(1.02, 1), loc="upper left")
    ax.set_xticks(sorted(trend["pub_year"].unique()))
    fig.tight_layout()
    fig.savefig(f"{OUT_DIR}/figure2_annual_trend.png", dpi=300)
    plt.close(fig)


def figure3_cvss_boxplot(df):
    """Figure 3: CVSS score distribution per web server (box plot)."""
    data = _filtered(df).dropna(subset=["cvss_score"])
    order = _ordered(data)

    fig, ax = plt.subplots(figsize=(8, 5))
    sns.boxplot(
        data=data, x="platform", y="cvss_score", order=order,
        hue="platform", palette=PALETTE, legend=False, ax=ax
    )
    ax.set_title("Figure 3: CVSS Score Distributions by Web Server")
    ax.set_xlabel("Web Server")
    ax.set_ylabel("CVSS Base Score")
    ax.set_ylim(0, 10)
    plt.setp(ax.get_xticklabels(), rotation=30, ha="right")
    fig.tight_layout()
    fig.savefig(f"{OUT_DIR}/figure3_cvss_boxplot.png", dpi=300)
    plt.close(fig)


def figure4_survival_curves(df):
    """Figure 4: Empirical survival curves for days-of-risk per web server.

    S(t) = proportion of records still "unpatched" (per the
    last_modified proxy, Section 3.6) at t days after publication.
    This is a simple empirical complementary-CDF, not a Kaplan-Meier
    estimator -- there is no explicit censoring information in the NVD
    proxy, so KM would not add anything beyond this direct empirical
    curve. State this simplification explicitly wherever Figure 4 is
    discussed.
    """
    valid = _filtered(df)
    valid = valid[valid["risk_estimate_valid"] == True].copy()
    order = _ordered(valid)

    fig, ax = plt.subplots(figsize=(8, 5))
    max_days = int(valid["days_of_risk"].quantile(0.99))  # trim extreme tail for readability
    t_grid = np.linspace(0, max_days, 200)

    for platform in order:
        days = valid.loc[valid["platform"] == platform, "days_of_risk"].sort_values().values
        if len(days) == 0:
            continue
        survival = [(days > t).mean() for t in t_grid]
        ax.plot(t_grid, survival, label=platform, color=PALETTE[platform])

    ax.axvline(365, color="grey", linestyle="--", linewidth=1)
    ax.text(365, 1.02, "365-day\nforever-day threshold", fontsize=8,
            ha="center", va="bottom", color="grey")
    ax.set_title("Figure 4: Vulnerability Survival Curves (Days-of-Risk) by Web Server")
    ax.set_xlabel("Days Since Publication")
    ax.set_ylabel("Proportion Still Unremediated (proxy)")
    ax.set_ylim(0, 1.08)
    ax.legend(title="Web Server", bbox_to_anchor=(1.02, 1), loc="upper left")
    fig.tight_layout()
    fig.savefig(f"{OUT_DIR}/figure4_survival_curves.png", dpi=300)
    plt.close(fig)


def figure5_overlap_heatmap(overlap_df):
    """Figure 5: Heatmap of pairwise CWE-level Jaccard overlap.

    Restricted to the three web-server pairs (apache_httpd-nginx,
    apache_httpd-iis, nginx-iis) per supervisor feedback: the OS rows
    that used to populate this matrix don't belong in a web-server
    diversity comparison, and mixing sampling methods (CPE-based
    primary data vs earlier keyword-derived subsets) into one heatmap
    was flagged as a problem in its own right. If overlap_matrix.csv
    still contains OS pairs (from an older overlap.py run), they are
    filtered out here rather than requiring you to regenerate the CSV
    first.
    """
    overlap_df = overlap_df[
        overlap_df["platform_a"].isin(PLATFORM_ORDER)
        & overlap_df["platform_b"].isin(PLATFORM_ORDER)
    ].copy()

    platforms = [p for p in PLATFORM_ORDER
                 if p in set(overlap_df["platform_a"]) | set(overlap_df["platform_b"])]
    matrix = pd.DataFrame(np.nan, index=platforms, columns=platforms)

    for _, row in overlap_df.iterrows():
        matrix.loc[row["platform_a"], row["platform_b"]] = row["jaccard_index"]
        matrix.loc[row["platform_b"], row["platform_a"]] = row["jaccard_index"]
    for p in platforms:
        matrix.loc[p, p] = 1.0

    fig, ax = plt.subplots(figsize=(5.5, 5))
    sns.heatmap(
        matrix.astype(float), annot=True, fmt=".3f", cmap="RdYlGn_r",
        vmin=0, vmax=1, square=True, cbar_kws={"label": "Jaccard Index (CWE overlap)"},
        linewidths=0.5, ax=ax
    )
    ax.set_title("Figure 5: Pairwise CWE-Level Overlap Between Web Servers")
    fig.tight_layout()
    fig.savefig(f"{OUT_DIR}/figure5_overlap_heatmap.png", dpi=300)
    plt.close(fig)


def run_all():
    os.makedirs(OUT_DIR, exist_ok=True)
    df = pd.read_csv("records_with_risk.csv", parse_dates=["published_date", "last_modified"])
    overlap_df = pd.read_csv("overlap_matrix.csv")

    figure2_annual_trend(df)
    print(f"Saved {OUT_DIR}/figure2_annual_trend.png")

    figure3_cvss_boxplot(df)
    print(f"Saved {OUT_DIR}/figure3_cvss_boxplot.png")

    figure4_survival_curves(df)
    print(f"Saved {OUT_DIR}/figure4_survival_curves.png")

    figure5_overlap_heatmap(overlap_df)
    print(f"Saved {OUT_DIR}/figure5_overlap_heatmap.png")


if __name__ == "__main__":
    run_all()