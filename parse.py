"""
parse.py
Section 3.6 — Data Processing.

Flattens raw nvdlib CVE objects (as saved by extract.py) into a single
tabular pandas DataFrame, applying the CVSS version-fallback logic
described in Section 3.3 (prefer v3.1 -> v3.0 -> v2.0).

Nested structures (CPE match ranges, references) are stored as JSON
strings in their columns so they survive a CSV round-trip intact --
db.py parses them back out with json.loads() when loading into the
normalized cpe_matches / cve_references tables.

Usage:
    python parse.py
Reads:
    raw_records.pkl
Produces:
    parsed_records.csv
"""

import pickle
import json
import pandas as pd


def parse_records(records, platform_label):
    rows = []
    for cve in records:
        try:
            score, severity, vector, cvss_version = None, None, None, None
            if getattr(cve, "v31score", None) is not None:
                score, severity, vector, cvss_version = cve.v31score, cve.v31severity, cve.v31vector, "3.1"
            elif getattr(cve, "v30score", None) is not None:
                score, severity, vector, cvss_version = cve.v30score, cve.v30severity, cve.v30vector, "3.0"
            elif getattr(cve, "v2score", None) is not None:
                score, severity, vector, cvss_version = cve.v2score, cve.v2severity, cve.v2vector, "2.0"

            cwe_ids = [w.value for w in cve.cwe] if getattr(cve, "cwe", None) else []

            cpe_matches = []
            if getattr(cve, "cpe", None):
                for c in cve.cpe:
                    cpe_matches.append({
                        "criteria": getattr(c, "criteria", None),
                        "vulnerable": getattr(c, "vulnerable", None),
                        "version_start_incl": getattr(c, "versionStartIncluding", None),
                        "version_start_excl": getattr(c, "versionStartExcluding", None),
                        "version_end_incl": getattr(c, "versionEndIncluding", None),
                        "version_end_excl": getattr(c, "versionEndExcluding", None),
                    })

            references = []
            if getattr(cve, "references", None):
                for r in cve.references:
                    references.append({
                        "url": getattr(r, "url", None),
                        "source": getattr(r, "source", None),
                        "tags": getattr(r, "tags", None) or [],
                    })

            rows.append({
                "cve_id": cve.id,
                "platform": platform_label,
                "published_date": cve.published,
                "last_modified": cve.lastModified,
                "description": cve.descriptions[0].value if cve.descriptions else None,
                "cvss_score": score,
                "cvss_severity": severity,
                "cvss_vector": vector,
                "cvss_version": cvss_version,
                "cwe_ids": ";".join(cwe_ids) if cwe_ids else None,
                "vuln_status": getattr(cve, "vulnStatus", None),
                "cpe_matches": json.dumps(cpe_matches),
                "references": json.dumps(references),
            })
        except Exception as e:
            print(f"skip {getattr(cve, 'id', '?')}: {e}")

    return pd.DataFrame(rows)


def parse_all(raw_dict):
    frames = [parse_records(records, label) for label, records in raw_dict.items()]
    return pd.concat(frames, ignore_index=True)


if __name__ == "__main__":
    with open("raw_records.pkl", "rb") as f:
        raw = pickle.load(f)

    df = parse_all(raw)
    df.to_csv("parsed_records.csv", index=False)
    print(f"Parsed {len(df)} total records -> parsed_records.csv")
    print(df.groupby("platform")["cve_id"].count())