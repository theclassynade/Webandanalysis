"""
db.py
Section 3.5 — Database Design (normalized schema).

Creates the seven-table PostgreSQL schema:
  cve_records, cvss_scores, weaknesses, cpe_matches,
  cve_references, risk_metrics, platform_overlap

and loads the cleaned/enriched dataset into it.

Usage:
    python db.py
Reads:
    records_with_risk.csv   (from clean.py -> risk_metrics.py)
    overlap_matrix.csv      (from overlap.py)
Requires:
    A reachable PostgreSQL instance; connection params from config.PG_CONN_PARAMS.
    Set via environment variables: PG_HOST, PG_PORT, PG_DBNAME, PG_USER, PG_PASSWORD
"""

import json
import pandas as pd
import psycopg2

from config import PG_CONN_PARAMS

DDL = """
CREATE TABLE IF NOT EXISTS cves (
    cve_id              VARCHAR(20) PRIMARY KEY,
    source_identifier   VARCHAR(100),
    published_date      TIMESTAMP NOT NULL,
    last_modified       TIMESTAMP,
    vuln_status         VARCHAR(30),
    description         TEXT,
    has_kev             BOOLEAN DEFAULT FALSE,
    kev_added_date       DATE,
    is_rejected           BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS cve_platforms (
    cve_id      VARCHAR(20) NOT NULL,
    platform    VARCHAR(50) NOT NULL,
    iis_component_mention BOOLEAN DEFAULT FALSE,
    PRIMARY KEY (cve_id, platform),
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
);

-- Belt-and-braces for databases created before this column existed:
-- CREATE TABLE IF NOT EXISTS is a no-op on an already-existing table, so
-- this ALTER is what actually adds the column on a schema that predates
-- the IIS-component analysis (Sections 3.4/3.9/4.x). Harmless/no-op if
-- the column is already there.
ALTER TABLE cve_platforms ADD COLUMN IF NOT EXISTS iis_component_mention BOOLEAN DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS cvss_scores (
    id                SERIAL PRIMARY KEY,
    cve_id            VARCHAR(20) NOT NULL,
    cvss_version      VARCHAR(10) NOT NULL,
    base_score        NUMERIC(3,1),
    base_severity     VARCHAR(20),
    vector_string     TEXT,
    access_vector     VARCHAR(20),
    is_primary_score  BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE,
    UNIQUE (cve_id, cvss_version)
);

CREATE TABLE IF NOT EXISTS weaknesses (
    id      SERIAL PRIMARY KEY,
    cve_id  VARCHAR(20) NOT NULL,
    cwe_id  VARCHAR(20) NOT NULL,
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE,
    UNIQUE (cve_id, cwe_id)
);

CREATE TABLE IF NOT EXISTS cpe_matches (
    id                    SERIAL PRIMARY KEY,
    cve_id                VARCHAR(20) NOT NULL,
    criteria              TEXT NOT NULL,
    vulnerable            BOOLEAN,
    version_start_incl    VARCHAR(50),
    version_start_excl    VARCHAR(50),
    version_end_incl      VARCHAR(50),
    version_end_excl      VARCHAR(50),
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cve_references (
    id      SERIAL PRIMARY KEY,
    cve_id  VARCHAR(20) NOT NULL,
    url     TEXT,
    source  VARCHAR(100),
    tags    TEXT[],
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS risk_metrics (
    cve_id            VARCHAR(20) NOT NULL,
    platform          VARCHAR(50) NOT NULL,
    patch_date_proxy  TIMESTAMP,
    days_of_risk      INTEGER,
    forever_day       BOOLEAN,
    estimate_valid    BOOLEAN,
    computed_at       TIMESTAMP DEFAULT NOW(),
    PRIMARY KEY (cve_id, platform),
    FOREIGN KEY (cve_id, platform) REFERENCES cve_platforms(cve_id, platform) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS platform_overlap (
    id                 SERIAL PRIMARY KEY,
    platform_a         VARCHAR(50) NOT NULL,
    platform_b         VARCHAR(50) NOT NULL,
    jaccard_index      NUMERIC(6,5),
    diversity_score    NUMERIC(6,5),
    shared_cwe_count   INTEGER,
    cwe_a_only         INTEGER,
    cwe_b_only         INTEGER,
    computed_at        TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cveplatform_platform ON cve_platforms(platform);
CREATE INDEX IF NOT EXISTS idx_cve_pubdate          ON cves(published_date);
CREATE INDEX IF NOT EXISTS idx_cvss_cve             ON cvss_scores(cve_id);
CREATE INDEX IF NOT EXISTS idx_cvss_severity        ON cvss_scores(base_severity);
CREATE INDEX IF NOT EXISTS idx_weakness_cwe         ON weaknesses(cwe_id);
CREATE INDEX IF NOT EXISTS idx_weakness_cve         ON weaknesses(cve_id);
CREATE INDEX IF NOT EXISTS idx_cpe_cve              ON cpe_matches(cve_id);
CREATE INDEX IF NOT EXISTS idx_cveplatform_iis       ON cve_platforms(iis_component_mention) WHERE iis_component_mention = TRUE;
"""


def create_schema(conn_params=PG_CONN_PARAMS):
    conn = psycopg2.connect(**conn_params)
    cur = conn.cursor()
    cur.execute(DDL)
    conn.commit()
    cur.close()
    conn.close()
    print("Schema created (7 tables + indexes).")


def load_cve_records(cur, df):
    for _, row in df.iterrows():
        # CVE-level facts go in cves (one row per cve_id, regardless of platform)
        cur.execute("""
            INSERT INTO cves
            (cve_id, source_identifier, published_date, last_modified,
             vuln_status, description, has_kev, is_rejected)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (cve_id) DO NOTHING
        """, (
            row["cve_id"], row.get("source_identifier"),
            row["published_date"], row.get("last_modified"), row.get("vuln_status"),
            row.get("description"), row.get("has_kev", False), row.get("is_rejected", False),
        ))

        # platform mapping goes in cve_platforms (many-to-many).
        # iis_component_mention comes from clean.py's reclassification step
        # (Sections 3.4/3.9/4.x): True marks a record that was moved from
        # windows_server to platform "iis" via keyword match, so on these
        # rows platform will already read "iis", not "windows_server".
        # ON CONFLICT here is DO UPDATE rather than DO NOTHING so that
        # re-running the loader after a fresh extract/clean pass refreshes
        # this flag too, instead of freezing it at whatever the first load saw.
        cur.execute("""
            INSERT INTO cve_platforms (cve_id, platform, iis_component_mention)
            VALUES (%s,%s,%s)
            ON CONFLICT (cve_id, platform)
            DO UPDATE SET iis_component_mention = EXCLUDED.iis_component_mention
        """, (row["cve_id"], row["platform"], bool(row.get("iis_component_mention", False))))

        # cvss_scores (one row per record here; extend if multiple versions retained)
        if pd.notna(row.get("cvss_score")):
            cur.execute("""
                INSERT INTO cvss_scores
                (cve_id, cvss_version, base_score, base_severity, vector_string, is_primary_score)
                VALUES (%s,%s,%s,%s,%s,%s)
                ON CONFLICT (cve_id, cvss_version) DO NOTHING
            """, (
                row["cve_id"], row.get("cvss_version"), row.get("cvss_score"),
                row.get("cvss_severity"), row.get("cvss_vector"), True,
            ))

        # weaknesses (semicolon-delimited cwe_ids column from clean.py)
        cwe_ids = row.get("cwe_ids")
        if isinstance(cwe_ids, str) and cwe_ids:
            for cwe in cwe_ids.split(";"):
                cur.execute("""
                    INSERT INTO weaknesses (cve_id, cwe_id)
                    VALUES (%s,%s) ON CONFLICT (cve_id, cwe_id) DO NOTHING
                """, (row["cve_id"], cwe))

        # cpe_matches (JSON-serialized list from parse.py)
        cpe_matches_raw = row.get("cpe_matches")
        if isinstance(cpe_matches_raw, str) and cpe_matches_raw:
            try:
                cpe_matches = json.loads(cpe_matches_raw)
            except (json.JSONDecodeError, TypeError):
                cpe_matches = []
            for m in cpe_matches:
                cur.execute("""
                    INSERT INTO cpe_matches
                    (cve_id, criteria, vulnerable, version_start_incl, version_start_excl,
                     version_end_incl, version_end_excl)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)
                """, (
                    row["cve_id"], m.get("criteria"), m.get("vulnerable"),
                    m.get("version_start_incl"), m.get("version_start_excl"),
                    m.get("version_end_incl"), m.get("version_end_excl"),
                ))

        # cve_references (JSON-serialized list from parse.py)
        references_raw = row.get("references")
        if isinstance(references_raw, str) and references_raw:
            try:
                references = json.loads(references_raw)
            except (json.JSONDecodeError, TypeError):
                references = []
            for r in references:
                cur.execute("""
                    INSERT INTO cve_references (cve_id, url, source, tags)
                    VALUES (%s,%s,%s,%s)
                """, (
                    row["cve_id"], r.get("url"), r.get("source"), r.get("tags") or [],
                ))

        # risk_metrics
        if pd.notna(row.get("days_of_risk")):
            cur.execute("""
                INSERT INTO risk_metrics
                (cve_id, platform, patch_date_proxy, days_of_risk, forever_day, estimate_valid)
                VALUES (%s,%s,%s,%s,%s,%s)
                ON CONFLICT (cve_id, platform) DO NOTHING
            """, (
                row["cve_id"], row["platform"], row.get("patch_date_proxy"),
                row.get("days_of_risk"), row.get("forever_day"), row.get("risk_estimate_valid"),
            ))


def load_overlap(cur, overlap_df):
    for _, row in overlap_df.iterrows():
        cur.execute("""
            INSERT INTO platform_overlap
            (platform_a, platform_b, jaccard_index, diversity_score,
             shared_cwe_count, cwe_a_only, cwe_b_only)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
        """, (
            row["platform_a"], row["platform_b"], row["jaccard_index"], row["diversity_score"],
            row["shared_cwe_count"], row["cwe_a_only"], row["cwe_b_only"],
        ))


def load_all(df, overlap_df=None, conn_params=PG_CONN_PARAMS):
    conn = psycopg2.connect(**conn_params)
    cur = conn.cursor()
    load_cve_records(cur, df)
    if overlap_df is not None:
        load_overlap(cur, overlap_df)
    conn.commit()
    cur.close()
    conn.close()
    print(f"Loaded {len(df)} CVE rows" + (f" and {len(overlap_df)} overlap rows" if overlap_df is not None else ""))


def test_connection(conn_params=PG_CONN_PARAMS):
    """Quick sanity check -- run this first before anything else."""
    try:
        conn = psycopg2.connect(**conn_params)
        cur = conn.cursor()
        cur.execute("SELECT version();")
        print("Connected OK:", cur.fetchone()[0])
        cur.close()
        conn.close()
        return True
    except Exception as e:
        print("Connection failed:", e)
        return False


if __name__ == "__main__":
    if test_connection():
        create_schema()
        try:
            df = pd.read_csv("records_with_risk.csv")
            overlap_df = pd.read_csv("overlap_matrix.csv")
            load_all(df, overlap_df)
        except FileNotFoundError:
            print("No CSVs found yet -- run extract.py/parse.py/clean.py/risk_metrics.py/overlap.py first.")