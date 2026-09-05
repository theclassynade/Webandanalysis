# Webandanalysis
Analysing Vulnerability statistics of web servers and their diversity for intrusion tolerance.
Webanalysis
Research pipeline for a study comparing vulnerability patterns across web server
platforms (Apache, Nginx, IIS) and operating systems (Ubuntu, RHEL, Debian,
Windows Server), built on data pulled from the NVD (National Vulnerability
Database) API.
What it does
The pipeline runs end-to-end in six stages:
Extract (`extract.py`) — pulls CVE records from NVD by CPE (product)
match string, chunked into ≤120-day windows per NVD's API limit. Warns
explicitly if any individual CPE variant returns zero records.
Parse (`parse.py`) — flattens the raw NVD objects into a tabular
DataFrame, applying CVSS version fallback (v3.1 → v3.0 → v2.0).
Clean (`clean.py`) — dedupes, coerces dates, standardizes severity
labels, derives year/month fields, and reclassifies any `windows_server`
record whose description mentions IIS into its own `iis` platform bucket
(since NVD/MSRC don't tag IIS separately from Windows).
Risk metrics (`risk_metrics.py`) — estimates "days of risk" /
forever-day status using `last_modified` as a conservative patch-date
proxy.
Overlap (`overlap.py`) — computes CWE-level Jaccard similarity between
every platform pair.
Analysis (`analysis.py`) — generates the thesis's Chapter 4 tables
(platform counts, severity distribution, days-of-risk, top CWEs, IIS
audit trail, annual trend) into `./analysis_output/`.
An optional 7th step (`db.py`) loads everything into a normalized
PostgreSQL schema.
Project layout
File	Purpose
`main.py`	Runs the full pipeline in order
`config.py`	CPE target lists, study date window, API key / DB config (requires `NVD_API_KEY`)
`patterns.py`	Shared IIS-matching regex (no API key needed — used by offline scripts)
`extract.py`	NVD API extraction
`parse.py`	Raw → tabular parsing
`clean.py`	Cleaning + IIS reclassification
`risk_metrics.py`	Days-of-risk / forever-day proxy
`overlap.py`	Cross-platform CWE Jaccard overlap
`analysis.py`	Chapter 4 tables & figures
`separate_iis_component.py`	Standalone re-export of the IIS audit trail table
`msrc_check.py` / `msrc_iis_check.py`	Diagnostic scripts probing Microsoft's MSRC API as a supplementary IIS data source
`db.py`	PostgreSQL schema + loader
Generated data files (already present in this project from a prior run):
`raw_records.pkl`, `parsed_records.csv`, `clean_records.csv`,
`records_with_risk.csv`, `overlap_matrix.csv`,
`windows_server_iis_component.csv`, and the `analysis_output/` folder with
Tables 2–7 and Figure 2.
Setup
```bash
pip install -r requirements.txt
```
Requires: `nvdlib`, `pandas`, `psycopg2-binary`, `python-dateutil`,
`python-dotenv`
Create a `.env` file (never commit this) with:
```
NVD_API_KEY=your-key-here
PG_HOST=...
PG_PORT=...
PG_DBNAME=...
PG_USER=...
PG_PASSWORD=...
```
> **Security note:** the project as shared includes a populated `.env` file
> with live credentials. Avoid sharing that file further, and rotate the
> NVD/PostgreSQL credentials if it's already been shared anywhere.
Running
```bash
python main.py
```
Set `LOAD_TO_DB = True` at the top of `main.py` once PostgreSQL is reachable
to also run the DB load step.
Individual stages can also be run standalone (each reads/writes the CSV
from the previous stage), e.g.:
```bash
python extract.py
python parse.py
python clean.py
python risk_metrics.py
python overlap.py
python analysis.py
```
Notes on the IIS handling
A recurring theme in the code comments: NVD's CPE dictionary has no field
that separates IIS from the Windows Server OS, so a direct IIS CPE query
returns ~zero records. The pipeline works around this by keyword-matching
IIS mentions in `windows_server` record descriptions (`patterns.py`'s
`IIS_COMPONENT_PATTERN`) and moving those rows into a dedicated `iis`
platform category during cleaning. `msrc_iis_check.py` is an exploratory
script testing whether Microsoft's own MSRC vulnerability feed tags IIS
separately — per its own docstring, it was written but not yet run
against a live response.
