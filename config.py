"""
config.py
Central configuration: CPE targets for the study and API key handling.

Secrets (NVD_API_KEY, PG_* variables) are loaded from a local .env file via
python-dotenv if one exists in the working directory. .env is never
committed to git or pasted anywhere -- see .env.example for the template
to copy from.

If no .env file is found, this falls back to whatever is already set in
the shell environment (e.g. via $env:NVD_API_KEY = "..." in PowerShell).
"""

import os
from dotenv import load_dotenv

from patterns import IIS_COMPONENT_PATTERN  # noqa: F401 -- re-exported for backward compatibility

load_dotenv()  # loads .env into the environment if present; harmless no-op otherwise

API_KEY = os.environ.get("NVD_API_KEY")

if not API_KEY:
    raise EnvironmentError(
        "NVD_API_KEY environment variable is not set. "
        "Run: export NVD_API_KEY='your-key-here'"
    )

# Study window (Section 1.5 scope)
STUDY_START_DATE = "2020-01-01"
STUDY_END_DATE = "2026-12-31"
# Querying past "today" is harmless -- NVD just won't have future records yet,
# so re-running extract.py periodically through 2026 will pick up whatever
# has been published since the last run without needing this edited again.

# Web server CPE targets (Objective 1 / RQ1)
# Each platform maps to a LIST of CPE match strings, since NVD's dictionary
# sometimes splits one real product across multiple naming variants (the
# same issue Garcia et al. (2014) found for Debian appearing as both
# "debian_linux" and "linux"). IIS specifically has a legacy
# "internet_information_server" (singular) product entry alongside the
# current "internet_information_services" one.
WEBSERVER_CPES = {
    "apache_httpd": [
        "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
    ],
    "nginx": [
        "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
        "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",  # pre-2019 F5 acquisition CPE tag
    ],
    "iis": [
        "cpe:2.3:a:microsoft:internet_information_services:*:*:*:*:*:*:*:*",
        "cpe:2.3:a:microsoft:internet_information_server:*:*:*:*:*:*:*:*",  # legacy naming variant
        "cpe:2.3:a:microsoft:iis:*:*:*:*:*:*:*:*",  # third, shorter product-name variant --
        # confirmed directly against NVD's own CPE dictionary detail pages (e.g. CPE record
        # 126703, "cpe:2.3:a:microsoft:iis:7.5:*..."), which cross-reference this as an
        # equivalent but separately-registered product name alongside the two above.
        # NOTE: IIS's CPE version numbering stops at 10.0 (shipped with Windows Server 2016).
        # Microsoft has not issued a new standalone IIS version since, so post-2016 IIS-related
        # CVEs (e.g. CVE-2023-36434, "Windows IIS Server Privilege Escalation", Oct 2023) are
        # commonly tagged against the Windows/Windows Server OS CPE instead of an IIS
        # application CPE, since IIS ships as a Windows feature rather than an independently
        # versioned product. A small or zero count from this three-variant query for 2020-2025
        # is therefore an expected, reportable methodological finding, not necessarily a bug --
        # see the zero-result warning this produces in extract.py, and Section 3.4/3.9.
    ],
}

# Operating system CPE targets (Section 1.5 OS scope, used in RQ3/RQ4 cross-stack analysis)
OS_CPES = {
    "ubuntu":         ["cpe:2.3:o:canonical:ubuntu_linux:*:*:*:*:*:*:*:*"],
    "rhel":           ["cpe:2.3:o:redhat:enterprise_linux:*:*:*:*:*:*:*:*"],
    "debian":         ["cpe:2.3:o:debian:debian_linux:*:*:*:*:*:*:*:*"],
    "windows_server": [
        "cpe:2.3:o:microsoft:windows_server:*:*:*:*:*:*:*:*",       # generic/legacy entries with year in version field
        "cpe:2.3:o:microsoft:windows_server_2016:*:*:*:*:*:*:*:*",
        "cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*",
        "cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*",
    ],
}

ALL_CPES = {**WEBSERVER_CPES, **OS_CPES}

# NOTE: IIS_COMPONENT_PATTERN itself now lives in patterns.py (imported
# above) so that clean.py / analysis.py can use it without needing
# NVD_API_KEY set -- this name is kept here too so nothing that already
# does `from config import IIS_COMPONENT_PATTERN` breaks.

# NVD API pacing
REQUEST_DELAY_SECONDS = 6          # conservative delay between requests
MAX_WINDOW_DAYS = 120               # NVD hard limit per date-range query

# PostgreSQL connection (override via environment in production)
PG_CONN_PARAMS = {
    "host": os.environ.get("PG_HOST", "localhost"),
    "port": os.environ.get("PG_PORT", "5432"),
    "dbname": os.environ.get("PG_DBNAME", "webserver_diversity"),
    "user": os.environ.get("PG_USER", "nvd_user"),
    "password": os.environ.get("PG_PASSWORD", ""),  # set via: $env:PG_PASSWORD="..."
}