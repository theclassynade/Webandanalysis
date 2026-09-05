"""
patterns.py
Small, dependency-free home for text-matching patterns shared across the
pipeline. Kept separate from config.py deliberately: config.py requires
NVD_API_KEY to be set (it raises on import otherwise), but clean.py,
analysis.py, and separate_iis_component.py should all be runnable on
already-fetched CSVs with no API key or network access at all. Importing
a regex shouldn't force an API-key requirement onto scripts that never
touch the API.
"""

import re

# IIS-component supplementary keyword filter (Sections 3.4, 3.9, 4.x).
# Single source of truth -- clean.py (per-record flagging) and analysis.py
# (Table 7 summary) both import this so the two can never drift apart.
# Word-boundary match on "iis" specifically (not mid-word substrings),
# plus both full product-name spellings.
IIS_COMPONENT_PATTERN = re.compile(
    r"\biis\b|internet information services|internet information server",
    re.IGNORECASE,
)