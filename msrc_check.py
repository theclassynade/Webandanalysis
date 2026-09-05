"""
msrc_schema_check.py
Diagnostic companion to msrc_iis_check.py -- run this FIRST if
msrc_iis_check.py reports zero hits, to rule out a silent schema-parsing
mismatch rather than a genuine "IIS not tagged" result.

Fetches one real month and reports:
  1. Whether the request succeeded and returned real content at all.
  2. The actual top-level JSON keys (to check ProductTree/Vulnerability
     really exist under those names).
  3. A POSITIVE CONTROL: counts how many products mention "Windows" --
     this MUST be non-zero for a real month, since Windows products are
     always present. If this comes back zero too, the parser itself is
     broken, not IIS specifically -- and msrc_iis_check.py's zero result
     cannot be trusted until that's fixed.
  4. Prints every distinct product name found, so you can visually
     confirm whether anything IIS-related exists under a different
     naming pattern than the script currently searches for.
"""

import requests
import json

MONTH = "2023-Oct"  # month CVE-2023-36434 (a real IIS CVE) was published
url = f"https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{MONTH}"
headers = {"Accept": "application/json"}

resp = requests.get(url, headers=headers, timeout=30)
print(f"HTTP status: {resp.status_code}")
print(f"Response content length: {len(resp.content)} bytes")

if resp.status_code != 200:
    print("Non-200 response -- print resp.text below to see what came back:")
    print(resp.text[:1000])
else:
    data = resp.json()
    print(f"\nTop-level JSON keys: {list(data.keys())}")

    product_tree = data.get("ProductTree", {})
    print(f"ProductTree keys: {list(product_tree.keys())}")
    full_products = product_tree.get("FullProductName", [])
    print(f"Number of FullProductName entries: {len(full_products)}")

    windows_count = sum(1 for p in full_products if "windows" in (p.get("Value") or "").lower())
    print(f"\nPOSITIVE CONTROL -- products mentioning 'Windows': {windows_count}")
    if windows_count == 0:
        print("  *** WARNING: this is 0. The parser is likely broken (wrong field")
        print("  names), NOT confirming IIS is absent. Print raw JSON below to inspect.")

    iis_count = sum(1 for p in full_products if "iis" in (p.get("Value") or "").lower()
                     or "internet information" in (p.get("Value") or "").lower())
    print(f"Products mentioning 'IIS'/'Internet Information': {iis_count}")

    print(f"\nAll {len(full_products)} distinct product names this month:")
    for p in full_products:
        print(f"  - {p.get('Value')}")