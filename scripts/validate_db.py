#!/usr/bin/env python3
"""
Validate component_db.json CPE entries against the NVD CPE API.

For each component, queries NVD to confirm the vendor:product pair exists
and has at least one registered CPE. Updates cpe_verified / cpe_verified_date
in-place on success.

Usage:
    python3 scripts/validate_db.py                    # validate all
    python3 scripts/validate_db.py --name "FreeRTOS"  # validate one

NVD API key (optional but recommended to avoid rate limiting):
    export NVD_API_KEY=your-key-here
"""

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.parse
from datetime import date

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "db", "component_db.json")
NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
REQUEST_DELAY = 6
REQUEST_DELAY_KEYED = 0.6


def query_nvd_cpe(cpe_template: str, api_key: str | None) -> dict:
    keyword = cpe_template.replace("{version}", "*")
    params = urllib.parse.urlencode({"cpeMatchString": keyword, "resultsPerPage": 1})
    url = f"{NVD_CPE_URL}?{params}"

    req = urllib.request.Request(url)
    if api_key:
        req.add_header("apiKey", api_key)

    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode())


def validate_component(component: dict, api_key: str | None) -> bool:
    name = component["name"]
    vendor = component.get("cpe_vendor")
    product = component.get("cpe_product")

    cpe_template = component.get("cpe_template")

    if not cpe_template:
        print(f"  {name} — skipped (no NVD CPE, inventory only)")
        return True

    print(f"  {name} ({vendor}:{product}) ... ", end="", flush=True)

    try:
        data = query_nvd_cpe(cpe_template, api_key)
        total = data.get("totalResults", 0)

        if total > 0:
            print(f"OK ({total} CPE entries)")
            component["cpe_verified"] = True
            component["cpe_verified_date"] = date.today().isoformat()
            return True
        else:
            print(f"FAIL (0 entries found)")
            component["cpe_verified"] = False
            return False

    except Exception as e:
        print(f"ERROR ({e})")
        component["cpe_verified"] = False
        return False


def main():
    parser = argparse.ArgumentParser(description="Validate component_db.json CPE entries against NVD.")
    parser.add_argument("--name", help="Validate a single component by name")
    args = parser.parse_args()

    api_key = os.environ.get("NVD_API_KEY")
    delay = REQUEST_DELAY_KEYED if api_key else REQUEST_DELAY

    if not api_key:
        print("Note: NVD_API_KEY not set — using unauthenticated rate limit (1 req / 6s)")
        print("      Set NVD_API_KEY for faster validation.\n")

    with open(DB_PATH) as f:
        db = json.load(f)

    to_validate = [
        c for c in db["components"]
        if not args.name or c["name"].lower() == args.name.lower()
    ]

    if not to_validate:
        print(f"No component named '{args.name}' found in database.")
        sys.exit(1)

    print(f"Validating {len(to_validate)} component(s)...\n")

    passed = failed = 0

    for i, component in enumerate(to_validate):
        ok = validate_component(component, api_key)
        if ok:
            passed += 1
        else:
            failed += 1

        if i < len(to_validate) - 1 and component.get("cpe_vendor"):
            time.sleep(delay)

    print(f"\nResults: {passed} passed, {failed} failed")

    with open(DB_PATH, "w") as f:
        json.dump(db, f, indent=2)
    print(f"Updated {DB_PATH}")

if __name__ == "__main__":
    main()
