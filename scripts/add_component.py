#!/usr/bin/env python3
"""
Add a new component to component_db.json interactively.

Prompts for required fields, validates the CPE against NVD,
then appends the entry to the database.

Usage:
    python3 scripts/add_component.py
"""

import json
import os
import sys
import urllib.request
import urllib.parse
from datetime import date

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "db", "component_db.json")
NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"


def prompt(label: str, required: bool = True, default: str = "") -> str:
    suffix = f" [{default}]" if default else (" (required)" if required else " (optional, enter to skip)")
    while True:
        value = input(f"  {label}{suffix}: ").strip()
        if not value and default:
            return default
        if not value and required:
            print("  This field is required.")
            continue
        return value


def prompt_list(label: str) -> list[str]:
    print(f"  {label} (comma-separated):")
    raw = input("  > ").strip()
    return [v.strip() for v in raw.split(",") if v.strip()]


def prompt_bool(label: str, default: bool = True) -> bool:
    default_str = "Y/n" if default else "y/N"
    raw = input(f"  {label} [{default_str}]: ").strip().lower()
    if not raw:
        return default
    return raw in ("y", "yes")


def query_nvd_cpe(vendor: str, product: str) -> int:
    api_key = os.environ.get("NVD_API_KEY")
    keyword = f"cpe:2.3:*:{vendor}:{product}"
    params = urllib.parse.urlencode({"cpeMatchString": keyword, "resultsPerPage": 1})
    url = f"{NVD_CPE_URL}?{params}"

    req = urllib.request.Request(url)
    if api_key:
        req.add_header("apiKey", api_key)

    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode())
        return data.get("totalResults", 0)


def main():
    with open(DB_PATH) as f:
        db = json.load(f)

    existing_names = {c["name"].lower() for c in db["components"]}

    print("\nAdd a new component to component_db.json")
    print("─" * 42)

    # --- Required fields ---
    while True:
        name = prompt("Component name (e.g. 'Mbed TLS')")
        if name.lower() in existing_names:
            print(f"  '{name}' already exists in the database.")
        else:
            break

    aliases = prompt_list("Aliases / alternate spellings")
    has_cpe = prompt_bool("Does this component have NVD CPE entries?")

    cpe_vendor = cpe_product = cpe_part = cpe_template = None
    cpe_verified = False
    cpe_verified_date = None

    if has_cpe:
        print()
        print("  Find the CPE at: https://nvd.nist.gov/products/cpe/search")
        cpe_vendor = prompt("CPE vendor (e.g. 'amazon')")
        cpe_product = prompt("CPE product (e.g. 'freertos')")
        cpe_part = prompt("CPE part", default="a")
        cpe_template = f"cpe:2.3:{cpe_part}:{cpe_vendor}:{cpe_product}:{{version}}:*:*:*:*:*:*:*"
        print(f"\n  Template: {cpe_template}")

        print(f"\n  Validating {cpe_vendor}:{cpe_product} against NVD...", end=" ", flush=True)
        try:
            total = query_nvd_cpe(cpe_vendor, cpe_product)
            if total > 0:
                print(f"OK ({total} CPE entries found)")
                cpe_verified = True
                cpe_verified_date = date.today().isoformat()
            else:
                print("WARN: 0 CPE entries found")
                if not prompt_bool("Continue anyway?", default=False):
                    print("Aborted.")
                    sys.exit(0)
        except Exception as e:
            print(f"ERROR ({e})")
            if not prompt_bool("Continue without verification?", default=False):
                print("Aborted.")
                sys.exit(0)

    # --- Version patterns ---
    print()
    version_patterns = prompt_list("Version regex patterns (e.g. VERSION_STRING[\\s=]+(\\d+\\.\\d+))")

    # --- CMake names ---
    cmake_fetch_names = prompt_list("CMake FetchContent / ExternalProject names")

    # --- Notes ---
    notes = prompt("Notes (gotchas, caveats)", required=False)

    # --- Build entry ---
    entry = {
        "name": name,
        "aliases": aliases,
        "cpe_vendor": cpe_vendor,
        "cpe_product": cpe_product,
        "cpe_part": cpe_part,
        "cpe_template": cpe_template,
        "version_patterns": version_patterns,
        "cmake_fetch_names": cmake_fetch_names,
        "notes": notes,
    }

    if has_cpe:
        entry["cpe_verified"] = cpe_verified
        entry["cpe_verified_date"] = cpe_verified_date

    # --- Confirm ---
    print("\nNew entry:")
    print(json.dumps(entry, indent=2))
    print()

    if not prompt_bool("Add this entry to the database?"):
        print("Aborted.")
        sys.exit(0)

    db["components"].append(entry)

    with open(DB_PATH, "w") as f:
        json.dump(db, f, indent=2)

    print(f"\nAdded '{name}' to {DB_PATH}")


if __name__ == "__main__":
    main()
