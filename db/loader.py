"""Component database loader — resolves dependency names to CPE identifiers."""

from __future__ import annotations

import json
import os
import re


def _normalise(s: str) -> str:
    """
    Example: "FreeRTOS" -> "freertos"
    Example: "FreeRTOS-Kernel" -> "freertoskernel"
    Example: "FreeRTOS_Kernel" -> "freertoskernel"
    Example: "FreeRTOS Kernel" -> "freertoskernel"
    """
    return re.sub(r"[-_.\s]", "", s).lower()

DB_PATH = os.path.join(os.path.dirname(__file__), "component_db.json")

def lookup(dependency_name: str) -> dict | None:
    with open(DB_PATH) as f:
        db = json.load(f)
    needle = _normalise(dependency_name)
    for component in db["components"]:
        aliases = [component["name"]] + component["aliases"]
        if needle in [_normalise(a) for a in aliases]:
            return {
                "name": component["name"],
                "cpe_vendor": component["cpe_vendor"],
                "cpe_product": component["cpe_product"],
                "cpe_part": component["cpe_part"],
                "cpe_template": component["cpe_template"],
                "version_patterns": component["version_patterns"],
                "cmake_fetch_names": component["cmake_fetch_names"],
                "notes": component["notes"],
            }
    return None
