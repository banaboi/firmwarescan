from __future__ import annotations

import sys
import yaml # type: ignore
from datetime import date
from models import Finding


def apply(findings: list[Finding], config_path: str) -> list[Finding]:
    config = _load_config(config_path)
    suppressed_ids = _collect_suppressed_ids(config.get("suppress") or [])
    return [f for f in findings if f.cve_id not in suppressed_ids]


def _load_config(config_path: str) -> dict:
    try:
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}


def _collect_suppressed_ids(entries: list[dict]) -> set:
    suppressed_ids = set()
    for entry in entries:
        cve_id = entry.get("cve_id")
        reason = entry.get("reason")
        expires = entry.get("expires")

        if not reason:
            print(f"warning: suppression for {cve_id} has no reason — skipping", file=sys.stderr)
            continue

        if expires and date.today() > _parse_date(expires):
            print(f"warning: suppression for {cve_id} expired on {expires}", file=sys.stderr)
            continue

        suppressed_ids.add(cve_id)
    return suppressed_ids


def _parse_date(value: str | date) -> date:
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value))
