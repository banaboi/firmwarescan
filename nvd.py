from __future__ import annotations

import json
import os
import sqlite3
import time
import requests # type: ignore
from pathlib import Path


from models import Finding, Dependency

CACHE_DIR = Path.home() / ".firmwarescan"
CACHE_DB = CACHE_DIR / "cache.db"
TTL = 60 * 60 * 24  # 24 hours
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def lookup(dependency: Dependency) -> list[Finding]:
    if dependency.cpe is None:
        return []
    cached = _cache_get(dependency.cpe)
    if cached is not None:
        return [_finding_from_dict(d, dependency) for d in cached]
    raw = _NVDClient().fetch(dependency.cpe)
    _cache_set(dependency.cpe, raw)
    return [_finding_from_dict(d, dependency) for d in raw]


class _NVDClient:
    def fetch(self, cpe: str) -> list[dict]:
        response = requests.get(
            NVD_URL,
            params={"cpeName": cpe},
            headers=self._headers(),
            timeout=10,
        )
        response.raise_for_status()
        return [self._parse_cve(item) for item in response.json().get("vulnerabilities", [])]

    def _headers(self) -> dict:
        api_key = os.environ.get("NVD_API_KEY")
        return {"apiKey": api_key} if api_key else {}

    def _parse_cve(self, item: dict) -> dict:
        cve = item["cve"]
        cve_id = cve["id"]
        description = next(
            (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
            "",
        )
        cvss_score, severity = self._extract_cvss(cve.get("metrics", {}))
        return {
            "cve_id": cve_id,
            "cvss_score": cvss_score,
            "severity": severity,
            "description": description,
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        }

    def _extract_cvss(self, metrics: dict) -> tuple[float | None, str]:
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if entries:
                data = entries[0]["cvssData"]
                return data.get("baseScore"), data.get("baseSeverity", "NONE")
        return None, "NONE"


class _CacheDB:
    def __enter__(self) -> sqlite3.Connection:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        self._con = sqlite3.connect(CACHE_DB)
        self._con.execute("""
            CREATE TABLE IF NOT EXISTS cve_cache (
                cpe        TEXT PRIMARY KEY,
                data       TEXT NOT NULL,
                fetched_at INTEGER NOT NULL
            )
        """)
        self._con.commit()
        return self._con

    def __exit__(self, *_) -> None:
        self._con.close()


def _cache_get(cpe: str) -> list[dict] | None:
    with _CacheDB() as db:
        row = db.execute(
            "SELECT data, fetched_at FROM cve_cache WHERE cpe = ?", (cpe,)
        ).fetchone()
    if row is None:
        return None
    data, fetched_at = row
    if time.time() - fetched_at > TTL:
        return None
    return json.loads(data)


def _cache_set(cpe: str, findings: list[dict]) -> None:
    with _CacheDB() as db:
        db.execute(
            "INSERT OR REPLACE INTO cve_cache (cpe, data, fetched_at) VALUES (?, ?, ?)",
            (cpe, json.dumps(findings), int(time.time())),
        )
        db.commit()


def _finding_from_dict(d: dict, dependency: Dependency) -> Finding:
    return Finding(
        dependency=dependency,
        cve_id=d["cve_id"],
        cvss_score=d["cvss_score"],
        severity=d["severity"],
        description=d["description"],
        nvd_url=d["nvd_url"],
        affected_versions=d.get("affected_versions", ""),
        patched_version=d.get("patched_version"),
    )
