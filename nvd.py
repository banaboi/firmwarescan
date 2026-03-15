from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from models import Finding, Dependency

CACHE_DIR = Path.home() / ".firmwarescan"
CACHE_DB = CACHE_DIR / "cache.db"
TTL = 60 * 60 * 24  # 24 hours


def lookup(dependency: Dependency) -> list[Finding]:
    if dependency.cpe is None:
        return []
    cached = _cache_get(dependency.cpe)
    if cached is not None:
        return [_finding_from_dict(d, dependency) for d in cached]
    raise NotImplementedError("NVD HTTP fetch not yet implemented")


def _cache_get(cpe: str) -> list[dict] | None:
    con = _connect()
    row = con.execute(
        "SELECT data, fetched_at FROM cve_cache WHERE cpe = ?", (cpe,)
    ).fetchone()
    con.close()
    if row is None:
        return None
    data, fetched_at = row
    if time.time() - fetched_at > TTL:
        return None
    return json.loads(data)


def _cache_set(cpe: str, findings: list[dict]) -> None:
    con = _connect()
    con.execute(
        "INSERT OR REPLACE INTO cve_cache (cpe, data, fetched_at) VALUES (?, ?, ?)",
        (cpe, json.dumps(findings), int(time.time())),
    )
    con.commit()
    con.close()


def _connect() -> sqlite3.Connection:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(CACHE_DB)
    con.execute("""
        CREATE TABLE IF NOT EXISTS cve_cache (
            cpe        TEXT PRIMARY KEY,
            data       TEXT NOT NULL,
            fetched_at INTEGER NOT NULL
        )
    """)
    con.commit()
    return con


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
