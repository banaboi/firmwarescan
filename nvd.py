"""NVD API v2 client with SQLite cache."""

from __future__ import annotations

from models import Dependency, Finding


def lookup(dependency: Dependency) -> list[Finding]:
    """Query NVD for CVEs matching the given dependency's CPE. Not yet implemented."""
    raise NotImplementedError
