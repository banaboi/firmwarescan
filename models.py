"""Shared data models used across all FirmwareScan modules."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Dependency:
    """A dependency detected in a firmware project."""

    name: str
    version: str | None
    confidence: str  # "high" | "medium" | "low"
    source_file: str
    line_number: int | None = None
    cpe: str | None = None  # resolved after DB lookup


@dataclass
class Finding:
    """A CVE finding matched against a detected dependency."""

    dependency: Dependency
    cve_id: str
    cvss_score: float | None
    severity: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE"
    description: str
    nvd_url: str
    affected_versions: str = ""
    patched_version: str | None = None


SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
