"""Suppression/allowlist management."""

from __future__ import annotations

from models import Finding


def apply(findings: list[Finding], config_path: str) -> list[Finding]:
    """Filter findings against the suppress list in the config file. Not yet implemented."""
    raise NotImplementedError
