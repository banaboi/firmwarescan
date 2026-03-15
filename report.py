"""Report rendering — terminal (ANSI) and JSON output modes."""

from __future__ import annotations

from models import Dependency, Finding


def render_terminal(dependencies: list[Dependency], findings: list[Finding]) -> None:
    """Render a human-readable ANSI report to stdout. Not yet implemented."""
    raise NotImplementedError


def render_json(dependencies: list[Dependency], findings: list[Finding]) -> str:
    """Render findings as a JSON string. Not yet implemented."""
    raise NotImplementedError
