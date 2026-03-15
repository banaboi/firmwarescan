"""Makefile extractor — parses Makefile for dependency declarations."""

from __future__ import annotations

from models import Dependency


class MakefileExtractor():
    """Extracts dependencies from Makefile files. Not yet implemented."""

    def extract(self, path: str) -> list[Dependency]:
        raise NotImplementedError
