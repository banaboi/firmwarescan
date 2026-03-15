"""Header extractor — scans version header files for version strings."""

from __future__ import annotations

from models import Dependency


class HeaderExtractor():
    """Extracts dependency versions from version header files. Not yet implemented."""

    def extract(self, path: str) -> list[Dependency]:
        raise NotImplementedError
