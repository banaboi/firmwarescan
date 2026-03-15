"""Binary extractor — parses compiled binaries for dependency declarations."""

from __future__ import annotations

from models import Dependency


class BinaryExtractor():
    """Extracts dependencies from compiled binaries. Not yet implemented."""

    def extract(self, path: str) -> list[Dependency]:
        raise NotImplementedError
