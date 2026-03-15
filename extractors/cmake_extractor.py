"""CMake extractor — parses CMakeLists.txt for dependency declarations."""

from __future__ import annotations

from models import Dependency


class CMakeExtractor():
    """Extracts dependencies from CMakeLists.txt files. Not yet implemented."""

    def extract(self, path: str) -> list[Dependency]:
        raise NotImplementedError
