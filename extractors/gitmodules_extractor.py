from __future__ import annotations

from models import Dependency


class GitmodulesExtractor:

    def extract(self, path: str) -> list[Dependency]:
        raise NotImplementedError
