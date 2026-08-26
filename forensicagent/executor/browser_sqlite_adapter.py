"""Project-local adapter for the read-only browser SQLite inspector."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

from forensicagent.executor.adapter import GenericAdapter
from forensicagent.tools import browser_sqlite


class BrowserSQLiteAdapter(GenericAdapter):
    def validate_prerequisites(self) -> tuple[bool, str]:
        return True, f"stdlib sqlite {sqlite3.sqlite_version}"

    def build_command(
        self,
        evidence_path: str,
        *,
        preferred_template: str | None = None,
        **vars: str,
    ) -> list[str]:
        self.selected_template = preferred_template or self._meta.command_templates[0].template
        return [
            sys.executable,
            str(Path(browser_sqlite.__file__).resolve()),
            evidence_path,
        ]


__all__ = ["BrowserSQLiteAdapter"]
