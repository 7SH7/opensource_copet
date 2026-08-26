"""JSON report serializer."""

from __future__ import annotations

import json
from pathlib import Path

from forensicagent.reporter.types import Report


def write_json(report: Report, path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps(report.to_dict(), ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    return p
