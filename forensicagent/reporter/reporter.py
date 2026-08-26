"""Reporter orchestrator — build + terminal render + file writes."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from rich.console import Console

from forensicagent.analyzer.types import ToolAnalysis
from forensicagent.executor.types import ExecutionBundle
from forensicagent.reporter.annotations import AnnotationStoreError, load_annotations
from forensicagent.reporter.builder import build
from forensicagent.reporter.json_out import write_json
from forensicagent.reporter.md_out import write_md
from forensicagent.reporter.terminal import render
from forensicagent.reporter.types import Report
from forensicagent.scanner.types import Inventory
from forensicagent.selector.types import Plan
from forensicagent.ui_text import safe_text


def write(
    *,
    inventory: Inventory,
    plan: Plan,
    execution: ExecutionBundle,
    analyses: list[ToolAnalysis],
    started_at: str,
    working_directory: str,
    output_dir: str | Path,
    console: Console | None = None,
    stage_ms: dict[str, int] | None = None,
    formats: tuple[str, ...] = ("terminal", "json", "md"),
) -> tuple[Report, dict[str, Path]]:
    """리포트 빌드 + 출력. (Report, {format: path}) 반환."""
    report = build(
        inventory=inventory,
        plan=plan,
        execution=execution,
        analyses=analyses,
        started_at=started_at,
        working_directory=working_directory,
        stage_ms=stage_ms,
    )

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        stored_annotations = load_annotations(out_dir)
    except AnnotationStoreError as exc:
        stored_annotations = {}
        if console is not None:
            console.print(
                safe_text(
                    f"Annotation store was not loaded; findings remain pending: {exc}",
                    style="yellow",
                )
            )
    current_fingerprints = {finding.fingerprint for finding in report.all_findings()}
    # Stale annotations remain in the case store for future matching, but are
    # not exposed by a report whose retained findings do not contain them.
    report.analyst_annotations = {
        fingerprint: annotation
        for fingerprint, annotation in stored_annotations.items()
        if fingerprint in current_fingerprints
    }
    # Include microseconds + run id so two reports emitted in the same second
    # never overwrite one another (common in tests and short no-op runs).
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    stem = f"report_{stamp}_{report.meta.run_id[:8]}"
    paths: dict[str, Path] = {}

    if "terminal" in formats and console is not None:
        render(report, console)

    if "json" in formats:
        paths["json"] = write_json(report, out_dir / f"{stem}.json")
    if "md" in formats:
        paths["md"] = write_md(report, out_dir / f"{stem}.md")

    return report, paths
