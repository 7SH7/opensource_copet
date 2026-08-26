"""Rich UI helpers shared by CLI commands."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from forensicagent.scanner.types import Evidence, Inventory
from forensicagent.ui_text import safe_text

_console = Console()


def console() -> Console:
    return _console


def render_inventory(inv: Inventory, *, max_rows: int = 30) -> Table:
    """Render a bounded inventory preview.

    Full inventories remain available in the JSON/Markdown report. Keeping the
    terminal preview bounded prevents a source tree or mounted image from
    flooding the console with thousands of rows before planning begins.
    """
    table = Table(
        title=safe_text(f"Evidence inventory - {inv.scan_root}", style="bold cyan"),
        show_lines=False,
    )
    table.add_column("type", style="bold")
    table.add_column("file", overflow="fold")
    table.add_column("size", justify="right")
    table.add_column("by", justify="center")
    table.add_column("platform")
    table.add_column("conf", justify="right")

    evidence = inv.evidence_list
    shown = evidence if max_rows <= 0 else evidence[:max_rows]
    for e in shown:
        table.add_row(
            _type_style(e),
            safe_text(e.path),
            _human_size(e.size_bytes),
            e.detected_by,
            e.platform_hint,
            f"{e.confidence:.2f}",
        )
    omitted = len(evidence) - len(shown)
    if omitted:
        table.caption = (
            f"showing {len(shown)} of {len(evidence)} detected items; "
            f"{omitted} more are retained in the report"
        )
    return table


def render_oversized_exclusions(inv: Inventory, *, max_rows: int = 30) -> Table:
    table = Table(title="1.5 GiB 이상 파일 자동 제외", show_lines=False)
    table.add_column("file", overflow="fold")
    table.add_column("size", justify="right")
    table.add_column("reason", overflow="fold")
    items = inv.oversized_files
    shown = items if max_rows <= 0 else items[:max_rows]
    for item in shown:
        table.add_row(
            safe_text(item.get("path", "")),
            _human_size(int(item.get("size_bytes", 0))),
            safe_text(
                item.get("reason", "size is at or above the 1.5 GiB scan limit")
            ),
        )
    omitted = len(items) - len(shown)
    if omitted:
        table.caption = (
            f"showing {len(shown)} of {len(items)} excluded files; "
            f"{omitted} more are retained in the report"
        )
    return table


def _type_style(e: Evidence) -> str:
    if e.evidence_type == "unknown":
        return f"[dim]{e.evidence_type}[/]"
    return f"[green]{e.evidence_type}[/]"


def _human_size(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(n)
    for u in units:
        if size < 1024 or u == units[-1]:
            return f"{size:.1f}{u}" if u != "B" else f"{int(size)}B"
        size /= 1024
    return f"{n}B"
