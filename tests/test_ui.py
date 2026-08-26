from io import StringIO
from pathlib import Path
from types import SimpleNamespace

from rich.console import Console

from forensicagent.cli.nl_router import handle
from forensicagent.cli.repl import do_scenario
from forensicagent.cli.ui import render_inventory, render_oversized_exclusions
from forensicagent.scanner.types import Evidence, Inventory
from forensicagent.ui_text import safe_text


def test_safe_text_preserves_layout_and_uses_console_portable_control_replacement():
    rendered = safe_text("first\nsecond\tvalue\x1b").plain

    assert rendered == "first\nsecond\tvalue?"


def test_inventory_preview_is_bounded():
    inventory = Inventory(
        evidence_list=[
            Evidence(
                path=f"/{i}.py",
                filename=f"{i}.py",
                size_bytes=1,
                evidence_type="source_code_python",
                detected_by="extension",
            )
            for i in range(35)
        ]
    )

    table = render_inventory(inventory, max_rows=10)

    assert table.row_count == 10
    assert table.caption is not None
    assert "showing 10 of 35" in table.caption


def test_inventory_and_oversized_paths_strip_terminal_controls():
    payload = "case\x1b]52;c;UEFZTE9BRA==\x1b\\.evtx"
    inventory = Inventory(
        scan_root=payload,
        evidence_list=[
            Evidence(
                path=payload,
                filename=payload,
                size_bytes=1,
                evidence_type="text_log",
                detected_by="extension",
            )
        ],
        oversized_files=[{"path": payload, "size_bytes": 2}],
    )
    stream = StringIO()
    console = Console(file=stream, force_terminal=True, color_system=None, width=400)

    console.print(render_inventory(inventory))
    exclusions = render_oversized_exclusions(inventory)
    console.print(exclusions)

    assert "\x1b" not in stream.getvalue()
    assert len(exclusions.columns) == 3
    assert str(exclusions.columns[2].header) == "reason"


def test_oversized_preview_is_bounded():
    inventory = Inventory(
        oversized_files=[{"path": f"/{index}.bin", "size_bytes": 10} for index in range(35)]
    )

    table = render_oversized_exclusions(inventory, max_rows=10)

    assert table.row_count == 10
    assert table.caption is not None
    assert "showing 10 of 35" in table.caption


def test_llm_router_and_scenario_output_strip_terminal_controls():
    payload = "text\x1b]52;c;UEFZTE9BRA==\x1b\\ [bold]literal[/bold]"

    class Client:
        def json_chat(self, _messages, *, format_schema):
            assert format_schema
            return {"message": payload, "actions": []}

    state = SimpleNamespace(
        options=SimpleNamespace(no_llm=False, quick=False),
        client=lambda: Client(),
        tool_metas={},
        target_path=Path("case"),
        inventory=None,
        plan=None,
        bundle=None,
        analyses=None,
        last_report=None,
        scenario=None,
        invalidate_after_inventory=lambda: None,
    )
    stream = StringIO()
    console = Console(file=stream, force_terminal=True, color_system=None, width=200)

    handle(state, console, "summarize")
    do_scenario(state, console, payload)

    output = stream.getvalue()
    assert "\x1b" not in output
    assert "[bold]literal[/bold]" in output
