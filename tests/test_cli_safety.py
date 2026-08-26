from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from forensicagent.cli import main as cli_main
from forensicagent.cli import tool_install
from forensicagent.scanner.types import Inventory


app = cli_main.app


runner = CliRunner()


def test_missing_target_is_nonzero(tmp_path):
    result = runner.invoke(
        app,
        ["--path", str(tmp_path / "missing"), "--dry-run", "--no-llm"],
    )

    assert result.exit_code == 2
    assert "경로가 없습니다" in result.output


def test_single_file_dry_run_is_supported(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("print('ok')\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "--path",
            str(source),
            "--dry-run",
            "--no-llm",
            "--no-rag",
        ],
    )

    assert result.exit_code == 0
    assert "bandit" in result.output


def test_noninteractive_execution_requires_auto(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("print('ok')\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["--path", str(source), "--no-llm", "--no-rag"],
    )

    assert result.exit_code == 2
    assert "--auto" in result.output


def test_scan_coverage_warning_is_shown_before_empty_inventory_exit(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        cli_main,
        "scan",
        lambda *_args, **_kwargs: Inventory(
            depth_limit_hit=True,
            unreadable_paths=2,
            reparse_paths=3,
        ),
    )

    result = runner.invoke(
        app,
        ["--path", str(tmp_path), "--dry-run", "--no-llm", "--no-rag"],
    )

    assert result.exit_code == 0
    assert "Scan coverage incomplete" in result.output
    assert "depth_limit_hit=true" in result.output
    assert "unreadable_paths=2" in result.output
    assert "reparse_paths=3" in result.output


def test_auto_install_failure_is_nonzero_in_every_mode(monkeypatch):
    spec = tool_install.ToolSpec(
        name="test-auto",
        kind="zip",
        description="test",
        homepage="https://example.test",
    )
    monkeypatch.setattr(tool_install, "TOOL_SPECS", {"test-auto": spec})
    monkeypatch.setattr(tool_install, "_spec_installed", lambda _spec: False)
    monkeypatch.setattr(tool_install, "install_one", lambda _spec, _console: False)

    for args in (
        ["--auto", "install", "test-auto"],
        ["--auto", "install", "--all"],
        ["--auto", "install"],
    ):
        result = runner.invoke(app, args)

        assert result.exit_code == 1
        assert "설치 실패:" in result.output


def test_output_limit_options_require_total_at_least_job():
    result = runner.invoke(
        app,
        ["--max-job-output-mib", "2", "--max-total-output-mib", "1"],
    )

    assert result.exit_code == 2
    assert "must be greater than or equal" in result.output


@pytest.mark.parametrize(
    ("status", "expected_exit"),
    [("cancelled", 130), ("output_limit", 3)],
)
def test_one_shot_passes_resource_limits_and_reports_before_status_exit(
    tmp_path, monkeypatch, status, expected_exit
):
    inventory = SimpleNamespace(
        depth_limit_hit=False,
        unreadable_paths=0,
        reparse_paths=0,
        oversized_files=[],
        evidence_list=[object()],
        unidentified_files=0,
        scanned_files=1,
    )
    selected = SimpleNamespace(
        tool_id="test-tool",
        priority=1,
        estimated_runtime="short",
        target_evidence=[object()],
        reason="test",
    )
    plan = SimpleNamespace(
        selected_tools=[selected],
        llm_used=False,
        llm_fallback=False,
        unhandled_evidence=[],
    )
    captured = {}
    report_written = []

    monkeypatch.setattr(cli_main, "scan", lambda *_args, **_kwargs: inventory)
    monkeypatch.setattr(cli_main, "render_inventory", lambda _inventory: "inventory")
    monkeypatch.setattr(
        cli_main, "_load_tools_or_exit", lambda _console: (tmp_path, [object()])
    )
    monkeypatch.setattr(cli_main, "select", lambda *_args, **_kwargs: plan)

    def fake_execute(*_args, **kwargs):
        captured.update(kwargs)
        result = SimpleNamespace(status=status, provenance={})
        return SimpleNamespace(results=[result])

    monkeypatch.setattr(cli_main, "execute", fake_execute)
    monkeypatch.setattr(cli_main, "analyze_all", lambda *_args, **_kwargs: [])

    def fake_report(**_kwargs):
        report_written.append(True)
        return object(), {}

    monkeypatch.setattr(cli_main, "write_report", fake_report)

    result = runner.invoke(
        app,
        [
            "--path",
            str(tmp_path),
            "--auto",
            "--no-llm",
            "--no-rag",
            "--max-job-output-mib",
            "2",
            "--max-total-output-mib",
            "3",
            "--min-free-disk-mib",
            "4",
        ],
    )

    assert result.exit_code == expected_exit
    assert captured["max_job_output_bytes"] == 2 * 1024**2
    assert captured["max_total_output_bytes"] == 3 * 1024**2
    assert captured["min_free_disk_bytes"] == 4 * 1024**2
    assert report_written == [True]
