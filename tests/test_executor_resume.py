from __future__ import annotations

import concurrent.futures
import hashlib
import importlib
import json
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from forensicagent.executor.executor import execute
from forensicagent.executor.runner import run_tool
from forensicagent.executor.state import (
    STATE_FILENAME,
    StateError,
    execution_lock,
    new_state,
    record_result,
    reusable_result,
)
from forensicagent.executor.types import ExecutionResult
from forensicagent.selector.types import Plan, ToolSelection
from forensicagent.tools.schema import CommandTemplate, InstallCheck, ToolMetadata


def _metadata(tool_id: str, template: str, *, generated: bool = True) -> ToolMetadata:
    return ToolMetadata(
        tool_id=tool_id,
        display_name=tool_id,
        category="test",
        applicable_evidence_types=["text_log"],
        parallelizable=True,
        output_format="text",
        install_check=InstallCheck(
            command=f"{sys.executable} --version",
            expected_pattern="Python",
        ),
        command_templates=[
            CommandTemplate(name="test", template=template, when="test")
        ],
        usage_description="resume/resource integration fixture",
    )


def _plan(tool_id: str, template: str, evidence: list[Path]) -> Plan:
    return Plan(
        selected_tools=[
            ToolSelection(
                tool_id=tool_id,
                target_evidence=[str(path) for path in evidence],
                command_template=template,
                priority=5,
            )
        ]
    )


def _counting_script(path: Path, *, output_bytes: int = 8) -> Path:
    path.write_text(
        "from pathlib import Path\n"
        "import sys\n"
        "counter = Path(__file__).with_suffix('.count')\n"
        "count = int(counter.read_text() or '0') + 1 if counter.exists() else 1\n"
        "counter.write_text(str(count), encoding='utf-8')\n"
        "out = Path(sys.argv[1])\n"
        "out.mkdir(parents=True, exist_ok=True)\n"
        f"(out / 'result.bin').write_bytes(b'x' * {output_bytes})\n"
        "print('done')\n",
        encoding="utf-8",
    )
    return path


def _run(
    script: Path,
    raw: Path,
    *,
    timeout: int = 10,
    job_cap: int = 1024 * 1024,
    total_cap: int = 4 * 1024 * 1024,
) -> ExecutionResult:
    template = f"{sys.executable} {{evidence_path}} {{output_dir}}"
    metadata = _metadata("resume", template)
    return execute(
        _plan("resume", template, [script]),
        {"resume": metadata},
        output_dir=raw,
        timeout_sec=timeout,
        max_job_output_bytes=job_cap,
        max_total_output_bytes=total_cap,
        min_free_disk_bytes=1,
    ).results[0]


def test_success_is_reused_only_after_artifacts_are_reverified(tmp_path):
    script = _counting_script(tmp_path / "tool.py")
    raw = tmp_path / "raw"

    first = _run(script, raw)
    state_path = raw / STATE_FILENAME
    state = json.loads(state_path.read_text(encoding="utf-8"))
    next(iter(state["jobs"].values()))["result"]["parsed_output"] = {
        "untrusted": "manifest copy"
    }
    state_path.write_text(json.dumps(state), encoding="utf-8")
    second = _run(script, raw)

    assert first.status == second.status == "success"
    assert script.with_suffix(".count").read_text(encoding="utf-8") == "1"
    assert second.provenance["resume"]["reused"] is True
    assert second.stdout_path == first.stdout_path
    assert second.parsed_output is None
    assert second.provenance["output_root"] == str(raw.resolve())
    assert second.provenance["job_output_dir"] == str(
        Path(first.stdout_path).parent.resolve()
    )


def test_input_or_execution_settings_change_creates_a_new_attempt(tmp_path):
    script = _counting_script(tmp_path / "tool.py")
    raw = tmp_path / "raw"
    first = _run(script, raw, timeout=10)

    script.write_text(script.read_text(encoding="utf-8") + "# changed\n", encoding="utf-8")
    changed_input = _run(script, raw, timeout=10)
    changed_settings = _run(script, raw, timeout=11)

    assert [first.status, changed_input.status, changed_settings.status] == [
        "success",
        "success",
        "success",
    ]
    assert script.with_suffix(".count").read_text(encoding="utf-8") == "3"
    assert len({Path(item.stdout_path).parent for item in (first, changed_input, changed_settings)}) == 3
    assert changed_input.provenance["resume"]["reused"] is False
    assert changed_settings.provenance["resume"]["reused"] is False


def test_tampered_cached_artifact_is_preserved_and_rerun_in_new_directory(tmp_path):
    script = _counting_script(tmp_path / "tool.py")
    raw = tmp_path / "raw"
    first = _run(script, raw)
    generated = next(item for item in first.artifacts if item.role == "generated")
    Path(generated.path).write_bytes(b"tampered")

    rerun = _run(script, raw)

    assert rerun.status == "success"
    assert script.with_suffix(".count").read_text(encoding="utf-8") == "2"
    assert Path(first.stdout_path).parent != Path(rerun.stdout_path).parent
    assert Path(generated.path).read_bytes() == b"tampered"
    assert any("cached result rejected" in warning for warning in rerun.warnings)


def test_corrupt_state_is_preserved_before_a_fresh_attempt(tmp_path):
    script = _counting_script(tmp_path / "tool.py")
    raw = tmp_path / "raw"
    _run(script, raw)
    (raw / STATE_FILENAME).write_text("{broken", encoding="utf-8")

    rerun = _run(script, raw)

    assert rerun.status == "success"
    assert script.with_suffix(".count").read_text(encoding="utf-8") == "2"
    assert list(raw.glob(".execution-state.corrupt-*.json"))
    assert any("ignored invalid execution state" in warning for warning in rerun.warnings)


def test_case_execution_lock_rejects_a_concurrent_owner(tmp_path):
    raw = tmp_path / "raw"

    with execution_lock(raw):
        with pytest.raises(StateError, match="another execution owns"):
            with execution_lock(raw):
                pass


def test_cached_artifact_outside_output_root_is_rejected(tmp_path):
    script = _counting_script(tmp_path / "tool.py")
    raw = tmp_path / "raw"
    first = _run(script, raw)
    state_path = raw / STATE_FILENAME
    state = json.loads(state_path.read_text(encoding="utf-8"))
    result = next(iter(state["jobs"].values()))["result"]
    outside = tmp_path / "outside.txt"
    outside.write_bytes(Path(first.stdout_path).read_bytes())
    stdout_artifact = next(
        item for item in result["artifacts"] if item["role"] == "stdout"
    )
    stdout_artifact["path"] = str(outside)
    stdout_artifact["size_bytes"] = outside.stat().st_size
    stdout_artifact["sha256"] = hashlib.sha256(outside.read_bytes()).hexdigest()
    result["stdout_path"] = str(outside)
    state_path.write_text(json.dumps(state), encoding="utf-8")

    rerun = _run(script, raw)

    assert rerun.status == "success"
    assert script.with_suffix(".count").read_text(encoding="utf-8") == "2"
    assert any("escapes output root" in warning for warning in rerun.warnings)


def test_cached_artifact_link_is_rejected_without_following_it(tmp_path):
    script = _counting_script(tmp_path / "tool.py")
    raw = tmp_path / "raw"
    first = _run(script, raw)
    generated = next(item for item in first.artifacts if item.role == "generated")
    link = Path(generated.path).with_name("linked-result.bin")
    try:
        link.symlink_to(Path(generated.path))
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    state_path = raw / STATE_FILENAME
    state = json.loads(state_path.read_text(encoding="utf-8"))
    cached = next(iter(state["jobs"].values()))["result"]
    artifact = next(item for item in cached["artifacts"] if item["role"] == "generated")
    artifact["path"] = str(link)
    state_path.write_text(json.dumps(state), encoding="utf-8")

    rerun = _run(script, raw)

    assert rerun.status == "success"
    assert script.with_suffix(".count").read_text(encoding="utf-8") == "2"
    assert any("link/reparse point" in warning for warning in rerun.warnings)


@pytest.mark.parametrize(
    "status",
    ["failed", "timeout", "cancelled", "output_limit", "output_missing"],
)
def test_incomplete_state_entries_are_never_reused(tmp_path, status):
    job_key = "a" * 64
    state = new_state()
    result = ExecutionResult(
        tool_id="tool",
        status=status,
        provenance={"resume": {"job_key": job_key}},
    )
    record_result(state, result)

    reused, reason = reusable_result(state, job_key, tmp_path)

    assert reused is None
    assert reason == "previous attempt was incomplete"


def test_per_job_output_limit_preserves_partial_stream(tmp_path):
    script = tmp_path / "large.py"
    script.write_text(
        "import time\n"
        "for _ in range(1000):\n"
        "    print('x' * 4096, flush=True)\n"
        "    time.sleep(0.001)\n",
        encoding="utf-8",
    )
    template = f"{sys.executable} {{evidence_path}}"
    metadata = _metadata("large", template, generated=False)

    result = execute(
        _plan("large", template, [script]),
        {"large": metadata},
        output_dir=tmp_path / "raw",
        max_job_output_bytes=32 * 1024,
        max_total_output_bytes=64 * 1024,
        min_free_disk_bytes=1,
    ).results[0]

    assert result.status == "output_limit"
    assert "per-job output limit exceeded" in result.error_message
    assert Path(result.stdout_path).stat().st_size > 32 * 1024
    assert result.duration_seconds < 2
    assert all(Path(item.path).is_file() for item in result.artifacts)


def test_total_output_limit_stops_case_but_keeps_completed_artifacts(tmp_path):
    scripts = []
    for index in range(2):
        script = tmp_path / f"large-{index}.py"
        script.write_text("print('x' * 71680)\n", encoding="utf-8")
        scripts.append(script)
    template = f"{sys.executable} {{evidence_path}}"
    metadata = _metadata("total", template, generated=False)

    results = execute(
        _plan("total", template, scripts),
        {"total": metadata},
        output_dir=tmp_path / "raw",
        max_parallel=2,
        max_job_output_bytes=100 * 1024,
        max_total_output_bytes=120 * 1024,
        min_free_disk_bytes=1,
    ).results

    assert "output_limit" in {result.status for result in results}
    assert any("total output limit exceeded" in result.error_message for result in results)
    assert all(
        Path(item.path).is_file()
        for result in results
        for item in result.artifacts
    )


def test_disk_preflight_fails_before_creating_a_job(tmp_path, monkeypatch):
    executor_module = importlib.import_module("forensicagent.executor.executor")
    script = _counting_script(tmp_path / "tool.py")
    monkeypatch.setattr(
        executor_module.shutil,
        "disk_usage",
        lambda path: SimpleNamespace(total=1000, used=999, free=1),
    )

    result = _run(script, tmp_path / "raw", job_cap=100, total_cap=200)

    assert result.status == "output_limit"
    assert "disk preflight failed" in result.error_message
    assert not script.with_suffix(".count").exists()
    assert not [path for path in (tmp_path / "raw").iterdir() if path.is_dir()]


def test_keyboard_interrupt_cancels_active_and_pending_jobs(tmp_path, monkeypatch):
    executor_module = importlib.import_module("forensicagent.executor.executor")
    evidence = [tmp_path / "one.py", tmp_path / "two.py"]
    for path in evidence:
        path.write_text("pass\n", encoding="utf-8")
    template = f"{sys.executable} {{evidence_path}}"
    metadata = _metadata("cancel", template, generated=False)
    real_wait = concurrent.futures.wait
    calls = 0

    def interrupt_once(futures, *, return_when):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise KeyboardInterrupt
        return real_wait(futures, return_when=return_when)

    def wait_for_cancel(prepared, output_dir, timeout_sec, budget, cancel_event):
        assert cancel_event.wait(5)
        return ExecutionResult(
            tool_id=prepared.job.metadata.tool_id,
            target_evidence=prepared.job.evidence,
            status="cancelled",
            exit_code=-1,
            error_message="execution cancelled by user",
            provenance=dict(prepared.provenance),
        )

    monkeypatch.setattr(executor_module, "wait", interrupt_once)
    monkeypatch.setattr(executor_module, "_execute_one", wait_for_cancel)

    results = execute(
        _plan("cancel", template, evidence),
        {"cancel": metadata},
        output_dir=tmp_path / "raw",
        max_parallel=1,
        max_job_output_bytes=1024,
        max_total_output_bytes=2048,
        min_free_disk_bytes=1,
    ).results

    assert [result.status for result in results] == ["cancelled", "cancelled"]


def test_runner_cancel_event_returns_manifested_partial_output(tmp_path):
    script = tmp_path / "sleep.py"
    ready = script.with_suffix(".ready")
    script.write_text(
        "from pathlib import Path\n"
        "import time\n"
        "print('started', flush=True)\n"
        "Path(__file__).with_suffix('.ready').write_text('ready')\n"
        "time.sleep(30)\n",
        encoding="utf-8",
    )
    metadata = _metadata("sleep", "unused", generated=False)
    cancelled = threading.Event()

    def cancel_when_ready() -> None:
        deadline = time.monotonic() + 5
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        cancelled.set()

    canceller = threading.Thread(target=cancel_when_ready)
    canceller.start()
    try:
        result = run_tool(
            metadata,
            [sys.executable, str(script)],
            str(script),
            tmp_path / "job",
            timeout_sec=10,
            cancel_event=cancelled,
        )
    finally:
        canceller.join(timeout=5)

    assert result.status == "cancelled"
    assert ready.is_file()
    assert Path(result.stdout_path).read_text(encoding="utf-8").strip() == "started"
    assert {item.role for item in result.artifacts} == {"stdout", "stderr"}
