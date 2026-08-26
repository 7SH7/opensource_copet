import os
import sys
import time
from pathlib import Path

import pytest

from forensicagent.executor import runner
from forensicagent.tools.schema import CommandTemplate, ToolMetadata


def test_system_taskkill_uses_verified_absolute_system32_path(tmp_path, monkeypatch):
    taskkill = tmp_path / "System32" / "taskkill.exe"
    taskkill.parent.mkdir()
    taskkill.write_bytes(b"fake")
    monkeypatch.setenv("SystemRoot", str(tmp_path))

    assert runner._system_taskkill() == taskkill.resolve()


def test_system_taskkill_rejects_relative_or_missing_root(tmp_path, monkeypatch):
    monkeypatch.setenv("SystemRoot", "relative-root")
    assert runner._system_taskkill() is None

    monkeypatch.setenv("SystemRoot", str(tmp_path))
    assert runner._system_taskkill() is None


def test_posix_timeout_kills_group_even_when_parent_exits(monkeypatch):
    calls: list[tuple[int, int]] = []

    class ParentExited:
        pid = 4321
        exited = False

        def poll(self):
            return 0 if self.exited else None

        def wait(self, timeout):
            self.exited = True
            return 0

        def kill(self):
            raise AssertionError("group kill should handle the descendant")

    monkeypatch.setattr(runner.os, "name", "posix")
    monkeypatch.setattr(runner.signal, "SIGKILL", 9, raising=False)
    monkeypatch.setattr(
        runner.os,
        "killpg",
        lambda pid, sig: calls.append((pid, sig)),
        raising=False,
    )

    assert runner._terminate_process_tree(ParentExited()) == []
    assert calls == [
        (4321, runner.signal.SIGTERM),
        (4321, 0),
        (4321, 9),
    ]


def test_tool_process_uses_isolated_output_as_cwd(tmp_path, monkeypatch):
    hostile = tmp_path / "attacker-evidence"
    hostile.mkdir()
    (hostile / "rogue-config").write_text("attacker-controlled", encoding="utf-8")
    script = tmp_path / "show_cwd.py"
    script.write_text("from pathlib import Path\nprint(Path.cwd())\n", encoding="utf-8")
    metadata = ToolMetadata(
        tool_id="cwd-probe",
        display_name="cwd-probe",
        category="test",
        applicable_evidence_types=["text_log"],
        command_templates=[CommandTemplate(name="test", template="test", when="test")],
        usage_description="trusted working-directory regression fixture",
        output_format="text",
    )
    job_dir = tmp_path / "trusted-job"
    monkeypatch.chdir(hostile)

    result = runner.run_tool(
        metadata,
        [sys.executable, str(script)],
        str(script),
        job_dir,
        timeout_sec=10,
    )

    assert result.status == "success"
    assert Path(result.stdout_path).read_text(encoding="utf-8").strip() == str(
        job_dir.resolve()
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object integration")
def test_windows_timeout_kills_spawned_descendant_without_taskkill(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        runner,
        "_system_taskkill",
        lambda: (_ for _ in ()).throw(
            AssertionError("Job Object containment must not rely on taskkill")
        ),
    )
    ready = tmp_path / "descendant-started"
    release = tmp_path / "release-descendant"
    marker = tmp_path / "descendant-survived"
    child = tmp_path / "child.py"
    child.write_text(
        "import sys, time\n"
        "from pathlib import Path\n"
        "Path(sys.argv[1]).write_text('ready', encoding='utf-8')\n"
        "while not Path(sys.argv[2]).exists(): time.sleep(0.01)\n"
        "Path(sys.argv[3]).write_text('alive', encoding='utf-8')\n",
        encoding="utf-8",
    )
    parent = tmp_path / "parent.py"
    parent.write_text(
        "import subprocess, sys, time\n"
        "subprocess.Popen([sys.executable, *sys.argv[1:5]])\n"
        "time.sleep(30)\n",
        encoding="utf-8",
    )
    metadata = ToolMetadata(
        tool_id="process-tree",
        display_name="process-tree",
        category="test",
        applicable_evidence_types=["text_log"],
        command_templates=[CommandTemplate(name="test", template="test", when="test")],
        usage_description="Windows process containment regression fixture",
        output_format="text",
    )

    real_popen = runner.subprocess.Popen

    class TimeoutAfterDescendantStarts(real_popen):
        def wait(self, timeout=None):
            if not getattr(self, "_timeout_injected", False):
                deadline = time.monotonic() + 10
                while not ready.is_file():
                    if time.monotonic() >= deadline:
                        raise AssertionError("descendant did not start within 10 seconds")
                    time.sleep(0.01)
                self._timeout_injected = True
                raise runner.subprocess.TimeoutExpired(self.args, timeout)
            return super().wait(timeout)

    monkeypatch.setattr(runner.subprocess, "Popen", TimeoutAfterDescendantStarts)

    result = runner.run_tool(
        metadata,
        [
            sys.executable,
            str(parent),
            str(child),
            str(ready),
            str(release),
            str(marker),
        ],
        str(parent),
        tmp_path / "job",
        timeout_sec=2,
    )
    release.write_text("go", encoding="utf-8")
    time.sleep(2)

    assert result.status == "timeout"
    assert ready.is_file(), "descendant never started, so containment was not tested"
    assert not marker.exists(), result.warnings
