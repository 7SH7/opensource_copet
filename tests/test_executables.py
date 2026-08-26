from __future__ import annotations

import os
from pathlib import Path

from forensicagent import config as settings
from forensicagent.cli import doctor, tool_install
from forensicagent.tools import executables


def _make_executable(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("echo fake\n", encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o755)


def test_tools_bin_resolver_finds_nested_executable(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "USER_HOME", tmp_path)
    filename = "fakeprobe.exe" if os.name == "nt" else "fakeprobe"
    expected = tmp_path / "tools_bin" / "fakeprobe" / "release" / filename
    _make_executable(expected)

    assert executables.resolve_executable("fakeprobe") == expected.resolve()
    assert executables.find_executable("fakeprobe") == str(expected.resolve())


def test_explicit_executable_path_is_resolved(tmp_path):
    filename = "direct.exe" if os.name == "nt" else "direct"
    expected = tmp_path / filename
    _make_executable(expected)

    assert executables.resolve_executable(expected) == expected.resolve()


def test_relative_executable_path_is_rejected(tmp_path, monkeypatch):
    filename = "relative.exe" if os.name == "nt" else "relative"
    expected = tmp_path / "bin" / filename
    _make_executable(expected)
    monkeypatch.chdir(tmp_path)

    assert executables.resolve_executable(Path("bin") / filename) is None


def test_tools_bin_takes_precedence_over_path(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "USER_HOME", tmp_path / "home")
    filename = "priorityprobe.exe" if os.name == "nt" else "priorityprobe"
    on_path = tmp_path / "path_bin" / filename
    local = tmp_path / "home" / "tools_bin" / "priorityprobe" / filename
    _make_executable(on_path)
    _make_executable(local)
    monkeypatch.setenv("PATH", str(on_path.parent))

    assert executables.resolve_executable("priorityprobe") == local.resolve()


def test_project_venv_takes_precedence_over_global_path(tmp_path, monkeypatch):
    project = tmp_path / "project"
    environment = project / ".venv"
    bin_dir = environment / ("Scripts" if os.name == "nt" else "bin")
    suffix = ".exe" if os.name == "nt" else ""
    interpreter = bin_dir / f"python{suffix}"
    local = bin_dir / f"bandit{suffix}"
    global_tool = tmp_path / "global" / f"bandit{suffix}"
    for candidate in (interpreter, local, global_tool):
        _make_executable(candidate)

    monkeypatch.setattr(settings, "PROJECT_ROOT", project)
    monkeypatch.setattr(settings, "USER_HOME", project / ".forensicagent")
    monkeypatch.setattr(executables.sys, "executable", str(interpreter))
    monkeypatch.setattr(executables.sys, "prefix", str(environment))
    monkeypatch.setenv("PATH", str(global_tool.parent))

    assert executables.resolve_executable("bandit") == local.resolve()


def test_interpreter_bin_outside_project_is_not_trusted(tmp_path, monkeypatch):
    project = tmp_path / "project"
    environment = tmp_path / "unrelated" / ".venv"
    bin_dir = environment / ("Scripts" if os.name == "nt" else "bin")
    suffix = ".exe" if os.name == "nt" else ""
    interpreter = bin_dir / f"python{suffix}"
    unrelated = bin_dir / f"bandit{suffix}"
    on_path = tmp_path / "global" / f"bandit{suffix}"
    for candidate in (interpreter, unrelated, on_path):
        _make_executable(candidate)

    project.mkdir()
    monkeypatch.setattr(settings, "PROJECT_ROOT", project)
    monkeypatch.setattr(settings, "USER_HOME", project / ".forensicagent")
    monkeypatch.setattr(executables.sys, "executable", str(interpreter))
    monkeypatch.setattr(executables.sys, "prefix", str(environment))
    monkeypatch.setenv("PATH", str(on_path.parent))

    assert executables.resolve_executable("bandit") == on_path.resolve()


def test_plain_name_never_resolves_from_current_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "USER_HOME", tmp_path / "home")
    evidence_dir = tmp_path / "evidence"
    filename = "rogueprobe.exe" if os.name == "nt" else "rogueprobe"
    _make_executable(evidence_dir / filename)
    monkeypatch.chdir(evidence_dir)
    monkeypatch.setenv("PATH", "")

    assert executables.resolve_executable("rogueprobe") is None


def test_path_access_error_means_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "USER_HOME", tmp_path / "home")
    monkeypatch.setenv("PATH", str(tmp_path / "path_bin"))

    def denied(*args, **kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr(executables.shutil, "which", denied)

    assert executables.resolve_executable("blockedprobe") is None


def test_installer_doctor_and_executor_share_resolver():
    assert tool_install.find_executable is executables.find_executable
    assert doctor.find_executable is executables.find_executable
