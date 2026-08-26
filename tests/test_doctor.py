from __future__ import annotations

import io

from rich.console import Console

from forensicagent.cli import doctor


def test_check_import_uses_module_discovery_without_import(monkeypatch):
    calls: list[str] = []

    def fake_find_spec(module: str):
        calls.append(module)
        return object()

    monkeypatch.setattr(doctor.importlib.util, "find_spec", fake_find_spec)

    result = doctor._check_import("sentence_transformers")

    assert result.ok is True
    assert calls == ["sentence_transformers"]
    assert "not imported" in result.detail


def test_check_import_reports_missing_spec(monkeypatch):
    monkeypatch.setattr(doctor.importlib.util, "find_spec", lambda module: None)

    result = doctor._check_import("missing_heavy_module", hint="install it")

    assert result.ok is False
    assert "module spec not found" in result.detail


def test_rag_index_check_only_probes_persistence_file(tmp_path, monkeypatch):
    marker = tmp_path / "chroma.sqlite3"
    marker.write_bytes(b"sqlite marker")
    monkeypatch.setattr(doctor.settings, "USE_RAG", True)
    monkeypatch.setattr(doctor.settings, "CHROMA_PERSIST_DIR", str(tmp_path))
    monkeypatch.setattr(doctor.settings, "TOOL_COLLECTION", "test_tools")

    result = doctor._check_rag_index()

    assert result.ok is True
    assert result.optional is True
    assert "collection not opened" in result.detail


def test_rag_index_check_reports_missing_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor.settings, "USE_RAG", True)
    monkeypatch.setattr(doctor.settings, "CHROMA_PERSIST_DIR", str(tmp_path))

    result = doctor._check_rag_index()

    assert result.ok is False
    assert "index files" in result.detail


def test_eztools_missing_check_points_to_registered_installer_name(monkeypatch):
    monkeypatch.setattr(doctor, "find_executable", lambda name: None)

    results = {result.name: result for result in doctor._check_optional_tools()}

    assert "forensicagent install recmd" in results["RECmd.exe"].detail
    assert "forensicagent install evtxecmd" in results["EvtxECmd.exe"].detail


def test_missing_optional_ai_stack_does_not_fail_core_doctor(monkeypatch):
    monkeypatch.setattr(
        doctor,
        "CORE_CHECKS",
        [lambda: doctor.CheckResult("python", True, "ok")],
    )
    monkeypatch.setattr(
        doctor,
        "OPTIONAL_CAPABILITY_CHECKS",
        [lambda: doctor.CheckResult("rag", False, "install .[rag]", optional=True)],
    )
    monkeypatch.setattr(
        doctor,
        "_check_rag_index",
        lambda: doctor.CheckResult("index", False, "missing", optional=True),
    )
    output = io.StringIO()

    result = doctor.run_doctor(
        console=Console(file=output, force_terminal=False),
        show_optional=False,
    )

    assert result == 0
    assert "optional AI capabilities" in output.getvalue()
    assert "All core checks passed" in output.getvalue()
