from pathlib import Path

from forensicagent.executor.recmd_adapter import RECmdAdapter, find_default_batch
from forensicagent.tools.loader import load_tool


def _metadata():
    root = Path(__file__).resolve().parents[1]
    return load_tool(root / "tools_metadata" / "recmd.yaml")


def test_default_batch_is_resolved_relative_to_executable(tmp_path, monkeypatch):
    executable = tmp_path / "RECmd" / "RECmd.exe"
    batch = executable.parent / "BatchExamples" / "RECmd_Batch_MC.reb"
    batch.parent.mkdir(parents=True)
    executable.write_bytes(b"")
    batch.write_text("batch", encoding="utf-8")
    monkeypatch.setattr(
        "forensicagent.executor.recmd_adapter.resolve_executable",
        lambda name: executable,
    )

    adapter = RECmdAdapter(_metadata())
    argv = adapter.build_command(
        r"C:\case\NTUSER.DAT",
        output_dir=r"C:\out with spaces",
    )

    assert argv == [
        str(executable),
        "-f",
        r"C:\case\NTUSER.DAT",
        "--bn",
        str(batch.resolve()),
        "--csv",
        r"C:\out with spaces",
    ]
    assert "{output_dir}" in adapter.selected_template


def test_batch_search_is_bounded_near_executable(tmp_path):
    executable = tmp_path / "archive" / "nested" / "RECmd.exe"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"")
    expected = tmp_path / "archive" / "BatchExamples" / "RECmd_Batch_MC.reb"
    expected.parent.mkdir()
    expected.write_text("batch", encoding="utf-8")

    assert find_default_batch(executable) == expected.resolve()
