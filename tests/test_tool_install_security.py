from __future__ import annotations

import hashlib
import io
import stat
import zipfile
from pathlib import Path

import pytest
from hypothesis import given, settings, strategies as st
from rich.console import Console

from forensicagent.cli import tool_install


class _Response(io.BytesIO):
    def geturl(self) -> str:
        return "https://objects.githubusercontent.com/release.zip"


def _zip_bytes(entries: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return output.getvalue()


def _spec(payload: bytes, *, digest: str | None = None) -> tool_install.ToolSpec:
    return tool_install.ToolSpec(
        name="chainsaw",
        kind="zip",
        description="test",
        homepage="https://example.test",
        zip_url="https://example.test/chainsaw.zip",
        zip_executable="chainsaw.exe",
        zip_sha256=digest or hashlib.sha256(payload).hexdigest(),
    )


def _write_distribution(root: Path, name: str, version: str) -> None:
    metadata = (
        tool_install._venv_site_packages(root)
        / f"{name}-{version}.dist-info"
        / "METADATA"
    )
    metadata.parent.mkdir(parents=True)
    metadata.write_text(f"Name: {name}\nVersion: {version}\n", encoding="utf-8")


@pytest.mark.parametrize(
    "member_name",
    ["../escape.txt", "..\\escape.txt", "/absolute.txt", "C:/drive.txt"],
)
def test_safe_extract_rejects_path_escape_before_writing(tmp_path: Path, member_name: str):
    archive_path = tmp_path / "malicious.zip"
    archive_path.write_bytes(
        _zip_bytes({"release/chainsaw.exe": b"binary", member_name: b"escape"})
    )
    destination = tmp_path / "payload"
    destination.mkdir()

    with zipfile.ZipFile(archive_path) as archive, pytest.raises(ValueError):
        tool_install._extract_zip_safely(archive, destination)

    assert list(destination.rglob("*")) == []


_ZIP_SEGMENT = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N")),
    min_size=1,
    max_size=24,
)
_UNSAFE_ZIP_MEMBER = st.one_of(
    st.builds(lambda left, right: f"{left}/../{right}", _ZIP_SEGMENT, _ZIP_SEGMENT),
    st.builds(lambda left, right: f"{left}\\..\\{right}", _ZIP_SEGMENT, _ZIP_SEGMENT),
    st.builds(lambda left, right: f"/{left}/{right}", _ZIP_SEGMENT, _ZIP_SEGMENT),
    st.builds(lambda left, right: f"{left}:{right}", _ZIP_SEGMENT, _ZIP_SEGMENT),
    st.builds(lambda left, right: f"{left}/{right}.", _ZIP_SEGMENT, _ZIP_SEGMENT),
    st.builds(lambda left, right: f"{left}/{right} ", _ZIP_SEGMENT, _ZIP_SEGMENT),
)


@given(_UNSAFE_ZIP_MEMBER)
@settings(max_examples=200, deadline=None)
def test_zip_member_parser_rejects_generated_escape_families(member_name: str):
    with pytest.raises(ValueError):
        tool_install._zip_member_parts(zipfile.ZipInfo(member_name))


def test_safe_extract_rejects_symlink(tmp_path: Path):
    archive_path = tmp_path / "symlink.zip"
    link = zipfile.ZipInfo("release/link")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(link, "../../escape")

    destination = tmp_path / "payload"
    destination.mkdir()
    with zipfile.ZipFile(archive_path) as archive, pytest.raises(ValueError):
        tool_install._extract_zip_safely(archive, destination)

    assert list(destination.rglob("*")) == []


def test_install_zip_verifies_then_replaces_previous_install(tmp_path: Path, monkeypatch):
    payload = _zip_bytes({"release/chainsaw.exe": b"verified binary"})
    tools_root = tmp_path / "tools"
    previous = tools_root / "chainsaw"
    previous.mkdir(parents=True)
    (previous / "partial.txt").write_text("old", encoding="utf-8")
    monkeypatch.setattr(tool_install, "tools_bin_root", lambda: tools_root)
    monkeypatch.setattr(
        tool_install.urllib.request,
        "urlopen",
        lambda url, timeout: _Response(payload),
    )

    result = tool_install.install_zip(_spec(payload), Console(file=io.StringIO()))

    assert result is True
    assert (previous / "release" / "chainsaw.exe").read_bytes() == b"verified binary"
    assert not (previous / "partial.txt").exists()
    assert sorted(path.name for path in tools_root.iterdir()) == ["chainsaw"]


def test_hash_failure_preserves_previous_install_and_cleans_stage(tmp_path: Path, monkeypatch):
    payload = _zip_bytes({"chainsaw.exe": b"tampered"})
    tools_root = tmp_path / "tools"
    previous = tools_root / "chainsaw"
    previous.mkdir(parents=True)
    marker = previous / "keep.txt"
    marker.write_text("keep", encoding="utf-8")
    monkeypatch.setattr(tool_install, "tools_bin_root", lambda: tools_root)
    monkeypatch.setattr(
        tool_install.urllib.request,
        "urlopen",
        lambda url, timeout: _Response(payload),
    )

    result = tool_install.install_zip(
        _spec(payload, digest="0" * 64),
        Console(file=io.StringIO()),
    )

    assert result is False
    assert marker.read_text(encoding="utf-8") == "keep"
    assert sorted(path.name for path in tools_root.iterdir()) == ["chainsaw"]


def test_promotion_failure_rolls_back_previous_install(tmp_path: Path):
    target = tmp_path / "chainsaw"
    target.mkdir()
    marker = target / "keep.txt"
    marker.write_text("keep", encoding="utf-8")

    with pytest.raises(OSError):
        tool_install._promote_install(
            tmp_path / "missing-payload",
            target,
            tmp_path / "previous",
        )

    assert marker.read_text(encoding="utf-8") == "keep"
    assert not (tmp_path / "previous").exists()


def test_auto_pip_specs_are_exactly_pinned_and_binwalk_is_not_pypi():
    pip_specs = [
        spec for spec in tool_install.TOOL_SPECS.values() if spec.kind == "pip"
    ]

    assert pip_specs
    assert all(spec.pip_package and "==" in spec.pip_package for spec in pip_specs)
    assert tool_install.TOOL_SPECS["binwalk"].kind == "manual"
    assert tool_install.TOOL_SPECS["binwalk"].pip_package is None


def test_semgrep_uses_an_isolated_pinned_venv():
    spec = tool_install.TOOL_SPECS["semgrep"]

    assert spec.kind == "venv"
    assert spec.pip_package == "semgrep==1.173.0"


def test_isolated_spec_does_not_accept_a_global_executable(tmp_path: Path, monkeypatch):
    spec = tool_install.TOOL_SPECS["semgrep"]
    monkeypatch.setattr(tool_install, "tools_bin_root", lambda: tmp_path)
    monkeypatch.setattr(tool_install, "find_executable", lambda name: "global-semgrep")

    assert tool_install._spec_installed(spec) is False
    executable = tool_install._venv_executable(tmp_path / "semgrep", "semgrep")
    executable.parent.mkdir(parents=True)
    executable.write_text("", encoding="utf-8")
    _write_distribution(tmp_path / "semgrep", "semgrep", "1.173.0")
    assert tool_install._spec_installed(spec) is False
    _write_distribution(tmp_path / "semgrep", "pip", "26.2.1")
    assert tool_install._spec_installed(spec) is True


def test_isolated_spec_rejects_wrong_pip_version(tmp_path: Path, monkeypatch):
    spec = tool_install.TOOL_SPECS["semgrep"]
    root = tmp_path / "semgrep"
    monkeypatch.setattr(tool_install, "tools_bin_root", lambda: tmp_path)
    executable = tool_install._venv_executable(root, "semgrep")
    executable.parent.mkdir(parents=True)
    executable.write_text("", encoding="utf-8")
    _write_distribution(root, "semgrep", "1.173.0")
    _write_distribution(root, "pip", "25.0")

    assert tool_install._spec_installed(spec) is False


def test_install_venv_places_cli_under_tools_bin(tmp_path: Path, monkeypatch):
    tools_root = tmp_path / "tools"
    spec = tool_install.ToolSpec(
        name="semgrep",
        kind="venv",
        description="test",
        homepage="https://example.test",
        pip_package="semgrep==1.173.0",
    )
    calls: list[tuple[list[str], Path]] = []

    def fake_run(argv, *, check, cwd):
        calls.append(([str(value) for value in argv], Path(cwd)))
        if argv[1:3] == ["-m", "venv"]:
            target = Path(argv[-1])
            tool_install._venv_python(target).parent.mkdir(parents=True)
            tool_install._venv_python(target).write_text("", encoding="utf-8")
        else:
            tool_install._venv_executable(tools_root / "semgrep", "semgrep").write_text(
                "", encoding="utf-8"
            )

    monkeypatch.setattr(tool_install, "tools_bin_root", lambda: tools_root)
    monkeypatch.setattr(tool_install.subprocess, "run", fake_run)

    assert tool_install.install_venv(spec, Console(file=io.StringIO())) is True
    assert calls[0][0] == [
        tool_install.sys.executable,
        "-m",
        "venv",
        str(tools_root / "semgrep"),
    ]
    assert calls[1][0][-3:] == [
        "install",
        "pip==26.2.1",
        "semgrep==1.173.0",
    ]
    assert {cwd for _, cwd in calls} == {tool_install.settings.PROJECT_ROOT}
    assert tool_install._venv_executable(tools_root / "semgrep", "semgrep").is_file()


def test_install_venv_removes_partial_target_when_cli_is_missing(
    tmp_path: Path, monkeypatch
):
    tools_root = tmp_path / "tools"
    spec = tool_install.ToolSpec(
        name="semgrep",
        kind="venv",
        description="test",
        homepage="https://example.test",
        pip_package="semgrep==1.173.0",
    )
    target = tools_root / "semgrep"
    target.mkdir(parents=True)
    marker = target / "keep.txt"
    marker.write_text("keep", encoding="utf-8")

    def fake_run(argv, *, check, cwd):
        assert Path(cwd) == tool_install.settings.PROJECT_ROOT
        if argv[1:3] == ["-m", "venv"]:
            created = Path(argv[-1])
            tool_install._venv_python(created).parent.mkdir(parents=True)
            tool_install._venv_python(created).write_text("", encoding="utf-8")

    monkeypatch.setattr(tool_install, "tools_bin_root", lambda: tools_root)
    monkeypatch.setattr(tool_install.subprocess, "run", fake_run)

    assert tool_install.install_venv(spec, Console(file=io.StringIO())) is False
    assert marker.read_text(encoding="utf-8") == "keep"


def test_install_venv_preserves_previous_when_backup_move_fails(
    tmp_path: Path, monkeypatch
):
    tools_root = tmp_path / "tools"
    target = tools_root / "semgrep"
    target.mkdir(parents=True)
    marker = target / "keep.txt"
    marker.write_text("keep", encoding="utf-8")
    spec = tool_install.TOOL_SPECS["semgrep"]
    path_type = type(target)
    real_replace = path_type.replace

    def fail_initial_move(self, destination):
        if self == target:
            raise PermissionError("backup move blocked")
        return real_replace(self, destination)

    monkeypatch.setattr(tool_install, "tools_bin_root", lambda: tools_root)
    monkeypatch.setattr(path_type, "replace", fail_initial_move)
    monkeypatch.setattr(
        tool_install.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("subprocess must not run"),
    )

    assert tool_install.install_venv(spec, Console(file=io.StringIO())) is False
    assert marker.read_text(encoding="utf-8") == "keep"
    assert not list(tools_root.glob(".semgrep-*"))


def test_install_venv_rolls_back_before_propagating_interrupt(
    tmp_path: Path, monkeypatch
):
    tools_root = tmp_path / "tools"
    target = tools_root / "semgrep"
    target.mkdir(parents=True)
    marker = target / "keep.txt"
    marker.write_text("keep", encoding="utf-8")
    spec = tool_install.TOOL_SPECS["semgrep"]

    def interrupt_after_move(argv, *, check, cwd):
        created = Path(argv[-1])
        created.mkdir(parents=True, exist_ok=True)
        raise KeyboardInterrupt

    monkeypatch.setattr(tool_install, "tools_bin_root", lambda: tools_root)
    monkeypatch.setattr(tool_install.subprocess, "run", interrupt_after_move)

    with pytest.raises(KeyboardInterrupt):
        tool_install.install_venv(spec, Console(file=io.StringIO()))
    assert marker.read_text(encoding="utf-8") == "keep"
    assert not list(tools_root.glob(".semgrep-*"))


def test_install_venv_rejects_link_to_sibling(tmp_path: Path, monkeypatch):
    tools_root = tmp_path / "tools"
    sibling = tools_root / "gitleaks"
    sibling.mkdir(parents=True)
    marker = sibling / "keep.txt"
    marker.write_text("keep", encoding="utf-8")
    target = tools_root / "semgrep"
    try:
        target.symlink_to(sibling, target_is_directory=True)
    except OSError as e:
        pytest.skip(f"directory symlinks unavailable: {e}")
    spec = tool_install.TOOL_SPECS["semgrep"]
    monkeypatch.setattr(tool_install, "tools_bin_root", lambda: tools_root)
    monkeypatch.setattr(
        tool_install.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("subprocess must not run"),
    )

    assert tool_install.install_venv(spec, Console(file=io.StringIO())) is False
    assert marker.read_text(encoding="utf-8") == "keep"


def test_install_venv_reports_unusable_tools_root(tmp_path: Path, monkeypatch):
    tools_root = tmp_path / "not-a-directory"
    tools_root.write_text("occupied", encoding="utf-8")
    spec = tool_install.TOOL_SPECS["semgrep"]
    output = io.StringIO()
    monkeypatch.setattr(tool_install, "tools_bin_root", lambda: tools_root)
    monkeypatch.setattr(
        tool_install.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("subprocess must not run"),
    )

    assert tool_install.install_venv(spec, Console(file=output)) is False
    assert "isolated venv setup failed" in output.getvalue()


def test_gitleaks_release_is_versioned_and_digest_pinned():
    spec = tool_install.TOOL_SPECS["gitleaks"]

    assert spec.kind == "zip"
    assert "/v8.30.0/" in (spec.zip_url or "")
    assert spec.zip_executable == "gitleaks.exe"
    assert spec.zip_sha256 == (
        "54fe94f644b832dd08e8c3a5915efb3bfa862386d59fb27ca0792cb687a83573"
    )


def test_unpinned_pip_install_is_refused(monkeypatch):
    spec = tool_install.ToolSpec(
        name="unsafe",
        kind="pip",
        description="test",
        homepage="https://example.test",
        pip_package="unsafe>=1",
    )
    monkeypatch.setattr(
        tool_install.subprocess,
        "run",
        lambda *args, **kwargs: pytest.fail("pip must not run for an unpinned spec"),
    )

    assert tool_install.install_pip(spec, Console(file=io.StringIO())) is False


def test_pip_install_uses_trusted_project_cwd(monkeypatch):
    spec = tool_install.ToolSpec(
        name="safe",
        kind="pip",
        description="test",
        homepage="https://example.test",
        pip_package="safe==1.0",
    )
    calls = []

    def fake_run(argv, *, check, cwd):
        calls.append((argv, check, Path(cwd)))

    monkeypatch.setattr(tool_install.subprocess, "run", fake_run)

    assert tool_install.install_pip(spec, Console(file=io.StringIO())) is True
    assert calls == [
        (
            [tool_install.sys.executable, "-m", "pip", "install", "safe==1.0"],
            True,
            tool_install.settings.PROJECT_ROOT,
        )
    ]
