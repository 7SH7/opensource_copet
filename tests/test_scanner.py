"""Scanner scan() — 깊이 제한 추적 + 크기 게이트 테스트.

LLM / 네트워크 없이 임시 디렉토리 트리로만 결정론 검증.
  * depth_limit_hit: max_depth 로 하위 디렉토리 하강을 끊으면 True,
    아니면 False (이전엔 항상 False 로 거짓 보고하던 버그).
  * MAX_FILE_SIZE_BYTES: 상한 초과 파일은 scanned 가 아니라 skipped 로 집계.
"""

from __future__ import annotations

import builtins
import hashlib
import os
from pathlib import Path

import pytest

from forensicagent.scanner import scanner
from forensicagent.scanner.scanner import scan


def _write(p: Path, content: bytes = b"hello") -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(content)


# ---- depth_limit_hit ----

def test_depth_limit_hit_true_when_tree_deeper_than_max_depth(tmp_path):
    # root(0) -> sub1(1) -> sub2(2)/deep.txt.  max_depth=1 이면 sub2 하강 불가.
    _write(tmp_path / "sub1" / "sub2" / "deep.txt")
    inv = scan(tmp_path, max_depth=1)
    assert inv.depth_limit_hit is True
    assert inv.to_dict()["depth_limit_hit"] is True


def test_depth_limit_hit_false_when_within_max_depth(tmp_path):
    _write(tmp_path / "sub1" / "sub2" / "deep.txt")
    inv = scan(tmp_path, max_depth=5)
    assert inv.depth_limit_hit is False
    # 깊은 파일이 실제로 스캔됐는지 (하강이 안 끊겼다는 증거).
    names = {Path(e.path).name for e in inv.evidence_list}
    assert "deep.txt" in names


def test_depth_limit_hit_false_on_flat_dir(tmp_path):
    _write(tmp_path / "a.txt")
    _write(tmp_path / "b.txt")
    inv = scan(tmp_path, max_depth=3)
    assert inv.depth_limit_hit is False


def test_ignored_dirs_do_not_trigger_depth_limit(tmp_path):
    # __pycache__ 는 _IGNORE_DIRS 라 의도적 skip — depth 초과와 무관해야 한다.
    _write(tmp_path / "__pycache__" / "x.pyc")
    _write(tmp_path / "top.txt")
    inv = scan(tmp_path, max_depth=1)
    assert inv.depth_limit_hit is False


# ---- MAX_FILE_SIZE_BYTES 크기 게이트 ----

def test_files_at_or_above_size_limit_are_recorded_and_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "MAX_FILE_SIZE_BYTES", 10)
    hashed: list[Path] = []
    real_sha256 = scanner._sha256_file

    def tracked_sha256(path: Path) -> str:
        hashed.append(path)
        return real_sha256(path)

    monkeypatch.setattr(scanner, "_sha256_file", tracked_sha256)
    _write(tmp_path / "small.txt", b"x" * 9)
    _write(tmp_path / "boundary.bin", b"x" * 10)
    _write(tmp_path / "big.bin", b"x" * 11)

    inv = scan(tmp_path, max_depth=2)

    assert inv.skipped_files == 2
    assert {Path(e.path).name for e in inv.evidence_list} == {"small.txt"}
    assert [Path(item["path"]).name for item in inv.oversized_files] == [
        "big.bin",
        "boundary.bin",
    ]
    assert sorted(item["size_bytes"] for item in inv.oversized_files) == [10, 11]
    assert {item["reason"] for item in inv.oversized_files} == {
        "size is at or above the 1.5 GiB scan limit"
    }
    assert {item["limit_bytes"] for item in inv.oversized_files} == {10}
    assert inv.to_dict()["oversized_files"] == inv.oversized_files
    assert {path.name for path in hashed} == {"small.txt"}


def test_included_evidence_records_stable_fingerprint_and_mtime(tmp_path):
    target = tmp_path / "case.txt"
    payload = b"forensic evidence\n"
    _write(target, payload)
    expected_mtime = target.stat().st_mtime_ns

    evidence = scan(target).evidence_list[0]

    assert evidence.sha256 == hashlib.sha256(payload).hexdigest()
    assert evidence.mtime_ns == expected_mtime
    assert evidence.to_dict()["sha256"] == evidence.sha256
    assert evidence.to_dict()["mtime_ns"] == expected_mtime


def test_zero_limit_means_no_size_gate(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "MAX_FILE_SIZE_BYTES", 0)
    _write(tmp_path / "big.bin", b"x" * 100_000)
    inv = scan(tmp_path, max_depth=2)
    names = {Path(e.path).name for e in inv.evidence_list}
    assert "big.bin" in names
    assert inv.oversized_files == []


def test_scan_accepts_a_file_root(tmp_path):
    target = tmp_path / "Security.evtx"
    _write(target, b"ElfFile\x00" + b"\x00" * 32)

    inv = scan(target)

    assert inv.scanned_files == 1
    assert len(inv.evidence_list) == 1
    assert inv.evidence_list[0].path == str(target.resolve())
    assert inv.evidence_list[0].evidence_type == "evtx_log"


def test_unknown_provenance_is_unclassified(tmp_path):
    _write(tmp_path / "unknown.xyz", b"not a known format")

    inv = scan(tmp_path)

    assert len(inv.evidence_list) == 1
    assert inv.unidentified_files == 1
    assert inv.evidence_list[0].evidence_type == "unknown"
    assert inv.evidence_list[0].detected_by == "unclassified"
    assert inv.to_dict()["unidentified_files"] == 1


def test_unidentified_count_survives_unknown_inventory_filter(tmp_path):
    _write(tmp_path / "unknown.xyz", b"not a known format")

    inv = scan(tmp_path, include_unknown=False)

    assert inv.scanned_files == 1
    assert inv.unidentified_files == 1
    assert inv.evidence_list == []


def test_exclude_paths_prunes_directory_descendants(tmp_path):
    _write(tmp_path / "case" / "Security.evtx", b"ElfFile\x00" + b"\x00" * 8)
    _write(tmp_path / "output" / "copied.evtx", b"ElfFile\x00" + b"\x00" * 8)

    inv = scan(tmp_path, exclude_paths=["output"])
    names = {Path(e.path).name for e in inv.evidence_list}

    assert names == {"Security.evtx"}


def test_exclude_paths_can_skip_a_file(tmp_path):
    _write(tmp_path / "keep.txt")
    _write(tmp_path / "skip.txt")

    inv = scan(tmp_path, exclude_paths=[tmp_path / "skip.txt"])
    names = {Path(e.path).name for e in inv.evidence_list}

    assert names == {"keep.txt"}


def test_project_generated_directories_are_ignored(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "PROJECT_ROOT", tmp_path)
    for dirname in (
        ".agents",
        ".cache",
        ".claude",
        ".codex",
        ".forensicagent",
        ".hypothesis",
        ".omc",
        ".pytest_cache",
        ".ruff_cache",
        ".serena",
        "bench_cli",
        "bench_full",
        "bench_scripts",
        "build",
        "dist",
        "forensicagent_output",
    ):
        _write(tmp_path / dirname / f"{dirname.strip('.')}.txt")
    _write(tmp_path / "case.txt")

    inv = scan(tmp_path)
    names = {Path(e.path).name for e in inv.evidence_list}

    assert names == {"case.txt"}


def test_project_named_directory_in_external_evidence_is_scanned(tmp_path):
    _write(tmp_path / ".codex" / "deploy.ps1", b"$env:TOKEN = 'secret'")

    inv = scan(tmp_path)

    assert {Path(e.path).name for e in inv.evidence_list} == {"deploy.ps1"}


def test_symlink_directory_is_not_followed(tmp_path):
    case = tmp_path / "case"
    outside = tmp_path / "outside"
    _write(case / "case.txt")
    _write(outside / "secret.txt")
    try:
        os.symlink(outside, case / "linked", target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("directory symlinks are unavailable on this host")

    inv = scan(case)

    assert {Path(item.path).name for item in inv.evidence_list} == {"case.txt"}
    assert inv.reparse_paths == 1
    assert inv.to_dict()["reparse_paths"] == 1


def test_reparse_candidate_is_not_descended(tmp_path, monkeypatch):
    _write(tmp_path / "case.txt")
    _write(tmp_path / "junction" / "secret.txt")
    original = scanner._entry_is_link_or_reparse

    def mark_junction(entry):
        return entry.name == "junction" or original(entry)

    monkeypatch.setattr(scanner, "_entry_is_link_or_reparse", mark_junction)

    inv = scan(tmp_path)

    assert {Path(item.path).name for item in inv.evidence_list} == {"case.txt"}
    assert inv.reparse_paths == 1


def test_reparse_root_is_reported(tmp_path, monkeypatch):
    target = tmp_path / "case.txt"
    _write(target)
    monkeypatch.setattr(scanner, "_stat_is_link_or_reparse", lambda _value: True)

    inv = scan(target)

    assert inv.reparse_paths == 1
    assert inv.scanned_files == 0


def test_file_replaced_by_reparse_after_walk_is_reported(tmp_path, monkeypatch):
    target = tmp_path / "case.txt"
    _write(target)
    calls = 0

    def mark_second_stat(_value):
        nonlocal calls
        calls += 1
        return calls == 2

    monkeypatch.setattr(scanner, "_stat_is_link_or_reparse", mark_second_stat)
    monkeypatch.setattr(
        scanner,
        "_walk",
        lambda *_args, **_kwargs: ([target], False, 0, 0),
    )

    inv = scan(tmp_path)

    assert inv.reparse_paths == 1
    assert inv.skipped_files == 1
    assert inv.scanned_files == 0


def test_unreadable_directory_is_reported_in_inventory(tmp_path, monkeypatch):
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    _write(tmp_path / "case.txt")
    real_scandir = scanner.os.scandir

    def guarded_scandir(path):
        if Path(path) == blocked:
            raise PermissionError("denied")
        return real_scandir(path)

    monkeypatch.setattr(scanner.os, "scandir", guarded_scandir)

    inv = scan(tmp_path)

    assert inv.unreadable_paths == 1
    assert inv.to_dict()["unreadable_paths"] == 1


def test_unreadable_file_is_skipped_and_reported(tmp_path, monkeypatch):
    blocked = tmp_path / "blocked.txt"
    _write(blocked)
    _write(tmp_path / "case.txt")
    real_open = builtins.open

    def guarded_open(path, *args, **kwargs):
        if Path(path) == blocked:
            raise PermissionError("denied")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", guarded_open)

    inv = scan(tmp_path)

    assert {Path(item.path).name for item in inv.evidence_list} == {"case.txt"}
    assert inv.skipped_files == 1
    assert inv.unreadable_paths == 1
