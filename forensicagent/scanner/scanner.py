"""CWD recursive scanner.

명세 2.1 의 구현 주의사항을 그대로 코드로:
  - 깊이 제한 (기본 5)
  - 심볼릭 링크 따라가지 않음
  - 큰 파일도 헤더만 읽음 (detectors 가 32 바이트만 읽도록 설계됨)
  - 식별 불가는 unknown 으로 두되 인벤토리에 포함시켜 사용자가 인지하게.
"""

from __future__ import annotations

import hashlib
import logging
import os
import stat
from pathlib import Path
from typing import Iterable

from forensicagent.config import PROJECT_ROOT
from forensicagent.observability import Stopwatch
from forensicagent.scanner.detectors import detect
from forensicagent.scanner.types import Evidence, Inventory

logger = logging.getLogger(__name__)

DEFAULT_MAX_DEPTH = 5
# scan() 크기 상한. 1.5 GiB 이상 파일은 경로/크기를 기록하고 자동 제외한다.
MAX_FILE_SIZE_BYTES = 3 * 1024**3 // 2

# Common dependency/VCS directories are skipped for every source tree.
_COMMON_IGNORE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".pytest_cache",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "build",
    "dist",
}

# These names are trusted only for this repository's own state.  An evidence
# tree can legitimately contain attacker-controlled files under the same names.
_PROJECT_ONLY_IGNORE_DIRS = {
    ".agents",
    ".cache",
    ".claude",
    ".codex",
    ".forensicagent",
    ".serena",
    ".hypothesis",
    ".omc",
    ".ruff_cache",
    "bench_cli",
    "bench_full",
    "bench_scripts",
    "forensicagent_output",
}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _is_excluded(path: Path, excludes: tuple[Path, ...]) -> bool:
    """Whether path is an explicitly excluded path or one of its descendants."""
    # Scandir paths are already absolute.  abspath normalizes ``..`` without
    # touching the filesystem, unlike resolve() which is costly for every file
    # (especially on OneDrive/network-backed evidence trees).
    normalized = Path(os.path.abspath(path))
    return any(normalized == base or normalized.is_relative_to(base) for base in excludes)


def _stat_is_link_or_reparse(value: os.stat_result) -> bool:
    """Detect symlinks and Windows junction/reparse points without following."""
    if stat.S_ISLNK(value.st_mode):
        return True
    attributes = getattr(value, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def _entry_is_link_or_reparse(entry: os.DirEntry[str]) -> bool:
    if entry.is_symlink():
        return True
    if os.name != "nt":
        return False
    return _stat_is_link_or_reparse(entry.stat(follow_symlinks=False))


def _walk(
    root: Path,
    max_depth: int,
    exclude_paths: tuple[Path, ...] = (),
    ignore_dirs: frozenset[str] = frozenset(_COMMON_IGNORE_DIRS),
) -> tuple[list[Path], bool, int, int]:
    """심볼릭 링크 무시 + 깊이 제한 BFS.

    Returns:
        (files, depth_limit_hit, unreadable_paths, reparse_paths).
        depth_limit_hit 은 max_depth 때문에 실제로 하위 디렉토리 하강을
        끊은 적이 있으면 True — 이 경우 더 깊은 증거를 놓쳤을 수 있다.
        (_IGNORE_DIRS 로 의도적으로 건너뛴 디렉토리는 여기 포함하지 않는다.)
    """
    files: list[Path] = []
    depth_limit_hit = False
    unreadable_paths = 0
    reparse_paths = 0
    root = root.resolve()

    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        cur, depth = stack.pop()
        if _is_excluded(cur, exclude_paths):
            continue
        try:
            if _stat_is_link_or_reparse(cur.lstat()):
                reparse_paths += 1
                continue
            entries = list(os.scandir(cur))
        except (OSError, PermissionError) as e:
            logger.debug("skip %s: %s", cur, e)
            unreadable_paths += 1
            continue

        for entry in entries:
            try:
                # Reject symlinks — both files and dirs — to avoid loops.
                if _entry_is_link_or_reparse(entry):
                    reparse_paths += 1
                    continue
                p = Path(entry.path)
                if _is_excluded(p, exclude_paths):
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if entry.name.casefold() in ignore_dirs:
                        continue
                    if depth + 1 <= max_depth:
                        stack.append((p, depth + 1))
                    else:
                        # max_depth 초과로 이 디렉토리를 하강하지 못함.
                        depth_limit_hit = True
                elif entry.is_file(follow_symlinks=False):
                    files.append(p)
            except OSError:
                unreadable_paths += 1
                continue
    return files, depth_limit_hit, unreadable_paths, reparse_paths


def scan(
    root: str | Path,
    *,
    max_depth: int = DEFAULT_MAX_DEPTH,
    include_unknown: bool = True,
    exclude_paths: Iterable[str | Path] | None = None,
    stage_ms: dict[str, int] | None = None,
) -> Inventory:
    """CWD 또는 지정 디렉토리를 스캔해 Evidence 인벤토리 반환.

    Args:
        root: 스캔 시작점.
        max_depth: 디렉토리 재귀 깊이 제한 (root 자체는 depth 0).
        include_unknown: 식별 실패한 파일도 인벤토리에 unknown 으로 남길지.
        exclude_paths: 스캔하지 않을 파일/디렉터리. 상대 경로는 root 기준이며,
            디렉터리를 지정하면 모든 하위 경로를 탐색 단계에서 제외한다.
        stage_ms: observability 누적 dict 가 있으면 "scan_walk", "scan_detect" 기록.

    Returns:
        Inventory.
    """
    raw_root = Path(root)
    display_root = Path(os.path.abspath(raw_root))
    inv = Inventory(scan_root=str(display_root))
    try:
        root_stat = raw_root.lstat()
    except FileNotFoundError:
        logger.warning("scan root does not exist: %s", display_root)
        return inv
    except OSError as e:
        logger.warning("scan root is unreadable: %s: %s", display_root, e)
        inv.unreadable_paths = 1
        return inv
    if _stat_is_link_or_reparse(root_stat):
        logger.warning("scan root is a link or reparse point: %s", display_root)
        inv.skipped_files = int(stat.S_ISREG(root_stat.st_mode))
        inv.reparse_paths = 1
        return inv
    try:
        root_path = raw_root.resolve(strict=True)
    except OSError as e:
        logger.warning("scan root is unreadable: %s: %s", display_root, e)
        inv.unreadable_paths = 1
        return inv
    inv.scan_root = str(root_path)

    exclude_base = root_path if root_path.is_dir() else root_path.parent
    normalized_excludes: list[Path] = []
    for raw in exclude_paths or ():
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = exclude_base / candidate
        normalized_excludes.append(Path(os.path.abspath(candidate)))
    excludes = tuple(normalized_excludes)
    project_root = PROJECT_ROOT.resolve()
    ignore_dirs = frozenset(
        _COMMON_IGNORE_DIRS
        | (_PROJECT_ONLY_IGNORE_DIRS if root_path == project_root else set())
    )

    with Stopwatch() as sw_walk:
        if root_path.is_file():
            files = [] if _is_excluded(root_path, excludes) else [root_path]
            depth_limit_hit = False
            unreadable_paths = 0
            reparse_paths = 0
        else:
            files, depth_limit_hit, unreadable_paths, reparse_paths = _walk(
                root_path, max_depth, excludes, ignore_dirs
            )
    inv.depth_limit_hit = depth_limit_hit
    inv.unreadable_paths = unreadable_paths
    inv.reparse_paths = reparse_paths
    if stage_ms is not None:
        stage_ms["scan_walk"] = stage_ms.get("scan_walk", 0) + sw_walk.elapsed_ms

    with Stopwatch() as sw_detect:
        for p in files:
            try:
                file_stat = p.lstat()
            except OSError:
                inv.skipped_files += 1
                inv.unreadable_paths += 1
                continue
            if _stat_is_link_or_reparse(file_stat):
                inv.skipped_files += 1
                inv.reparse_paths += 1
                continue
            size = file_stat.st_size
            # 크기 상한 게이트 (0 = 무제한). 초과 파일은 검사하지 않고 skip 로 집계.
            if MAX_FILE_SIZE_BYTES > 0 and size >= MAX_FILE_SIZE_BYTES:
                logger.debug("skip oversized %s (%d bytes)", p, size)
                inv.skipped_files += 1
                inv.oversized_files.append(
                    {
                        "path": str(p),
                        "size_bytes": size,
                        "mtime_ns": file_stat.st_mtime_ns,
                        "reason": "size is at or above the 1.5 GiB scan limit",
                        "limit_bytes": MAX_FILE_SIZE_BYTES,
                    }
                )
                continue
            try:
                with open(p, "rb") as stream:
                    stream.read(1)
            except OSError:
                inv.skipped_files += 1
                inv.unreadable_paths += 1
                continue
            inv.scanned_files += 1

            hit = detect(p)
            if hit is None:
                inv.unidentified_files += 1
                if not include_unknown:
                    continue
                etype, plat, conf, method = (
                    "unknown",
                    "unknown",
                    0.0,
                    "unclassified",
                )
            else:
                etype, plat, conf, method = hit
            try:
                digest = _sha256_file(p)
                final_stat = p.lstat()
                stable = (
                    not _stat_is_link_or_reparse(final_stat)
                    and os.path.samestat(file_stat, final_stat)
                    and file_stat.st_size == final_stat.st_size
                    and file_stat.st_mtime_ns == final_stat.st_mtime_ns
                )
                if not stable:
                    raise OSError("evidence changed while it was being fingerprinted")
            except OSError:
                inv.scanned_files -= 1
                inv.skipped_files += 1
                inv.unreadable_paths += 1
                continue
            inv.evidence_list.append(
                Evidence(
                    path=str(p),
                    filename=p.name,
                    size_bytes=size,
                    evidence_type=etype,
                    detected_by=method,
                    platform_hint=plat,
                    confidence=conf,
                    sha256=digest,
                    mtime_ns=file_stat.st_mtime_ns,
                )
            )
    if stage_ms is not None:
        stage_ms["scan_detect"] = stage_ms.get("scan_detect", 0) + sw_detect.elapsed_ms

    return inv
