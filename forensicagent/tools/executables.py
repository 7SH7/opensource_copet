"""Shared executable discovery for installer, doctor, and executor.

Executables are resolved from the configured ``tools_bin`` tree first, then
from the active project-local environment, and finally from absolute
directories in the process ``PATH``.
Keeping this policy here prevents the environment check from reporting a tool
as available while the executor is unable to launch it.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import Optional

from forensicagent import config as settings


_WINDOWS_EXTENSIONS = ("", ".exe", ".cmd", ".bat", ".com")


def tools_bin_root() -> Path:
    """Return the directory used for locally installed standalone tools."""
    return Path(settings.USER_HOME) / "tools_bin"


def installed_bin_dirs() -> list[Path]:
    """Return deterministic search directories below ``tools_bin``.

    Release archives are commonly either flat (``tools_bin/tool/tool.exe``)
    or contain one additional top-level directory.  The root itself is also
    searched for manually installed binaries.
    """
    root = tools_bin_root()
    if not root.is_dir():
        return []

    directories = [root]
    try:
        children = sorted(
            (p for p in root.iterdir() if p.is_dir()),
            key=lambda p: p.name.lower(),
        )
    except OSError:
        return directories

    directories.extend(children)
    for child in children:
        try:
            directories.extend(
                sorted(
                    (p for p in child.iterdir() if p.is_dir()),
                    key=lambda p: p.name.lower(),
                )
            )
        except OSError:
            continue
    return directories


def _candidate_names(name: str) -> list[str]:
    p = Path(name)
    if p.suffix:
        return [p.name]
    if os.name == "nt":
        return [f"{p.name}{ext}" for ext in _WINDOWS_EXTENSIONS]
    return [p.name]


def _is_launchable(path: Path) -> bool:
    try:
        if not path.is_file():
            return False
        # Windows launchability is determined by the file association/extension.
        # On POSIX, reject files without any execute bit just as shutil.which does.
        return os.name == "nt" or os.access(path, os.X_OK)
    except OSError:
        return False


def _resolved_candidate(path: Path) -> Path | None:
    """Return a launchable canonical path; access failures mean unavailable."""
    if not _is_launchable(path):
        return None
    try:
        return path.resolve()
    except (OSError, RuntimeError):
        return None


def _resolve_from_path(names: list[str]) -> Path | None:
    """Search explicit absolute PATH entries without Windows CWD fallback."""
    for raw_directory in os.environ.get("PATH", "").split(os.pathsep):
        raw_directory = raw_directory.strip().strip('"')
        if not raw_directory:
            # An empty PATH component means CWD on both POSIX and Windows.
            continue
        try:
            directory = Path(os.path.expandvars(raw_directory)).expanduser()
        except (OSError, RuntimeError):
            continue
        if not directory.is_absolute():
            continue
        for candidate_name in names:
            candidate = directory / candidate_name
            try:
                # Passing an explicit candidate and path prevents shutil.which
                # from consulting an implicit current/evidence directory.
                found = shutil.which(os.fspath(candidate), path="")
            except OSError:
                continue
            if found and (resolved := _resolved_candidate(Path(found))):
                return resolved
    return None


def _project_environment_bin() -> Path | None:
    """Return the active project-local environment's Scripts/bin directory."""
    try:
        executable = Path(sys.executable).expanduser()
        if not executable.is_absolute() or not executable.is_file():
            return None
        bin_dir = executable.parent.resolve(strict=True)
        prefix = Path(sys.prefix).resolve(strict=True)
        project_root = Path(settings.PROJECT_ROOT).resolve(strict=True)
    except (OSError, RuntimeError):
        return None

    expected_name = "Scripts" if os.name == "nt" else "bin"
    if bin_dir.name.casefold() != expected_name.casefold():
        return None
    if bin_dir.parent != prefix or not prefix.is_relative_to(project_root):
        return None
    return bin_dir


def resolve_executable(name: str | os.PathLike[str]) -> Path | None:
    """Resolve from an explicit path, tools_bin, project venv, or ``PATH``."""
    raw = os.fspath(name).strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in {'"', "'"}:
        raw = raw[1:-1]
    if not raw:
        return None

    requested = Path(raw).expanduser()
    if requested.is_absolute():
        try:
            candidate = requested.resolve()
        except (OSError, RuntimeError):
            return None
        return _resolved_candidate(candidate)
    if requested.parent != Path(".") or "/" in raw or "\\" in raw:
        return None

    names = _candidate_names(raw)
    for directory in installed_bin_dirs():
        for candidate_name in names:
            if resolved := _resolved_candidate(directory / candidate_name):
                return resolved
    if environment_bin := _project_environment_bin():
        for candidate_name in names:
            if resolved := _resolved_candidate(environment_bin / candidate_name):
                return resolved
    return _resolve_from_path(names)


def find_executable(name: str | os.PathLike[str]) -> Optional[str]:
    """String-returning compatibility wrapper around :func:`resolve_executable`."""
    resolved = resolve_executable(name)
    return str(resolved) if resolved is not None else None


__all__ = [
    "find_executable",
    "installed_bin_dirs",
    "resolve_executable",
    "tools_bin_root",
]
