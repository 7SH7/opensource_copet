"""Small, defensive execution-state manifest for safe job reuse."""

from __future__ import annotations

import json
import math
import os
import stat
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from forensicagent.executor.runner import contained_directory, hash_file
from forensicagent.executor.types import ExecutionResult, OutputArtifact

STATE_FILENAME = ".execution-state.json"
LOCK_FILENAME = ".execution-state.lock"
STATE_VERSION = 1
MAX_STATE_BYTES = 16 * 1024 * 1024
MAX_JOBS = 10_000
MAX_ARTIFACTS_PER_JOB = 4_096
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 100_000

_RESULT_KEYS = {
    "tool_id",
    "target_evidence",
    "status",
    "command_executed",
    "command_template_used",
    "stdout_path",
    "stderr_path",
    "exit_code",
    "duration_seconds",
    "output_format",
    "output_size_bytes",
    "error_message",
    "artifacts",
    "warnings",
    "provenance",
    "parsed_output",
}
_STATUSES = {
    "success",
    "failed",
    "timeout",
    "cancelled",
    "output_limit",
    "skipped",
    "output_missing",
}
_ROLES = {"stdout", "stderr", "generated"}


class StateError(RuntimeError):
    pass


def canonical_sha256(value: object) -> str:
    import hashlib

    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def new_state() -> dict[str, Any]:
    return {"version": STATE_VERSION, "jobs": {}}


@contextmanager
def execution_lock(root: str | Path) -> Iterator[None]:
    """Hold a non-blocking OS lock for one case execution."""
    directory = Path(root)
    directory.mkdir(parents=True, exist_ok=True)
    lock_path = directory / LOCK_FILENAME
    try:
        existing = lock_path.lstat()
    except FileNotFoundError:
        existing = None
    if existing is not None and (
        _is_link_or_reparse(existing) or not stat.S_ISREG(existing.st_mode)
    ):
        raise StateError("execution lock path is not a regular non-link file")
    flags = os.O_CREAT | os.O_RDWR
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise StateError(f"could not open execution lock safely: {exc}") from exc
    opened = os.fstat(descriptor)
    if _is_link_or_reparse(opened) or not stat.S_ISREG(opened.st_mode):
        os.close(descriptor)
        raise StateError("execution lock resolved to an unsafe file")
    stream = os.fdopen(descriptor, "a+b")
    try:
        stream.seek(0, os.SEEK_END)
        if stream.tell() == 0:
            stream.write(b"\0")
            stream.flush()
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise StateError(f"another execution owns {lock_path}") from exc
        yield
    finally:
        try:
            stream.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        stream.close()


def load_state(root: str | Path) -> tuple[dict[str, Any], list[str]]:
    path = Path(root) / STATE_FILENAME
    try:
        value = path.lstat()
    except FileNotFoundError:
        return new_state(), []
    try:
        if _is_link_or_reparse(value) or not stat.S_ISREG(value.st_mode):
            raise StateError("state path is not a regular non-link file")
        if value.st_size > MAX_STATE_BYTES:
            raise StateError(
                f"state file exceeds {MAX_STATE_BYTES} bytes: {value.st_size}"
            )
        encoded = path.read_bytes()
        after = path.lstat()
        if (
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        ) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise StateError("state changed while it was read")
        payload = json.loads(encoded.decode("utf-8"))
        _validate_state(payload)
        return payload, []
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        RecursionError,
        StateError,
    ) as exc:
        preserved = path.with_name(
            f"{path.stem}.corrupt-{uuid.uuid4().hex[:10]}{path.suffix}"
        )
        try:
            os.replace(path, preserved)
            detail = f"; preserved as {preserved.name}"
        except OSError as preserve_error:
            raise StateError(
                f"invalid execution state could not be preserved: {preserve_error}"
            ) from exc
        return new_state(), [f"ignored invalid execution state: {exc}{detail}"]


def save_state(root: str | Path, payload: dict[str, Any]) -> Path:
    _validate_state(payload)
    directory = Path(root).resolve(strict=True)
    path = directory / STATE_FILENAME
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(encoded) > MAX_STATE_BYTES:
        raise StateError(f"execution state exceeds {MAX_STATE_BYTES} bytes")
    temporary = directory / f".{STATE_FILENAME}.{uuid.uuid4().hex}.tmp"
    try:
        with open(temporary, "xb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return path


def record_result(payload: dict[str, Any], result: ExecutionResult) -> None:
    resume = result.provenance.get("resume")
    if not isinstance(resume, dict):
        return
    job_key = resume.get("job_key")
    if not _is_sha256(job_key):
        return
    if (
        result.provenance.get("chainsaw_no_matches") is True
        and not result.provenance.get("job_output_dir")
    ):
        return
    jobs = payload["jobs"]
    if job_key not in jobs and len(jobs) >= MAX_JOBS:
        raise StateError(f"execution state contains more than {MAX_JOBS} jobs")
    serialized = result.to_dict()
    if isinstance(serialized.get("provenance"), dict):
        serialized["provenance"] = dict(serialized["provenance"])
        serialized["provenance"]["resume"] = dict(resume, reused=False)
    jobs[job_key] = {"result": serialized}


def reusable_result(
    payload: dict[str, Any],
    job_key: str,
    output_root: str | Path,
) -> tuple[ExecutionResult | None, str]:
    entry = payload.get("jobs", {}).get(job_key)
    if not isinstance(entry, dict) or not isinstance(entry.get("result"), dict):
        return None, ""
    try:
        result = _result_from_dict(entry["result"])
        if result.status != "success":
            return None, "previous attempt was incomplete"
        resume = result.provenance.get("resume")
        if not isinstance(resume, dict) or resume.get("job_key") != job_key:
            raise StateError("cached job identity mismatch")
        input_integrity = result.provenance.get("input_integrity")
        if (
            not isinstance(input_integrity, dict)
            or input_integrity.get("status") != "verified"
        ):
            return None, "previous attempt lacks verified input integrity"
        job_output_dir = result.provenance.get("job_output_dir")
        if not isinstance(job_output_dir, str) or not job_output_dir:
            return None, "previous attempt lacks verified output containment"
        safe_job_output_dir = contained_directory(job_output_dir, output_root)
        _validate_result_artifacts(result, Path(output_root))
        result.provenance = dict(result.provenance)
        result.provenance["output_root"] = str(Path(output_root).resolve(strict=True))
        result.provenance["job_output_dir"] = str(safe_job_output_dir)
        result.provenance["resume"] = dict(resume, reused=True)
        # Parsed data is not an immutable artifact. Re-analyze the verified raw
        # artifact instead of trusting a mutable manifest copy.
        result.parsed_output = None
        return result, ""
    except (OSError, StateError, ValueError, TypeError) as exc:
        return None, f"cached result rejected: {exc}"


def _validate_state(payload: object) -> None:
    if not isinstance(payload, dict) or set(payload) != {"version", "jobs"}:
        raise StateError("state root schema mismatch")
    if payload.get("version") != STATE_VERSION:
        raise StateError(f"unsupported state version: {payload.get('version')!r}")
    jobs = payload.get("jobs")
    if not isinstance(jobs, dict) or len(jobs) > MAX_JOBS:
        raise StateError("state jobs schema/limit mismatch")
    for key, entry in jobs.items():
        if not _is_sha256(key):
            raise StateError("invalid job key")
        if not isinstance(entry, dict) or set(entry) != {"result"}:
            raise StateError("invalid job entry")
        _result_from_dict(entry["result"])


def _result_from_dict(value: object) -> ExecutionResult:
    if not isinstance(value, dict) or set(value) != _RESULT_KEYS:
        raise StateError("execution result schema mismatch")
    status = value.get("status")
    if status not in _STATUSES:
        raise StateError(f"invalid execution status: {status!r}")
    artifacts_value = value.get("artifacts")
    if not isinstance(artifacts_value, list) or len(artifacts_value) > MAX_ARTIFACTS_PER_JOB:
        raise StateError("artifact schema/limit mismatch")
    artifacts: list[OutputArtifact] = []
    for item in artifacts_value:
        if not isinstance(item, dict) or set(item) != {
            "path",
            "role",
            "format",
            "size_bytes",
            "sha256",
        }:
            raise StateError("artifact entry schema mismatch")
        if item.get("role") not in _ROLES or not _is_sha256(item.get("sha256")):
            raise StateError("artifact role/hash is invalid")
        if not isinstance(item.get("path"), str) or not item["path"]:
            raise StateError("artifact path is invalid")
        if not isinstance(item.get("format"), str):
            raise StateError("artifact format is invalid")
        if not isinstance(item.get("size_bytes"), int) or item["size_bytes"] < 0:
            raise StateError("artifact size is invalid")
        artifacts.append(OutputArtifact(**item))
    warnings = value.get("warnings")
    provenance = value.get("provenance")
    if not isinstance(warnings, list) or not all(isinstance(item, str) for item in warnings):
        raise StateError("warnings schema mismatch")
    if not isinstance(provenance, dict):
        raise StateError("provenance schema mismatch")
    parsed = value.get("parsed_output")
    if parsed is not None and not isinstance(parsed, dict):
        raise StateError("parsed_output schema mismatch")
    _validate_json_tree(provenance)
    if parsed is not None:
        _validate_json_tree(parsed)
    return ExecutionResult(
        tool_id=_string(value, "tool_id"),
        target_evidence=_string(value, "target_evidence"),
        status=status,
        command_executed=_string(value, "command_executed"),
        stdout_path=_string(value, "stdout_path"),
        stderr_path=_string(value, "stderr_path"),
        exit_code=_integer(value, "exit_code"),
        duration_seconds=_number(value, "duration_seconds"),
        output_format=_string(value, "output_format"),
        output_size_bytes=_integer(value, "output_size_bytes", minimum=0),
        error_message=_string(value, "error_message"),
        parsed_output=parsed,
        command_template_used=_string(value, "command_template_used"),
        artifacts=artifacts,
        warnings=list(warnings),
        provenance=dict(provenance),
    )


def _validate_result_artifacts(result: ExecutionResult, root: Path) -> None:
    resolved_root = root.resolve(strict=True)
    for artifact in result.artifacts:
        path = _contained_regular_file(Path(artifact.path), resolved_root)
        size, sha256 = hash_file(path)
        if size != artifact.size_bytes or sha256 != artifact.sha256:
            raise StateError(f"artifact integrity mismatch: {path}")
    artifact_paths = {str(Path(item.path)) for item in result.artifacts}
    for path_text in (result.stdout_path, result.stderr_path):
        if path_text and path_text not in artifact_paths:
            raise StateError(f"unmanifested cached stream path: {path_text}")


def _contained_regular_file(path: Path, root: Path) -> Path:
    absolute = path if path.is_absolute() else root / path
    lexical = Path(os.path.abspath(absolute))
    if lexical == root or not lexical.is_relative_to(root):
        raise StateError(f"artifact escapes output root: {path}")
    relative = lexical.relative_to(root)
    current = root
    for part in relative.parts:
        current = current / part
        value = current.lstat()
        if _is_link_or_reparse(value):
            raise StateError(f"artifact path contains link/reparse point: {path}")
    resolved = lexical.resolve(strict=True)
    if resolved == root or not resolved.is_relative_to(root):
        raise StateError(f"artifact escapes output root: {path}")
    if not stat.S_ISREG(resolved.lstat().st_mode):
        raise StateError(f"artifact is not a regular file: {path}")
    return resolved


def _is_link_or_reparse(value: os.stat_result) -> bool:
    return stat.S_ISLNK(value.st_mode) or bool(
        getattr(value, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _is_sha256(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _string(value: dict[str, Any], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str):
        raise StateError(f"{key} must be a string")
    return item


def _integer(value: dict[str, Any], key: str, *, minimum: int | None = None) -> int:
    item = value.get(key)
    if type(item) is not int:
        raise StateError(f"{key} must be an integer")
    if minimum is not None and item < minimum:
        raise StateError(f"{key} is below its minimum")
    return item


def _number(value: dict[str, Any], key: str) -> float:
    item = value.get(key)
    if isinstance(item, bool) or not isinstance(item, (int, float)):
        raise StateError(f"{key} must be numeric")
    number = float(item)
    if not math.isfinite(number) or number < 0:
        raise StateError(f"{key} must be a finite non-negative number")
    return number


def _validate_json_tree(value: object) -> None:
    pending: list[tuple[object, int]] = [(value, 0)]
    seen = 0
    while pending:
        item, depth = pending.pop()
        seen += 1
        if seen > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise StateError("nested JSON value exceeds state limits")
        if item is None or isinstance(item, (str, bool, int)):
            continue
        if isinstance(item, float):
            if not math.isfinite(item):
                raise StateError("state contains a non-finite number")
            continue
        if isinstance(item, dict):
            if not all(isinstance(key, str) for key in item):
                raise StateError("state object keys must be strings")
            pending.extend((child, depth + 1) for child in item.values())
            continue
        if isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
            continue
        raise StateError(f"unsupported state value: {type(item).__name__}")


__all__ = [
    "LOCK_FILENAME",
    "STATE_FILENAME",
    "StateError",
    "canonical_sha256",
    "execution_lock",
    "load_state",
    "new_state",
    "record_result",
    "reusable_result",
    "save_state",
]
