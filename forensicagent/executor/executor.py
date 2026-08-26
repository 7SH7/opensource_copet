"""Executor orchestrator.

Each tool/evidence pair runs in an isolated job directory.  Jobs share one
priority-aware scheduler; tools marked non-parallelizable are serialized per
tool while remaining able to overlap with jobs from other tools.
"""

from __future__ import annotations

import inspect
import logging
import os
import re
import shutil
import stat
import threading
import uuid
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from forensicagent import __version__, config as settings
from forensicagent.executor.adapter import GenericAdapter, get_adapter
from forensicagent.executor.runner import (
    collect_generated_artifacts,
    command_header_bytes,
    contained_regular_file,
    hash_file,
    logical_tree_size,
    run_tool,
)
from forensicagent.executor.state import (
    StateError,
    canonical_sha256,
    execution_lock,
    load_state,
    record_result,
    reusable_result,
    save_state,
)
from forensicagent.executor.types import (
    MAX_INLINE_JSON_BYTES,
    ExecutionBundle,
    ExecutionResult,
)
from forensicagent.observability import Stopwatch
from forensicagent.scanner.types import Inventory
from forensicagent.selector.types import Plan, ToolSelection
from forensicagent.tools.executables import resolve_executable
from forensicagent.tools.schema import ToolMetadata

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _Job:
    sequence: int
    selection: ToolSelection
    metadata: ToolMetadata
    evidence: str
    command_template: str
    variables: dict[str, str]
    label: str = ""

    @property
    def priority(self) -> int:
        return self.selection.priority


@dataclass(frozen=True)
class _PreparedJob:
    job: _Job
    input_path: str
    input_size: int
    input_sha256: str
    input_mtime_ns: int
    input_dev: int
    input_ino: int
    settings_sha256: str
    job_key: str
    selected_template: str
    argv_fingerprint: tuple[str, ...]
    provenance: dict[str, object]


PreflightResult = tuple[bool, str]


_canonical_sha256 = canonical_sha256
_ANALYZER_RULES_SHA256 = hash_file(
    Path(__file__).resolve().parents[1] / "analyzer" / "rules.py"
)[1]


def _input_stat(path: str | Path) -> tuple[int, int, int, int]:
    value = Path(path).lstat()
    is_reparse = bool(
        getattr(value, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )
    if stat.S_ISLNK(value.st_mode) or is_reparse or not stat.S_ISREG(value.st_mode):
        raise OSError(f"not a regular non-link file: {path}")
    return value.st_size, value.st_mtime_ns, value.st_dev, value.st_ino


def _input_fingerprint(path: str | Path) -> tuple[int, str, int, int, int]:
    before = _input_stat(path)
    size, sha256 = hash_file(path)
    after = _input_stat(path)
    stat_size, mtime_ns, device, inode = after
    if before != after or size != stat_size:
        raise OSError(f"file changed while it was fingerprinted: {path}")
    return size, sha256, mtime_ns, device, inode


def _tool_provenance(
    metadata: ToolMetadata,
    preflight: PreflightResult,
    *,
    argv: list[str] | None = None,
) -> dict[str, object]:
    snapshot = metadata.model_dump(mode="json")
    ok, detail = preflight
    provenance: dict[str, object] = {
        "app_version": __version__,
        "tool_metadata": snapshot,
        "tool_metadata_sha256": _canonical_sha256(snapshot),
        "rule_definition_sha256": _canonical_sha256(
            snapshot.get("suspicious_indicators", [])
        ),
        "analyzer_rules_sha256": _ANALYZER_RULES_SHA256,
        "preflight": {
            "status": "passed" if ok else "failed",
            "detail": detail,
        },
    }
    if ok:
        provenance["tool_version"] = detail
    if argv:
        executable = Path(argv[0])
        provenance["executable_path"] = str(executable)
        try:
            provenance["executable_sha256"] = hash_file(executable)[1]
        except OSError as exc:
            provenance["executable_sha256"] = ""
            provenance["executable_sha256_error"] = str(exc)[:240]
    return provenance


def _build_jobs(plan: Plan, tools: dict[str, ToolMetadata]) -> list[_Job]:
    """Expand the plan and return a stable priority-descending job list."""
    planned_owners: dict[str, str] = {}
    for _, selection in sorted(
        enumerate(plan.selected_tools),
        key=lambda item: (-item[1].priority, item[0]),
    ):
        targets = (
            [spec.target_evidence for spec in selection.run_specs]
            if selection.run_specs
            else selection.target_evidence
        )
        for evidence in targets:
            evidence_key = os.path.normcase(os.path.abspath(evidence))
            planned_owners.setdefault(evidence_key, selection.tool_id)

    expanded: list[
        tuple[int, ToolSelection, ToolMetadata, str, str, dict[str, str], str]
    ] = []
    original_order = 0
    for selection in plan.selected_tools:
        metadata = tools.get(selection.tool_id)
        if metadata is None:
            logger.warning(
                "plan references unknown tool_id=%r, skipping", selection.tool_id
            )
            continue
        if selection.run_specs:
            specs = [
                (
                    spec.target_evidence,
                    spec.command_template,
                    dict(spec.variables),
                    spec.label,
                )
                for spec in selection.run_specs
            ]
        else:
            specs = [
                (evidence, selection.command_template, {}, "")
                for evidence in selection.target_evidence
            ]
        for evidence, command_template, variables, label in specs:
            evidence_key = os.path.normcase(os.path.abspath(evidence))
            if planned_owners[evidence_key] != selection.tool_id:
                continue
            expanded.append(
                (
                    original_order,
                    selection,
                    metadata,
                    evidence,
                    command_template,
                    variables,
                    label,
                )
            )
            original_order += 1

    expanded.sort(key=lambda item: (-item[1].priority, item[0]))

    return [
        _Job(
            sequence=index,
            selection=selection,
            metadata=metadata,
            evidence=evidence,
            command_template=command_template,
            variables=variables,
            label=label,
        )
        for index, (
            _,
            selection,
            metadata,
            evidence,
            command_template,
            variables,
            label,
        ) in enumerate(expanded, 1)
    ]


def _preflight_tools(jobs: list[_Job]) -> dict[str, PreflightResult]:
    """Validate prerequisites exactly once for each tool in this execution."""
    results: dict[str, PreflightResult] = {}
    for job in jobs:
        tool_id = job.metadata.tool_id
        if tool_id in results:
            continue
        try:
            results[tool_id] = get_adapter(job.metadata).validate_prerequisites()
        except Exception as e:  # noqa: BLE001 - a bad adapter must not abort the run.
            results[tool_id] = (False, f"preflight crashed: {e}")
    return results


def _safe_slug(value: str, *, fallback: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._-")
    return (cleaned or fallback)[:60]


def _make_job_dirs(root: Path, job: _Job) -> tuple[Path, Path]:
    tool = _safe_slug(job.metadata.tool_id, fallback="tool")
    evidence = _safe_slug(Path(job.evidence).name, fallback="evidence")
    unique = uuid.uuid4().hex[:10]
    job_dir = root / f"{job.sequence:04d}_{tool}_{evidence}_{unique}"
    generated_dir = job_dir / "generated"
    generated_dir.mkdir(parents=True, exist_ok=False)
    return job_dir, generated_dir


def _remove_if_empty(path: Path) -> None:
    try:
        path.rmdir()
    except (FileNotFoundError, OSError):
        pass


def _has_substantive_output(result: ExecutionResult) -> bool:
    if result.provenance.get("chainsaw_no_matches") is True:
        return False
    if any(
        artifact.role in ("stdout", "generated") and artifact.size_bytes > 0
        for artifact in result.artifacts
    ):
        return True
    stderr = next(
        (artifact for artifact in result.artifacts if artifact.role == "stderr"),
        None,
    )
    return bool(
        stderr
        and stderr.size_bytes > len(command_header_bytes(result.command_executed))
    )


def _prune_empty_success(
    result: ExecutionResult,
    *,
    job_dir: Path,
    output_dir: Path,
) -> None:
    """Remove a successful job only when it produced no result or diagnostics."""
    if result.status != "success" or result.warnings or _has_substantive_output(result):
        return
    try:
        resolved_job = job_dir.resolve(strict=True)
        resolved_root = output_dir.resolve(strict=True)
    except OSError as exc:
        result.warnings.append(f"could not validate empty output cleanup: {exc}")
        return
    if resolved_job.parent != resolved_root:
        result.warnings.append(
            f"refused to clean output outside execution root: {resolved_job}"
        )
        return
    stream_paths = [Path(result.stdout_path), Path(result.stderr_path)]
    expected_names = {path.name for path in stream_paths}
    try:
        entries = list(resolved_job.iterdir())
    except OSError as exc:
        result.warnings.append(f"could not inspect empty job output: {exc}")
        return
    if any(
        entry.name not in expected_names
        or (not entry.is_file() and not entry.is_symlink())
        for entry in entries
    ):
        return
    for path in stream_paths:
        if path.parent != resolved_job:
            result.warnings.append(f"refused to clean stream outside job directory: {path}")
            return
    try:
        for path in stream_paths:
            path.unlink(missing_ok=True)
        resolved_job.rmdir()
    except OSError as exc:
        result.warnings.append(f"could not remove empty job output: {exc}")
        result.artifacts = [
            item for item in result.artifacts if Path(item.path).exists()
        ]
        result.stdout_path = result.stdout_path if Path(result.stdout_path).exists() else ""
        result.stderr_path = result.stderr_path if Path(result.stderr_path).exists() else ""
        return
    result.stdout_path = ""
    result.stderr_path = ""
    result.artifacts = []
    result.output_size_bytes = 0
    if result.provenance.get("chainsaw_no_matches") is True:
        result.provenance.pop("job_output_dir", None)


def _adapter_accepts_preferred_template(adapter: GenericAdapter) -> bool:
    try:
        parameters = inspect.signature(adapter.build_command).parameters.values()
    except (TypeError, ValueError):
        return True
    return any(
        parameter.name == "preferred_template"
        or parameter.kind == inspect.Parameter.VAR_KEYWORD
        for parameter in parameters
    )


def _build_command(
    adapter: GenericAdapter,
    job: _Job,
    generated_dir: Path,
) -> tuple[list[str], str]:
    preferred = job.command_template or None
    kwargs = dict(job.variables)
    # The executor owns output isolation; a plan cannot redirect generated
    # files into another job's directory via template variables.
    kwargs["output_dir"] = str(generated_dir)
    if preferred and _adapter_accepts_preferred_template(adapter):
        kwargs["preferred_template"] = preferred
    argv = adapter.build_command(job.evidence, **kwargs)
    if not argv:
        raise ValueError("adapter returned an empty command")

    resolved = resolve_executable(argv[0])
    if resolved is None:
        raise FileNotFoundError(
            f"command executable {argv[0]!r} not found on PATH or tools_bin"
        )
    argv[0] = str(resolved)

    selected = getattr(adapter, "selected_template", "") or ""
    if not selected:
        # A custom adapter may construct argv without a metadata template.  Do
        # not claim its preferred metadata template was actually executed.
        implementation = type(adapter).build_command
        if implementation is not GenericAdapter.build_command:
            selected = f"custom:{type(adapter).__name__}"
        else:
            selected = preferred or ""
    return argv, selected


def _canonical_argv(argv: list[str], generated_dir: Path) -> tuple[str, ...]:
    marker = str(generated_dir)
    return tuple(item.replace(marker, "{output_dir}") for item in argv)


def _command_dependencies(
    argv: list[str],
    *,
    evidence_path: Path,
    generated_dir: Path,
) -> list[dict[str, object]]:
    """Hash direct regular-file command arguments used by the tool invocation."""
    evidence = evidence_path.resolve(strict=True)
    generated = generated_dir.resolve(strict=False)
    dependencies: list[dict[str, object]] = []
    seen: set[Path] = set()
    for argument in argv:
        candidate = Path(argument)
        try:
            resolved = candidate.resolve(strict=True)
            if (
                resolved == evidence
                or resolved == generated
                or generated in resolved.parents
                or resolved in seen
                or not resolved.is_file()
            ):
                continue
            size, sha256 = hash_file(resolved)
        except (OSError, RuntimeError):
            continue
        seen.add(resolved)
        dependencies.append(
            {"path": str(resolved), "size_bytes": size, "sha256": sha256}
        )
    dependencies.sort(key=lambda item: os.path.normcase(str(item["path"])))
    return dependencies


def _prepare_job(
    job: _Job,
    output_dir: Path,
    timeout_sec: int,
    max_parallel: int,
    max_job_output_bytes: int,
    max_total_output_bytes: int,
    min_free_disk_bytes: int,
    preflight: PreflightResult,
    verified_input: tuple[str, int, str, int, int, int] | None = None,
) -> _PreparedJob:
    if verified_input is None:
        evidence = Path(job.evidence).resolve(strict=True)
        (
            input_size,
            input_sha256,
            input_mtime_ns,
            input_dev,
            input_ino,
        ) = _input_fingerprint(evidence)
    else:
        (
            input_path,
            input_size,
            input_sha256,
            input_mtime_ns,
            input_dev,
            input_ino,
        ) = verified_input
        evidence = Path(input_path)
    placeholder = output_dir / ".fingerprint-output"
    adapter = get_adapter(job.metadata)
    argv, selected_template = _build_command(adapter, job, placeholder)
    provenance = _tool_provenance(job.metadata, preflight, argv=argv)
    dependencies = _command_dependencies(
        argv,
        evidence_path=evidence,
        generated_dir=placeholder,
    )
    argv_fingerprint = _canonical_argv(argv, placeholder)
    settings_payload = {
        "app_version": __version__,
        "tool_id": job.metadata.tool_id,
        "tool_metadata_sha256": provenance["tool_metadata_sha256"],
        "rule_definition_sha256": provenance["rule_definition_sha256"],
        "analyzer_rules_sha256": provenance["analyzer_rules_sha256"],
        "tool_version": provenance.get("tool_version", ""),
        "executable_path": provenance.get("executable_path", ""),
        "executable_sha256": provenance.get("executable_sha256", ""),
        "command_dependencies": dependencies,
        "argv": argv_fingerprint,
        "command_template_used": selected_template,
        "variables": job.variables,
        "label": job.label,
        "timeout_sec": timeout_sec,
        "max_parallel": max_parallel,
        "max_job_output_bytes": max_job_output_bytes,
        "max_total_output_bytes": max_total_output_bytes,
        "min_free_disk_bytes": min_free_disk_bytes,
    }
    settings_sha256 = canonical_sha256(settings_payload)
    input_identity = {
        "path": str(evidence),
        "size_bytes": input_size,
        "sha256": input_sha256,
        "mtime_ns": input_mtime_ns,
    }
    job_key = canonical_sha256(
        {"input": input_identity, "settings_sha256": settings_sha256}
    )
    provenance["input"] = input_identity
    provenance["input_integrity"] = {
        "status": "pending_final_verification",
        "strategy": "start_sha256_per_job_stat_final_sha256",
    }
    provenance["command_dependencies"] = dependencies
    provenance["resume"] = {
        "job_key": job_key,
        "settings_sha256": settings_sha256,
        "input_sha256": input_sha256,
        "input_mtime_ns": input_mtime_ns,
        "reused": False,
    }
    return _PreparedJob(
        job=job,
        input_path=str(evidence),
        input_size=input_size,
        input_sha256=input_sha256,
        input_mtime_ns=input_mtime_ns,
        input_dev=input_dev,
        input_ino=input_ino,
        settings_sha256=settings_sha256,
        job_key=job_key,
        selected_template=selected_template,
        argv_fingerprint=argv_fingerprint,
        provenance=provenance,
    )


def _output_directory_bytes(root: Path) -> int:
    total = 0
    for entry in os.scandir(root):
        value = entry.stat(follow_symlinks=False)
        is_reparse = bool(
            getattr(value, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        )
        if entry.is_symlink() or is_reparse:
            continue
        if entry.is_dir(follow_symlinks=False):
            total += logical_tree_size(entry.path)
    return total


class _OutputBudget:
    """Thread-safe logical-output and free-space accounting for one case."""

    def __init__(
        self,
        root: Path,
        *,
        initial_bytes: int,
        per_job_bytes: int,
        total_bytes: int,
        reserve_bytes: int,
    ) -> None:
        self.root = root
        self.initial_bytes = initial_bytes
        self.per_job_bytes = per_job_bytes
        self.total_bytes = total_bytes
        self.reserve_bytes = reserve_bytes
        self._job_sizes: dict[Path, int] = {}
        self._global_reason = ""
        self._lock = threading.Lock()

    def global_reason(self) -> str:
        with self._lock:
            return self._global_reason

    def check(self, job_dir: Path, captured_stream_bytes: int = 0) -> str | None:
        try:
            nonstream_bytes = logical_tree_size(
                job_dir,
                exclude_root_names=frozenset({"stdout", "stderr"}),
            )
            visible_stream_bytes = sum(
                path.stat().st_size
                for path in (job_dir / "stdout", job_dir / "stderr")
                if path.is_file()
            )
            size = nonstream_bytes + max(
                visible_stream_bytes,
                captured_stream_bytes,
            )
            free = shutil.disk_usage(self.root).free
        except OSError as exc:
            with self._lock:
                self._global_reason = f"output accounting failed safely: {exc}"
                return self._global_reason
        with self._lock:
            self._job_sizes[job_dir] = size
            if size > self.per_job_bytes:
                return (
                    "per-job output limit exceeded: "
                    f"{size} > {self.per_job_bytes} bytes"
                )
            total = self.initial_bytes + sum(self._job_sizes.values())
            if total > self.total_bytes:
                self._global_reason = (
                    "total output limit exceeded: "
                    f"{total} > {self.total_bytes} bytes"
                )
            elif free < self.reserve_bytes:
                self._global_reason = (
                    "free disk reserve reached: "
                    f"{free} < {self.reserve_bytes} bytes"
                )
            return self._global_reason or None


def _disk_preflight(
    root: Path,
    *,
    existing_bytes: int,
    job_count: int,
    per_job_bytes: int,
    total_bytes: int,
    reserve_bytes: int,
) -> str:
    if existing_bytes > total_bytes:
        return (
            "existing logical output exceeds total limit: "
            f"{existing_bytes} > {total_bytes} bytes"
        )
    free = shutil.disk_usage(root).free
    remaining_total = total_bytes - existing_bytes
    possible_new_output = min(remaining_total, job_count * per_job_bytes)
    required = reserve_bytes + possible_new_output
    if free < required:
        return (
            "disk preflight failed: "
            f"{free} free bytes < {required} required bytes "
            f"({reserve_bytes} reserve + {possible_new_output} output budget)"
        )
    return ""


def _terminal_result(
    prepared: _PreparedJob,
    status: str,
    message: str,
) -> ExecutionResult:
    return ExecutionResult(
        tool_id=prepared.job.metadata.tool_id,
        target_evidence=prepared.job.evidence,
        status=status,  # type: ignore[arg-type]
        command_template_used=prepared.selected_template,
        exit_code=-1,
        error_message=message,
        output_format=prepared.job.metadata.output_format,
        provenance=dict(prepared.provenance),
    )


def _mark_input_integrity_failed(
    result: ExecutionResult,
    message: str,
) -> ExecutionResult:
    result.provenance = dict(result.provenance)
    result.provenance["input_integrity"] = {
        "status": "failed",
        "detail": message,
    }
    result.status = "failed"
    result.error_message = message
    result.parsed_output = None
    if message not in result.warnings:
        result.warnings.append(message)
    return result


def _execute_one(
    prepared: _PreparedJob,
    output_dir: Path,
    timeout_sec: int,
    budget: _OutputBudget,
    cancel_event: threading.Event,
) -> ExecutionResult:
    job = prepared.job
    metadata = job.metadata
    if cancel_event.is_set():
        return _terminal_result(prepared, "cancelled", "execution cancelled by user")

    try:
        current_stat = _input_stat(prepared.input_path)
    except OSError as exc:
        return _mark_input_integrity_failed(
            _terminal_result(prepared, "failed", ""),
            f"could not verify input before execution: {exc}",
        )
    if current_stat != (
        prepared.input_size,
        prepared.input_mtime_ns,
        prepared.input_dev,
        prepared.input_ino,
    ):
        return _mark_input_integrity_failed(
            _terminal_result(prepared, "failed", ""),
            "input changed after fingerprinting; refusing inconsistent execution",
        )

    try:
        job_dir, generated_dir = _make_job_dirs(output_dir, job)
    except OSError as exc:
        return _terminal_result(
            prepared,
            "failed",
            f"failed to create isolated job directory: {exc}",
        )

    adapter = get_adapter(metadata)
    try:
        argv, selected_template = _build_command(adapter, job, generated_dir)
        if selected_template != prepared.selected_template:
            raise ValueError("selected command template changed after fingerprinting")
        if _canonical_argv(argv, generated_dir) != prepared.argv_fingerprint:
            raise ValueError("command changed after fingerprinting")
        dependencies = _command_dependencies(
            argv,
            evidence_path=Path(prepared.input_path),
            generated_dir=generated_dir,
        )
        if dependencies != prepared.provenance.get("command_dependencies"):
            raise ValueError("tool dependency changed after fingerprinting")
    except (FileNotFoundError, KeyError, IndexError, OSError, TypeError, ValueError) as exc:
        _remove_if_empty(generated_dir)
        _remove_if_empty(job_dir)
        return _terminal_result(
            prepared,
            "failed",
            f"failed to build verified command: {exc}",
        )

    result = run_tool(
        metadata=metadata,
        argv=argv,
        evidence_path=job.evidence,
        output_dir=job_dir,
        timeout_sec=timeout_sec,
        run_index=job.sequence,
        command_template_used=selected_template,
        cancel_event=cancel_event,
        limit_check=lambda captured_bytes: budget.check(job_dir, captured_bytes),
    )
    result.provenance = dict(prepared.provenance)
    result.provenance["output_root"] = str(output_dir)
    result.provenance["job_output_dir"] = str(job_dir)

    generated, warnings = collect_generated_artifacts(
        generated_dir,
        default_format=metadata.output_format,
        containment_root=output_dir,
    )
    empty_chainsaw_outputs = [
        artifact
        for artifact in generated
        if Path(artifact.path).name.casefold() == "chainsaw.jsonl"
        and artifact.size_bytes == 0
    ]
    chainsaw_no_matches = (
        result.status == "success"
        and metadata.tool_id.casefold() == "chainsaw"
        and bool(empty_chainsaw_outputs)
        and not any(artifact.size_bytes > 0 for artifact in generated)
    )
    if chainsaw_no_matches:
        try:
            empty_paths = [
                contained_regular_file(artifact.path, output_dir)
                for artifact in empty_chainsaw_outputs
            ]
            if any(path.stat().st_size != 0 for path in empty_paths):
                raise OSError("Chainsaw output changed before empty cleanup")
            for path in empty_paths:
                path.unlink()
        except OSError as exc:
            chainsaw_no_matches = False
            warnings.append(f"could not remove empty Chainsaw output safely: {exc}")
    if metadata.tool_id.casefold() == "chainsaw":
        generated = [
            artifact
            for artifact in generated
            if not (
                Path(artifact.path).name.casefold() == "chainsaw.jsonl"
                and artifact.size_bytes == 0
            )
        ]
    if chainsaw_no_matches:
        result.provenance["chainsaw_no_matches"] = True
    result.artifacts.extend(generated)
    result.warnings.extend(warnings)

    if not generated and not warnings:
        _remove_if_empty(generated_dir)

    expects_generated_output = "{output_dir}" in selected_template
    has_generated_output = any(artifact.size_bytes > 0 for artifact in generated)
    if (
        result.status == "success"
        and expects_generated_output
        and not has_generated_output
        and not chainsaw_no_matches
    ):
        message = (
            "selected command template expected generated output, but no files "
            f"were produced under {generated_dir}"
        )
        result.status = "output_missing"
        result.error_message = message
        result.warnings.append(message)

    # Preserve the legacy stdout JSON fast-path only for genuinely small
    # output. Large JSON remains available through the artifact manifest and
    # is never duplicated into the report payload.
    if result.status in ("success", "output_missing"):
        if (
            metadata.output_format == "json"
            and result.output_size_bytes > MAX_INLINE_JSON_BYTES
        ):
            result.warnings.append(
                "JSON eager parse/report embedding skipped: stdout is "
                f"{result.output_size_bytes} bytes (limit "
                f"{MAX_INLINE_JSON_BYTES}); raw artifact retained"
            )
        else:
            result.parsed_output = adapter.parse_output(result.stdout_path)
    if chainsaw_no_matches:
        result.parsed_output = {"items": []}

    try:
        final_stat = _input_stat(prepared.input_path)
    except OSError as exc:
        return _mark_input_integrity_failed(
            result,
            f"could not verify input after execution: {exc}",
        )
    if final_stat != (
        prepared.input_size,
        prepared.input_mtime_ns,
        prepared.input_dev,
        prepared.input_ino,
    ):
        _mark_input_integrity_failed(
            result,
            "input changed during execution; this attempt is not reusable",
        )

    final_dependencies = _command_dependencies(
        argv,
        evidence_path=Path(prepared.input_path),
        generated_dir=generated_dir,
    )
    if final_dependencies != prepared.provenance.get("command_dependencies"):
        result.warnings.append(
            "tool dependency changed during execution; this attempt is not reusable"
        )
        if result.status in ("success", "output_missing"):
            result.status = "failed"
            result.error_message = "tool dependency changed during execution"

    _prune_empty_success(result, job_dir=job_dir, output_dir=output_dir)
    return result


def _execute_with_lock(
    lock: threading.Lock,
    prepared: _PreparedJob,
    output_dir: Path,
    timeout_sec: int,
    budget: _OutputBudget,
    cancel_event: threading.Event,
) -> ExecutionResult:
    with lock:
        return _execute_one(
            prepared,
            output_dir,
            timeout_sec,
            budget,
            cancel_event,
        )


def _crashed_result(prepared: _PreparedJob, error: Exception) -> ExecutionResult:
    return _terminal_result(prepared, "failed", f"executor crashed: {error}")


def execute(
    plan: Plan,
    tools: dict[str, ToolMetadata],
    *,
    output_dir: str | Path,
    timeout_sec: int | None = None,
    max_parallel: int | None = None,
    max_job_output_bytes: int | None = None,
    max_total_output_bytes: int | None = None,
    min_free_disk_bytes: int | None = None,
    inventory: Inventory | None = None,
    console: Console | None = None,
    stage_ms: dict[str, int] | None = None,
) -> ExecutionBundle:
    """Execute every planned job with isolation, manifests, and failure isolation."""
    timeout = timeout_sec if timeout_sec is not None else settings.DEFAULT_TIMEOUT_SEC
    max_par = max_parallel if max_parallel is not None else settings.MAX_PARALLEL_TOOLS
    job_cap = (
        max_job_output_bytes
        if max_job_output_bytes is not None
        else settings.MAX_JOB_OUTPUT_BYTES
    )
    total_cap = (
        max_total_output_bytes
        if max_total_output_bytes is not None
        else settings.MAX_TOTAL_OUTPUT_BYTES
    )
    disk_reserve = (
        min_free_disk_bytes
        if min_free_disk_bytes is not None
        else settings.MIN_FREE_DISK_BYTES
    )
    if timeout < 1:
        raise ValueError(f"timeout_sec must be >= 1, got {timeout}")
    if max_par < 1:
        raise ValueError(f"max_parallel must be >= 1, got {max_par}")
    if job_cap < 1:
        raise ValueError(f"max_job_output_bytes must be >= 1, got {job_cap}")
    if total_cap < job_cap:
        raise ValueError(
            "max_total_output_bytes must be >= max_job_output_bytes, got "
            f"{total_cap} < {job_cap}"
        )
    if disk_reserve < 1:
        raise ValueError(f"min_free_disk_bytes must be >= 1, got {disk_reserve}")
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_dir = out_dir.resolve(strict=True)

    jobs = _build_jobs(plan, tools)
    scanned_inputs = (
        {
            os.path.normcase(os.path.abspath(item.path)): (
                item.size_bytes,
                item.sha256,
                item.mtime_ns,
            )
            for item in inventory.evidence_list
        }
        if inventory is not None
        else None
    )
    bundle = ExecutionBundle(output_dir=str(out_dir), parallel_max=max_par)
    if not jobs:
        _remove_if_empty(out_dir)
        return bundle

    progress: Progress | None = None
    task_id = None
    if console is not None:
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        )
        progress.start()
        task_id = progress.add_task("Running tools", total=len(jobs))

    completed: dict[int, ExecutionResult] = {}
    try:
        with Stopwatch() as sw:
            with execution_lock(out_dir):
                state, state_warnings = load_state(out_dir)
                verified_inputs: dict[
                    str, tuple[str, int, str, int, int, int]
                ] = {}
                sequences_by_input: dict[str, list[int]] = {}
                path_errors: dict[str, str] = {}
                integrity_errors: dict[int, str] = {}
                for job in jobs:
                    evidence_key = os.path.normcase(os.path.abspath(job.evidence))
                    sequences_by_input.setdefault(evidence_key, []).append(job.sequence)
                    if evidence_key in path_errors:
                        integrity_errors[job.sequence] = path_errors[evidence_key]
                        continue
                    expected = (
                        scanned_inputs.get(evidence_key)
                        if scanned_inputs is not None
                        else None
                    )
                    if scanned_inputs is not None and expected is None:
                        error = (
                            "evidence is not present in the scan inventory; "
                            "rescan before execution"
                        )
                    elif evidence_key in verified_inputs:
                        continue
                    else:
                        try:
                            evidence_path = Path(job.evidence).resolve(strict=True)
                            current = _input_fingerprint(evidence_path)
                        except (OSError, RuntimeError) as exc:
                            error = f"could not verify scanned evidence: {exc}"
                        else:
                            if expected is None or current[:3] == expected:
                                verified_inputs[evidence_key] = (
                                    str(evidence_path),
                                    *current,
                                )
                                continue
                            error = (
                                "evidence no longer matches scan inventory "
                                "(size, SHA-256, or mtime changed); rescan before "
                                "execution"
                            )
                    path_errors[evidence_key] = error
                    integrity_errors[job.sequence] = error

                preflight = _preflight_tools(
                    [job for job in jobs if job.sequence not in integrity_errors]
                )
                pending: list[_PreparedJob] = []
                cache_warnings: dict[int, str] = {}

                def finish(result: ExecutionResult, sequence: int) -> None:
                    completed[sequence] = result
                    try:
                        input_integrity = result.provenance.get("input_integrity")
                        pending_verification = (
                            isinstance(input_integrity, dict)
                            and input_integrity.get("status")
                            == "pending_final_verification"
                        )
                        if not pending_verification:
                            record_result(state, result)
                        if (
                            not pending_verification
                            and isinstance(result.provenance.get("resume"), dict)
                        ):
                            save_state(out_dir, state)
                    except (OSError, StateError) as exc:
                        result.warnings.append(
                            f"execution state could not be saved safely: {exc}"
                        )
                    if progress is not None and task_id is not None:
                        progress.update(
                            task_id,
                            advance=1,
                            description=f"[{result.status}] {result.tool_id}",
                        )

                for job in jobs:
                    integrity_error = integrity_errors.get(job.sequence)
                    if integrity_error:
                        check = (False, "not run: scan inventory verification failed")
                        result = ExecutionResult(
                            tool_id=job.metadata.tool_id,
                            target_evidence=job.evidence,
                            status="failed",
                            exit_code=-1,
                            output_format=job.metadata.output_format,
                            provenance=_tool_provenance(job.metadata, check),
                        )
                        finish(
                            _mark_input_integrity_failed(
                                result,
                                f"failed to fingerprint job: {integrity_error}",
                            ),
                            job.sequence,
                        )
                        continue
                    check = preflight[job.metadata.tool_id]
                    if not check[0]:
                        finish(
                            ExecutionResult(
                                tool_id=job.metadata.tool_id,
                                target_evidence=job.evidence,
                                status="skipped",
                                exit_code=-1,
                                error_message=f"prerequisites failed: {check[1]}",
                                output_format=job.metadata.output_format,
                                provenance=_tool_provenance(job.metadata, check),
                            ),
                            job.sequence,
                        )
                        continue
                    try:
                        evidence_key = os.path.normcase(
                            os.path.abspath(job.evidence)
                        )
                        prepared = _prepare_job(
                            job,
                            out_dir,
                            timeout,
                            max_par,
                            job_cap,
                            total_cap,
                            disk_reserve,
                            check,
                            verified_inputs[evidence_key],
                        )
                    except (OSError, RuntimeError, TypeError, ValueError) as exc:
                        finish(
                            ExecutionResult(
                                tool_id=job.metadata.tool_id,
                                target_evidence=job.evidence,
                                status="failed",
                                exit_code=-1,
                                error_message=f"failed to fingerprint job: {exc}",
                                output_format=job.metadata.output_format,
                                provenance=_tool_provenance(job.metadata, check),
                            ),
                            job.sequence,
                        )
                        continue
                    reused, cache_warning = reusable_result(
                        state, prepared.job_key, out_dir
                    )
                    if reused is not None:
                        try:
                            reused_target = str(
                                Path(reused.target_evidence).resolve(strict=True)
                            )
                        except OSError:
                            reused_target = ""
                        if (
                            reused.tool_id != job.metadata.tool_id
                            or reused_target != prepared.input_path
                            or reused.command_template_used
                            != prepared.selected_template
                            or reused.output_format != job.metadata.output_format
                        ):
                            reused = None
                            cache_warning = (
                                "cached result rejected: execution identity mismatch"
                            )
                    if reused is not None:
                        cached_job_output_dir = reused.provenance["job_output_dir"]
                        reused.provenance = dict(prepared.provenance)
                        reused.provenance["output_root"] = str(out_dir)
                        reused.provenance["job_output_dir"] = cached_job_output_dir
                        resume = reused.provenance.get("resume")
                        if isinstance(resume, dict):
                            reused.provenance["resume"] = dict(resume, reused=True)
                        completed[job.sequence] = reused
                        if progress is not None and task_id is not None:
                            progress.update(
                                task_id,
                                advance=1,
                                description=f"[reused] {reused.tool_id}",
                            )
                        continue
                    if cache_warning:
                        cache_warnings[job.sequence] = cache_warning
                    pending.append(prepared)

                try:
                    existing_bytes = _output_directory_bytes(out_dir)
                    preflight_error = _disk_preflight(
                        out_dir,
                        existing_bytes=existing_bytes,
                        job_count=len(pending),
                        per_job_bytes=job_cap,
                        total_bytes=total_cap,
                        reserve_bytes=disk_reserve,
                    ) if pending else ""
                except OSError as exc:
                    existing_bytes = 0
                    preflight_error = f"disk preflight failed safely: {exc}"

                budget = _OutputBudget(
                    out_dir,
                    initial_bytes=existing_bytes,
                    per_job_bytes=job_cap,
                    total_bytes=total_cap,
                    reserve_bytes=disk_reserve,
                )
                if preflight_error:
                    for prepared in pending:
                        result = _terminal_result(
                            prepared, "output_limit", preflight_error
                        )
                        warning = cache_warnings.get(prepared.job.sequence)
                        if warning:
                            result.warnings.append(warning)
                        finish(result, prepared.job.sequence)
                    pending.clear()

                serial_locks = {
                    prepared.job.metadata.tool_id: threading.Lock()
                    for prepared in pending
                    if not prepared.job.metadata.parallelizable
                }
                active_serial_tools: set[str] = set()
                cancel_event = threading.Event()

                with ThreadPoolExecutor(max_workers=max_par) as pool:
                    futures: dict[Future[ExecutionResult], _PreparedJob] = {}
                    interrupted = False
                    while pending or futures:
                        global_limit = budget.global_reason()
                        if cancel_event.is_set() or global_limit:
                            status = "cancelled" if cancel_event.is_set() else "output_limit"
                            message = (
                                "execution cancelled by user"
                                if cancel_event.is_set()
                                else global_limit
                            )
                            for prepared in pending:
                                result = _terminal_result(prepared, status, message)
                                warning = cache_warnings.get(prepared.job.sequence)
                                if warning:
                                    result.warnings.append(warning)
                                finish(result, prepared.job.sequence)
                            pending.clear()

                        while len(futures) < max_par and pending:
                            eligible_index = next(
                                (
                                    index
                                    for index, prepared in enumerate(pending)
                                    if prepared.job.metadata.parallelizable
                                    or prepared.job.metadata.tool_id
                                    not in active_serial_tools
                                ),
                                None,
                            )
                            if eligible_index is None:
                                break
                            prepared = pending.pop(eligible_index)
                            job = prepared.job
                            if job.metadata.parallelizable:
                                future = pool.submit(
                                    _execute_one,
                                    prepared,
                                    out_dir,
                                    timeout,
                                    budget,
                                    cancel_event,
                                )
                            else:
                                active_serial_tools.add(job.metadata.tool_id)
                                future = pool.submit(
                                    _execute_with_lock,
                                    serial_locks[job.metadata.tool_id],
                                    prepared,
                                    out_dir,
                                    timeout,
                                    budget,
                                    cancel_event,
                                )
                            futures[future] = prepared

                        if not futures:
                            break

                        try:
                            done, _ = wait(futures, return_when=FIRST_COMPLETED)
                        except KeyboardInterrupt:
                            cancel_event.set()
                            interrupted = True
                            continue
                        for future in done:
                            prepared = futures.pop(future)
                            job = prepared.job
                            if not job.metadata.parallelizable:
                                active_serial_tools.discard(job.metadata.tool_id)
                            try:
                                result = future.result()
                            except Exception as exc:  # noqa: BLE001
                                result = _crashed_result(prepared, exc)
                            warning = cache_warnings.get(job.sequence)
                            if warning:
                                result.warnings.append(warning)
                            finish(result, job.sequence)

                    if interrupted:
                        cancel_event.set()

                # Full-file hashing is shared per evidence: one scan/start check and
                # one final check, with cheap stable-file identity checks per job.
                # A local writer that performs and fully restores an ABA change
                # between checks requires an immutable evidence snapshot to defeat.
                state_needs_save = False
                for evidence_key, expected in verified_inputs.items():
                    input_path, size, sha256, mtime_ns, device, inode = expected
                    try:
                        final_fingerprint = _input_fingerprint(input_path)
                    except OSError as exc:
                        integrity_error = (
                            f"could not verify input after execution: {exc}"
                        )
                    else:
                        integrity_error = ""
                        if final_fingerprint != (
                            size,
                            sha256,
                            mtime_ns,
                            device,
                            inode,
                        ):
                            integrity_error = (
                                "input changed during case execution; every result "
                                "for this evidence is not reusable"
                            )
                    for sequence in sequences_by_input[evidence_key]:
                        result = completed.get(sequence)
                        if result is None:
                            continue
                        current_integrity = result.provenance.get("input_integrity")
                        already_failed = (
                            isinstance(current_integrity, dict)
                            and current_integrity.get("status") == "failed"
                        )
                        if integrity_error:
                            _mark_input_integrity_failed(result, integrity_error)
                        elif not already_failed:
                            result.provenance = dict(result.provenance)
                            result.provenance["input_integrity"] = {
                                "status": "verified",
                                "strategy": (
                                    "start_sha256_per_job_stat_final_sha256"
                                ),
                            }
                        if isinstance(result.provenance.get("resume"), dict):
                            try:
                                record_result(state, result)
                                state_needs_save = True
                            except StateError as exc:
                                result.warnings.append(
                                    "final execution state could not be updated "
                                    f"safely: {exc}"
                                )
                if state_needs_save:
                    try:
                        save_state(out_dir, state)
                    except (OSError, StateError) as exc:
                        if completed:
                            completed[min(completed)].warnings.append(
                                f"final execution state could not be saved safely: {exc}"
                            )

                if state_warnings and completed:
                    completed[min(completed)].warnings[:0] = state_warnings

        if stage_ms is not None:
            stage_ms["execute"] = stage_ms.get("execute", 0) + sw.elapsed_ms
    finally:
        if progress is not None:
            progress.stop()

    bundle.results = [completed[index] for index in sorted(completed)]
    _remove_if_empty(out_dir)
    return bundle
