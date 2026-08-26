"""Analyzer orchestration over structured executor artifacts.

Generated artifacts are authoritative when a tool writes progress text to
stdout. CSV and text artifacts are streamed in overlapping batches so evidence
near the tail is not silently omitted.
"""

from __future__ import annotations

import csv
import hashlib
import heapq
import json
import logging
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter_ns
from typing import Any, Callable, Iterable, Iterator

from forensicagent.analyzer.llm_extract import extract as llm_extract
from forensicagent.analyzer.rules import (
    apply_rules_with_status,
    cross_batch_correlation_family,
    supported_indicator_ids,
)
from forensicagent.analyzer.time_scope import (
    TimeScope,
    extract_time_scope,
    parse_timestamp,
    row_timestamps,
)
from forensicagent.analyzer.timeline import iter_timeline_events
from forensicagent.analyzer.types import (
    MAX_RETAINED_FINDINGS,
    SEVERITY_RANK,
    Finding,
    ToolAnalysis,
    by_severity_count,
)
from forensicagent.executor.runner import (
    contained_directory,
    contained_regular_file,
    hash_file,
)
from forensicagent.executor.types import MAX_INLINE_JSON_BYTES, ExecutionResult
from forensicagent.llm import OllamaClient
from forensicagent.observability import Stopwatch
from forensicagent.tools.schema import ToolMetadata

logger = logging.getLogger(__name__)

CASE_A_MAX = MAX_INLINE_JSON_BYTES
CASE_B_MAX = 4 * 1024 * 1024
ROW_BATCH_SIZE = 5_000
ROW_OVERLAP = 512
ROW_BATCH_MAX_CHARS = CASE_B_MAX
# Only Event IDs used by cross-row matchers are retained. Families are isolated
# so a failed-logon flood cannot evict account events (or vice versa), and each
# family remains bounded to one batch's worth of relevant records.
CORRELATION_FAMILY_CARRY = ROW_BATCH_SIZE
CORRELATION_FAMILY_MAX_CHARS = CASE_B_MAX
TEXT_CHUNK_CHARS = 512 * 1024
TEXT_OVERLAP_CHARS = 8 * 1024
CSV_EXTRA_FIELDS_KEY = "__extra_fields__"
_RULES_ONLY_SUBCATEGORIES = {"prefetch"}
_TIMELINE_SUBCATEGORIES = {
    "amcache",
    "prefetch",
    "shimcache",
    "windows_event_log",
    "windows_hive",
    "windows_hive_batch",
}
TIMELINE_PREVIEW_LIMIT = 256
SUMMARY_DETAIL_LIMIT = 240


def _bounded_excerpt(text: str, limit: int = SUMMARY_DETAIL_LIMIT) -> str:
    """Keep both the reason and outcome when compacting a diagnostic."""
    if len(text) <= limit:
        return text
    marker = "...[truncated]..."
    head = (limit - len(marker)) // 2
    return f"{text[:head]}{marker}{text[-(limit - len(marker) - head):]}"

# Python's platform default is commonly 128 KiB, below our already-bounded
# 4 MiB record budget. Align the parser so valid wide PECmd rows are not lost.
if csv.field_size_limit() < ROW_BATCH_MAX_CHARS:
    csv.field_size_limit(ROW_BATCH_MAX_CHARS)


@dataclass(frozen=True)
class _ArtifactInput:
    path: Path
    role: str
    format: str
    size_bytes: int
    sha256: str = ""


class _CsvRecordLimitError(Exception):
    def __init__(self, *, line_number: int, recoverable: bool) -> None:
        super().__init__("CSV record exceeds the analysis limit")
        self.line_number = line_number
        self.recoverable = recoverable


class _BoundedCsvLines:
    """Feed csv.reader without allowing it to buffer an unbounded record."""

    def __init__(self, handle: Any) -> None:
        self.handle = handle
        self.line_number = 0
        self.record_chars = 0

    def __iter__(self) -> _BoundedCsvLines:
        return self

    def __next__(self) -> str:
        line = self.handle.readline(ROW_BATCH_MAX_CHARS + 1)
        if not line:
            raise StopIteration
        self.line_number += 1
        prior_chars = self.record_chars
        if len(line) > ROW_BATCH_MAX_CHARS:
            while line and not line.endswith(("\n", "\r")):
                line = self.handle.readline(ROW_BATCH_MAX_CHARS + 1)
            self.record_chars = 0
            raise _CsvRecordLimitError(
                line_number=self.line_number,
                recoverable=prior_chars == 0,
            )
        self.record_chars += len(line)
        if self.record_chars > ROW_BATCH_MAX_CHARS:
            raise _CsvRecordLimitError(
                line_number=self.line_number,
                recoverable=False,
            )
        return line

    def reset_record(self) -> None:
        self.record_chars = 0


def _rag_context_for(metadata: ToolMetadata) -> str:
    """Retrieve only the current tool's knowledge document."""
    from forensicagent.rag.retrieval import retrieve_tools

    indicator_text = " ".join(
        f"{item.pattern} {item.description}"
        for item in metadata.suspicious_indicators
    ).strip()
    query = (
        f"{metadata.display_name} {metadata.category}: "
        f"what output patterns are suspicious? {indicator_text}"
    )
    hits = retrieve_tools(query, tool_ids={metadata.tool_id})
    if not hits:
        return ""
    return "\n".join(
        f"- {' '.join(hit.snippet.split())[:400]}" for hit in hits[:3]
    )


def _artifact_value(artifact: Any, name: str, default: Any = "") -> Any:
    if isinstance(artifact, dict):
        return artifact.get(name, default)
    return getattr(artifact, name, default)


def _link_or_reparse(value: os.stat_result) -> bool:
    return stat.S_ISLNK(value.st_mode) or bool(
        getattr(value, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _artifact_inputs(
    result: ExecutionResult,
    coverage_warnings: list[str],
) -> tuple[list[_ArtifactInput], bool]:
    generated: list[_ArtifactInput] = []
    stdout: list[_ArtifactInput] = []
    seen: set[str] = set()
    integrity_failed = False
    provenance = _artifact_value(result, "provenance", {})
    job_output_dir = (
        provenance.get("job_output_dir") if isinstance(provenance, dict) else None
    )
    output_root = (
        provenance.get("output_root") if isinstance(provenance, dict) else None
    )
    if job_output_dir and output_root:
        try:
            job_output_dir = str(contained_directory(job_output_dir, output_root))
        except OSError:
            coverage_warnings.append(
                "artifact integrity verification failed: unsafe job output directory"
            )
            return [], True

    for artifact in _artifact_value(result, "artifacts", None) or []:
        path_text = _artifact_value(artifact, "path")
        if not path_text:
            continue
        path = Path(str(path_text))
        expected_sha256 = str(_artifact_value(artifact, "sha256", "") or "")
        try:
            if job_output_dir:
                path = contained_regular_file(path, str(job_output_dir))
            else:
                value = path.lstat()
                if _link_or_reparse(value) or not stat.S_ISREG(value.st_mode):
                    raise OSError("artifact is not a regular non-link file")
            actual_size, actual_sha256 = hash_file(path)
        except OSError:
            if expected_sha256:
                integrity_failed = True
                coverage_warnings.append(
                    f"artifact integrity verification failed before analysis: {path}"
                )
            continue
        if actual_size <= 0:
            continue
        key = str(path.resolve()).casefold()
        if key in seen:
            continue
        seen.add(key)
        role = str(_artifact_value(artifact, "role", "generated")).casefold()
        fmt = str(_artifact_value(artifact, "format", "")).casefold()
        declared_size = _artifact_value(artifact, "size_bytes", actual_size)
        try:
            recorded_size = int(declared_size)
        except (TypeError, ValueError):
            recorded_size = -1
        if expected_sha256 and (
            recorded_size != actual_size or expected_sha256 != actual_sha256
        ):
            integrity_failed = True
            coverage_warnings.append(
                f"artifact integrity mismatch before analysis: {path}; artifact skipped"
            )
            continue
        size = max(actual_size, recorded_size, 0)
        item = _ArtifactInput(
            path=path,
            role=role,
            format=fmt,
            size_bytes=size,
            sha256=expected_sha256,
        )
        if role == "generated":
            generated.append(item)
        elif role == "stdout":
            stdout.append(item)

    # Compatibility with pre-artifact executor results.
    stdout_path = Path(str(_artifact_value(result, "stdout_path", "") or ""))
    if stdout_path:
        try:
            if job_output_dir:
                stdout_path = contained_regular_file(
                    stdout_path, str(job_output_dir)
                )
            elif not stdout_path.is_file():
                raise OSError("stdout artifact is not a regular file")
        except OSError:
            stdout_path = Path()
    if stdout_path.is_file():
        key = str(stdout_path.resolve()).casefold()
        if key not in seen:
            try:
                size = stdout_path.stat().st_size
            except OSError:
                size = 0
            if size > 0:
                stdout.append(
                    _ArtifactInput(
                        path=stdout_path,
                        role="stdout",
                        format=str(_artifact_value(result, "output_format", "") or "").casefold(),
                        size_bytes=size,
                    )
                )

    # Generated files are authoritative and are analyzed first.  Stdout is
    # still evidence for tools that emit a useful summary in addition to a
    # generated CSV/JSON; canonical de-duplication removes repeated records.
    return generated + stdout, integrity_failed


def _artifacts_still_match(artifacts: list[_ArtifactInput]) -> bool:
    for artifact in artifacts:
        if not artifact.sha256:
            continue
        try:
            value = artifact.path.lstat()
            if _link_or_reparse(value) or not stat.S_ISREG(value.st_mode):
                return False
            size, digest = hash_file(artifact.path)
        except OSError:
            return False
        if size != artifact.size_bytes or digest != artifact.sha256:
            return False
    return True


def _infer_format(artifact: _ArtifactInput) -> str:
    hint = artifact.format.casefold().strip().lstrip(".")
    suffix = artifact.path.suffix.casefold()
    # Executors commonly describe line-delimited JSON as generic ``json``.
    # The more-specific filename suffix wins so we do not try json.load() on
    # a stream containing multiple top-level objects.
    if suffix in {".jsonl", ".ndjson"}:
        return suffix[1:]
    if hint in {"csv", "json", "jsonl", "ndjson", "text", "txt", "log"}:
        return "text" if hint in {"txt", "log"} else hint
    return {
        ".csv": "csv",
        ".json": "json",
        ".jsonl": "jsonl",
        ".ndjson": "ndjson",
        ".log": "text",
        ".txt": "text",
    }.get(suffix, "text")


def _serialize_row(row: dict[str, Any]) -> str:
    try:
        return json.dumps(row, ensure_ascii=False, default=str, sort_keys=True)
    except TypeError:
        # JSON-supported mixed key types cannot be ordered. Preserve every
        # entry instead of coercing keys into a collision-prone string dict.
        return json.dumps(row, ensure_ascii=False, default=str)


def _render_rows(rows: list[dict[str, Any]], budget: int = CASE_A_MAX) -> str:
    pieces: list[str] = []
    used = 0
    for row in rows:
        rendered = _serialize_row(row)
        if used + len(rendered) + 1 > budget:
            break
        pieces.append(rendered)
        used += len(rendered) + 1
    return "\n".join(pieces)


def _record_coverage_warnings(parsed: Any, warnings: list[str]) -> None:
    if not isinstance(parsed, dict):
        return
    candidates = parsed.get("items")
    rows = candidates if isinstance(candidates, list) else [parsed]
    for row in rows:
        if not isinstance(row, dict) or row.get("record_type") != "coverage_warning":
            continue
        message = str(row.get("message") or "tool reported incomplete coverage")
        warning = f"tool-reported coverage: {message[:240]}"
        if warning not in warnings:
            warnings.append(warning)


def _row_size(row: dict[str, Any]) -> int:
    return len(_serialize_row(row)) + 1


def _iter_row_batches(
    rows: Iterator[dict[str, Any]],
    coverage_warnings: list[str],
    *,
    row_observer: Callable[[dict[str, Any], int], None] | None = None,
) -> Iterator[tuple[dict[str, list[dict[str, Any]]], str]]:
    carry: list[dict[str, Any]] = []
    correlation_carry: dict[str, list[tuple[dict[str, Any], int]]] = {}
    pending_correlation: list[dict[str, Any]] | None = None
    current: list[dict[str, Any]] = []
    current_chars = 0
    for row in rows:
        row_chars = _row_size(row)
        if row_chars > ROW_BATCH_MAX_CHARS:
            warning = (
                "structured artifact contains a record above the "
                f"{ROW_BATCH_MAX_CHARS}-character analysis limit; the record was "
                "skipped and the raw artifact was retained"
            )
            if warning not in coverage_warnings:
                logger.warning(warning)
                coverage_warnings.append(warning)
            continue
        if row_observer is not None:
            row_observer(row, row_chars)
        # Delay state retention until another row proves that a later batch
        # exists. An exact-size final batch cannot lose a future correlation.
        if pending_correlation is not None:
            _update_correlation_carry(
                correlation_carry,
                pending_correlation,
                coverage_warnings,
            )
            pending_correlation = None
        current.append(row)
        current_chars += row_chars
        if len(current) < ROW_BATCH_SIZE and current_chars < ROW_BATCH_MAX_CHARS:
            continue
        correlation_groups = [
            [item[0] for item in family_rows]
            for family_rows in correlation_carry.values()
        ]
        batch = _merge_unique_rows(*correlation_groups, carry, current)
        yield {"items": batch}, _render_rows(batch)
        carry = current[-ROW_OVERLAP:]
        pending_correlation = current
        current = []
        current_chars = 0
    if current:
        correlation_groups = [
            [item[0] for item in family_rows]
            for family_rows in correlation_carry.values()
        ]
        batch = _merge_unique_rows(*correlation_groups, carry, current)
        yield {"items": batch}, _render_rows(batch)


def _merge_unique_rows(
    *groups: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge row references without double-counting overlap/correlation carry."""
    out: list[dict[str, Any]] = []
    seen: set[int] = set()
    for group in groups:
        for row in group:
            identity = id(row)
            if identity in seen:
                continue
            seen.add(identity)
            out.append(row)
    return out


def _update_correlation_carry(
    carry: dict[str, list[tuple[dict[str, Any], int]]],
    current: list[dict[str, Any]],
    coverage_warnings: list[str],
) -> None:
    for row in current:
        family = cross_batch_correlation_family(row)
        if family is not None:
            carry.setdefault(family, []).append((row, _row_size(row)))

    for family, family_rows in carry.items():
        total_chars = sum(item[1] for item in family_rows)
        drop = 0
        while drop < len(family_rows) and (
            len(family_rows) - drop > CORRELATION_FAMILY_CARRY
            or total_chars > CORRELATION_FAMILY_MAX_CHARS
        ):
            total_chars -= family_rows[drop][1]
            drop += 1
        if drop == 0:
            continue
        del family_rows[:drop]
        warning = (
            f"{family} event correlation carry exceeded its bounded "
            f"{CORRELATION_FAMILY_CARRY}-row/{CORRELATION_FAMILY_MAX_CHARS}-character "
            "budget; cross-batch correlation "
            "coverage was truncated"
        )
        if warning not in coverage_warnings:
            logger.warning(warning)
            coverage_warnings.append(warning)


def _iter_csv(
    artifact: _ArtifactInput,
    coverage_warnings: list[str],
    *,
    row_observer: Callable[[dict[str, Any], int], None] | None = None,
) -> Iterator[tuple[Any, str]]:
    with artifact.path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        source = _BoundedCsvLines(handle)
        header_reader = csv.reader(source)
        try:
            fieldnames = next(header_reader)
        except (StopIteration, csv.Error, _CsvRecordLimitError) as exc:
            warning = (
                f"CSV artifact {artifact.path} has an unreadable or oversized header: "
                f"{exc}; the raw artifact was retained"
            )
            logger.warning(warning)
            coverage_warnings.append(warning)
            return
        source.reset_record()
        # DictReader otherwise stores surplus columns under a ``None`` key.
        # That mixed key type crashes the deterministic JSON rendering used by
        # both batch sizing and row rendering when ``sort_keys=True``.
        restkey = CSV_EXTRA_FIELDS_KEY
        while restkey in fieldnames:
            restkey = "_" + restkey
        reader = csv.DictReader(
            source,
            fieldnames=fieldnames,
            restkey=restkey,
        )

        def rows() -> Iterator[dict[str, Any]]:
            nonlocal reader
            errors = 0
            while True:
                try:
                    row = next(reader)
                except StopIteration:
                    return
                except _CsvRecordLimitError as exc:
                    errors += 1
                    warning = (
                        f"CSV artifact {artifact.path} contains a record above the "
                        f"{ROW_BATCH_MAX_CHARS}-character limit near line "
                        f"{exc.line_number}; the record was skipped and the raw "
                        "artifact was retained"
                    )
                    logger.warning(warning)
                    if warning not in coverage_warnings:
                        coverage_warnings.append(warning)
                    source.reset_record()
                    if not exc.recoverable or errors >= 100:
                        return
                    reader = csv.DictReader(
                        source,
                        fieldnames=fieldnames,
                        restkey=restkey,
                    )
                    continue
                except csv.Error as exc:
                    errors += 1
                    warning = (
                        f"CSV artifact {artifact.path} contains an oversized or "
                        f"malformed record near line {reader.line_num}: {exc}; "
                        "the record was skipped and the raw artifact was retained"
                    )
                    logger.warning(warning)
                    if warning not in coverage_warnings:
                        coverage_warnings.append(warning)
                    if errors >= 100:
                        return
                    source.reset_record()
                    reader = csv.DictReader(
                        source,
                        fieldnames=fieldnames,
                        restkey=restkey,
                    )
                    continue
                source.reset_record()
                yield dict(row)

        yield from _iter_row_batches(
            rows(), coverage_warnings, row_observer=row_observer
        )


def _iter_ndjson(
    artifact: _ArtifactInput,
    coverage_warnings: list[str],
    *,
    row_observer: Callable[[dict[str, Any], int], None] | None = None,
) -> Iterator[tuple[Any, str]]:
    def rows() -> Iterator[dict[str, Any]]:
        oversized_warning_emitted = False
        malformed_warning_emitted = False
        with artifact.path.open("r", encoding="utf-8-sig", errors="replace") as handle:
            line_number = 0
            while True:
                line = handle.readline(CASE_A_MAX + 1)
                if not line:
                    break
                line_number += 1
                if len(line) > CASE_A_MAX:
                    while line and not line.endswith("\n"):
                        line = handle.readline(CASE_A_MAX + 1)
                    if not oversized_warning_emitted:
                        warning = (
                            f"NDJSON artifact {artifact.path} contains records above "
                            f"the {CASE_A_MAX}-character line limit; oversized records "
                            "were skipped and the raw artifact was retained"
                        )
                        logger.warning(warning)
                        coverage_warnings.append(warning)
                        oversized_warning_emitted = True
                    continue
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    value = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    logger.warning(
                        "skip malformed NDJSON %s:%d: %s",
                        artifact.path,
                        line_number,
                        exc,
                    )
                    if not malformed_warning_emitted:
                        warning = (
                            f"NDJSON artifact {artifact.path} contains malformed "
                            "records; invalid records were skipped and the raw "
                            "artifact was retained"
                        )
                        coverage_warnings.append(warning)
                        malformed_warning_emitted = True
                    continue
                if isinstance(value, dict):
                    yield value

    yield from _iter_row_batches(
        rows(), coverage_warnings, row_observer=row_observer
    )


def _iter_json(
    artifact: _ArtifactInput,
    coverage_warnings: list[str],
    *,
    row_observer: Callable[[dict[str, Any], int], None] | None = None,
) -> Iterator[tuple[Any, str]]:
    if artifact.size_bytes > CASE_B_MAX:
        warning = (
            f"JSON artifact {artifact.path} is {artifact.size_bytes} bytes, above "
            f"the {CASE_B_MAX}-byte parser limit; raw artifact retained but "
            "content was not analyzed"
        )
        logger.warning(warning)
        coverage_warnings.append(warning)
        return
    try:
        with artifact.path.open("r", encoding="utf-8-sig", errors="replace") as handle:
            value = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("cannot parse JSON artifact %s: %s", artifact.path, exc)
        coverage_warnings.append(
            f"JSON artifact {artifact.path} could not be parsed; raw artifact "
            "retained but content was not analyzed"
        )
        return
    rows: list[dict[str, Any]] | None = None
    if isinstance(value, list):
        rows = [row for row in value if isinstance(row, dict)]
    elif isinstance(value, dict):
        for key, candidate in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", str(key).casefold())
            if normalized in {"items", "results", "rows", "events", "records"}:
                if isinstance(candidate, list):
                    rows = [row for row in candidate if isinstance(row, dict)]
                    break
    if rows is not None:
        yield from _iter_row_batches(
            iter(rows), coverage_warnings, row_observer=row_observer
        )
        return

    if row_observer is not None and isinstance(value, dict):
        row_observer(value, _row_size(value))

    raw = ""
    if artifact.size_bytes <= CASE_A_MAX:
        try:
            raw = artifact.path.read_text(encoding="utf-8-sig", errors="replace")
        except OSError:
            raw = ""
    yield value, raw


def _iter_text(
    artifact: _ArtifactInput,
    coverage_warnings: list[str],
) -> Iterator[tuple[Any, str]]:
    try:
        with artifact.path.open("r", encoding="utf-8-sig", errors="replace") as handle:
            overlap = ""
            while True:
                chunk = handle.read(TEXT_CHUNK_CHARS)
                if not chunk:
                    break
                text = overlap + chunk
                yield None, text
                overlap = text[-TEXT_OVERLAP_CHARS:]
    except OSError as exc:
        logger.warning("cannot read text artifact %s: %s", artifact.path, exc)
        coverage_warnings.append(
            f"text artifact {artifact.path} could not be read; raw artifact "
            "coverage is incomplete"
        )


def _iter_artifact_batches(
    artifact: _ArtifactInput,
    coverage_warnings: list[str],
    *,
    row_observer: Callable[[dict[str, Any], int], None] | None = None,
) -> Iterator[tuple[Any, str]]:
    fmt = _infer_format(artifact)
    if fmt == "csv":
        yield from _iter_csv(
            artifact, coverage_warnings, row_observer=row_observer
        )
    elif fmt in {"jsonl", "ndjson"}:
        yield from _iter_ndjson(
            artifact, coverage_warnings, row_observer=row_observer
        )
    elif fmt == "json":
        yield from _iter_json(
            artifact, coverage_warnings, row_observer=row_observer
        )
    else:
        yield from _iter_text(artifact, coverage_warnings)


def _line_hint(finding: Finding) -> str:
    match = re.search(r":(\d+)(?:\b|\s+-)", finding.description)
    return match.group(1) if match else ""


def _canonical_key(finding: Finding, tool_id: str) -> tuple[str, ...]:
    ref = finding.evidence_ref
    rule = (finding.rule_id or finding.title).strip().casefold()
    source_file = ref.source_file.strip().casefold()
    line = _line_hint(finding)
    location = (
        source_file,
        line,
        str(ref.event_id or ""),
        ref.channel.strip().casefold(),
        ref.provider.strip().casefold(),
        ref.timestamp.strip(),
    )
    # Event IDs and timestamps are not unique: several records can occur in
    # the same second.  Keep the normalized excerpt in every key; exact rows
    # repeated by streaming overlap still collapse, while distinct events do
    # not disappear.
    excerpt = re.sub(r"\s+", " ", ref.raw_excerpt).strip()
    excerpt_hash = hashlib.sha256(excerpt.encode("utf-8")).hexdigest()[:20]
    return (tool_id.casefold(), rule, *location, excerpt_hash)


def _dedupe(findings: list[Finding], *, tool_id: str = "") -> list[Finding]:
    """Dedupe by stable rule and tool-output location, never display title."""
    seen: dict[tuple[str, ...], Finding] = {}
    for finding in findings:
        finding.refresh_fingerprint()
        key = _canonical_key(finding, tool_id)
        previous = seen.get(key)
        if previous is None:
            seen[key] = finding
            continue
        previous_rank = SEVERITY_RANK[previous.severity]
        current_rank = SEVERITY_RANK[finding.severity]
        if current_rank > previous_rank or (
            current_rank == previous_rank and finding.confidence > previous.confidence
        ):
            seen[key] = finding
    return list(seen.values())


def _sort_severity_desc(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda finding: (SEVERITY_RANK[finding.severity], finding.confidence),
        reverse=True,
    )


def _merge_bounded(
    existing: list[Finding], incoming: list[Finding], *, tool_id: str
) -> tuple[list[Finding], bool]:
    merged = _dedupe(existing + incoming, tool_id=tool_id)
    ordered = _sort_severity_desc(merged)
    return ordered[:MAX_RETAINED_FINDINGS], len(ordered) > MAX_RETAINED_FINDINGS


def _grounded_rule_input(findings: list[Finding]) -> str:
    blocks: list[str] = []
    used = 0
    for finding in findings:
        excerpt = finding.evidence_ref.raw_excerpt.strip()
        if not excerpt:
            continue
        block = (
            f"Rule: {finding.rule_id or finding.title}\n"
            f"Deterministic title: {finding.title}\n"
            f"Evidence excerpt:\n{excerpt}"
        )
        if used + len(block) > 12_000:
            break
        blocks.append(block)
        used += len(block)
    return "\n\n".join(blocks)


def _case_for(size: int) -> str:
    if size <= CASE_A_MAX:
        return "A"
    if size <= CASE_B_MAX:
        return "B"
    return "C"


def _structured_rows(parsed: Any) -> Iterator[dict[str, Any]]:
    if isinstance(parsed, list):
        yield from (row for row in parsed if isinstance(row, dict))
        return
    if not isinstance(parsed, dict):
        return
    for key, value in parsed.items():
        normalized = re.sub(r"[^a-z0-9]", "", str(key).casefold())
        if normalized in {"items", "results", "rows", "events", "records"}:
            if isinstance(value, list):
                yield from (row for row in value if isinstance(row, dict))
                return
    if parsed and any(not isinstance(value, (dict, list)) for value in parsed.values()):
        yield parsed


def _llm_route(
    metadata: ToolMetadata,
    *,
    case_used: str,
    use_llm: bool,
    deterministic: list[Finding],
    deterministic_coverage: bool,
    time_scope: TimeScope | None,
    has_scoped_context: bool,
) -> str:
    if not use_llm:
        return "rules_only_disabled"
    if metadata.category == "code_security":
        return "rules_only_sensitive"
    if (
        metadata.subcategory.casefold() in _RULES_ONLY_SUBCATEGORIES
        or "prefetch" in metadata.applicable_evidence_types
    ):
        return "rules_only_simple"
    if time_scope is not None:
        return (
            "scoped_context_llm"
            if has_scoped_context
            else "rules_only_no_scoped_rows"
        )
    if deterministic_coverage:
        return "rules_only_deterministic"
    if case_used == "C":
        return "rules_only_large"
    if case_used == "B":
        return "findings_only_llm" if deterministic else "rules_only_no_candidates"
    return "raw_context_llm"


def analyze_one(
    result: ExecutionResult,
    metadata: ToolMetadata,
    *,
    use_llm: bool = True,
    use_rag: bool = True,
    client: OllamaClient | None = None,
    scenario: str | None = None,
    stage_ms: dict[str, int] | None = None,
) -> ToolAnalysis:
    target_evidence = str(_artifact_value(result, "target_evidence", "") or "")
    analysis = ToolAnalysis(
        tool_id=metadata.tool_id,
        target_evidence=target_evidence,
    )
    coverage_warnings = analysis.coverage_warnings
    status = str(_artifact_value(result, "status", "skipped"))
    provenance = _artifact_value(result, "provenance", {})
    input_integrity = (
        provenance.get("input_integrity") if isinstance(provenance, dict) else None
    )
    if (
        isinstance(input_integrity, dict)
        and input_integrity.get("status") == "failed"
    ):
        detail = str(input_integrity.get("detail", "input integrity failed"))[:240]
        coverage_warnings.append(f"input integrity failure: {detail}")
        analysis.status = "not_analyzed"
        analysis.summary = f"not analyzed: input integrity failure: {detail}"
        return analysis
    artifacts, artifact_integrity_failed = _artifact_inputs(
        result, coverage_warnings
    )
    parsed_inline = _artifact_value(result, "parsed_output", None)
    if artifact_integrity_failed:
        parsed_inline = None
    if not artifacts and parsed_inline is None:
        analysis.status = "not_analyzed"
        analysis.summary = (
            f"deterministic=0; total=0; execution_status={status}: "
            f"{str(_artifact_value(result, 'error_message', ''))[:160]}"
        )
        return analysis

    total_size = sum(artifact.size_bytes for artifact in artifacts)
    if not total_size:
        total_size = int(_artifact_value(result, "output_size_bytes", 0) or 0)
    analysis.case_used = _case_for(total_size)

    declared_rule_ids = {
        indicator.id for indicator in metadata.suspicious_indicators
    }
    rules_complete = (
        bool(declared_rule_ids)
        and declared_rule_ids <= supported_indicator_ids()
    )
    timeline_capable = (
        metadata.subcategory.casefold() in _TIMELINE_SUBCATEGORIES
        or bool(
            {"evtx_log", "prefetch", "registry_hive"}
            & set(metadata.applicable_evidence_types)
        )
    )
    # This means only that every rule declared by this tool has a concrete
    # matcher. Timeline normalization alone is not threat-detection coverage.
    analysis.deterministic_coverage = rules_complete

    time_scope = extract_time_scope(scenario)
    scope_counts = {
        "selected": 0,
        "outside": 0,
        "undated": 0,
        "retained": 0,
        "selected_chars": 0,
    }
    scope_parts: list[str] = []
    scope_chars = 0
    scope_context_truncated = False

    def observe_scoped_row(row: dict[str, Any], row_chars: int) -> None:
        nonlocal scope_chars, scope_context_truncated
        if time_scope is None:
            return
        timestamps = row_timestamps(row)
        if not timestamps:
            scope_counts["undated"] += 1
            return
        if not any(time_scope.contains(timestamp) for timestamp in timestamps):
            scope_counts["outside"] += 1
            return
        scope_counts["selected"] += 1
        rendered = _serialize_row(row)
        scope_counts["selected_chars"] += row_chars
        if scope_chars + row_chars <= CASE_A_MAX:
            scope_parts.append(rendered)
            scope_chars += row_chars
            scope_counts["retained"] += 1
        else:
            scope_context_truncated = True

    timeline_preview: list[tuple[int, int, dict[str, Any]]] = []
    timeline_sequence = 0

    def row_observer_for(
        profile: dict[str, Any],
        *,
        source_artifact: str,
        collect_timeline: bool,
    ) -> Callable[[dict[str, Any], int], None]:
        def observe(row: dict[str, Any], row_chars: int) -> None:
            nonlocal timeline_sequence
            profile["rows_seen"] += 1
            profile["structured_chars"] += row_chars
            observe_scoped_row(row, row_chars)
            if not collect_timeline:
                return
            events = iter_timeline_events(
                (row,),
                tool_id=metadata.tool_id,
                source_file=target_evidence,
            )
            normalized = 0
            for event in events:
                normalized += 1
                profile["normalized_events"] += 1
                profile["timeline_types"][event.artifact_type] = (
                    profile["timeline_types"].get(event.artifact_type, 0) + 1
                )
                if event.timestamp_utc is None:
                    profile["undated_events"] += 1
                    continue
                analysis.timeline_event_count += 1
                item = event.to_dict()
                # Full normalized attributes remain available from the parser
                # API. Reports retain only identity fields to stay bounded.
                item.pop("attributes", None)
                item["tool_id"] = metadata.tool_id
                item["target_evidence"] = target_evidence
                item["source_artifact"] = source_artifact
                timestamp = event.timestamp_utc
                instant = (
                    timestamp.toordinal() * 86_400_000_000
                    + timestamp.hour * 3_600_000_000
                    + timestamp.minute * 60_000_000
                    + timestamp.second * 1_000_000
                    + timestamp.microsecond
                )
                entry = (-instant, -timeline_sequence, item)
                timeline_sequence += 1
                if len(timeline_preview) < TIMELINE_PREVIEW_LIMIT:
                    heapq.heappush(timeline_preview, entry)
                else:
                    analysis.timeline_events_truncated = True
                    if entry[:2] > timeline_preview[0][:2]:
                        heapq.heapreplace(timeline_preview, entry)
            if normalized == 0:
                profile["unsupported_rows"] += 1

        return observe

    def new_profile(artifact: _ArtifactInput | None) -> dict[str, Any]:
        return {
            "source_artifact": str(artifact.path) if artifact else "<inline>",
            "role": artifact.role if artifact else "inline",
            "format": _infer_format(artifact) if artifact else "json",
            "input_bytes": artifact.size_bytes if artifact else total_size,
            "rows_seen": 0,
            "structured_chars": 0,
            "estimated_tokens": 0,
            "normalized_events": 0,
            "undated_events": 0,
            "unsupported_rows": 0,
            "timeline_types": {},
            "peak_batch_chars": 0,
            "parse_ms": 0,
            "rules_ms": 0,
        }

    rule_findings: list[Finding] = []
    failed_rule_ids: list[str] = []
    llm_raw_parts: list[str] = []
    total_parse_ns = 0
    total_rules_ns = 0
    if artifacts:
        has_prefetch_primary = metadata.tool_id.casefold() == "pecmd" and any(
            artifact.role == "generated"
            and "timeline" not in artifact.path.stem.casefold()
            for artifact in artifacts
        )
        for artifact in artifacts:
            profile = new_profile(artifact)
            analysis.artifact_profiles.append(profile)
            collect_timeline = (
                timeline_capable
                and artifact.role == "generated"
                and not (
                    has_prefetch_primary
                    and "timeline" in artifact.path.stem.casefold()
                )
            )
            observer = row_observer_for(
                profile,
                source_artifact=str(artifact.path),
                collect_timeline=collect_timeline,
            )
            iterator = iter(
                _iter_artifact_batches(
                    artifact,
                    coverage_warnings,
                    row_observer=observer,
                )
            )
            parse_ns = 0
            rules_ns = 0
            while True:
                started = perf_counter_ns()
                try:
                    parsed, raw = next(iterator)
                except StopIteration:
                    parse_ns += perf_counter_ns() - started
                    break
                parse_ns += perf_counter_ns() - started
                profile["peak_batch_chars"] = max(
                    profile["peak_batch_chars"], len(raw)
                )
                _record_coverage_warnings(parsed, coverage_warnings)
                if (
                    use_llm
                    and metadata.category != "code_security"
                    and metadata.subcategory.casefold()
                    not in _RULES_ONLY_SUBCATEGORIES
                    and time_scope is None
                    and analysis.case_used == "A"
                    and raw
                ):
                    remaining = CASE_A_MAX - sum(
                        len(part) for part in llm_raw_parts
                    )
                    if remaining > 0:
                        llm_raw_parts.append(raw[:remaining])
                started = perf_counter_ns()
                batch_findings, batch_limit_reached = apply_rules_with_status(
                    parsed,
                    raw,
                    metadata,
                    evidence_path=target_evidence,
                    failed_rule_ids=failed_rule_ids,
                )
                rules_ns += perf_counter_ns() - started
                rule_findings, merge_limit_reached = _merge_bounded(
                    rule_findings,
                    batch_findings,
                    tool_id=metadata.tool_id,
                )
                if batch_limit_reached or merge_limit_reached:
                    analysis.finding_limit_reached = True
            profile["parse_ms"] = parse_ns // 1_000_000
            profile["rules_ms"] = rules_ns // 1_000_000
            profile["estimated_tokens"] = (
                profile["structured_chars"] + 3
            ) // 4
            total_parse_ns += parse_ns
            total_rules_ns += rules_ns
    else:
        profile = new_profile(None)
        analysis.artifact_profiles.append(profile)
        started = perf_counter_ns()
        rows = list(_structured_rows(parsed_inline))
        observer = row_observer_for(
            profile,
            source_artifact="<inline>",
            collect_timeline=timeline_capable,
        )
        for row in rows:
            observer(row, _row_size(row))
        total_parse_ns = perf_counter_ns() - started
        profile["parse_ms"] = total_parse_ns // 1_000_000
        profile["estimated_tokens"] = (
            profile["structured_chars"] + 3
        ) // 4
        _record_coverage_warnings(parsed_inline, coverage_warnings)
        started = perf_counter_ns()
        batch_findings, batch_limit_reached = apply_rules_with_status(
            parsed_inline,
            "",
            metadata,
            evidence_path=target_evidence,
            failed_rule_ids=failed_rule_ids,
        )
        total_rules_ns = perf_counter_ns() - started
        profile["rules_ms"] = total_rules_ns // 1_000_000
        rule_findings, merge_limit_reached = _merge_bounded(
            rule_findings,
            batch_findings,
            tool_id=metadata.tool_id,
        )
        analysis.finding_limit_reached = (
            batch_limit_reached or merge_limit_reached
        )

    analysis.timeline_events = sorted(
        (entry[2] for entry in timeline_preview),
        key=lambda item: parse_timestamp(item.get("timestamp_utc"))
        or datetime.max.replace(tzinfo=timezone.utc),
    )

    if stage_ms is not None:
        parse_key = f"analyze_parse:{metadata.tool_id}"
        rules_key = f"analyze_rules:{metadata.tool_id}"
        stage_ms[parse_key] = stage_ms.get(parse_key, 0) + total_parse_ns // 1_000_000
        stage_ms[rules_key] = stage_ms.get(rules_key, 0) + total_rules_ns // 1_000_000

    if not _artifacts_still_match(artifacts):
        coverage_warnings.append(
            "artifact integrity changed during analysis; findings were discarded"
        )
        analysis.status = "not_analyzed"
        analysis.findings = []
        analysis.timeline_events = []
        analysis.timeline_event_count = 0
        analysis.timeline_events_truncated = False
        analysis.summary = "not analyzed: artifact integrity changed during analysis"
        return analysis

    if failed_rule_ids:
        failed_text = ", ".join(dict.fromkeys(failed_rule_ids))
        coverage_warnings.append(
            f"deterministic rule execution failed: {failed_text}"
        )
    analysis.deterministic_coverage = (
        rules_complete
        and status == "success"
        and not failed_rule_ids
        and not analysis.finding_limit_reached
        and not coverage_warnings
    )

    deterministic = _dedupe(rule_findings, tool_id=metadata.tool_id)
    llm_findings: list[Finding] = []
    llm_summary = ""
    invoked = False
    failed = False
    llm_input = ""
    scoped_context = "\n".join(scope_parts)
    route = _llm_route(
        metadata,
        case_used=analysis.case_used,
        use_llm=use_llm,
        deterministic=deterministic,
        deterministic_coverage=analysis.deterministic_coverage,
        time_scope=time_scope,
        has_scoped_context=bool(scoped_context.strip()),
    )
    if route == "scoped_context_llm":
        llm_input = scoped_context
    elif route == "findings_only_llm":
        # Case B never sends a raw multi-megabyte artifact to the model.
        llm_input = _grounded_rule_input(deterministic)
    elif route == "raw_context_llm":
        llm_input = "\n".join(llm_raw_parts)
        if not llm_input and deterministic:
            llm_input = _grounded_rule_input(deterministic)
    if route.endswith("_llm") and not llm_input.strip():
        route = "rules_only_no_context"
    analysis.llm_route = route
    analysis.llm_input_chars = len(llm_input)
    analysis.llm_input_estimated_tokens = (len(llm_input) + 3) // 4
    if time_scope is not None:
        analysis.time_scope = time_scope.to_dict()
        analysis.scope_rows = dict(scope_counts)
        analysis.scope_context_truncated = scope_context_truncated

    if llm_input.strip():
        rag_context = _rag_context_for(metadata) if use_rag else ""
        with Stopwatch() as sw_llm:
            llm_findings, llm_summary, invoked, failed = llm_extract(
                metadata,
                llm_input,
                evidence_path=target_evidence,
                client=client,
                scenario=scenario,
                rag_context=rag_context or None,
            )
        if stage_ms is not None:
            key = f"analyze_llm:{metadata.tool_id}"
            stage_ms[key] = stage_ms.get(key, 0) + sw_llm.elapsed_ms

    merged = _dedupe(deterministic + llm_findings, tool_id=metadata.tool_id)
    merged = _sort_severity_desc(merged)
    if len(merged) > MAX_RETAINED_FINDINGS:
        analysis.finding_limit_reached = True
        merged = merged[:MAX_RETAINED_FINDINGS]
    analysis.findings = merged
    analysis.llm_invoked = invoked
    analysis.llm_failed = failed

    counts = by_severity_count(merged)
    categories: dict[str, int] = {}
    for finding in merged:
        categories[finding.category] = categories.get(finding.category, 0) + 1
    top_categories = sorted(categories.items(), key=lambda item: item[1], reverse=True)[:3]
    category_text = ", ".join(f"{name}({count})" for name, count in top_categories) or "n/a"
    severity_text = (
        f"critical={counts['critical']} high={counts['high']} "
        f"medium={counts['medium']} low={counts['low']} info={counts['info']}"
    )
    summary_parts = [
        f"deterministic={len(deterministic)}",
        f"total={len(merged)} ({severity_text})",
        f"top={category_text}",
        f"route={route}",
        f"llm_input_chars={len(llm_input)}",
        f"llm_input_estimated_tokens={analysis.llm_input_estimated_tokens}",
        f"deterministic_coverage={str(analysis.deterministic_coverage).lower()}",
        f"parsed_artifacts={len(analysis.artifact_profiles)}",
        f"timeline_events={analysis.timeline_event_count}",
        f"parse_ms={total_parse_ns // 1_000_000}",
        f"rules_ms={total_rules_ns // 1_000_000}",
    ]
    if time_scope is not None:
        summary_parts.extend(
            (
                f"time_scope={time_scope.summary()}",
                "scope_rows="
                f"selected:{scope_counts['selected']},"
                f"outside:{scope_counts['outside']},"
                f"undated:{scope_counts['undated']},"
                f"retained:{scope_counts['retained']},"
                f"selected_chars:{scope_counts['selected_chars']}",
            )
        )
        if scope_context_truncated:
            summary_parts.append("scope_context_truncated=true")
    if status != "success":
        summary_parts.append(f"execution_status={status} (partial artifact analyzed)")
    warnings = _artifact_value(result, "warnings", None) or []
    if warnings:
        summary_parts.append(f"executor_warnings={len(warnings)}")
    if coverage_warnings:
        summary_parts.append("coverage_truncated=true")
        summary_parts.append(
            f"coverage_warning={_bounded_excerpt(coverage_warnings[0])}"
        )
    if llm_summary.strip():
        # The model may add context, but can never replace deterministic counts.
        summary_parts.append(f"llm_note={llm_summary.strip()[:240]}")
    if analysis.finding_limit_reached:
        summary_parts.append("finding_limit_reached=true")
    analysis.summary = "; ".join(summary_parts)
    return analysis


def analyze_all(
    execution_results: list[ExecutionResult],
    tools: dict[str, ToolMetadata],
    *,
    use_llm: bool = True,
    use_rag: bool = True,
    client: OllamaClient | None = None,
    scenario: str | None = None,
    stage_ms: dict[str, int] | None = None,
) -> list[ToolAnalysis]:
    out: list[ToolAnalysis] = []
    for result in execution_results:
        tool_id = str(_artifact_value(result, "tool_id", ""))
        metadata = tools.get(tool_id)
        if metadata is None:
            logger.warning("no metadata for tool_id=%r", tool_id)
            continue
        try:
            analysis = analyze_one(
                result,
                metadata,
                use_llm=use_llm,
                use_rag=use_rag,
                client=client,
                scenario=scenario,
                stage_ms=stage_ms,
            )
        except Exception as exc:  # noqa: BLE001 - isolate one malformed tool artifact.
            logger.exception("analysis failed for tool_id=%s", tool_id)
            analysis = ToolAnalysis(
                tool_id=tool_id,
                target_evidence=str(
                    _artifact_value(result, "target_evidence", "") or ""
                ),
                status="not_analyzed",
                summary=f"not analyzed: analyzer error: {exc}",
                coverage_warnings=[
                    f"analyzer failed for {tool_id}; raw artifacts were retained"
                ],
            )
        out.append(analysis)
    return out
