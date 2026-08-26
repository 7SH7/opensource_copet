"""Deterministic, bounded normalization of forensic rows into a timeline.

The adapters consume already-structured tool output.  They never execute
evidence and never call an LLM.  Iteration is streaming; only ``sort_timeline``
materializes events and therefore enforces an explicit upper bound.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator, Mapping

from forensicagent.analyzer.time_scope import (
    TimeScope,
    parse_timestamp,
    timestamp_timezone_assumed,
)

SUPPORTED_ARTIFACTS = frozenset(
    {"evtx", "prefetch", "amcache", "shimcache", "registry"}
)
DEFAULT_MAX_SORT_EVENTS = 100_000
MAX_ATTRIBUTE_FIELDS = 32
MAX_ATTRIBUTE_VALUE_CHARS = 4_096
MAX_ATTRIBUTE_TOTAL_CHARS = 16_384
MAX_IDENTITY_CHARS = 4_096
MAX_SUMMARY_CHARS = 2_048
MAX_TIMESTAMP_CHARS = 256
MAX_PREFETCH_RUN_TIMESTAMPS = 8

_TOOL_ARTIFACTS = {
    "evtxecmd": "evtx",
    "chainsaw": "evtx",
    "pecmd": "prefetch",
    "amcacheparser": "amcache",
    "appcompatcacheparser": "shimcache",
    "shimcacheparser": "shimcache",
    "recmd": "registry",
    "regripper": "registry",
}


class TimelineLimitError(ValueError):
    """A materializing or benchmark operation exceeded its declared bound."""


@dataclass(frozen=True)
class TimelineEvent:
    """One normalized forensic event with explicit timestamp semantics."""

    timestamp_utc: datetime | None
    timestamp_original: str
    timestamp_kind: str
    timestamp_field: str
    artifact_type: str
    event_kind: str
    timezone_assumed: bool = False
    source_tool: str = ""
    source_file: str = ""
    record_id: str = ""
    summary: str = ""
    attributes: dict[str, Any] = field(default_factory=dict, compare=False)
    attributes_truncated: bool = False

    def __post_init__(self) -> None:
        if self.artifact_type not in SUPPORTED_ARTIFACTS:
            raise ValueError(f"unsupported artifact type: {self.artifact_type!r}")
        if self.timestamp_utc is not None:
            if self.timestamp_utc.tzinfo is None:
                raise ValueError("timeline timestamps must be timezone-aware")
            object.__setattr__(
                self,
                "timestamp_utc",
                self.timestamp_utc.astimezone(timezone.utc),
            )

    def to_dict(self) -> dict[str, Any]:
        timestamp = (
            self.timestamp_utc.isoformat().replace("+00:00", "Z")
            if self.timestamp_utc is not None
            else None
        )
        return {
            "timestamp_utc": timestamp,
            "timestamp_original": self.timestamp_original,
            "timestamp_kind": self.timestamp_kind,
            "timestamp_field": self.timestamp_field,
            "timezone_assumed": self.timezone_assumed,
            "artifact_type": self.artifact_type,
            "event_kind": self.event_kind,
            "source_tool": self.source_tool,
            "source_file": self.source_file,
            "record_id": self.record_id,
            "summary": self.summary,
            "attributes": dict(self.attributes),
            "attributes_truncated": self.attributes_truncated,
        }


@dataclass(frozen=True)
class TimelineBenchmark:
    rows: int
    events: int
    elapsed_ms: float
    peak_python_bytes: int
    serialized_chars: int
    estimated_tokens: int

    def to_dict(self) -> dict[str, int | float]:
        return {
            "rows": self.rows,
            "events": self.events,
            "elapsed_ms": self.elapsed_ms,
            "peak_python_bytes": self.peak_python_bytes,
            "serialized_chars": self.serialized_chars,
            "estimated_tokens": self.estimated_tokens,
        }


def _canonical(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").casefold())


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _index(row: Mapping[str, Any]) -> dict[str, tuple[str, Any]]:
    indexed: dict[str, tuple[str, Any]] = {}

    def walk(value: Mapping[str, Any], prefix: str = "") -> None:
        for raw_key, child in value.items():
            key = _canonical(raw_key)
            if not key:
                continue
            qualified = f"{prefix}{key}" if prefix else key
            if isinstance(child, Mapping):
                walk(child, qualified)
                continue
            indexed.setdefault(key, (str(raw_key), child))
            indexed.setdefault(qualified, (str(raw_key), child))

    walk(row)
    return indexed


def _value(
    indexed: Mapping[str, tuple[str, Any]], *aliases: str
) -> tuple[str, Any]:
    for alias in aliases:
        suffix = _canonical(alias)
        hit = indexed.get(suffix)
        if hit is not None and _text(hit[1]):
            return hit
        if suffix.startswith("eventsystem"):
            matches = [
                (key, hit)
                for key, hit in indexed.items()
                if key.endswith(suffix) and _text(hit[1])
            ]
            if matches:
                return min(matches, key=lambda item: len(item[0]))[1]
    return "", ""


def _normalize_artifact_type(value: str | None) -> str | None:
    key = _canonical(value)
    if not key:
        return None
    aliases = {
        "windowseventlog": "evtx",
        "eventlog": "evtx",
        "evtxlog": "evtx",
        "appcompatcache": "shimcache",
        "registryhive": "registry",
    }
    kind = aliases.get(key, key)
    return kind if kind in SUPPORTED_ARTIFACTS else None


def detect_artifact_type(
    headers: Iterable[str], *, tool_id: str = ""
) -> str | None:
    """Choose an adapter from a known tool or a deterministic header signature."""
    keys = {_canonical(header) for header in headers}
    tool_key = _canonical(tool_id)

    # AppCompatCacheParser is a specialized SYSTEM-hive parser.  It must win
    # over the generic registry classification.
    if "appcompatcache" in tool_key or "shimcache" in tool_key:
        return "shimcache"
    tool_kind = _TOOL_ARTIFACTS.get(tool_key)
    if tool_kind and tool_kind != "registry":
        return tool_kind

    if (
        "lastmodifiedtimeutc" in keys
        and "path" in keys
        and keys.intersection({"entryposition", "executed", "sourcefile"})
    ):
        return "shimcache"
    if "filekeylastwritetimestamp" in keys or (
        "sha1" in keys
        and keys.intersection({"applicationname", "programname", "fullpath"})
    ):
        return "amcache"
    if keys.intersection({"lastrun", "lastruntime"}) and keys.intersection(
        {"executablename", "executable", "sourcefilename", "runcount"}
    ):
        return "prefetch"
    if "eventid" in keys and keys.intersection(
        {"timecreated", "systemtime", "timestamp", "eventtime"}
    ):
        return "evtx"
    if keys.intersection(
        {"lastwritetimestamp", "keylastwritetimestamp", "lastwritetime"}
    ) and keys.intersection({"keypath", "path", "valuename", "hivepath"}):
        return "registry"
    return tool_kind


def _row_artifact_type(
    row: Mapping[str, Any],
    indexed: Mapping[str, tuple[str, Any]],
    *,
    tool_id: str,
) -> str | None:
    detected = detect_artifact_type(indexed.keys(), tool_id=tool_id)
    if detected != "registry":
        return detected

    # RECmd may produce decoded AppCompatCache rows.  Relabel only when both a
    # marker and entry-shaped columns exist; a raw registry value whose key is
    # named AppCompatCache must remain a registry event.
    marker = " ".join(
        _text(_value(indexed, alias)[1]).casefold()
        for alias in ("artifact", "category", "parser", "description", "keypath")
    )
    if (
        ("appcompatcache" in marker or "shimcache" in marker)
        and "lastmodifiedtimeutc" in indexed
        and set(indexed).intersection({"entryposition", "executed", "path"})
    ):
        return "shimcache"
    return detected


def _bounded_attributes(row: Mapping[str, Any]) -> tuple[dict[str, Any], bool]:
    out: dict[str, Any] = {}
    used = 0
    truncated = False
    for position, (raw_key, value) in enumerate(row.items()):
        if position >= MAX_ATTRIBUTE_FIELDS:
            truncated = True
            break
        key = str(raw_key)[:128]
        if isinstance(value, (str, int, float, bool)) or value is None:
            rendered = "" if value is None else str(value)
        else:
            try:
                rendered = json.dumps(
                    value, ensure_ascii=False, sort_keys=True, default=str
                )
            except (TypeError, ValueError):
                rendered = str(value)
        if len(rendered) > MAX_ATTRIBUTE_VALUE_CHARS:
            rendered = rendered[:MAX_ATTRIBUTE_VALUE_CHARS]
            truncated = True
        remaining = MAX_ATTRIBUTE_TOTAL_CHARS - used - len(key)
        if remaining <= 0:
            truncated = True
            break
        if len(rendered) > remaining:
            rendered = rendered[:remaining]
            truncated = True
        out[key] = rendered
        used += len(key) + len(rendered)
    return out, truncated


def _source_file(
    indexed: Mapping[str, tuple[str, Any]], explicit: str
) -> str:
    if explicit:
        return explicit
    return _text(
        _value(indexed, "SourceFile", "SourceFilename", "EvidenceFile")[1]
    )


def _record_id(indexed: Mapping[str, tuple[str, Any]]) -> str:
    return _text(
        _value(
            indexed,
            "EventRecordId",
            "RecordNumber",
            "RecordId",
            "EntryPosition",
            "EntryNumber",
        )[1]
    )


def _event(
    row: Mapping[str, Any],
    indexed: Mapping[str, tuple[str, Any]],
    *,
    timestamp_field: str,
    timestamp_value: Any,
    timestamp_kind: str,
    artifact_type: str,
    event_kind: str,
    source_tool: str,
    source_file: str,
    summary: str,
) -> TimelineEvent:
    attributes, attributes_truncated = _bounded_attributes(row)
    original = _text(timestamp_value)
    return TimelineEvent(
        timestamp_utc=(
            parse_timestamp(
                timestamp_value,
                numeric_unit=(
                    "filetime"
                    if "filetime" in _canonical(timestamp_field)
                    else "auto"
                ),
            )
            if original
            else None
        ),
        timestamp_original=original[:MAX_TIMESTAMP_CHARS],
        timestamp_kind=timestamp_kind,
        timestamp_field=_text(timestamp_field)[:128],
        artifact_type=artifact_type,
        event_kind=event_kind,
        timezone_assumed=(
            timestamp_timezone_assumed(timestamp_value) if original else False
        ),
        source_tool=_text(source_tool)[:128],
        source_file=_source_file(indexed, source_file)[:MAX_IDENTITY_CHARS],
        record_id=_record_id(indexed)[:256],
        summary=_text(summary)[:MAX_SUMMARY_CHARS],
        attributes=attributes,
        attributes_truncated=attributes_truncated,
    )


def _evtx_events(
    row: Mapping[str, Any],
    indexed: Mapping[str, tuple[str, Any]],
    *,
    tool_id: str,
    source_file: str,
) -> Iterator[TimelineEvent]:
    field_name, value = _value(
        indexed,
        "EventSystemTimeCreatedAttributesSystemTime",
        "EventSystemTimeCreatedSystemTime",
        "EventSystemTimeCreated",
        "TimeCreated",
        "TimeCreatedSystemTime",
        "SystemTime",
        "Timestamp",
        "EventTime",
        "DateTime",
    )
    event_id = _text(
        _value(indexed, "EventSystemEventId", "EventId", "Id")[1]
    ) or "unknown"
    channel = _text(
        _value(indexed, "EventSystemChannel", "Channel", "LogName")[1]
    )
    label = f"{channel} event {event_id}" if channel else f"EVTX event {event_id}"
    yield _event(
        row,
        indexed,
        timestamp_field=field_name,
        timestamp_value=value,
        timestamp_kind="event_recorded",
        artifact_type="evtx",
        event_kind="event_log_record",
        source_tool=tool_id,
        source_file=source_file,
        summary=label,
    )


def _prefetch_events(
    row: Mapping[str, Any],
    indexed: Mapping[str, tuple[str, Any]],
    *,
    tool_id: str,
    source_file: str,
) -> Iterator[TimelineEvent]:
    timestamps: list[tuple[int, int, str, Any, str]] = []
    for canonical, (field_name, value) in indexed.items():
        if canonical in {"lastrun", "lastruntime"}:
            timestamps.append((0, 0, field_name, value, "prefetch_last_run"))
            continue
        match = re.fullmatch(r"previousrun(?:time)?(\d+)", canonical)
        if match:
            timestamps.append(
                (1, int(match.group(1)), field_name, value, "prefetch_previous_run")
            )
    timestamps.sort(key=lambda item: (item[0], item[1], item[2].casefold()))
    timestamps = timestamps[:MAX_PREFETCH_RUN_TIMESTAMPS]
    executable = _text(
        _value(indexed, "ExecutableName", "Executable", "ProgramName")[1]
    ) or "unknown executable"
    seen: set[datetime] = set()
    emitted = False
    first_invalid: tuple[str, Any, str] | None = None
    for _, _, field_name, value, timestamp_kind in timestamps:
        original = _text(value)
        parsed = parse_timestamp(value) if original else None
        if parsed is None:
            if original and first_invalid is None:
                first_invalid = (field_name, value, timestamp_kind)
            continue
        if parsed in seen:
            continue
        seen.add(parsed)
        emitted = True
        yield _event(
            row,
            indexed,
            timestamp_field=field_name,
            timestamp_value=value,
            timestamp_kind=timestamp_kind,
            artifact_type="prefetch",
            event_kind="prefetch_execution_evidence",
            source_tool=tool_id,
            source_file=source_file,
            summary=f"Prefetch execution evidence: {executable}",
        )
    if not emitted:
        field_name, value, timestamp_kind = first_invalid or (
            "",
            "",
            "prefetch_run_time",
        )
        yield _event(
            row,
            indexed,
            timestamp_field=field_name,
            timestamp_value=value,
            timestamp_kind=timestamp_kind,
            artifact_type="prefetch",
            event_kind="prefetch_execution_evidence",
            source_tool=tool_id,
            source_file=source_file,
            summary=f"Prefetch execution evidence: {executable}",
        )


def _amcache_events(
    row: Mapping[str, Any],
    indexed: Mapping[str, tuple[str, Any]],
    *,
    tool_id: str,
    source_file: str,
) -> Iterator[TimelineEvent]:
    field_name, value = _value(
        indexed,
        "FileKeyLastWriteTimestamp",
        "KeyLastWriteTimestamp",
        "LastWriteTimestamp",
        "LastModifiedTimeUTC",
    )
    path = _text(
        _value(indexed, "FullPath", "Path", "ApplicationName", "ProgramName")[1]
    ) or "unknown entry"
    timestamp_kind = (
        "registry_key_last_write"
        if "keylastwrite" in _canonical(field_name)
        else "file_last_modified"
    )
    yield _event(
        row,
        indexed,
        timestamp_field=field_name,
        timestamp_value=value,
        timestamp_kind=timestamp_kind,
        artifact_type="amcache",
        event_kind="amcache_entry_observed",
        source_tool=tool_id,
        source_file=source_file,
        summary=f"Amcache entry observed: {path}",
    )


def _shimcache_events(
    row: Mapping[str, Any],
    indexed: Mapping[str, tuple[str, Any]],
    *,
    tool_id: str,
    source_file: str,
) -> Iterator[TimelineEvent]:
    field_name, value = _value(
        indexed,
        "LastModifiedTimeUTC",
        "LastModifiedTime",
        "FileLastModifiedTime",
        "Timestamp",
    )
    path = _text(_value(indexed, "Path", "FullPath", "FilePath")[1]) or "unknown entry"
    timestamp_kind = (
        "file_last_modified"
        if "lastmodified" in _canonical(field_name)
        else "shimcache_timestamp_observed"
    )
    yield _event(
        row,
        indexed,
        timestamp_field=field_name,
        timestamp_value=value,
        timestamp_kind=timestamp_kind,
        artifact_type="shimcache",
        event_kind="shimcache_entry_observed",
        source_tool=tool_id,
        source_file=source_file,
        summary=f"Shimcache entry observed: {path}",
    )


def _registry_events(
    row: Mapping[str, Any],
    indexed: Mapping[str, tuple[str, Any]],
    *,
    tool_id: str,
    source_file: str,
) -> Iterator[TimelineEvent]:
    field_name, value = _value(
        indexed,
        "LastWriteTimestamp",
        "KeyLastWriteTimestamp",
        "LastWriteTime",
        "Timestamp",
    )
    key_path = _text(_value(indexed, "KeyPath", "HivePath", "Path")[1]) or "unknown key"
    timestamp_kind = (
        "registry_key_last_write"
        if "lastwrite" in _canonical(field_name)
        else "registry_timestamp_observed"
    )
    yield _event(
        row,
        indexed,
        timestamp_field=field_name,
        timestamp_value=value,
        timestamp_kind=timestamp_kind,
        artifact_type="registry",
        event_kind="registry_key_observed",
        source_tool=tool_id,
        source_file=source_file,
        summary=f"Registry key observed: {key_path}",
    )


_ADAPTERS = {
    "evtx": _evtx_events,
    "prefetch": _prefetch_events,
    "amcache": _amcache_events,
    "shimcache": _shimcache_events,
    "registry": _registry_events,
}


def iter_timeline_events(
    rows: Iterable[Mapping[str, Any]],
    *,
    tool_id: str = "",
    artifact_type: str | None = None,
    source_file: str = "",
) -> Iterator[TimelineEvent]:
    """Stream normalized events, selecting adapters by type, tool, or headers."""
    explicit_type = _normalize_artifact_type(artifact_type)
    if artifact_type and explicit_type is None:
        raise ValueError(f"unsupported artifact type: {artifact_type!r}")
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        indexed = _index(row)
        kind = explicit_type or _row_artifact_type(row, indexed, tool_id=tool_id)
        adapter = _ADAPTERS.get(kind or "")
        if adapter is None:
            continue
        yield from adapter(
            row,
            indexed,
            tool_id=tool_id,
            source_file=source_file,
        )


def filter_timeline(
    events: Iterable[TimelineEvent],
    scope: TimeScope,
    *,
    include_undated: bool = False,
) -> Iterator[TimelineEvent]:
    """Stream events inside an inclusive time range."""
    for event in events:
        if event.timestamp_utc is None:
            if include_undated:
                yield event
            continue
        if scope.contains(event.timestamp_utc):
            yield event


def sort_timeline(
    events: Iterable[TimelineEvent],
    *,
    max_events: int = DEFAULT_MAX_SORT_EVENTS,
) -> list[TimelineEvent]:
    """Return chronological events, placing undated records last.

    Sorting necessarily materializes the input, so it fails closed at
    ``max_events``.  Streaming callers should use ``iter_timeline_events`` and
    ``filter_timeline`` directly.
    """
    if max_events < 1:
        raise ValueError("max_events must be positive")
    buffered: list[TimelineEvent] = []
    for event in events:
        if len(buffered) >= max_events:
            raise TimelineLimitError(
                f"timeline exceeds the {max_events}-event sort limit"
            )
        buffered.append(event)
    ceiling = datetime.max.replace(tzinfo=timezone.utc)
    return sorted(
        buffered,
        key=lambda event: (
            event.timestamp_utc is None,
            event.timestamp_utc or ceiling,
            event.artifact_type,
            event.source_file.casefold(),
            event.record_id,
        ),
    )


def benchmark_timeline(
    rows: Iterable[Mapping[str, Any]],
    *,
    tool_id: str = "",
    artifact_type: str | None = None,
    source_file: str = "",
    max_rows: int = 1_000_000,
) -> TimelineBenchmark:
    """Explicitly benchmark streaming normalization with Python allocations.

    Token count is a transparent four-characters-per-token estimate; it is not
    presented as a model tokenizer result.
    """
    if max_rows < 1:
        raise ValueError("max_rows must be positive")

    # Local imports keep normal parsing free of tracing machinery.
    import tracemalloc
    from time import perf_counter

    rows_seen = 0

    def counted_rows() -> Iterator[Mapping[str, Any]]:
        nonlocal rows_seen
        for row in rows:
            if rows_seen >= max_rows:
                raise TimelineLimitError(
                    f"benchmark exceeds the {max_rows}-row limit"
                )
            rows_seen += 1
            yield row

    tracing_was_active = tracemalloc.is_tracing()
    started_tracing = not tracing_was_active
    if started_tracing:
        tracemalloc.start()
    baseline_current, _ = tracemalloc.get_traced_memory()
    observed_current_delta = 0
    started = perf_counter()
    events = 0
    serialized_chars = 0
    try:
        for event in iter_timeline_events(
            counted_rows(),
            tool_id=tool_id,
            artifact_type=artifact_type,
            source_file=source_file,
        ):
            events += 1
            serialized_chars += len(
                json.dumps(
                    event.to_dict(),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    default=str,
                )
            )
            if tracing_was_active:
                current, _ = tracemalloc.get_traced_memory()
                observed_current_delta = max(
                    observed_current_delta,
                    current - baseline_current,
                )
        elapsed_ms = (perf_counter() - started) * 1_000
        current, peak = tracemalloc.get_traced_memory()
        peak_python_bytes = (
            max(0, peak - baseline_current, current - baseline_current)
            if started_tracing
            else max(0, observed_current_delta, current - baseline_current)
        )
    finally:
        if started_tracing:
            tracemalloc.stop()

    return TimelineBenchmark(
        rows=rows_seen,
        events=events,
        elapsed_ms=elapsed_ms,
        peak_python_bytes=peak_python_bytes,
        serialized_chars=serialized_chars,
        estimated_tokens=(serialized_chars + 3) // 4,
    )


__all__ = [
    "DEFAULT_MAX_SORT_EVENTS",
    "SUPPORTED_ARTIFACTS",
    "TimelineBenchmark",
    "TimelineEvent",
    "TimelineLimitError",
    "benchmark_timeline",
    "detect_artifact_type",
    "filter_timeline",
    "iter_timeline_events",
    "sort_timeline",
]
