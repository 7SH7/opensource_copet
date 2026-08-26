from __future__ import annotations

import tracemalloc
from datetime import datetime, timezone

import pytest

from forensicagent.analyzer.time_scope import TimeScope
from forensicagent.analyzer.timeline import (
    MAX_ATTRIBUTE_TOTAL_CHARS,
    MAX_PREFETCH_RUN_TIMESTAMPS,
    MAX_SUMMARY_CHARS,
    TimelineEvent,
    TimelineLimitError,
    benchmark_timeline,
    detect_artifact_type,
    filter_timeline,
    iter_timeline_events,
    sort_timeline,
)


def test_evtx_tool_adapter_normalizes_to_utc_and_preserves_semantics():
    events = list(
        iter_timeline_events(
            [
                {
                    "TimeCreated": "2025-01-02T09:30:00+09:00",
                    "EventId": "4624",
                    "Channel": "Security",
                    "Provider": "Microsoft-Windows-Security-Auditing",
                }
            ],
            tool_id="EvtxECmd",
            source_file="Security.evtx",
        )
    )

    assert len(events) == 1
    event = events[0]
    assert event.timestamp_utc == datetime(2025, 1, 2, 0, 30, tzinfo=timezone.utc)
    assert event.timestamp_kind == "event_recorded"
    assert event.event_kind == "event_log_record"
    assert event.source_file == "Security.evtx"
    assert event.to_dict()["timestamp_utc"] == "2025-01-02T00:30:00Z"


def test_nested_chainsaw_event_is_normalized_without_an_llm():
    event = next(
        iter_timeline_events(
            [
                {
                    "Event": {
                        "System": {
                            "TimeCreated": {"SystemTime": "2025-01-02T00:30:00Z"},
                            "EventID": 1102,
                            "Channel": "Security",
                        }
                    }
                }
            ],
            tool_id="chainsaw",
            source_file="Security.evtx",
        )
    )

    assert event.timestamp_utc == datetime(2025, 1, 2, 0, 30, tzinfo=timezone.utc)
    assert event.summary == "Security event 1102"


def test_nested_payload_systemtime_cannot_override_event_time():
    event = next(
        iter_timeline_events(
            [
                {
                    "Event": {
                        "EventData": {"SystemTime": "2030-01-01T00:00:00Z"},
                        "System": {
                            "TimeCreated": {
                                "SystemTime": "2025-01-02T00:30:00Z"
                            },
                            "EventID": 1102,
                            "Channel": "Security",
                        },
                    }
                }
            ],
            tool_id="chainsaw",
        )
    )

    assert event.timestamp_utc == datetime(2025, 1, 2, 0, 30, tzinfo=timezone.utc)


def test_wrapped_chainsaw_attributes_shape_detects_without_tool_hint():
    event = next(
        iter_timeline_events(
            [
                {
                    "document": {
                        "data": {
                            "Event": {
                                "EventData": {
                                    "SystemTime": "2030-01-01T00:00:00Z"
                                },
                                "System": {
                                    "TimeCreated_attributes": {
                                        "SystemTime": "2025-01-02T00:30:00Z"
                                    },
                                    "EventID": 1102,
                                    "Channel": "Security",
                                },
                            }
                        }
                    }
                }
            ]
        )
    )

    assert event.timestamp_utc == datetime(2025, 1, 2, 0, 30, tzinfo=timezone.utc)
    assert event.summary == "Security event 1102"


def test_prefetch_explodes_previous_runs_and_deduplicates_instants():
    events = list(
        iter_timeline_events(
            [
                {
                    "ExecutableName": "EVIL.EXE",
                    "LastRun": "2025-01-03T03:00:00Z",
                    "PreviousRun0": "2025-01-03T03:00:00+00:00",
                    "PreviousRun1": "2025-01-01T01:00:00Z",
                    "PreviousRun2": "",
                }
            ],
            tool_id="PECmd",
        )
    )

    assert len(events) == 2
    assert [event.timestamp_kind for event in events] == [
        "prefetch_last_run",
        "prefetch_previous_run",
    ]
    assert all(event.event_kind == "prefetch_execution_evidence" for event in events)
    assert "EVIL.EXE" in events[0].summary


def test_amcache_and_shimcache_never_claim_execution():
    amcache = next(
        iter_timeline_events(
            [
                {
                    "FileKeyLastWriteTimestamp": "2025-01-01T00:00:00Z",
                    "FullPath": r"C:\Users\alice\Downloads\sample.exe",
                    "SHA1": "abc",
                }
            ],
            tool_id="AmcacheParser",
        )
    )
    shimcache = next(
        iter_timeline_events(
            [
                {
                    "LastModifiedTimeUTC": "2025-01-02T00:00:00Z",
                    "Path": r"C:\Temp\sample.exe",
                    "EntryPosition": 7,
                    "Executed": True,
                }
            ],
            tool_id="AppCompatCacheParser",
        )
    )

    assert amcache.timestamp_kind == "registry_key_last_write"
    assert amcache.event_kind == "amcache_entry_observed"
    assert "execut" not in amcache.summary.casefold()
    assert shimcache.timestamp_kind == "file_last_modified"
    assert shimcache.event_kind == "shimcache_entry_observed"
    assert "execut" not in shimcache.summary.casefold()


def test_amcache_generic_last_modified_is_not_called_a_registry_write():
    event = next(
        iter_timeline_events(
            [
                {
                    "LastModifiedTimeUTC": "2025-01-01T00:00:00Z",
                    "FullPath": r"C:\Temp\sample.exe",
                    "SHA1": "abc",
                }
            ],
            tool_id="AmcacheParser",
        )
    )

    assert event.timestamp_kind == "file_last_modified"


def test_header_detection_and_recmm_shimcache_override_are_deterministic():
    assert (
        detect_artifact_type(
            ["LastWriteTimestamp", "KeyPath", "ValueName"], tool_id="unknown"
        )
        == "registry"
    )
    row = {
        "Category": "Decoded AppCompatCache",
        "LastModifiedTimeUTC": "2025-01-02T00:00:00Z",
        "Path": r"C:\Temp\decoded.exe",
        "EntryPosition": 2,
    }
    event = next(iter_timeline_events([row], tool_id="RECmd"))

    assert event.artifact_type == "shimcache"
    assert event.timestamp_kind == "file_last_modified"


def test_public_artifact_type_accepts_scanner_evtx_alias():
    event = next(
        iter_timeline_events(
            [{"TimeCreated": "2025-01-01T00:00:00Z", "EventId": 1}],
            artifact_type="evtx_log",
        )
    )

    assert event.artifact_type == "evtx"


def test_registry_header_adapter_and_undated_filter_policy():
    events = list(
        iter_timeline_events(
            [
                {
                    "LastWriteTimestamp": "2025-01-01T10:00:00Z",
                    "KeyPath": r"HKLM\Software\Example",
                },
                {"LastWriteTimestamp": "bad", "KeyPath": r"HKLM\Bad"},
            ]
        )
    )
    scope = TimeScope(
        datetime(2025, 1, 1, 10, tzinfo=timezone.utc),
        datetime(2025, 1, 1, 10, tzinfo=timezone.utc),
        source="test",
    )

    assert len(events) == 2
    assert list(filter_timeline(events, scope)) == [events[0]]
    assert list(filter_timeline(events, scope, include_undated=True)) == events


def test_sort_is_chronological_bounded_and_puts_undated_last():
    events = [
        TimelineEvent(
            timestamp_utc=datetime(2025, 1, 2, tzinfo=timezone.utc),
            timestamp_original="2025-01-02T00:00:00Z",
            timestamp_kind="event_recorded",
            timestamp_field="Timestamp",
            artifact_type="evtx",
            event_kind="event_log_record",
        ),
        TimelineEvent(
            timestamp_utc=None,
            timestamp_original="bad",
            timestamp_kind="registry_key_last_write",
            timestamp_field="LastWriteTimestamp",
            artifact_type="registry",
            event_kind="registry_key_observed",
        ),
        TimelineEvent(
            timestamp_utc=datetime(2025, 1, 1, tzinfo=timezone.utc),
            timestamp_original="2025-01-01T00:00:00Z",
            timestamp_kind="event_recorded",
            timestamp_field="Timestamp",
            artifact_type="evtx",
            event_kind="event_log_record",
        ),
    ]

    assert sort_timeline(events) == [events[2], events[0], events[1]]
    with pytest.raises(TimelineLimitError, match="2-event"):
        sort_timeline(events, max_events=2)


def test_attributes_are_bounded_without_dropping_event_identity():
    event = next(
        iter_timeline_events(
            [
                {
                    "TimeCreated": "2025-01-01T00:00:00Z",
                    "EventId": 1,
                    "Payload": "x" * 20_000,
                }
            ],
            tool_id="EvtxECmd",
        )
    )

    assert event.attributes_truncated is True
    assert len(event.attributes["Payload"]) == 4_096
    assert event.timestamp_utc is not None
    assert (
        sum(len(key) + len(value) for key, value in event.attributes.items())
        <= MAX_ATTRIBUTE_TOTAL_CHARS
    )


def test_identity_fields_and_prefetch_event_fanout_are_bounded():
    row = {
        "ExecutableName": "A" * 100_000,
        "LastRun": "2025-01-10T00:00:00Z",
        **{
            f"PreviousRun{index}": f"2025-01-{index + 1:02d}T00:00:00Z"
            for index in range(100)
        },
    }

    events = list(iter_timeline_events([row], tool_id="PECmd"))

    assert len(events) == MAX_PREFETCH_RUN_TIMESTAMPS
    assert all(len(event.summary) <= MAX_SUMMARY_CHARS for event in events)


def test_naive_artifact_timestamp_is_marked_as_assumed_utc():
    event = next(
        iter_timeline_events(
            [{"TimeCreated": "2025-01-01 10:00:00", "EventId": 1}],
            tool_id="EvtxECmd",
        )
    )

    assert event.timezone_assumed is True
    assert event.to_dict()["timezone_assumed"] is True


def test_benchmark_is_explicit_streaming_and_reports_memory_and_token_estimate():
    assert tracemalloc.is_tracing() is False
    result = benchmark_timeline(
        (
            {
                "ExecutableName": f"APP{index}.EXE",
                "LastRun": f"2025-01-01T00:00:{index:02d}Z",
            }
            for index in range(3)
        ),
        tool_id="PECmd",
    )

    assert result.rows == 3
    assert result.events == 3
    assert result.elapsed_ms >= 0
    assert result.peak_python_bytes > 0
    assert result.serialized_chars > 0
    assert result.estimated_tokens == (result.serialized_chars + 3) // 4
    assert tracemalloc.is_tracing() is False


def test_benchmark_row_bound_fails_closed():
    with pytest.raises(TimelineLimitError, match="1-row"):
        benchmark_timeline(
            [
                {"LastRun": "2025-01-01T00:00:00Z", "ExecutableName": "A.EXE"},
                {"LastRun": "2025-01-02T00:00:00Z", "ExecutableName": "B.EXE"},
            ],
            tool_id="PECmd",
            max_rows=1,
        )


def test_benchmark_ignores_a_preexisting_tracemalloc_peak():
    tracemalloc.start()
    try:
        prior = bytearray(2_000_000)
        del prior
        result = benchmark_timeline(
            [{"LastRun": "2025-01-01T00:00:00Z", "ExecutableName": "A.EXE"}],
            tool_id="PECmd",
        )
    finally:
        tracemalloc.stop()

    assert 0 < result.peak_python_bytes < 1_000_000
