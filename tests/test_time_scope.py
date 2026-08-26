from __future__ import annotations

from datetime import datetime, timedelta, timezone

from hypothesis import given, settings, strategies as st

from forensicagent.analyzer.time_scope import (
    TimeScope,
    extract_time_scope,
    filter_rows,
    parse_timestamp,
    row_timestamp,
    row_timestamps,
)


_FIXED_TIMEZONES = st.integers(min_value=-14 * 60, max_value=14 * 60).map(
    lambda minutes: timezone(timedelta(minutes=minutes))
)


@given(
    st.datetimes(
        min_value=datetime(1970, 1, 2),
        max_value=datetime(2099, 12, 30),
        timezones=_FIXED_TIMEZONES,
    )
)
@settings(max_examples=100, deadline=None)
def test_iso_timestamp_normalization_preserves_the_instant(value: datetime):
    parsed = parse_timestamp(value.isoformat())

    assert parsed == value.astimezone(timezone.utc)


@given(st.lists(st.integers(min_value=-1_000, max_value=1_000), max_size=100))
@settings(max_examples=100, deadline=None)
def test_time_scope_filter_is_inclusive_and_excludes_undated_rows(offsets):
    center = datetime(2025, 1, 1, tzinfo=timezone.utc)
    scope = TimeScope(
        center - timedelta(seconds=100),
        center + timedelta(seconds=100),
        source="test",
    )
    rows = [
        {"TimeCreated": (center + timedelta(seconds=offset)).isoformat(), "id": index}
        for index, offset in enumerate(offsets)
    ] + [{"id": "undated"}]

    selected = list(filter_rows(rows, scope))

    assert [row["id"] for row in selected] == [
        index for index, offset in enumerate(offsets) if -100 <= offset <= 100
    ]


def test_scenario_range_and_korean_padding_are_deterministic():
    scope = extract_time_scope(
        "2025년 1월 2일 10시부터 2025년 1월 2일 12시까지 전후 6시간"
    )

    assert scope is not None
    assert scope.start_utc == datetime(2025, 1, 2, 4, tzinfo=timezone.utc)
    assert scope.end_utc == datetime(2025, 1, 2, 18, tzinfo=timezone.utc)
    assert scope.padding_hours == 6
    assert scope.timezone_assumed is True


def test_numeric_timestamp_normalizes_filetime_and_unix_units():
    expected = datetime(2025, 1, 1, tzinfo=timezone.utc)
    unix_seconds = expected.timestamp()
    filetime = int((unix_seconds + 11_644_473_600) * 10_000_000)

    assert parse_timestamp(filetime) == expected
    assert parse_timestamp(int(unix_seconds * 1_000)) == expected
    assert parse_timestamp(int(unix_seconds * 1_000_000)) == expected
    assert parse_timestamp(int(unix_seconds * 1_000_000_000)) == expected


def test_explicit_numeric_unit_resolves_ambiguous_early_epoch_values():
    expected = datetime(1975, 1, 1, tzinfo=timezone.utc)
    seconds = int(expected.timestamp())

    assert parse_timestamp(seconds * 1_000_000_000, numeric_unit="unix_ns") == expected
    assert parse_timestamp(0, numeric_unit="unix_ms") == datetime(
        1970, 1, 1, tzinfo=timezone.utc
    )


def test_pre_2001_unix_units_are_not_shifted_by_decimal_thresholds():
    expected = datetime(2000, 1, 1, tzinfo=timezone.utc)
    seconds = int(expected.timestamp())

    assert parse_timestamp(seconds * 1_000) == expected
    assert parse_timestamp(seconds * 1_000_000) == expected
    assert parse_timestamp(seconds * 1_000_000_000) == expected


def test_1971_unix_units_use_the_expected_scale():
    expected = datetime(1971, 1, 1, tzinfo=timezone.utc)
    seconds = int(expected.timestamp())

    assert parse_timestamp(seconds * 1_000) == expected
    assert parse_timestamp(seconds * 1_000_000) == expected
    assert parse_timestamp(seconds * 1_000_000_000) == expected


def test_integer_filetime_preserves_microseconds_without_float_rounding():
    expected = datetime(2025, 1, 1, 12, 34, 56, 123456, tzinfo=timezone.utc)
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    delta = expected - epoch
    filetime = (
        (delta.days * 86_400 + delta.seconds) * 10_000_000
        + delta.microseconds * 10
    )

    assert parse_timestamp(str(filetime)) == expected
    assert parse_timestamp(f"{filetime}.0") == expected


def test_more_than_two_scenario_timestamps_is_not_guessed():
    assert extract_time_scope("2025-01-01, 2025-01-02, 2025-01-03") is None


def test_two_unconnected_scenario_timestamps_are_not_guessed_as_a_range():
    assert extract_time_scope("compare 2025-01-01 and event 2025-01-02") is None


def test_explicit_kst_scenario_is_converted_to_utc():
    scope = extract_time_scope("2025년 1월 2일 10시 전후 1시간 KST")

    assert scope is not None
    assert scope.start_utc == datetime(2025, 1, 2, 0, tzinfo=timezone.utc)
    assert scope.end_utc == datetime(2025, 1, 2, 2, tzinfo=timezone.utc)
    assert scope.timezone_assumed is False


def test_nested_timestamp_uses_fixed_priority_over_other_time_fields():
    row = {
        "Event": {"System": {"TimeCreated": "2025-01-01T01:00:00Z"}},
        "LastRun": "2025-01-02T01:00:00Z",
    }

    assert row_timestamp(row) == datetime(2025, 1, 1, 1, tzinfo=timezone.utc)
    assert row_timestamp(
        {"Event.System.TimeCreated": "2025-01-03T01:00:00Z"}
    ) == datetime(2025, 1, 3, 1, tzinfo=timezone.utc)


def test_system_timecreated_wins_over_nested_payload_timestamp():
    row = {
        "Event": {
            "System": {"TimeCreated": "2025-01-01T01:00:00Z"},
            "EventData": {"Timestamp": "2025-01-02T01:00:00Z"},
        }
    }

    assert row_timestamp(row) == datetime(2025, 1, 1, 1, tzinfo=timezone.utc)


def test_payload_systemtime_cannot_override_nested_event_time_by_key_order():
    row = {
        "Event": {
            "EventData": {"SystemTime": "2030-01-01T00:00:00Z"},
            "System": {
                "TimeCreated": {"SystemTime": "2025-01-01T01:00:00Z"}
            },
        }
    }

    assert row_timestamps(row) == (
        datetime(2025, 1, 1, 1, tzinfo=timezone.utc),
    )


def test_chainsaw_timecreated_attributes_wins_inside_wrappers():
    row = {
        "document": {
            "data": {
                "Event": {
                    "EventData": {"SystemTime": "2030-01-01T00:00:00Z"},
                    "System": {
                        "TimeCreated_attributes": {
                            "SystemTime": "2025-01-01T01:00:00Z"
                        }
                    },
                }
            }
        }
    }

    assert row_timestamps(row) == (
        datetime(2025, 1, 1, 1, tzinfo=timezone.utc),
    )


def test_prefetch_scope_accepts_any_previous_run_timestamp():
    row = {
        "ExecutableName": "APP.EXE",
        "LastRun": "2025-02-01T00:00:00Z",
        "PreviousRun0": "2025-01-01T12:00:00Z",
    }
    scope = TimeScope(
        datetime(2025, 1, 1, tzinfo=timezone.utc),
        datetime(2025, 1, 2, tzinfo=timezone.utc),
        source="test",
    )

    assert len(row_timestamps(row)) == 2
    assert list(filter_rows([row], scope)) == [row]
