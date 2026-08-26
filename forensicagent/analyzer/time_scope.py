"""Deterministic UTC time-window extraction for structured tool output."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from math import isfinite
from typing import Any, Iterable, Iterator

_ISO_DATE_RE = re.compile(
    r"(?<!\d)(\d{4}[-/.]\d{1,2}[-/.]\d{1,2}"
    r"(?:[T\s]\d{1,2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?"
    r"(?:Z|[+-]\d{2}:?\d{2})?)?)(?!\d)"
)
_KOREAN_DATE_RE = re.compile(
    r"(?<!\d)(\d{4})\s*\ub144\s*(\d{1,2})\s*\uc6d4\s*"
    r"(\d{1,2})\s*\uc77c(?:\s*(\d{1,2})\s*\uc2dc"
    r"(?:\s*(\d{1,2})\s*\ubd84)?(?:\s*(\d{1,2})\s*\ucd08)?)?"
)
_PADDING_RES = (
    re.compile(
        r"(?:\u00b1|\+/-|\+-)\s*(\d+(?:\.\d+)?)\s*"
        r"(?:hours?|hrs?|h|\uc2dc\uac04)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:\uc804\ud6c4|\uc55e\ub4a4(?:\ub85c)?)\s*"
        r"(\d+(?:\.\d+)?)\s*\uc2dc\uac04"
    ),
    re.compile(
        r"(\d+(?:\.\d+)?)\s*\uc2dc\uac04\s*"
        r"(?:\uc804\ud6c4|\uc55e\ub4a4)"
    ),
)
_TIMESTAMP_KEYS = (
    "timecreated",
    "systemtime",
    "datetime",
    "eventtime",
    "lastrun",
    "lastruntime",
    "lastwritetime",
    "lastwritetimestamp",
    "filekeylastwritetimestamp",
    "keylastwritetimestamp",
    "lastmodified",
    "lastmodifiedtime",
    "lastmodifiedtimeutc",
    "createdtime",
    "modifiedtime",
    "timestamp",
)
_RANGE_CONNECTOR_RE = re.compile(
    r"(?:\ubd80\ud130|\uc5d0\uc11c|~|\.{2,}|\bto\b|\buntil\b|\bthrough\b|"
    r"\bend\s*=)",
    re.IGNORECASE,
)
_MAX_PADDING_HOURS = 24 * 31
_MAX_PREFETCH_SCOPE_TIMESTAMPS = 8


@dataclass(frozen=True)
class TimeScope:
    start_utc: datetime
    end_utc: datetime
    source: str
    padding_hours: float = 0.0
    timezone_assumed: bool = False

    def __post_init__(self) -> None:
        if self.start_utc.tzinfo is None or self.end_utc.tzinfo is None:
            raise ValueError("time scope must be timezone-aware")
        if self.start_utc > self.end_utc:
            raise ValueError("time scope start must not be after end")
        object.__setattr__(self, "start_utc", self.start_utc.astimezone(timezone.utc))
        object.__setattr__(self, "end_utc", self.end_utc.astimezone(timezone.utc))

    def contains(self, value: datetime) -> bool:
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        value = value.astimezone(timezone.utc)
        return self.start_utc <= value <= self.end_utc

    def summary(self) -> str:
        return (
            f"{self.start_utc.isoformat()}..{self.end_utc.isoformat()}"
            f" (source={self.source}, padding_hours={self.padding_hours:g}, "
            f"timezone_assumed={str(self.timezone_assumed).lower()})"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "start_utc": self.start_utc.isoformat(),
            "end_utc": self.end_utc.isoformat(),
            "source": self.source,
            "padding_hours": self.padding_hours,
            "timezone_assumed": self.timezone_assumed,
        }

def parse_timestamp(
    value: Any,
    *,
    default_offset_minutes: int = 0,
    numeric_unit: str = "auto",
) -> datetime | None:
    """Normalize ISO-8601, Unix epoch units, and Windows FILETIME to UTC."""
    if numeric_unit not in {
        "auto",
        "filetime",
        "unix_s",
        "unix_ms",
        "unix_us",
        "unix_ns",
    }:
        raise ValueError(f"unsupported numeric timestamp unit: {numeric_unit!r}")
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        parsed = _numeric_timestamp(value, numeric_unit=numeric_unit)
        return parsed.astimezone(timezone.utc) if parsed else None
    else:
        text = str(value or "").strip()
        if not text:
            return None
        if re.fullmatch(r"[+-]?\d+(?:\.\d+)?", text):
            try:
                decimal = Decimal(text)
            except InvalidOperation:
                return None
            numeric: int | float = (
                int(decimal)
                if decimal == decimal.to_integral_value()
                else float(decimal)
            )
            parsed = _numeric_timestamp(numeric, numeric_unit=numeric_unit)
            return parsed.astimezone(timezone.utc) if parsed else None
        candidate = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            parsed = None
            for fmt in (
                "%Y/%m/%d %H:%M:%S",
                "%m/%d/%Y %H:%M:%S",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
            ):
                try:
                    parsed = datetime.strptime(text, fmt)
                    break
                except ValueError:
                    continue
            if parsed is None:
                return None
    if parsed.tzinfo is None:
        offset = max(-23 * 60 - 59, min(23 * 60 + 59, default_offset_minutes))
        parsed = parsed.replace(tzinfo=timezone(timedelta(minutes=offset)))
    try:
        return parsed.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        return None


def timestamp_timezone_assumed(value: Any) -> bool:
    """Whether parsing a timestamp requires the default UTC offset."""
    if isinstance(value, datetime):
        return value.tzinfo is None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return False
    text = str(value or "").strip()
    if not text or re.fullmatch(r"[+-]?\d+(?:\.\d+)?", text):
        return False
    candidate = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    try:
        return datetime.fromisoformat(candidate).tzinfo is None
    except ValueError:
        return True


def _numeric_timestamp(
    value: int | float,
    *,
    numeric_unit: str = "auto",
) -> datetime | None:
    if isinstance(value, float) and not isfinite(value):
        return None
    magnitude = abs(value)
    try:
        if numeric_unit == "filetime":
            if isinstance(value, int):
                seconds, ticks = divmod(value, 10_000_000)
                return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(
                    seconds=seconds,
                    microseconds=ticks // 10,
                )
            return datetime.fromtimestamp(
                value / 10_000_000 - 11_644_473_600,
                tz=timezone.utc,
            )
        unix_scales = {
            "unix_s": 1,
            "unix_ms": 1_000,
            "unix_us": 1_000_000,
            "unix_ns": 1_000_000_000,
        }
        if numeric_unit in unix_scales:
            scale = unix_scales[numeric_unit]
            if isinstance(value, int):
                seconds, remainder = divmod(value, scale)
                microseconds = remainder * 1_000_000 // scale
                return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(
                    seconds=seconds,
                    microseconds=microseconds,
                )
            return datetime.fromtimestamp(value / scale, tz=timezone.utc)
        if 10**17 <= magnitude < 5 * 10**17:
            # Windows FILETIME: 100 ns ticks since 1601-01-01.
            if isinstance(value, int):
                seconds, ticks = divmod(value, 10_000_000)
                return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(
                    seconds=seconds,
                    microseconds=ticks // 10,
                )
            seconds = value / 10_000_000 - 11_644_473_600
        elif magnitude >= 10**16:
            if isinstance(value, int):
                seconds, remainder = divmod(value, 1_000_000_000)
                return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(
                    seconds=seconds,
                    microseconds=remainder // 1_000,
                )
            seconds = value / 1_000_000_000
        elif magnitude >= 10**13:
            if isinstance(value, int):
                seconds, microseconds = divmod(value, 1_000_000)
                return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(
                    seconds=seconds,
                    microseconds=microseconds,
                )
            seconds = value / 1_000_000
        elif magnitude >= 10**10:
            if isinstance(value, int):
                seconds, milliseconds = divmod(value, 1_000)
                return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(
                    seconds=seconds,
                    microseconds=milliseconds * 1_000,
                )
            seconds = value / 1_000
        else:
            seconds = value
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def row_timestamps(row: dict[str, Any]) -> tuple[datetime, ...]:
    """Return all recognized row timestamps in deterministic priority order."""
    values: list[tuple[str, str, Any, bool]] = []

    def walk(value: Any, prefix: str = "") -> None:
        if not isinstance(value, dict):
            return
        for raw_key, child in value.items():
            key = re.sub(r"[^a-z0-9]", "", str(raw_key).casefold())
            qualified = f"{prefix}{key}"
            if isinstance(child, dict):
                walk(child, qualified)
            else:
                flattened = any(mark in str(raw_key) for mark in (".", "/", "\\"))
                values.append((key, qualified, child, flattened))

    walk(row)
    parsed_values: list[datetime] = []
    seen: set[datetime] = set()
    aliases = [alias for alias in _TIMESTAMP_KEYS if alias != "timestamp"]
    previous_aliases = sorted(
        {
            key
            for key, _, _, _ in values
            if re.fullmatch(r"previousrun(?:time)?\d+", key)
        },
        key=lambda key: int(re.search(r"\d+$", key).group()),  # type: ignore[union-attr]
    )
    aliases.extend(previous_aliases[: _MAX_PREFETCH_SCOPE_TIMESTAMPS - 1])
    for alias in aliases:
        matched = False
        for key, qualified, value, flattened in values:
            qualified_timecreated = (
                alias == "timecreated"
                and qualified.endswith(
                    (
                        "timecreatedsystemtime",
                        "timecreatedattributessystemtime",
                    )
                )
            )
            if (
                key == alias
                or (flattened and key.endswith(alias))
                or qualified_timecreated
            ):
                numeric_unit = (
                    "filetime"
                    if "filetime" in key or "filetime" in qualified
                    else "auto"
                )
                parsed = parse_timestamp(value, numeric_unit=numeric_unit)
                if parsed is not None and parsed not in seen:
                    seen.add(parsed)
                    parsed_values.append(parsed)
                    matched = True
        if alias == "timecreated" and matched:
            return tuple(parsed_values)
    if not parsed_values:
        for key, _, value, flattened in values:
            if key == "timestamp" or (flattened and key.endswith("timestamp")):
                numeric_unit = (
                    "filetime"
                    if "filetime" in key
                    else "auto"
                )
                parsed = parse_timestamp(value, numeric_unit=numeric_unit)
                if parsed is not None and parsed not in seen:
                    seen.add(parsed)
                    parsed_values.append(parsed)
    return tuple(parsed_values)


def row_timestamp(row: dict[str, Any]) -> datetime | None:
    """Return the highest-priority recognized timestamp, including nested rows."""
    return next(iter(row_timestamps(row)), None)


def filter_rows(
    rows: Iterable[dict[str, Any]], scope: TimeScope
) -> Iterator[dict[str, Any]]:
    """Yield dated rows inside the inclusive scope; undated rows are excluded."""
    for row in rows:
        timestamps = row_timestamps(row)
        if any(scope.contains(timestamp) for timestamp in timestamps):
            yield row


def extract_time_scope(
    text: str | None,
    *,
    default_padding_hours: float = 24.0,
    default_offset_minutes: int = 0,
) -> TimeScope | None:
    """Extract one point or one explicit range from Korean/ISO scenario text.

    One timestamp is treated as an incident point and expanded by ``±N``
    (24 hours by default). A date without a time covers that calendar day.
    Two timestamps form an exact range; an explicit ``±N`` expands both ends.
    More than two timestamps are intentionally considered ambiguous.
    """
    if not text or not text.strip():
        return None
    offset_minutes, timezone_explicit = _scenario_offset(
        text, default_offset_minutes
    )
    matches = _datetime_matches(
        text,
        default_offset_minutes=offset_minutes,
        global_timezone_explicit=timezone_explicit,
    )
    if not 1 <= len(matches) <= 2:
        return None
    padding = _padding_hours(text)
    assumed = any(item[2] for item in matches)

    if len(matches) == 2:
        between = text[matches[0][4] : matches[1][3]]
        prefix = text[: matches[0][3]]
        if not _RANGE_CONNECTOR_RE.search(between) and not (
            re.search(r"\bbetween\b", prefix, re.IGNORECASE)
            and re.search(r"\band\b", between, re.IGNORECASE)
        ):
            return None
        start, start_date_only, _, _, _ = matches[0]
        end, end_date_only, _, _, _ = matches[1]
        if end_date_only:
            end += timedelta(days=1) - timedelta(microseconds=1)
        if start > end:
            return None
        applied_padding = padding or 0.0
        return TimeScope(
            start - timedelta(hours=applied_padding),
            end + timedelta(hours=applied_padding),
            source="scenario_range",
            padding_hours=applied_padding,
            timezone_assumed=assumed,
        )

    point, date_only, _, _, _ = matches[0]
    if date_only:
        start = point
        end = point + timedelta(days=1) - timedelta(microseconds=1)
        applied_padding = padding or 0.0
    else:
        applied_padding = padding if padding is not None else default_padding_hours
        start = point
        end = point
    applied_padding = max(0.0, min(float(applied_padding), _MAX_PADDING_HOURS))
    return TimeScope(
        start - timedelta(hours=applied_padding),
        end + timedelta(hours=applied_padding),
        source="scenario_point" if not date_only else "scenario_date",
        padding_hours=applied_padding,
        timezone_assumed=assumed,
    )


def _datetime_matches(
    text: str,
    *,
    default_offset_minutes: int,
    global_timezone_explicit: bool,
) -> list[tuple[datetime, bool, bool, int, int]]:
    found: list[tuple[int, int, datetime, bool, bool]] = []
    for match in _ISO_DATE_RE.finditer(text):
        raw = match.group(1)
        parsed = parse_timestamp(
            raw, default_offset_minutes=default_offset_minutes
        )
        if parsed is not None:
            date_only = "T" not in raw and " " not in raw
            explicit_zone = raw.endswith(("Z", "z")) or bool(
                re.search(r"[+-]\d{2}:?\d{2}$", raw)
            )
            found.append(
                (
                    match.start(),
                    match.end(),
                    parsed,
                    date_only,
                    not (explicit_zone or global_timezone_explicit),
                )
            )
    for match in _KOREAN_DATE_RE.finditer(text):
        year, month, day, hour, minute, second = match.groups()
        try:
            parsed = datetime(
                int(year),
                int(month),
                int(day),
                int(hour or 0),
                int(minute or 0),
                int(second or 0),
                tzinfo=timezone(timedelta(minutes=default_offset_minutes)),
            ).astimezone(timezone.utc)
        except ValueError:
            continue
        found.append(
            (
                match.start(),
                match.end(),
                parsed,
                hour is None,
                not global_timezone_explicit,
            )
        )
    found.sort(key=lambda item: item[0])
    return [
        (parsed, date_only, assumed, start, end)
        for start, end, parsed, date_only, assumed in found
    ]


def _scenario_offset(text: str, default: int) -> tuple[int, bool]:
    if re.search(r"\b(?:KST|JST)\b", text, re.IGNORECASE):
        return 9 * 60, True
    match = re.search(
        r"\b(?:UTC|GMT)\s*(?:([+-])\s*(\d{1,2})(?::?(\d{2}))?)?",
        text,
        re.IGNORECASE,
    )
    if not match:
        return default, False
    sign, hours, minutes = match.groups()
    if not sign:
        return 0, True
    value = int(hours or 0) * 60 + int(minutes or 0)
    if value > 23 * 60 + 59:
        return default, False
    return (value if sign == "+" else -value), True


def _padding_hours(text: str) -> float | None:
    for pattern in _PADDING_RES:
        match = pattern.search(text)
        if match:
            return max(0.0, min(float(match.group(1)), _MAX_PADDING_HOURS))
    return None
