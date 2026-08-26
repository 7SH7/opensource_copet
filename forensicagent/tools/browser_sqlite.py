"""Read common browser SQLite artifacts without modifying the evidence file."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote


MAX_ROWS_PER_SOURCE = 10_000
MAX_TEXT_CHARS = 4_096
_CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _text(value: Any) -> str:
    return str(value or "")[:MAX_TEXT_CHARS]


def _integer(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _timestamp(value: Any, *, chrome: bool) -> str:
    try:
        number = int(value or 0)
        if number <= 0:
            return ""
        if chrome:
            parsed = _CHROME_EPOCH + timedelta(microseconds=number)
        else:
            parsed = datetime.fromtimestamp(number / 1_000_000, tz=timezone.utc)
    except (OverflowError, TypeError, ValueError):
        return ""
    return parsed.isoformat().replace("+00:00", "Z")


def _open_read_only(path: Path) -> sqlite3.Connection:
    resolved = path.resolve(strict=True)
    uri = f"file:{quote(resolved.as_posix(), safe='/:')}?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=2)
    try:
        connection.execute("PRAGMA query_only=ON")
        try:
            connection.execute("PRAGMA trusted_schema=OFF")
        except sqlite3.DatabaseError:
            pass
    except BaseException:
        connection.close()
        raise
    return connection


def _tables(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        if row and isinstance(row[0], str)
    }


def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
    # Callers pass only fixed, program-owned table names.
    return {str(row[1]) for row in connection.execute(f'PRAGMA table_info("{table}")')}


def _emit_rows(rows: Iterable[dict[str, Any]]) -> int:
    count = 0
    for row in rows:
        print(json.dumps(row, ensure_ascii=False, separators=(",", ":")))
        count += 1
    return count


def _missing_columns_warning(
    source: str,
    table: str,
    missing: set[str],
) -> dict[str, str]:
    return {
        "record_type": "coverage_warning",
        "source": source,
        "message": f'{table} is missing required columns: {", ".join(sorted(missing))}',
    }


def _numeric(column: str, *, prefix: str = "") -> str:
    """Read a fixed numeric column without materializing attacker-sized blobs."""
    qualified = f'{prefix}."{column}"' if prefix else f'"{column}"'
    return (
        f"CASE WHEN typeof({qualified}) IN ('integer','real') "
        f"THEN CAST({qualified} AS INTEGER) ELSE 0 END"
    )


def _chrome_history(connection: sqlite3.Connection) -> Iterable[dict[str, Any]]:
    required = {"url", "title", "visit_count", "last_visit_time"}
    missing = required - _columns(connection, "urls")
    if missing:
        yield _missing_columns_warning("chromium_history", "urls", missing)
        return
    rows = connection.execute(
        f"SELECT substr(CAST(url AS TEXT), 1, {MAX_TEXT_CHARS}), "
        f"substr(CAST(title AS TEXT), 1, {MAX_TEXT_CHARS}), "
        f"{_numeric('visit_count')}, {_numeric('last_visit_time')} FROM urls "
        "ORDER BY last_visit_time DESC LIMIT ?",
        (MAX_ROWS_PER_SOURCE + 1,),
    )
    for index, (url, title, visits, original_time) in enumerate(rows):
        if index == MAX_ROWS_PER_SOURCE:
            yield {
                "record_type": "coverage_warning",
                "source": "chromium_history",
                "message": f"history rows exceeded {MAX_ROWS_PER_SOURCE}; remaining rows were not emitted",
            }
            break
        yield {
            "record_type": "browser_history",
            "browser": "chromium",
            "timestamp": _timestamp(original_time, chrome=True),
            "timestamp_original": _text(original_time),
            "url": _text(url),
            "title": _text(title),
            "visit_count": _integer(visits),
        }


def _chrome_downloads(
    connection: sqlite3.Connection,
    tables: set[str],
) -> Iterable[dict[str, Any]]:
    columns = _columns(connection, "downloads")
    required = {"id", "start_time"}
    missing = required - columns
    if missing:
        yield _missing_columns_warning("chromium_downloads", "downloads", missing)
        return

    optional = (
        "current_path",
        "target_path",
        "end_time",
        "received_bytes",
        "total_bytes",
        "state",
        "danger_type",
        "interrupt_reason",
        "tab_url",
        "site_url",
        "referrer",
    )
    selected = ["start_time", *(name for name in optional if name in columns)]
    text_columns = {
        "current_path",
        "target_path",
        "tab_url",
        "site_url",
        "referrer",
    }
    # selected contains only the fixed names above, never identifiers from evidence.
    select_sql = ", ".join(
        f'substr(CAST(d."{name}" AS TEXT), 1, {MAX_TEXT_CHARS})'
        if name in text_columns
        else _numeric(name, prefix="d")
        for name in selected
    )
    has_chain = "downloads_url_chains" in tables and {
        "id",
        "chain_index",
        "url",
    } <= _columns(connection, "downloads_url_chains")
    if has_chain:
        select_sql += (
            f', substr(CAST(c."url" AS TEXT), 1, {MAX_TEXT_CHARS})'
        )
        join_sql = (
            " LEFT JOIN downloads_url_chains c "
            "ON c.id=d.id AND c.chain_index=0"
        )
    else:
        join_sql = ""
    query = (
        f"SELECT {select_sql} FROM downloads d{join_sql} "
        "ORDER BY d.start_time DESC LIMIT ?"
    )
    rows = connection.execute(query, (MAX_ROWS_PER_SOURCE + 1,))
    for index, values in enumerate(rows):
        if index == MAX_ROWS_PER_SOURCE:
            yield {
                "record_type": "coverage_warning",
                "source": "chromium_downloads",
                "message": f"download rows exceeded {MAX_ROWS_PER_SOURCE}; remaining rows were not emitted",
            }
            break
        row = dict(zip(selected, values[: len(selected)]))
        chain_url = values[-1] if has_chain else ""
        source_url = chain_url or row.get("tab_url") or row.get("site_url") or row.get("referrer")
        yield {
            "record_type": "browser_download",
            "browser": "chromium",
            "timestamp": _timestamp(row.get("start_time"), chrome=True),
            "timestamp_original": _text(row.get("start_time")),
            "url": _text(source_url),
            "current_path": _text(row.get("current_path")),
            "target_path": _text(row.get("target_path")),
            "received_bytes": _integer(row.get("received_bytes")),
            "total_bytes": _integer(row.get("total_bytes")),
            "state": _text(row.get("state")),
            "danger_type": _text(row.get("danger_type")),
            "interrupt_reason": _text(row.get("interrupt_reason")),
        }


def _firefox_history(connection: sqlite3.Connection) -> Iterable[dict[str, Any]]:
    required = {"url", "title", "visit_count", "last_visit_date"}
    missing = required - _columns(connection, "moz_places")
    if missing:
        yield _missing_columns_warning("firefox_history", "moz_places", missing)
        return
    rows = connection.execute(
        f"SELECT substr(CAST(url AS TEXT), 1, {MAX_TEXT_CHARS}), "
        f"substr(CAST(title AS TEXT), 1, {MAX_TEXT_CHARS}), "
        f"{_numeric('visit_count')}, {_numeric('last_visit_date')} FROM moz_places "
        "ORDER BY last_visit_date DESC LIMIT ?",
        (MAX_ROWS_PER_SOURCE + 1,),
    )
    for index, (url, title, visits, original_time) in enumerate(rows):
        if index == MAX_ROWS_PER_SOURCE:
            yield {
                "record_type": "coverage_warning",
                "source": "firefox_history",
                "message": f"history rows exceeded {MAX_ROWS_PER_SOURCE}; remaining rows were not emitted",
            }
            break
        yield {
            "record_type": "browser_history",
            "browser": "firefox",
            "timestamp": _timestamp(original_time, chrome=False),
            "timestamp_original": _text(original_time),
            "url": _text(url),
            "title": _text(title),
            "visit_count": _integer(visits),
        }


def inspect_database(path: Path) -> int:
    with closing(_open_read_only(path)) as connection:
        tables = _tables(connection)
        emitted = 0
        if "urls" in tables:
            emitted += _emit_rows(_chrome_history(connection))
        if "downloads" in tables:
            emitted += _emit_rows(_chrome_downloads(connection, tables))
        if "moz_places" in tables:
            emitted += _emit_rows(_firefox_history(connection))
        if not {"urls", "downloads", "moz_places"} & tables:
            emitted += _emit_rows(
                [
                    {
                        "record_type": "coverage_warning",
                        "source": "browser_sqlite",
                        "message": "recognized SQLite file has no supported browser history/download schema",
                    }
                ]
            )
        return emitted


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args(argv)
    try:
        with args.evidence.open("rb") as handle:
            if handle.read(16) != b"SQLite format 3\x00":
                raise ValueError("input is not a SQLite 3 database")
        inspect_database(args.evidence)
    except (OSError, sqlite3.DatabaseError, ValueError) as exc:
        print(f"browser SQLite analysis failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
