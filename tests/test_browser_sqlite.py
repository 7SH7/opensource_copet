from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
from contextlib import closing
from pathlib import Path

from forensicagent.analyzer.analyzer import analyze_all, analyze_one
from forensicagent.executor import execute, get_adapter
from forensicagent.executor.types import ExecutionResult, OutputArtifact
from forensicagent.reporter.builder import build
from forensicagent.scanner import scan
from forensicagent.selector import select
from forensicagent.tools import browser_sqlite
from forensicagent.tools.browser_sqlite import inspect_database, main
from forensicagent.tools.loader import load_tool


def _chrome_history(path: Path) -> None:
    with closing(sqlite3.connect(path)) as connection:
        connection.executescript(
            """
            CREATE TABLE urls (
                id INTEGER PRIMARY KEY,
                url TEXT,
                title TEXT,
                visit_count INTEGER,
                last_visit_time INTEGER
            );
            CREATE TABLE downloads (
                id INTEGER PRIMARY KEY,
                current_path TEXT,
                target_path TEXT,
                start_time INTEGER,
                received_bytes INTEGER,
                total_bytes INTEGER,
                state INTEGER,
                danger_type INTEGER
            );
            CREATE TABLE downloads_url_chains (
                id INTEGER,
                chain_index INTEGER,
                url TEXT
            );
            INSERT INTO urls VALUES (
                1, 'https://example.test/page', 'Example', 3, 13300000000000000
            );
            INSERT INTO downloads VALUES (
                7, 'C:/Temp/payload.exe', 'C:/Temp/payload.exe',
                13300000000000000, 12, 12, 1, 0
            );
            INSERT INTO downloads_url_chains VALUES (
                7, 0, 'https://downloads.example.test/payload.exe'
            );
            """
        )


def test_browser_sqlite_inspection_is_read_only_and_structured(tmp_path, capsys):
    database = tmp_path / "History"
    _chrome_history(database)
    before = hashlib.sha256(database.read_bytes()).hexdigest()

    assert inspect_database(database) == 2

    after = hashlib.sha256(database.read_bytes()).hexdigest()
    records = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert after == before
    assert [record["record_type"] for record in records] == [
        "browser_history",
        "browser_download",
    ]
    assert records[0]["timestamp"].endswith("Z")
    assert records[1]["url"].endswith("payload.exe")
    assert records[1]["target_path"] == "C:/Temp/payload.exe"


def test_browser_sqlite_bounds_large_text_inside_sqlite(tmp_path, capsys, monkeypatch):
    database = tmp_path / "History"
    _chrome_history(database)
    huge = "x" * (1024 * 1024)
    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            "UPDATE urls SET url=?, title=?",
            ("https://example.test/" + huge, "title-" + huge),
        )
        connection.execute(
            "UPDATE downloads SET current_path=?, target_path=?",
            ("C:/current/" + huge, "C:/target/" + huge),
        )
        connection.execute(
            "UPDATE downloads_url_chains SET url=?",
            ("https://downloads.example.test/" + huge,),
        )
        connection.commit()

    original_text = browser_sqlite._text

    def assert_already_bounded(value):
        assert len(str(value or "")) <= browser_sqlite.MAX_TEXT_CHARS
        return original_text(value)

    monkeypatch.setattr(browser_sqlite, "_text", assert_already_bounded)

    assert inspect_database(database) == 2

    records = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    history, download = records
    assert history["url"] == ("https://example.test/" + huge)[: browser_sqlite.MAX_TEXT_CHARS]
    assert history["title"] == ("title-" + huge)[: browser_sqlite.MAX_TEXT_CHARS]
    assert download["url"] == (
        "https://downloads.example.test/" + huge
    )[: browser_sqlite.MAX_TEXT_CHARS]
    assert download["current_path"] == (
        "C:/current/" + huge
    )[: browser_sqlite.MAX_TEXT_CHARS]
    assert download["target_path"] == (
        "C:/target/" + huge
    )[: browser_sqlite.MAX_TEXT_CHARS]
    assert history["visit_count"] == 3


def test_browser_sqlite_rejects_large_blobs_in_numeric_columns_before_python(
    tmp_path, capsys, monkeypatch
):
    database = tmp_path / "History"
    _chrome_history(database)
    huge = b"x" * (1024 * 1024)
    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            "UPDATE urls SET visit_count=?, last_visit_time=?",
            (huge, huge),
        )
        connection.execute(
            "UPDATE downloads SET start_time=?, received_bytes=?, total_bytes=?",
            (huge, huge, huge),
        )
        connection.execute(
            "CREATE TABLE moz_places (url TEXT, title TEXT, visit_count, last_visit_date)"
        )
        connection.execute(
            "INSERT INTO moz_places VALUES ('https://example.test', 'title', ?, ?)",
            (huge, huge),
        )
        connection.commit()

    original_integer = browser_sqlite._integer
    original_timestamp = browser_sqlite._timestamp

    def assert_small_integer(value):
        assert not isinstance(value, bytes)
        return original_integer(value)

    def assert_small_timestamp(value, *, chrome):
        assert not isinstance(value, bytes)
        return original_timestamp(value, chrome=chrome)

    monkeypatch.setattr(browser_sqlite, "_integer", assert_small_integer)
    monkeypatch.setattr(browser_sqlite, "_timestamp", assert_small_timestamp)

    assert inspect_database(database) == 3

    records = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    history, download, firefox = records
    assert history["visit_count"] == 0
    assert history["timestamp"] == ""
    assert download["received_bytes"] == 0
    assert download["total_bytes"] == 0
    assert download["timestamp"] == ""
    assert firefox["visit_count"] == 0
    assert firefox["timestamp"] == ""


def test_browser_sqlite_unknown_schema_reports_incomplete_coverage(tmp_path, capsys):
    database = tmp_path / "Cookies"
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("CREATE TABLE cookies (name TEXT)")
        connection.commit()

    assert inspect_database(database) == 1

    record = json.loads(capsys.readouterr().out)
    assert record["record_type"] == "coverage_warning"
    assert "no supported browser" in record["message"]


def test_browser_sqlite_known_incompatible_schemas_report_missing_columns(
    tmp_path,
    capsys,
):
    database = tmp_path / "History"
    with closing(sqlite3.connect(database)) as connection:
        connection.executescript(
            """
            CREATE TABLE urls (url TEXT);
            CREATE TABLE downloads (id INTEGER);
            CREATE TABLE moz_places (title TEXT);
            """
        )

    assert inspect_database(database) == 3

    records = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert {record["source"] for record in records} == {
        "chromium_history",
        "chromium_downloads",
        "firefox_history",
    }
    assert all(record["record_type"] == "coverage_warning" for record in records)
    assert all("missing required columns" in record["message"] for record in records)


def test_browser_sqlite_rejects_non_sqlite_without_reading_it_all(tmp_path, capsys):
    evidence = tmp_path / "History"
    evidence.write_bytes(b"not sqlite" + b"x" * 1024)

    assert main([str(evidence)]) == 2
    assert "not a SQLite" in capsys.readouterr().err


def test_browser_adapter_runs_from_an_unrelated_working_directory(tmp_path):
    database = tmp_path / "History"
    _chrome_history(database)
    metadata = load_tool(
        Path(__file__).resolve().parents[1] / "tools_metadata" / "browser_sqlite.yaml"
    )
    adapter = get_adapter(metadata)

    ok, detail = adapter.validate_prerequisites()
    command = adapter.build_command(str(database))
    completed = subprocess.run(
        command,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )

    assert ok is True
    assert "sqlite" in detail
    assert Path(command[1]).name == "browser_sqlite.py"
    assert completed.returncode == 0, completed.stderr
    assert '"record_type":"browser_download"' in completed.stdout


def test_browser_tool_coverage_record_is_not_misreported_as_zero_findings(tmp_path):
    output = tmp_path / "stdout.jsonl"
    output.write_text(
        '{"record_type":"coverage_warning","message":"unsupported schema"}\n',
        encoding="utf-8",
    )
    metadata = load_tool(
        Path(__file__).resolve().parents[1] / "tools_metadata" / "browser_sqlite.yaml"
    )
    result = ExecutionResult(
        tool_id="browser_sqlite",
        target_evidence=str(tmp_path / "History"),
        status="success",
        stdout_path=str(output),
        output_format="jsonl",
        output_size_bytes=output.stat().st_size,
        artifacts=[
            OutputArtifact(
                path=str(output),
                role="stdout",
                format="jsonl",
                size_bytes=output.stat().st_size,
            )
        ],
    )

    analysis = analyze_one(result, metadata, use_llm=False, use_rag=False)

    assert analysis.findings == []
    assert analysis.coverage_warnings == [
        "tool-reported coverage: unsupported schema"
    ]


def test_browser_artifact_full_pipeline_reports_and_resumes_exact_input(tmp_path):
    database = tmp_path / "History"
    _chrome_history(database)
    metadata = load_tool(
        Path(__file__).resolve().parents[1] / "tools_metadata" / "browser_sqlite.yaml"
    )
    tools = {metadata.tool_id: metadata}
    raw = tmp_path / "raw"

    inventory = scan(database)
    plan = select(inventory, tools, use_llm=False, use_rag=False)
    first = execute(
        plan,
        tools,
        output_dir=raw,
        max_parallel=1,
        max_job_output_bytes=1024**2,
        max_total_output_bytes=2 * 1024**2,
        min_free_disk_bytes=1,
    )
    analyses = analyze_all(first.results, tools, use_llm=False, use_rag=False)
    report = build(
        inventory=inventory,
        plan=plan,
        execution=first,
        analyses=analyses,
        started_at="2026-08-22T00:00:00Z",
        working_directory=str(tmp_path),
    )

    assert first.results[0].status == "success"
    assert first.results[0].provenance["tool_version"] == (
        f"stdlib sqlite {sqlite3.sqlite_version}"
    )
    assert [finding.rule_id for finding in report.all_findings()] == [
        "browser_suspicious_download"
    ]
    assert report.timeline()["events"][0]["timestamp_utc"].endswith("Z")
    assert report.artifact_ledger[0]["sha256"] == inventory.evidence_list[0].sha256
    assert report.artifact_ledger[0]["analysis_status"] == "analyzed"

    reused = execute(
        plan,
        tools,
        output_dir=raw,
        max_parallel=1,
        max_job_output_bytes=1024**2,
        max_total_output_bytes=2 * 1024**2,
        min_free_disk_bytes=1,
    ).results[0]
    assert reused.provenance["resume"]["reused"] is True

    with closing(sqlite3.connect(database)) as connection:
        connection.execute("UPDATE downloads SET target_path='C:/Temp/changed.exe'")
        connection.commit()
    changed_inventory = scan(database)
    changed_plan = select(changed_inventory, tools, use_llm=False, use_rag=False)
    changed = execute(
        changed_plan,
        tools,
        output_dir=raw,
        max_parallel=1,
        max_job_output_bytes=1024**2,
        max_total_output_bytes=2 * 1024**2,
        min_free_disk_bytes=1,
    ).results[0]

    assert changed.status == "success"
    assert changed.provenance["resume"]["reused"] is False
    assert Path(changed.stdout_path).parent != Path(first.results[0].stdout_path).parent
