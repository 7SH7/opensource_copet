from collections import Counter
from datetime import datetime, timedelta, timezone
from io import StringIO

from hypothesis import given, settings, strategies as st
from rich.console import Console

from forensicagent.analyzer.types import (
    MAX_RETAINED_FINDINGS,
    EvidenceRef,
    Finding,
    ToolAnalysis,
)
from forensicagent.executor.types import ExecutionBundle, ExecutionResult, OutputArtifact
from forensicagent.reporter.builder import build
from forensicagent.reporter.md_out import write_md
from forensicagent.reporter.terminal import render, render_summary
from forensicagent.reporter.types import Report, ToolBundle
from forensicagent.scanner.types import Evidence, Inventory
from forensicagent.selector.types import Plan, ToolSelection


def _plan() -> Plan:
    return Plan(
        selected_tools=[ToolSelection(tool_id="fake", target_evidence=["evidence"])]
    )


def test_failed_execution_is_not_reported_as_clean_zero_findings(tmp_path):
    execution = ExecutionBundle(
        results=[
            ExecutionResult(
                tool_id="fake",
                status="output_missing",
                error_message="CSV output was not created",
            )
        ]
    )
    report = build(
        inventory=Inventory(),
        plan=_plan(),
        execution=execution,
        analyses=[ToolAnalysis(tool_id="fake", summary="0 findings")],
        started_at="now",
        working_directory=str(tmp_path),
    )

    assert report.summary.tools_failed == 1
    assert "not analyzed" in report.tool_bundles[0].analysis.summary
    assert "CSV output was not created" in report.tool_bundles[0].analysis.summary


def test_partial_output_limit_analysis_and_resume_status_are_reported(tmp_path):
    finding = Finding(title="Recovered from partial output")
    result = ExecutionResult(
        tool_id="fake",
        status="output_limit",
        error_message="per-job output limit exceeded",
        output_size_bytes=42,
        artifacts=[
            OutputArtifact(
                path=str(tmp_path / "partial.txt"),
                role="stdout",
                format="text",
                size_bytes=42,
                sha256="a" * 64,
            )
        ],
        provenance={
            "resume": {
                "job_key": "b" * 64,
                "input_sha256": "c" * 64,
                "settings_sha256": "d" * 64,
                "reused": False,
            }
        },
    )
    report = build(
        inventory=Inventory(),
        plan=_plan(),
        execution=ExecutionBundle(results=[result]),
        analyses=[ToolAnalysis(tool_id="fake", findings=[finding])],
        started_at="now",
        working_directory=str(tmp_path),
    )

    analysis = report.tool_bundles[0].analysis
    assert analysis is not None
    assert analysis.findings == [finding]
    assert "partial_artifacts_analyzed=true" in analysis.summary
    assert "execution_status=output_limit=1" in analysis.summary
    assert report.summary.tools_failed == 1
    markdown = write_md(report, tmp_path / "partial.md").read_text(encoding="utf-8")
    assert "status: **output_limit**" in markdown
    assert "resume: reused=false" in markdown


def test_markdown_escapes_tool_controlled_text_and_lists_artifact(tmp_path):
    finding = Finding(
        title="# injected [link](https://bad.invalid)",
        description="| table | break |",
        evidence_ref=EvidenceRef(raw_excerpt="value `with` ticks"),
    )
    result = ExecutionResult(
        tool_id="fake",
        status="success",
        command_executed="fake --arg `unsafe`",
        artifacts=[
            OutputArtifact(
                path=str(tmp_path / "out.csv"),
                role="generated",
                format="csv",
                size_bytes=10,
                sha256="abc",
            )
        ],
    )
    report = build(
        inventory=Inventory(),
        plan=_plan(),
        execution=ExecutionBundle(results=[result]),
        analyses=[ToolAnalysis(tool_id="fake", findings=[finding])],
        started_at="now",
        working_directory=str(tmp_path),
    )

    path = write_md(report, tmp_path / "report.md")
    text = path.read_text(encoding="utf-8")
    assert "\\# injected \\[link\\]" in text
    assert "artifact (generated/csv" in text
    assert "out.csv" in text


def test_report_preserves_time_scope_and_llm_routing_ledger(tmp_path):
    analysis = ToolAnalysis(
        tool_id="fake",
        llm_route="scoped_context_llm",
        llm_input_chars=321,
        time_scope={
            "start_utc": "2025-01-01T00:00:00+00:00",
            "end_utc": "2025-01-02T00:00:00+00:00",
            "source": "scenario_range",
        },
        scope_rows={"selected": 2, "outside": 3, "undated": 1},
    )
    report = build(
        inventory=Inventory(),
        plan=_plan(),
        execution=ExecutionBundle(
            results=[
                ExecutionResult(
                    tool_id="fake", status="success", parsed_output={"items": []}
                )
            ]
        ),
        analyses=[analysis],
        started_at="now",
        working_directory=str(tmp_path),
    )

    merged = report.tool_bundles[0].analysis
    assert merged is not None
    assert merged.llm_route == "scoped_context_llm"
    assert merged.scope_rows == {"selected": 2, "outside": 3, "undated": 1}
    assert "route=scoped_context_llm" in merged.summary
    assert "scope_rows=selected:2,outside:3,undated:1" in merged.summary
    markdown = write_md(report, tmp_path / "routing.md").read_text(encoding="utf-8")
    assert "llm_route=scoped_context_llm" in markdown


def test_terminal_renders_untrusted_finding_text_without_control_sequences(tmp_path):
    payload = "A\x1b]52;c;UEFZTE9BRA==\x1b\\B [bold]literal[/bold]"
    report = build(
        inventory=Inventory(),
        plan=_plan(),
        execution=ExecutionBundle(
            results=[ExecutionResult(tool_id="fake", status="success")]
        ),
        analyses=[
            ToolAnalysis(
                tool_id="fake",
                findings=[
                    Finding(
                        title=payload,
                        description=payload,
                        suggested_followup=payload,
                    )
                ],
            )
        ],
        started_at="now",
        working_directory=str(tmp_path),
    )
    stream = StringIO()

    render(
        report,
        Console(file=stream, force_terminal=True, color_system=None, width=200),
    )

    terminal = stream.getvalue()
    assert "\x1b" not in terminal
    assert "[bold]literal[/bold]" in terminal


def test_finding_timeline_normalizes_utc_and_separates_bad_timestamps(tmp_path):
    findings = [
        Finding(
            title="offset",
            evidence_ref=EvidenceRef(
                timestamp="2025-01-01T03:00:00+03:00",
                event_id=1102,
                channel="Security",
                provider="Microsoft-Windows-Eventlog",
            ),
        ),
        Finding(
            title="naive",
            evidence_ref=EvidenceRef(timestamp="2025-01-01 01:00:00"),
        ),
        Finding(title="invalid", evidence_ref=EvidenceRef(timestamp="not-a-time")),
        Finding(title="missing", evidence_ref=EvidenceRef()),
    ]
    report = build(
        inventory=Inventory(),
        plan=_plan(),
        execution=ExecutionBundle(),
        analyses=[ToolAnalysis(tool_id="fake", findings=findings)],
        started_at="now",
        working_directory=str(tmp_path),
    )

    timeline = report.to_dict()["timeline"]
    assert [item["title"] for item in timeline["events"]] == ["offset", "naive"]
    assert [item["timestamp_utc"] for item in timeline["events"]] == [
        "2025-01-01T00:00:00Z",
        "2025-01-01T01:00:00Z",
    ]
    assert [item["timezone_assumed"] for item in timeline["events"]] == [False, True]
    assert {item["reason"] for item in timeline["undated"]} == {
        "missing",
        "unparseable",
    }

    markdown = write_md(report, tmp_path / "report.md").read_text(encoding="utf-8")
    assert "## Finding timeline" in markdown
    assert "2025-01-01T00:00:00Z" in markdown
    assert "2025-01-01T03:00:00+03:00" in markdown
    assert "2025-01-01 01:00:00" in markdown
    assert "not-a-time" in markdown
    assert "### Findings without a usable timestamp" in markdown
    assert "Security / Microsoft-Windows-Eventlog / 1102" in markdown

    console = Console(record=True, width=240)
    render(report, console)
    terminal = console.export_text()
    assert "Finding timeline" in terminal
    assert "2025-01-01T03:00:00+03:00" in terminal
    assert "2025-01-01 01:00:00" in terminal
    assert "not-a-time" in terminal
    assert "Findings without a usable timestamp" in terminal
    assert "Security / Microsoft-Windows-Eventlog / 1102" in terminal


def test_finding_timeline_uses_shared_filetime_normalizer():
    expected = datetime(2025, 1, 1, tzinfo=timezone.utc)
    filetime = int((expected.timestamp() + 11_644_473_600) * 10_000_000)
    report = Report(
        tool_bundles=[
            ToolBundle(
                tool_id="fake",
                analysis=ToolAnalysis(
                    tool_id="fake",
                    findings=[
                        Finding(
                            title="filetime",
                            evidence_ref=EvidenceRef(timestamp=str(filetime)),
                        )
                    ],
                ),
            )
        ]
    )

    event = report.timeline()["events"][0]
    assert event["timestamp_utc"] == "2025-01-01T00:00:00Z"
    assert event["timezone_assumed"] is False


def test_normalized_artifact_timeline_is_in_json_markdown_and_terminal(tmp_path):
    analysis = ToolAnalysis(
        tool_id="evtxecmd",
        timeline_event_count=1,
        timeline_events=[
            {
                "timestamp_utc": "2025-01-01T00:00:00Z",
                "timestamp_kind": "event_recorded",
                "artifact_type": "evtx",
                "tool_id": "evtxecmd",
                "summary": "Security event 1102",
                "target_evidence": "Security.evtx",
            }
        ],
    )
    report = Report(tool_bundles=[ToolBundle(tool_id="evtxecmd", analysis=analysis)])

    payload = report.to_dict()["artifact_timeline"]
    assert payload["total_events"] == 1
    assert payload["events"][0]["summary"] == "Security event 1102"

    markdown = write_md(report, tmp_path / "timeline.md").read_text(encoding="utf-8")
    assert "Normalized artifact timeline" in markdown
    assert "Security event 1102" in markdown

    stream = StringIO()
    render(report, Console(file=stream, force_terminal=False, width=180))
    assert "Normalized artifact timeline" in stream.getvalue()


@settings(max_examples=50, deadline=None)
@given(
    st.lists(
        st.datetimes(
            min_value=datetime(2000, 1, 1),
            max_value=datetime(2030, 12, 31, 23, 59, 59),
            timezones=st.integers(min_value=-14 * 60, max_value=14 * 60).map(
                lambda minutes: timezone(timedelta(minutes=minutes))
            ),
        ),
        max_size=20,
    )
)
def test_timeline_preserves_and_orders_aware_timestamp_domain(values):
    originals = [value.isoformat() for value in values]
    report = Report(
        tool_bundles=[
            ToolBundle(
                tool_id="fake",
                analysis=ToolAnalysis(
                    tool_id="fake",
                    findings=[
                        Finding(title=str(index), evidence_ref=EvidenceRef(timestamp=value))
                        for index, value in enumerate(originals)
                    ],
                ),
            )
        ]
    )

    events = report.timeline()["events"]
    observed = [
        datetime.fromisoformat(item["timestamp_utc"].replace("Z", "+00:00"))
        for item in events
    ]

    assert observed == sorted(value.astimezone(timezone.utc) for value in values)
    assert Counter(item["timestamp_original"] for item in events) == Counter(originals)
    assert all(item["timezone_assumed"] is False for item in events)


def test_timeline_separates_timestamps_that_overflow_during_utc_conversion():
    timestamps = [
        "0001-01-01T00:00:00+23:59",
        "9999-12-31T23:59:59-23:59",
    ]
    report = Report(
        tool_bundles=[
            ToolBundle(
                tool_id="fake",
                analysis=ToolAnalysis(
                    tool_id="fake",
                    findings=[
                        Finding(
                            title=str(index),
                            evidence_ref=EvidenceRef(timestamp=value),
                        )
                        for index, value in enumerate(timestamps)
                    ],
                ),
            )
        ]
    )

    timeline = report.timeline()

    assert timeline["events"] == []
    assert [item["timestamp_original"] for item in timeline["undated"]] == timestamps
    assert {item["reason"] for item in timeline["undated"]} == {"unparseable"}


def test_merged_finding_limit_is_preserved_in_json_and_markdown(tmp_path):
    low_findings = [
        Finding(
            severity="low",
            title=f"Noisy {index}",
            rule_id=f"noise:{index}",
            evidence_ref=EvidenceRef(raw_excerpt=f"noise {index}"),
        )
        for index in range(500)
    ]
    critical = Finding(
        severity="critical",
        title="Critical tail",
        rule_id="critical:tail",
        evidence_ref=EvidenceRef(raw_excerpt="critical tail"),
    )
    report = build(
        inventory=Inventory(),
        plan=_plan(),
        execution=ExecutionBundle(
            results=[ExecutionResult(tool_id="fake", status="success")]
        ),
        analyses=[
            ToolAnalysis(tool_id="fake", findings=low_findings),
            ToolAnalysis(
                tool_id="fake",
                findings=[critical],
                finding_limit_reached=True,
            ),
        ],
        started_at="now",
        working_directory=str(tmp_path),
    )

    analysis = report.tool_bundles[0].analysis
    assert analysis is not None
    assert len(analysis.findings) == 500
    assert critical in analysis.findings
    assert analysis.finding_limit_reached is True
    assert report.to_dict()["summary"]["finding_limit_reached"] is True
    text = write_md(report, tmp_path / "report.md").read_text(encoding="utf-8")
    assert "finding limit reached: **yes**" in text
    assert "finding_limit_reached=True" in text


def test_report_limit_flag_requires_an_actually_dropped_finding(tmp_path):
    findings = [
        Finding(
            title=f"Finding {index}",
            rule_id=f"finding:{index}",
            evidence_ref=EvidenceRef(raw_excerpt=f"row {index}"),
        )
        for index in range(MAX_RETAINED_FINDINGS + 1)
    ]

    def report_for(items):
        return build(
            inventory=Inventory(),
            plan=_plan(),
            execution=ExecutionBundle(
                results=[ExecutionResult(tool_id="fake", status="success")]
            ),
            analyses=[ToolAnalysis(tool_id="fake", findings=items)],
            started_at="now",
            working_directory=str(tmp_path),
        )

    exact = report_for(findings[:MAX_RETAINED_FINDINGS])
    overflow = report_for(findings)
    exact_analysis = exact.tool_bundles[0].analysis
    overflow_analysis = overflow.tool_bundles[0].analysis

    assert exact_analysis is not None
    assert exact_analysis.finding_limit_reached is False
    assert exact.summary.finding_limit_reached is False
    assert overflow_analysis is not None
    assert len(overflow_analysis.findings) == MAX_RETAINED_FINDINGS
    assert overflow_analysis.finding_limit_reached is True
    assert overflow.summary.finding_limit_reached is True


def test_markdown_keeps_skipped_tools_in_their_own_appendix(tmp_path):
    plan = _plan()
    plan.skipped_no_evidence = ["unused-tool"]
    plan.unhandled_evidence = ["legacy.evt"]
    report = build(
        inventory=Inventory(),
        plan=plan,
        execution=ExecutionBundle(),
        analyses=[],
        started_at="now",
        working_directory=str(tmp_path),
    )

    text = write_md(report, tmp_path / "report.md").read_text(encoding="utf-8")
    skipped_heading = text.index("## Appendix: tools skipped")
    skipped_item = text.index("- unused-tool")
    unhandled_heading = text.index("## Appendix: identified evidence")
    unhandled_item = text.index("- `legacy.evt`")

    assert skipped_heading < skipped_item < unhandled_heading < unhandled_item


def test_scan_coverage_is_preserved_in_summary_and_renderers(tmp_path):
    report = build(
        inventory=Inventory(
            depth_limit_hit=True,
            unreadable_paths=2,
            reparse_paths=3,
        ),
        plan=_plan(),
        execution=ExecutionBundle(),
        analyses=[],
        started_at="now",
        working_directory=str(tmp_path),
    )

    summary = report.to_dict()["summary"]
    assert summary["depth_limit_hit"] is True
    assert summary["unreadable_paths"] == 2
    assert summary["reparse_paths"] == 3

    markdown = write_md(report, tmp_path / "report.md").read_text(encoding="utf-8")
    assert "scan coverage: **incomplete**" in markdown
    assert "depth_limit_hit=true, unreadable_paths=2, reparse_paths=3" in markdown

    console = Console(record=True, width=120)
    render(report, console)
    terminal = console.export_text()
    assert "Scan coverage incomplete" in terminal
    assert "depth_limit_hit=true, unreadable_paths=2, reparse_paths=3" in terminal


def test_oversized_files_are_reported_without_skipped_tools(tmp_path):
    excluded = tmp_path / "large image.E01"
    report = build(
        inventory=Inventory(
            oversized_files=[{"path": str(excluded), "size_bytes": 1610612736}]
        ),
        plan=_plan(),
        execution=ExecutionBundle(),
        analyses=[],
        started_at="now",
        working_directory=str(tmp_path),
    )

    assert report.to_dict()["summary"]["oversized_files"] == 1
    assert report.to_dict()["evidence_inventory"]["oversized_files"][0][
        "path"
    ] == str(excluded)
    markdown = write_md(report, tmp_path / "report.md").read_text(encoding="utf-8")
    assert "Files excluded from scan (>=1.5 GiB)" in markdown
    assert "large image.E01" in markdown


def test_artifact_ledger_distinguishes_zero_findings_from_not_analyzed(tmp_path):
    analyzed_path = str(tmp_path / "analyzed.evtx")
    skipped_path = str(tmp_path / "skipped.evtx")
    oversized_path = str(tmp_path / "large.E01")
    inventory = Inventory(
        evidence_list=[
            Evidence(
                path=analyzed_path,
                filename="analyzed.evtx",
                size_bytes=100,
                evidence_type="evtx_log",
                detected_by="extension",
                sha256="a" * 64,
                mtime_ns=123,
            ),
            Evidence(
                path=skipped_path,
                filename="skipped.evtx",
                size_bytes=200,
                evidence_type="evtx_log",
                detected_by="extension",
                sha256="b" * 64,
                mtime_ns=456,
            ),
        ],
        oversized_files=[
            {"path": oversized_path, "size_bytes": 1610612736, "mtime_ns": 789}
        ],
    )
    plan = Plan(
        selected_tools=[
            ToolSelection(tool_id="analyzer", target_evidence=[analyzed_path]),
            ToolSelection(tool_id="missing", target_evidence=[skipped_path]),
        ]
    )
    execution = ExecutionBundle(
        results=[
            ExecutionResult(
                tool_id="analyzer",
                target_evidence=analyzed_path,
                status="success",
                command_executed="analyzer --json",
                artifacts=[
                    OutputArtifact(
                        path=str(tmp_path / "out.json"),
                        role="stdout",
                        format="json",
                        size_bytes=2,
                        sha256="c" * 64,
                    )
                ],
                provenance={"app_version": "0.0.1"},
            ),
            ExecutionResult(
                tool_id="missing",
                target_evidence=skipped_path,
                status="skipped",
                error_message="prerequisites failed: missing",
                provenance={"app_version": "0.0.1"},
            ),
        ]
    )
    report = build(
        inventory=inventory,
        plan=plan,
        execution=execution,
        analyses=[
            ToolAnalysis(
                tool_id="analyzer",
                target_evidence=analyzed_path,
                status="analyzed",
            ),
            ToolAnalysis(
                tool_id="missing",
                target_evidence=skipped_path,
                status="not_analyzed",
            ),
        ],
        started_at="now",
        working_directory=str(tmp_path),
    )

    by_path = {item["path"]: item for item in report.artifact_ledger}
    analyzed = by_path[analyzed_path]
    assert analyzed["sha256"] == "a" * 64
    assert analyzed["selected_tool_id"] == "analyzer"
    assert analyzed["executed_tool_ids"] == ["analyzer"]
    assert analyzed["preflight_status"] == "passed"
    assert analyzed["execution_status"] == "success"
    assert analyzed["analysis_status"] == "analyzed"
    assert analyzed["finding_count"] == 0

    skipped = by_path[skipped_path]
    assert skipped["preflight_status"] == "failed"
    assert skipped["analysis_status"] == "not_analyzed"
    assert skipped["finding_count"] is None

    oversized = by_path[oversized_path]
    assert oversized["discovery_status"] == "excluded_oversized"
    assert oversized["exclusion_reason"] == (
        "size is at or above the 1.5 GiB scan limit"
    )
    assert oversized["sha256"] is None
    assert oversized["selected_tool_id"] is None
    assert oversized["execution_status"] == "not_run"
    assert oversized["analysis_status"] == "not_analyzed"

    payload = report.to_dict()
    assert payload["artifact_ledger"] == report.artifact_ledger
    markdown = write_md(report, tmp_path / "coverage.md").read_text(encoding="utf-8")
    assert "## Artifact coverage ledger" in markdown
    assert "SHA-256 was not computed" in markdown

    stream = StringIO()
    render(
        report,
        Console(file=stream, force_terminal=False, color_system=None, width=200),
    )
    assert "Artifact coverage ledger" in stream.getvalue()


def test_summary_treats_finding_limit_as_incomplete_coverage(tmp_path):
    report = build(
        inventory=Inventory(),
        plan=_plan(),
        execution=ExecutionBundle(),
        analyses=[],
        started_at="now",
        working_directory=str(tmp_path),
    )
    report.summary.finding_limit_reached = True
    stream = StringIO()

    render_summary(
        report,
        Console(file=stream, force_terminal=False, color_system=None, width=160),
    )

    assert "기록된 coverage 경고 없음" not in stream.getvalue()
