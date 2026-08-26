from __future__ import annotations

import json
from datetime import datetime, timedelta
from io import StringIO

import pytest
from hypothesis import given, settings, strategies as st
from rich.console import Console

from forensicagent.analyzer.rules import _canonical_ip, apply_rules
from forensicagent.analyzer.types import EvidenceRef, Finding, ToolAnalysis
from forensicagent.cli.repl import _summary_context, do_annotate, do_show
from forensicagent.cli.session import SessionState
from forensicagent.executor.types import ExecutionBundle, ExecutionResult
from forensicagent.reporter.annotations import (
    AnnotationStoreError,
    annotation_path,
    load_annotations,
    save_annotation,
)
from forensicagent.reporter.md_out import write_md
from forensicagent.reporter.reporter import write
from forensicagent.reporter.terminal import render
from forensicagent.reporter.types import Report, Summary, ToolBundle
from forensicagent.scanner.types import Inventory
from forensicagent.selector.types import Plan, ToolSelection
from forensicagent.tools.schema import CommandTemplate, SuspiciousIndicator, ToolMetadata


def _meta(*indicator_ids: str) -> ToolMetadata:
    return ToolMetadata(
        tool_id="fake",
        display_name="Fake",
        category="log_analysis",
        applicable_evidence_types=["evtx_log"],
        command_templates=[
            CommandTemplate(name="test", template="test {evidence_path}", when="test")
        ],
        usage_description="test",
        suspicious_indicators=[
            SuspiciousIndicator(
                id=indicator_id,
                pattern="structured test",
                severity_baseline="high",
            )
            for indicator_id in indicator_ids
        ],
    )


@settings(max_examples=100, deadline=None)
@given(st.ip_addresses())
def test_ip_normalization_matches_stdlib_for_the_address_domain(address):
    expected = "" if address.is_unspecified else address.compressed.casefold()
    assert _canonical_ip(str(address)) == expected


@settings(max_examples=100, deadline=None)
@given(st.ip_addresses(v=4), st.integers(min_value=1, max_value=65_535))
def test_ipv4_port_wrapper_does_not_change_normalized_identity(address, port):
    expected = "" if address.is_unspecified else address.compressed
    assert _canonical_ip(f"{address}:{port}") == expected


@settings(max_examples=100, deadline=None)
@given(st.ip_addresses(v=6), st.integers(min_value=1, max_value=65_535))
def test_bracketed_ipv6_port_wrapper_does_not_change_identity(address, port):
    expected = "" if address.is_unspecified else address.compressed.casefold()
    assert _canonical_ip(f"[{address}]:{port}") == expected


def test_entities_are_explicit_and_do_not_change_fingerprint():
    finding = Finding(
        rule_id="rule:test",
        evidence_ref=EvidenceRef(
            source_file="evidence.evtx",
            event_id=4624,
            timestamp="2026-01-01T00:00:00Z",
            raw_excerpt="same evidence",
        ),
    )
    original = finding.fingerprint

    finding.entities = {"user": ["alice"], "ip": ["2001:db8::1"]}

    assert finding.refresh_fingerprint() == original
    assert finding.to_dict()["entities"] == finding.entities
    assert Finding(source="llm").entities == {}


def test_semantic_rules_emit_canonical_user_ip_and_process_entities():
    rdp = apply_rules(
        {
            "items": [
                {
                    "EventID": 4624,
                    "Channel": "Security",
                    "Provider": "Microsoft-Windows-Security-Auditing",
                    "LogonType": 10,
                    "IpAddress": "8.8.8.8:3389",
                    "TargetUserName": "DOMAIN\\Alice",
                }
            ]
        },
        "",
        _meta("rdp_logon_external_ip"),
    )[0]
    network = apply_rules(
        {
            "items": [
                {
                    "State": "ESTABLISHED",
                    "ForeignAddr": "[2606:4700:4700::1111]",
                    "ForeignPort": 4444,
                    "Owner": "C:\\Temp\\EVIL.EXE",
                }
            ]
        },
        "",
        _meta("netscan_to_known_bad_or_rare_ip"),
    )[0]

    assert rdp.entities == {"user": ["alice"], "ip": ["8.8.8.8"]}
    assert network.entities == {
        "ip": ["2606:4700:4700::1111"],
        "process": ["evil.exe"],
    }


def test_annotation_store_roundtrip_preserves_notes_and_stale_entries(tmp_path):
    first = "a" * 64
    stale = "b" * 64
    save_annotation(tmp_path, first, "confirmed", "reviewed")
    save_annotation(tmp_path, stale, "false_positive", "old case finding")

    updated = save_annotation(tmp_path, first, "pending")
    stored = load_annotations(tmp_path)

    assert updated["notes"] == "reviewed"
    assert set(stored) == {first, stale}
    assert stored[first]["status"] == "pending"
    parsed = datetime.fromisoformat(stored[first]["updated_at"])
    assert parsed.utcoffset() == timedelta(0)


@pytest.mark.parametrize(
    "contents",
    [
        "not json",
        '{"schema_version":2,"annotations":{}}',
        '{"schema_version":1,"annotations":{},"unknown":true}',
    ],
)
def test_unsafe_annotation_store_is_never_overwritten(tmp_path, contents):
    path = annotation_path(tmp_path)
    path.write_text(contents, encoding="utf-8")
    before = path.read_bytes()

    with pytest.raises(AnnotationStoreError):
        save_annotation(tmp_path, "a" * 64, "confirmed", "do not write")

    assert path.read_bytes() == before


def test_deep_annotation_json_does_not_crash_or_overwrite_report_store(tmp_path):
    path = annotation_path(tmp_path)
    nested = (
        '{"schema_version":1,"annotations":'
        + "[" * 2_000
        + "0"
        + "]" * 2_000
        + "}"
    )
    path.write_text(nested, encoding="utf-8")
    before = path.read_bytes()
    finding = Finding(title="current", rule_id="current")

    with pytest.raises(AnnotationStoreError):
        load_annotations(tmp_path)
    report, paths = write(
        inventory=Inventory(),
        plan=Plan(
            selected_tools=[
                ToolSelection(tool_id="fake", target_evidence=["evidence.evtx"])
            ]
        ),
        execution=ExecutionBundle(
            results=[ExecutionResult(tool_id="fake", status="success")]
        ),
        analyses=[ToolAnalysis(tool_id="fake", findings=[finding])],
        started_at="2026-01-01T00:00:00+00:00",
        working_directory=str(tmp_path),
        output_dir=tmp_path,
        formats=("json",),
    )

    assert paths["json"].exists()
    assert report.annotation_for(finding.fingerprint)["status"] == "pending"
    assert path.read_bytes() == before


def _correlation_report() -> tuple[Report, list[Finding]]:
    findings = [
        Finding(
            severity="high",
            title="First",
            rule_id="first",
            evidence_ref=EvidenceRef(
                timestamp="2026-01-01T00:00:00Z",
                raw_excerpt="secret excerpt one",
            ),
            entities={"user": ["alice"], "process": ["cmd.exe"]},
        ),
        Finding(
            severity="medium",
            title="Second",
            rule_id="second",
            evidence_ref=EvidenceRef(timestamp="2026-01-01T00:01:00Z"),
            entities={"user": ["alice"], "ip": ["8.8.8.8"]},
        ),
        Finding(
            severity="low",
            title="Third",
            rule_id="third",
            evidence_ref=EvidenceRef(timestamp="2026-01-01T00:02:00Z"),
            entities={"process": ["cmd.exe"]},
        ),
    ]
    report = Report(
        tool_bundles=[
            ToolBundle(
                tool_id="fake",
                analysis=ToolAnalysis(tool_id="fake", findings=findings),
            )
        ],
        summary=Summary(
            total_findings=3,
            by_severity={"high": 1, "medium": 1, "low": 1},
        ),
        analyst_annotations={
            findings[0].fingerprint: {
                "status": "false_positive",
                "notes": "# note | [literal]\x1b]52;payload",
                "updated_at": "2026-01-01T01:00:00+00:00",
            }
        },
    )
    return report, findings


def test_correlations_and_annotations_render_without_suppressing_findings(tmp_path):
    report, findings = _correlation_report()

    payload = report.to_dict()
    correlations = payload["correlations"]
    assert [(item["entity_type"], item["entity_value"]) for item in correlations] == [
        ("user", "alice"),
        ("process", "cmd.exe"),
    ]
    assert "raw_excerpt" not in json.dumps(correlations)
    assert "secret excerpt one" not in json.dumps(correlations)
    assert payload["summary"]["total_findings"] == 3
    assert len(payload["tool_results"][0]["analysis"]["findings"]) == 3
    assert len(payload["timeline"]["events"]) == 3
    assert payload["timeline"]["events"][0]["annotation_status"] == "false_positive"
    assert all(
        any(ref["fingerprint"] == findings[0].fingerprint for ref in item["findings"])
        for item in correlations
    )

    markdown = write_md(report, tmp_path / "report.md").read_text(encoding="utf-8")
    assert "Related findings sharing an entity" in markdown
    assert "false\\_positive" in markdown
    assert "\\# note \\| \\[literal\\]" in markdown
    assert "\x1b" not in markdown

    stream = StringIO()
    render(
        report,
        Console(file=stream, force_terminal=True, color_system=None, width=220),
    )
    terminal = stream.getvalue()
    assert "Related findings sharing an entity" in terminal
    assert "false_positive" in terminal
    assert "analyst note" in terminal
    assert "\x1b" not in terminal


def test_report_loads_only_current_annotations_but_preserves_stale_store(tmp_path):
    finding = Finding(title="current", rule_id="current")
    stale = "f" * 64
    save_annotation(tmp_path, finding.fingerprint, "confirmed", "current note")
    save_annotation(tmp_path, stale, "false_positive", "stale note")

    report, paths = write(
        inventory=Inventory(),
        plan=Plan(
            selected_tools=[
                ToolSelection(tool_id="fake", target_evidence=["evidence.evtx"])
            ]
        ),
        execution=ExecutionBundle(
            results=[ExecutionResult(tool_id="fake", status="success")]
        ),
        analyses=[ToolAnalysis(tool_id="fake", findings=[finding])],
        started_at="2026-01-01T00:00:00+00:00",
        working_directory=str(tmp_path),
        output_dir=tmp_path,
        formats=("json",),
    )

    assert set(report.analyst_annotations) == {finding.fingerprint}
    assert set(report.to_dict()["analyst_annotations"]) == {finding.fingerprint}
    assert set(load_annotations(tmp_path)) == {finding.fingerprint, stale}
    saved = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert set(saved["analyst_annotations"]) == {finding.fingerprint}


def test_annotate_uses_unique_prefix_and_invalidates_only_report(tmp_path):
    finding = Finding(title="one", rule_id="one")
    analyses = [ToolAnalysis(tool_id="fake", findings=[finding])]
    state = SessionState(
        target_path=tmp_path,
        output_dir=tmp_path / "case",
        tool_metas={},
        analyses=analyses,
        last_report=Report(),
        last_report_paths={"json": tmp_path / "old.json"},
    )
    stream = StringIO()
    console = Console(file=stream, force_terminal=True, color_system=None, width=400)

    do_annotate(
        state,
        console,
        finding.fingerprint[:12],
        "confirmed",
        "[bold]literal[/bold]\x1b]52;payload",
    )

    stored = load_annotations(state.output_dir)[finding.fingerprint]
    assert stored["status"] == "confirmed"
    assert state.analyses is analyses
    assert state.last_report is None
    assert state.last_report_paths == {}
    assert "\x1b" not in stream.getvalue()

    do_show(state, console, "findings")
    assert "confirmed" in stream.getvalue()


def test_annotate_rejects_short_or_ambiguous_prefix_without_mutation(tmp_path):
    first = Finding(title="first")
    second = Finding(title="second")
    first.fingerprint = "a" * 64
    second.fingerprint = "a" * 8 + "b" * 56
    report = Report()
    state = SessionState(
        target_path=tmp_path,
        output_dir=tmp_path / "case",
        tool_metas={},
        analyses=[ToolAnalysis(tool_id="fake", findings=[first, second])],
        last_report=report,
    )
    console = Console(file=StringIO(), force_terminal=False, color_system=None)

    do_annotate(state, console, "a" * 7, "confirmed")
    do_annotate(state, console, "a" * 8, "confirmed")

    assert not annotation_path(state.output_dir).exists()
    assert state.last_report is report


def test_annotation_notes_never_enter_summary_llm_context():
    report, findings = _correlation_report()
    context = _summary_context(report)

    assert report.annotation_for(findings[0].fingerprint)["notes"] not in context
    assert "analyst_annotations" not in context
