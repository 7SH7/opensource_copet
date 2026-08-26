from __future__ import annotations

from datetime import datetime, timedelta, timezone

import forensicagent.analyzer.rules as rules
from forensicagent.tools.schema import (
    CommandTemplate,
    SuspiciousIndicator,
    ToolMetadata,
)


def _metadata(*indicator_ids: str, evidence_type: str = "evtx_log") -> ToolMetadata:
    return ToolMetadata(
        tool_id="test",
        display_name="test",
        category="log_analysis",
        applicable_evidence_types=[evidence_type],
        command_templates=[
            CommandTemplate(name="test", template="test {evidence_path}", when="test")
        ],
        usage_description="test",
        suspicious_indicators=[
            SuspiciousIndicator(id=indicator_id, pattern="test")
            for indicator_id in indicator_ids
        ],
    )


def _security_event(event_id: int, timestamp: datetime, **fields: object) -> dict:
    return {
        "EventId": event_id,
        "Channel": "Security",
        "Provider": "Microsoft-Windows-Security-Auditing",
        "TimeCreated": timestamp.isoformat(),
        **fields,
    }


def _signature(finding: rules.Finding) -> tuple:
    return (
        finding.rule_id,
        finding.title,
        finding.description,
        finding.evidence_ref.event_id,
        finding.evidence_ref.timestamp,
        finding.evidence_ref.raw_excerpt,
        finding.entities,
    )


def test_evtx_prefilter_matches_full_input_and_preserves_event_order() -> None:
    start = datetime(2025, 1, 1, tzinfo=timezone.utc)
    rows = []
    for offset in range(10):
        rows.extend(
            (
                _security_event(
                    4625,
                    start + timedelta(seconds=offset),
                    IpAddress="203.0.113.10",
                    TargetUserName="alice",
                ),
                _security_event(1, start + timedelta(seconds=offset)),
            )
        )
    rows.extend(
        (
            _security_event(
                4624,
                start + timedelta(seconds=20),
                IpAddress="203.0.113.10",
                TargetUserName="alice",
                LogonType=3,
            ),
            _security_event(4720, start, TargetUserName="backdoor"),
            _security_event(1, start + timedelta(seconds=21)),
            _security_event(
                4732,
                start + timedelta(seconds=30),
                MemberName="backdoor",
                TargetSid="S-1-5-32-544",
            ),
        )
    )
    parsed = {"items": rows}
    metadata = _metadata(
        "brute_force_followed_by_success",
        "failed_logon_burst",
        "account_creation_4720",
    )

    expected = []
    for indicator in metadata.suspicious_indicators:
        expected.extend(
            rules._SPECIFIC_MATCHERS[indicator.id](
                parsed, "", metadata, indicator
            )
        )
    actual = rules.apply_rules(parsed, "", metadata)

    assert [_signature(item) for item in actual] == [
        _signature(item) for item in expected
    ]
    assert {item.rule_id for item in actual} == {
        "brute_force_followed_by_success",
        "failed_logon_burst",
        "account_creation_4720",
    }


def test_evtx_prefilter_indexes_each_irrelevant_row_once(monkeypatch) -> None:
    metadata = _metadata(*rules._EVTX_EVENT_IDS)
    rows = [{"EventId": 1, "marker": index} for index in range(100)]
    original = rules._event_id
    calls = 0

    def counted(row: dict) -> int | None:
        nonlocal calls
        calls += 1
        return original(row)

    monkeypatch.setattr(rules, "_event_id", counted)

    assert rules.apply_rules({"items": rows}, "", metadata) == []
    assert calls == len(rows)


def test_non_evtx_matcher_receives_original_input(monkeypatch) -> None:
    metadata = _metadata("clear_log_event", evidence_type="text_log")
    parsed = {"items": [{"EventId": 104}]}
    received = []

    def matcher(value, *_args):
        received.append(value)
        return []

    monkeypatch.setitem(rules._SPECIFIC_MATCHERS, "clear_log_event", matcher)

    assert rules.apply_rules(parsed, "", metadata) == []
    assert received == [parsed]
