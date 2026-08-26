"""Analyzer rules 단위 테스트.

id 기반 specific matcher (sigma_rule_hit, run_key_unusual_binary,
malfind_pe_in_unbacked_region) + 미등록 indicator 의 키워드 AND fallback
matcher 의 동작을 검증.
"""

from __future__ import annotations

import pytest

from forensicagent.analyzer.rules import apply_rules, supported_indicator_ids
from forensicagent.analyzer.types import SEVERITY_RANK
from forensicagent.tools.schema import CommandTemplate, SuspiciousIndicator, ToolMetadata


def _meta(
    *,
    tool_id: str = "fake",
    indicators: list[SuspiciousIndicator] | None = None,
) -> ToolMetadata:
    return ToolMetadata(
        tool_id=tool_id,
        display_name="Fake",
        category="log_analysis",
        applicable_evidence_types=["evtx_log"],
        command_templates=[
            CommandTemplate(name="x", template="x {evidence_path}", when="test"),
        ],
        usage_description="test",
        suspicious_indicators=indicators or [],
    )


def test_finding_cap_prioritizes_a_later_critical_indicator():
    meta = _meta(
        tool_id="evtxecmd",
        indicators=[
            SuspiciousIndicator(
                id="service_install_4697",
                pattern="service path",
                severity_baseline="low",
            ),
            SuspiciousIndicator(
                id="clear_log_event",
                pattern="log clear",
                severity_baseline="critical",
            ),
        ],
    )
    rows = [
        {
            "EventID": 4697,
            "Channel": "Security",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "ServiceFileName": f"%TEMP%\\svc-{index}.exe",
        }
        for index in range(501)
    ]
    rows.append(
        {
            "EventID": 1102,
            "Channel": "Security",
            "Provider": "Microsoft-Windows-Eventlog",
        }
    )

    findings = apply_rules({"items": rows}, "", meta)

    assert len(findings) == 500
    assert findings[0].rule_id == "clear_log_event:1102"


class TestSigmaRuleHit:
    def test_emits_finding_per_rule_name(self):
        meta = _meta(
            indicators=[
                SuspiciousIndicator(
                    id="sigma_rule_hit",
                    pattern="rule_name field exists",
                    severity_baseline="medium",
                )
            ]
        )
        parsed = {"items": [
            {"rule_name": "Encoded PowerShell", "event_id": 4104},
            {"rule_name": "RDP from external IP", "event_id": 4624},
            {"event_id": 1234},  # no rule_name → should be skipped
        ]}
        findings = apply_rules(parsed, "", meta)
        assert len(findings) == 2
        titles = {f.title for f in findings}
        assert "Sigma rule match: Encoded PowerShell" in titles
        assert "Sigma rule match: RDP from external IP" in titles
        for f in findings:
            assert f.severity == "medium"
            assert f.category == "threat_intel"
            assert f.source == "rule"

    def test_handles_alternate_rule_field_names(self):
        meta = _meta(
            indicators=[SuspiciousIndicator(id="sigma_rule_hit", pattern="x")]
        )
        # `name` 또는 `rule` 도 fallback 으로 받아들여야 한다.
        parsed = {"items": [{"name": "Alt Field Match"}]}
        findings = apply_rules(parsed, "", meta)
        assert len(findings) == 1
        assert "Alt Field Match" in findings[0].title

    def test_empty_items_no_finding(self):
        meta = _meta(
            indicators=[SuspiciousIndicator(id="sigma_rule_hit", pattern="x")]
        )
        assert apply_rules({"items": []}, "", meta) == []
        assert apply_rules({}, "", meta) == []
        assert apply_rules([], "", meta) == []


class TestRunKeyUnusualBinary:
    def test_detects_appdata_path(self):
        meta = _meta(
            indicators=[
                SuspiciousIndicator(
                    id="run_key_unusual_binary",
                    pattern="Run key in AppData/Temp",
                    severity_baseline="high",
                )
            ]
        )
        raw = (
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
            "  malware = %AppData%\\foo.exe\n"
            "  legit = C:\\Program Files\\Vendor\\app.exe\n"
            "  another = C:\\Users\\Public\\xyz.exe\n"
        )
        findings = apply_rules({}, raw, meta)
        # %AppData% line + Public line → 2 matches.
        assert len(findings) == 2
        assert all(f.severity == "high" for f in findings)
        assert all(f.category == "persistence" for f in findings)

    def test_no_match_on_clean_run_keys(self):
        meta = _meta(
            indicators=[SuspiciousIndicator(id="run_key_unusual_binary", pattern="x")]
        )
        raw = (
            "  OneDrive = C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe\n"
            "  SecurityHealth = C:\\Windows\\System32\\SecurityHealthSystray.exe\n"
        )
        findings = apply_rules({}, raw, meta)
        assert findings == []

    def test_temp_executable_named_runme_is_not_a_run_key(self):
        meta = _meta(
            indicators=[SuspiciousIndicator(id="run_key_unusual_binary", pattern="x")]
        )
        assert apply_rules({}, "C:\\Temp\\runme.exe\n", meta) == []


class TestUnsupportedIndicator:
    """등록되지 않은 indicator의 자연어 pattern은 실행하지 않는다."""

    def test_returns_no_findings_and_warns(self, caplog):
        meta = _meta(
            indicators=[
                SuspiciousIndicator(
                    id="custom_unregistered",
                    pattern="suspicious pattern in security log",
                    severity_baseline="high",
                )
            ]
        )
        raw = "\n".join([
            "SUSPICIOUS pattern observed in SECURITY",
            "normal log line",
            "another suspicious pattern in event log",
            "only suspicious without the other word",
        ])
        findings = apply_rules({}, raw, meta)
        assert findings == []
        assert "custom_unregistered" not in supported_indicator_ids()
        assert "unsupported suspicious indicator id='custom_unregistered'" in caplog.text

    def test_short_unknown_pattern_returns_empty(self):
        meta = _meta(
            indicators=[
                SuspiciousIndicator(id="short", pattern="a b c d", severity_baseline="low")
            ]
        )
        assert apply_rules({}, "any text here", meta) == []

    def test_unknown_pattern_does_not_scan_repeated_matching_lines(self):
        meta = _meta(
            indicators=[
                SuspiciousIndicator(
                    id="cap_test",
                    pattern="suspicious pattern detection",
                    severity_baseline="low",
                )
            ]
        )
        raw = "\n".join(
            f"line {i}: suspicious pattern repeated again" for i in range(200)
        )
        assert apply_rules({}, raw, meta) == []


class TestMultipleIndicators:
    def test_all_indicators_applied(self):
        meta = _meta(
            indicators=[
                SuspiciousIndicator(id="sigma_rule_hit", pattern="x", severity_baseline="medium"),
                SuspiciousIndicator(id="run_key_unusual_binary", pattern="y", severity_baseline="high"),
            ]
        )
        parsed = {"items": [
            {"rule_name": "Suspect Login"},
            {
                "Key Path": "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "Value Data": "%Temp%\\bad.exe",
            },
        ]}
        raw = ""
        findings = apply_rules(parsed, raw, meta)
        # 1 from sigma_rule_hit + 1 from run_key_unusual_binary.
        assert len(findings) == 2
        sources = {f.category for f in findings}
        assert sources == {"threat_intel", "persistence"}


class TestEvidencePathInjection:
    def test_path_filled_when_missing(self):
        meta = _meta(
            indicators=[
                SuspiciousIndicator(id="sigma_rule_hit", pattern="x")
            ]
        )
        findings = apply_rules(
            {"items": [{"rule_name": "X"}]},
            "",
            meta,
            evidence_path="/case/Security.evtx",
        )
        assert findings[0].evidence_ref.source_file == "/case/Security.evtx"


class TestRuleIsolation:
    """한 룰이 예외를 던져도 다른 룰은 계속 실행되어야 한다."""

    def test_robust_to_bad_indicator(self, monkeypatch):
        # specific matcher 가 예외를 던지도록 임시 패치.
        from forensicagent.analyzer import rules as rules_mod

        def boom(*a, **k):
            raise RuntimeError("rule crash")

        original = rules_mod._SPECIFIC_MATCHERS.get("sigma_rule_hit")
        try:
            rules_mod._SPECIFIC_MATCHERS["sigma_rule_hit"] = boom
            meta = _meta(
                indicators=[
                    SuspiciousIndicator(id="sigma_rule_hit", pattern="x"),
                    SuspiciousIndicator(
                        id="run_key_unusual_binary", pattern="x", severity_baseline="high"
                    ),
                ]
            )
            # sigma_rule_hit 는 터지지만 run_key_unusual_binary 는 정상 동작해야.
            findings = apply_rules(
                {},
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
                "  bad = %AppData%\\x.exe\n",
                meta,
            )
            assert len(findings) == 1
            assert findings[0].category == "persistence"
        finally:
            if original is not None:
                rules_mod._SPECIFIC_MATCHERS["sigma_rule_hit"] = original
