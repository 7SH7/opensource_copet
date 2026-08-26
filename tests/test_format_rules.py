from __future__ import annotations

from pathlib import Path

from forensicagent.analyzer.rules import apply_rules
from forensicagent.tools.loader import load_tool


TOOLS = Path(__file__).resolve().parents[1] / "tools_metadata"


def test_browser_download_rule_uses_structured_download_rows():
    metadata = load_tool(TOOLS / "browser_sqlite.yaml")
    findings = apply_rules(
        {
            "items": [
                {
                    "record_type": "browser_download",
                    "timestamp": "2026-01-02T03:04:05Z",
                    "url": "https://example.test/payload.exe",
                    "target_path": "C:/Users/alice/Downloads/payload.exe",
                },
                {
                    "record_type": "browser_download",
                    "url": "https://example.test/archive.zip",
                    "target_path": "C:/Users/alice/Downloads/archive.zip",
                },
            ]
        },
        "",
        metadata,
        evidence_path="History",
    )

    assert [finding.rule_id for finding in findings] == ["browser_suspicious_download"]
    assert findings[0].evidence_ref.timestamp == "2026-01-02T03:04:05Z"
    assert findings[0].evidence_ref.source_file == "History"
    assert findings[0].category == "file_acquisition"
    assert "does not prove execution" in findings[0].alternative_explanation


def test_pcap_rules_are_conservative_and_preserve_packet_time():
    metadata = load_tool(TOOLS / "tshark.yaml")
    encoded = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0"
    rows = {
        "items": [
            {
                "frame.time_epoch": "1760000000.5",
                "ip.dst": "8.8.8.8",
                "tcp.dstport": "4444",
            },
            {"ip.dst": "10.0.0.4", "tcp.dstport": "4444"},
            {"dns.qry.name": ".".join([encoded, encoded, encoded, encoded, "example"])},
            {"dns.qry.name": "ordinary.example"},
        ]
    }

    findings = apply_rules(rows, "", metadata, evidence_path="capture.pcap")

    assert {finding.rule_id for finding in findings} == {
        "pcap_suspicious_remote_port",
        "pcap_long_dns_query",
    }
    remote = next(
        finding for finding in findings if finding.rule_id == "pcap_suspicious_remote_port"
    )
    assert remote.evidence_ref.timestamp.endswith("Z")
    assert {finding.category for finding in findings} == {"network_anomaly"}


def test_fls_rule_requires_deleted_marker_path_and_executable_suffix():
    metadata = load_tool(TOOLS / "fls.yaml")
    raw = "\n".join(
        [
            "r/r * 1304-128-1: Users/alice/AppData/Local/Temp/dropper.exe",
            "r/r 1305-128-1: Users/alice/AppData/Local/Temp/live.exe",
            "r/r * 1306-128-1: Users/alice/Documents/note.txt",
        ]
    )

    findings = apply_rules(None, raw, metadata, evidence_path="disk.dd")

    assert [finding.rule_id for finding in findings] == [
        "fls_deleted_suspicious_file"
    ]
    assert "dropper.exe" in findings[0].description
