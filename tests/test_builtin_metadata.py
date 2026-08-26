from pathlib import Path

from forensicagent.analyzer.rules import supported_indicator_ids
from forensicagent.tools.loader import load_all_tools


def test_all_builtin_indicators_have_concrete_matchers():
    tools_dir = Path(__file__).resolve().parents[1] / "tools_metadata"
    tools = load_all_tools(tools_dir)
    declared = {
        indicator.id
        for metadata in tools.values()
        for indicator in metadata.suspicious_indicators
    }

    supported = supported_indicator_ids()

    assert len(declared) == 34
    assert len(supported) == 41
    assert declared <= supported
    assert "amcache_signing_status_invalid" not in {
        indicator.id for indicator in tools["amcacheparser"].suspicious_indicators
    }
    assert "prefetch_unusual_path" not in {
        indicator.id for indicator in tools["pecmd"].suspicious_indicators
    }
    assert {
        "rdp_logon_external_ip",
        "failed_logon_burst",
        "account_creation_4720",
        "clear_log_event",
    } <= {indicator.id for indicator in tools["chainsaw"].suspicious_indicators}
    assert tools["gitleaks"].version_supported.startswith("8.30.0")
    assert tools["gitleaks"].install_check.expected_pattern == "8.30.0"


def test_code_security_commands_resist_evidence_controlled_suppressions():
    tools_dir = Path(__file__).resolve().parents[1] / "tools_metadata"
    tools = load_all_tools(tools_dir)
    bandit = tools["bandit"]
    gitleaks = tools["gitleaks"]
    semgrep = tools["semgrep"]

    assert bandit.output_format == "csv"
    assert "--ignore-nosec" in bandit.command_templates[0].template
    assert "{output_dir}/bandit.csv" in bandit.command_templates[0].template
    assert gitleaks.output_format == "csv"
    assert "--ignore-gitleaks-allow" in gitleaks.command_templates[0].template
    assert "--gitleaks-ignore-path {output_dir}" in gitleaks.command_templates[0].template
    assert "--redact" in gitleaks.command_templates[0].template
    assert "{output_dir}/gitleaks.csv" in gitleaks.command_templates[0].template
    assert "--disable-nosem" in semgrep.command_templates[0].template
    assert "--no-git-ignore" in semgrep.command_templates[0].template
    assert "--metrics" not in semgrep.command_templates[0].template


def test_platform_and_memory_input_contracts_match_executables():
    tools_dir = Path(__file__).resolve().parents[1] / "tools_metadata"
    tools = load_all_tools(tools_dir)

    for tool_id in (
        "amcacheparser",
        "appcompatcacheparser",
        "evtxecmd",
        "mftecmd",
        "recmd",
    ):
        assert tools[tool_id].platform == ["windows"]
    assert "ext:.bin" in tools["volatility3"].input_format
