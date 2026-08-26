"""ChainsawAdapter — 파일(채널)별 Event ID 타겟팅 + Tau 질의 테스트.

핵심 회귀 방지 대상:
  * Event ID는 직렬화된 전체 레코드 정규식이 아니라 Tau 필드 질의로 찾는다.
  * Event ID 는 채널마다 다르다: 4624/4625 는 Security, 4104 는 PowerShell
    Operational. 파일명으로 올바른 ID 를 골라야 한다.

LLM / 네트워크 없이 결정론적으로 검증한다.
"""

from __future__ import annotations

from pathlib import Path

from forensicagent.executor.adapter import get_adapter
from forensicagent.executor.chainsaw_adapter import (
    DEFAULT_EVENT_IDS,
    ChainsawAdapter,
    event_ids_for_file,
)
from forensicagent.tools.loader import load_tool
from forensicagent.tools.schema import CommandTemplate, InstallCheck, ToolMetadata


_METADATA = Path(__file__).resolve().parents[1] / "tools_metadata"
_SEARCH_TEMPLATE = (
    "chainsaw search -t {channel_event_ids} --match-any --jsonl "
    "--output {output_dir}/chainsaw.jsonl {evidence_path}"
)


def _chainsaw_meta() -> ToolMetadata:
    return ToolMetadata(
        tool_id="chainsaw",
        display_name="Chainsaw",
        category="log_analysis",
        applicable_evidence_types=["evtx_log"],  # type: ignore[arg-type]
        command_templates=[
            CommandTemplate(
                name="search",
                template=_SEARCH_TEMPLATE,
                when="특정 Event ID 검색.",
            )
        ],
        install_check=InstallCheck(
            command="chainsaw --version", expected_pattern="chainsaw"
        ),
        output_format="jsonl",
        usage_description="Windows EVTX hunting.",
    )


# ---- channel → event id mapping ----

def test_security_channel_gets_logon_ids():
    ids = event_ids_for_file("Security.evtx")
    assert "4624" in ids
    assert "4625" in ids
    assert "1102" in ids


def test_powershell_channel_gets_scriptblock_id():
    assert event_ids_for_file(
        "Microsoft-Windows-PowerShell%4Operational.evtx"
    ) == ["4103", "4104"]


def test_channel_detection_is_case_insensitive():
    assert "4624" in event_ids_for_file("security.EVTX")


def test_powershell_takes_precedence_and_is_not_treated_as_security():
    # PowerShell 파일명엔 'security' 가 없어 로그온 ID 로 새지 않아야 한다.
    ids = event_ids_for_file("microsoft-windows-powershell%4operational.evtx")
    assert ids == ["4103", "4104"]


def test_unknown_channel_uses_small_cross_channel_fallback():
    ids = event_ids_for_file("host123.evtx")
    assert {"4104", "4697", "4720", "4732", "7045"} <= set(ids)


def test_security_substring_is_not_mistaken_for_security_channel():
    ids = event_ids_for_file(
        "Microsoft-Windows-Security-Mitigations%4KernelMode.evtx"
    )
    assert ids == DEFAULT_EVENT_IDS


def test_system_substring_is_not_mistaken_for_system_channel():
    ids = event_ids_for_file(
        "Microsoft-Windows-SystemEventsBroker%4Operational.evtx"
    )
    assert ids == DEFAULT_EVENT_IDS


def test_system_and_sysmon_channels_get_channel_specific_ids():
    assert event_ids_for_file("System.evtx") == ["104", "7045"]
    assert "1" in event_ids_for_file(
        "Microsoft-Windows-Sysmon%4Operational.evtx"
    )


# ---- command building ----

def test_registry_wires_chainsaw_to_specialized_adapter():
    adapter = get_adapter(_chainsaw_meta())
    assert isinstance(adapter, ChainsawAdapter)


def test_build_command_uses_tau_and_match_any():
    adapter = ChainsawAdapter(_chainsaw_meta())
    argv = adapter.build_command(r"C:\ev\Security.evtx", output_dir="out")
    assert argv[:2] == ["chainsaw", "search"]
    assert "-e" not in argv
    assert "--match-any" in argv
    assert "Event.System.EventID: =4624" in argv
    assert "Event.System.EventID: =4625" in argv
    assert argv[-4:] == [
        "--jsonl",
        "--output",
        str(Path("out") / "chainsaw.jsonl"),
        r"C:\ev\Security.evtx",
    ]
    assert adapter.selected_template == _SEARCH_TEMPLATE


def test_metadata_declares_only_the_command_the_adapter_can_execute():
    metadata = load_tool(_METADATA / "chainsaw.yaml")
    adapter = ChainsawAdapter(metadata)
    argv = adapter.build_command(
        r"C:\ev\Security.evtx",
        output_dir="out",
        preferred_template=metadata.command_templates[0].template,
    )

    assert argv[:2] == ["chainsaw", "search"]
    assert adapter.selected_template == metadata.command_templates[0].template
    assert {indicator.id for indicator in metadata.suspicious_indicators} >= {
        "rdp_logon_offhours",
        "brute_force_followed_by_success",
        "powershell_encoded_command",
        "service_install_4697",
    }
    assert "sigma_rule_hit" not in {
        indicator.id for indicator in metadata.suspicious_indicators
    }


def test_sigma_template_is_rejected_without_rules_and_mapping_paths():
    adapter = ChainsawAdapter(_chainsaw_meta())

    try:
        adapter.build_command(
            r"C:\ev\Security.evtx",
            output_dir="out",
            preferred_template=(
                "chainsaw hunt {evidence_path} -s {sigma_path} "
                "--mapping {mapping_path} --json"
            ),
        )
    except ValueError as error:
        assert "rules and mapping paths" in str(error)
    else:
        raise AssertionError("unsupported Sigma hunt template was accepted")


def test_build_command_per_file_event_ids():
    adapter = ChainsawAdapter(_chainsaw_meta())
    ps = adapter.build_command(
        r"C:\ev\Microsoft-Windows-PowerShell%4Operational.evtx",
        output_dir="out",
    )
    assert "Event.System.EventID: =4104" in ps


def test_path_with_spaces_stays_single_argv_element():
    adapter = ChainsawAdapter(_chainsaw_meta())
    argv = adapter.build_command(r"C:\eviing dir\Security.evtx", output_dir="o")
    assert r"C:\eviing dir\Security.evtx" in argv
