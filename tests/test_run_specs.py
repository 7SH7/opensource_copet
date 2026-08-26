from __future__ import annotations

from pathlib import Path

import pytest

from forensicagent.scanner.types import Evidence, Inventory
from forensicagent.selector import RunSpec, select
from forensicagent.tools.loader import load_tool


_METADATA = Path(__file__).resolve().parents[1] / "tools_metadata"


def _evidence(
    path: Path,
    evidence_type: str,
    *,
    platform_hint: str = "unknown",
) -> Evidence:
    return Evidence(
        path=str(path),
        filename=path.name,
        size_bytes=100,
        evidence_type=evidence_type,  # type: ignore[arg-type]
        detected_by="extension",
        platform_hint=platform_hint,  # type: ignore[arg-type]
        confidence=0.9,
    )


def test_volatility_without_scenario_runs_complete_detector_coverage(tmp_path):
    metadata = load_tool(_METADATA / "volatility3.yaml")
    inventory = Inventory(
        evidence_list=[_evidence(tmp_path / "memory.raw", "memory_dump")]
    )

    default = select(
        inventory,
        {metadata.tool_id: metadata},
        use_llm=False,
        use_rag=False,
    ).selected_tools[0]
    full = select(
        inventory,
        {metadata.tool_id: metadata},
        use_llm=False,
        use_rag=False,
        scenario="full triage for suspicious network and memory injection",
    ).selected_tools[0]

    assert [spec.label for spec in default.run_specs] == [
        "pslist",
        "cmdline",
        "netscan",
        "malfind",
        "pstree",
    ]
    assert [spec.label for spec in full.run_specs] == [
        "pslist",
        "cmdline",
        "netscan",
        "malfind",
        "pstree",
    ]
    assert all(spec.target_evidence.endswith("memory.raw") for spec in full.run_specs)


@pytest.mark.parametrize(
    "scenario",
    [
        "Investigate unusual network connections",
        "Investigate account compromise",
    ],
)
def test_volatility_scenario_preserves_complete_detector_coverage(
    tmp_path,
    scenario,
):
    metadata = load_tool(_METADATA / "volatility3.yaml")
    inventory = Inventory(
        evidence_list=[_evidence(tmp_path / "capture.vmem", "memory_dump")]
    )

    selection = select(
        inventory,
        {metadata.tool_id: metadata},
        use_llm=False,
        use_rag=False,
        scenario=scenario,
    ).selected_tools[0]

    assert [spec.label for spec in selection.run_specs] == [
        "pslist",
        "cmdline",
        "netscan",
        "malfind",
        "pstree",
    ]


@pytest.mark.parametrize(
    ("filename", "platform_hint"),
    [
        ("capture.lime", "linux"),
        ("capture.raw", "linux"),
        ("capture.mem", "linux"),
        ("capture.raw", "macos"),
    ],
)
def test_volatility_does_not_route_non_windows_memory_to_windows_plugins(
    tmp_path,
    filename,
    platform_hint,
):
    metadata = load_tool(_METADATA / "volatility3.yaml")
    evidence = _evidence(
        tmp_path / filename,
        "memory_dump",
        platform_hint=platform_hint,
    )

    plan = select(
        Inventory(evidence_list=[evidence]),
        {metadata.tool_id: metadata},
        use_llm=False,
        use_rag=False,
    )

    assert metadata.platform == ["windows", "linux", "macos"]
    assert metadata.applicable_evidence_platforms == ["windows"]
    assert plan.selected_tools == []
    assert plan.unhandled_evidence == [evidence.path]


@pytest.mark.parametrize("platform_hint", ["unknown", "windows"])
def test_volatility_keeps_unknown_and_windows_memory_routing(
    tmp_path,
    platform_hint,
):
    metadata = load_tool(_METADATA / "volatility3.yaml")
    evidence = _evidence(
        tmp_path / "capture.raw",
        "memory_dump",
        platform_hint=platform_hint,
    )

    plan = select(
        Inventory(evidence_list=[evidence]),
        {metadata.tool_id: metadata},
        use_llm=False,
        use_rag=False,
    )

    assert [spec.label for spec in plan.selected_tools[0].run_specs] == [
        "pslist",
        "cmdline",
        "netscan",
        "malfind",
        "pstree",
    ]


def test_regripper_selects_plugin_by_hive_basename(tmp_path):
    metadata = load_tool(_METADATA / "regripper.yaml")
    names = ["NTUSER.DAT", "SYSTEM", "SOFTWARE", "SECURITY", "SAM"]
    inventory = Inventory(
        evidence_list=[
            _evidence(tmp_path / name, "registry_hive") for name in names
        ]
    )

    selection = select(
        inventory,
        {metadata.tool_id: metadata},
        use_llm=False,
        use_rag=False,
    ).selected_tools[0]

    by_name: dict[str, list[RunSpec]] = {}
    for spec in selection.run_specs:
        by_name.setdefault(Path(spec.target_evidence).name, []).append(spec)

    ntuser_templates = {spec.command_template for spec in by_name["NTUSER.DAT"]}
    assert any("-p userassist" in template for template in ntuser_templates)
    assert any("-p run" in template for template in ntuser_templates)
    assert "-p services" in by_name["SYSTEM"][0].command_template
    assert "-p run" in by_name["SOFTWARE"][0].command_template
    assert by_name["SECURITY"][0].variables == {"profile": "security"}
    assert by_name["SAM"][0].variables == {"profile": "sam"}
    assert isinstance(selection.run_specs[0], RunSpec)
    assert selection.to_dict()["run_specs"][0]["command_template"]
