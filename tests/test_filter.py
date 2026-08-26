"""Selector Stage 1 (결정론 evidence_type 매칭) 테스트.

LLM 의존성 없음 — 합성 Inventory + ToolMetadata fixture 로 교집합 로직만.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import forensicagent.selector.filter as selector_filter
from forensicagent.scanner.types import Evidence, Inventory
from forensicagent.scanner.scanner import scan
from forensicagent.selector.filter import (
    filter_by_evidence,
    input_format_matches,
    skipped_by_evidence_gap,
    unhandled_evidence_paths,
)
from forensicagent.selector.selector import select
from forensicagent.tools.schema import CommandTemplate, ToolMetadata
from forensicagent.tools.loader import load_all_tools


def _meta(
    tool_id: str,
    *,
    applicable: list[str],
    category: str = "log_analysis",
    runtime: str = "short",
    parallelizable: bool = True,
    input_format: list[str] | None = None,
    platform: list[str] | None = None,
) -> ToolMetadata:
    return ToolMetadata(
        tool_id=tool_id,
        display_name=tool_id.title(),
        category=category,
        applicable_evidence_types=applicable,  # type: ignore[arg-type]
        command_templates=[
            CommandTemplate(
                name="default",
                template=f"{tool_id} {{evidence_path}}",
                when="default",
            )
        ],
        usage_description="test",
        estimated_runtime=runtime,  # type: ignore[arg-type]
        parallelizable=parallelizable,
        input_format=input_format or [],
        platform=platform or ["any"],  # type: ignore[arg-type]
    )


def _evidence(path: str, etype: str) -> Evidence:
    return Evidence(
        path=path,
        filename=path.split("/")[-1],
        size_bytes=100,
        evidence_type=etype,  # type: ignore[arg-type]
        detected_by="magic_bytes",
        platform_hint="unknown",
        confidence=0.9,
    )


@pytest.fixture
def tools_pool() -> dict[str, ToolMetadata]:
    return {
        "chainsaw": _meta("chainsaw", applicable=["evtx_log"]),
        "volatility3": _meta(
            "volatility3",
            applicable=["memory_dump"],
            category="memory_analysis",
            runtime="long",
            parallelizable=False,
        ),
        "regripper": _meta(
            "regripper",
            applicable=["registry_hive"],
            category="registry_analysis",
        ),
        "yara_disk": _meta(
            "yara_disk",
            applicable=["disk_image", "memory_dump"],
            category="string_extraction",
        ),
    }


class TestFilterByEvidence:
    def test_evtx_only_inventory_picks_chainsaw(self, tools_pool):
        inv = Inventory(
            scan_root="/case",
            evidence_list=[_evidence("/case/Security.evtx", "evtx_log")],
        )
        sels = filter_by_evidence(inv, tools_pool)
        tool_ids = {s.tool_id for s in sels}
        assert tool_ids == {"chainsaw"}

    def test_memory_dump_picks_vol_and_yara(self, tools_pool):
        inv = Inventory(
            scan_root="/case",
            evidence_list=[_evidence("/case/memory.raw", "memory_dump")],
        )
        sels = filter_by_evidence(inv, tools_pool)
        tool_ids = {s.tool_id for s in sels}
        assert tool_ids == {"volatility3", "yara_disk"}

    def test_multi_evidence_union(self, tools_pool):
        inv = Inventory(
            scan_root="/case",
            evidence_list=[
                _evidence("/case/Security.evtx", "evtx_log"),
                _evidence("/case/memory.raw", "memory_dump"),
                _evidence("/case/NTUSER.DAT", "registry_hive"),
            ],
        )
        sels = filter_by_evidence(inv, tools_pool)
        tool_ids = {s.tool_id for s in sels}
        assert tool_ids == {"chainsaw", "volatility3", "regripper", "yara_disk"}

    def test_unknown_evidence_ignored(self, tools_pool):
        """unknown 타입은 어떤 도구에도 매칭되면 안 된다."""
        inv = Inventory(
            scan_root="/case",
            evidence_list=[_evidence("/case/file.xyz", "unknown")],
        )
        sels = filter_by_evidence(inv, tools_pool)
        assert sels == []

    def test_target_evidence_lists_all_matching_paths(self, tools_pool):
        """한 도구에 여러 evidence 가 매칭되면 모두 target_evidence 에 들어가야 한다."""
        inv = Inventory(
            scan_root="/case",
            evidence_list=[
                _evidence("/case/memory.raw", "memory_dump"),
                _evidence("/case/disk.e01", "disk_image"),
            ],
        )
        sels = filter_by_evidence(inv, tools_pool)
        # yara_disk 는 두 evidence 모두 처리 가능.
        yara = next(s for s in sels if s.tool_id == "yara_disk")
        assert set(yara.target_evidence) == {"/case/memory.raw", "/case/disk.e01"}

    def test_command_template_from_first(self, tools_pool):
        inv = Inventory(
            scan_root="/case",
            evidence_list=[_evidence("/case/Security.evtx", "evtx_log")],
        )
        sels = filter_by_evidence(inv, tools_pool)
        assert sels[0].command_template == "chainsaw {evidence_path}"

    def test_estimated_runtime_inherited(self, tools_pool):
        inv = Inventory(
            scan_root="/case",
            evidence_list=[_evidence("/case/memory.raw", "memory_dump")],
        )
        sels = filter_by_evidence(inv, tools_pool)
        vol = next(s for s in sels if s.tool_id == "volatility3")
        assert vol.estimated_runtime == "long"

    def test_empty_inventory_returns_empty(self, tools_pool):
        inv = Inventory(scan_root="/case", evidence_list=[])
        assert filter_by_evidence(inv, tools_pool) == []

    def test_empty_tools_returns_empty(self):
        inv = Inventory(
            scan_root="/case",
            evidence_list=[_evidence("/case/Security.evtx", "evtx_log")],
        )
        assert filter_by_evidence(inv, {}) == []


class TestSkippedByEvidenceGap:
    def test_lists_tools_with_no_matching_evidence(self, tools_pool):
        inv = Inventory(
            scan_root="/case",
            evidence_list=[_evidence("/case/Security.evtx", "evtx_log")],
        )
        skipped = skipped_by_evidence_gap(inv, tools_pool)
        # chainsaw 는 매칭되므로 제외; 나머지 3개는 모두 skipped.
        assert set(skipped) == {"volatility3", "regripper", "yara_disk"}

    def test_no_skips_when_all_match(self, tools_pool):
        inv = Inventory(
            scan_root="/case",
            evidence_list=[
                _evidence("/case/Security.evtx", "evtx_log"),
                _evidence("/case/memory.raw", "memory_dump"),
                _evidence("/case/NTUSER.DAT", "registry_hive"),
                _evidence("/case/disk.e01", "disk_image"),
            ],
        )
        # yara_disk 의 두 applicable 중 하나 (disk_image) 만 매칭돼도 통과.
        skipped = skipped_by_evidence_gap(inv, tools_pool)
        assert skipped == []


class TestInputFormatRouting:
    @pytest.mark.parametrize(
        "formats,path,expected",
        [
            (["any"], "/case/anything.bin", True),
            ([], "/case/anything.bin", True),
            (["ext:.EVTX"], "/case/security.evtx", True),
            (["ext:py"], "/case/app.PY", True),
            (["name:ntuser.dat"], "/case/NTUSER.DAT", True),
            ([".py"], "/case/app.py", True),
            (["$MFT"], "/case/$mft", True),
            (["ext:.evtx"], "/case/security.evt", False),
            (["name:SYSTEM"], "/case/SOFTWARE", False),
        ],
    )
    def test_match_syntax_and_legacy_compatibility(self, formats, path, expected):
        assert input_format_matches(_evidence(path, "evtx_log"), formats) is expected

    def test_type_match_is_rejected_when_input_format_does_not_match(self):
        tool = _meta(
            "amcacheparser",
            applicable=["registry_hive"],
            input_format=["name:Amcache.hve"],
        )
        inv = Inventory(
            evidence_list=[_evidence("/case/NTUSER.DAT", "registry_hive")]
        )

        assert filter_by_evidence(inv, {tool.tool_id: tool}) == []
        assert skipped_by_evidence_gap(inv, {tool.tool_id: tool}) == [tool.tool_id]

    def test_target_paths_are_deduplicated(self):
        tool = _meta("bandit", applicable=["source_code_python"], input_format=["ext:.py"])
        evidence = _evidence("/case/app.py", "source_code_python")
        inv = Inventory(evidence_list=[evidence, evidence])

        selections = filter_by_evidence(inv, {tool.tool_id: tool})

        assert selections[0].target_evidence == ["/case/app.py"]


class TestHostPlatformRouting:
    @pytest.mark.parametrize(
        "host,allowed",
        [
            ("win32", True),
            ("linux", False),
            ("darwin", False),
            ("freebsd14", False),
        ],
    )
    def test_windows_only_tool_is_gated_by_current_host(
        self, monkeypatch, host, allowed
    ):
        monkeypatch.setattr(selector_filter.sys, "platform", host)
        tool = _meta(
            "windows_tool",
            applicable=["evtx_log"],
            platform=["windows"],
        )
        inv = Inventory(evidence_list=[_evidence("/case/Security.evtx", "evtx_log")])

        selections = filter_by_evidence(inv, {tool.tool_id: tool})

        assert bool(selections) is allowed

    def test_any_host_tool_remains_eligible_on_unknown_host(self, monkeypatch):
        monkeypatch.setattr(selector_filter.sys, "platform", "freebsd14")
        tool = _meta("portable", applicable=["text_document"], platform=["any"])
        inv = Inventory(evidence_list=[_evidence("/case/.env", "text_document")])

        assert filter_by_evidence(inv, {tool.tool_id: tool})


class TestRealMetadataRouting:
    @pytest.fixture(autouse=True)
    def _windows_host(self, monkeypatch):
        monkeypatch.setattr(selector_filter.sys, "platform", "win32")

    @pytest.fixture(scope="class")
    @staticmethod
    def real_tools():
        return load_all_tools(Path(__file__).resolve().parents[1] / "tools_metadata")

    @pytest.mark.parametrize(
        "path,etype,expected",
        [
            ("/case/NTUSER.DAT", "registry_hive", {"recmd", "regripper"}),
            ("/case/Amcache.hve", "registry_hive", {"amcacheparser"}),
            (
                "/case/SYSTEM",
                "registry_hive",
                {"appcompatcacheparser", "recmd", "regripper"},
            ),
            ("/case/$MFT", "ntfs_metadata", {"mftecmd"}),
            ("/case/disk.e01", "disk_image", {"fls"}),
            ("/case/capture.pcap", "pcap", {"tshark"}),
            ("/case/History", "browser_artifact", {"browser_sqlite"}),
            ("/case/browser.sqlite", "sqlite_database", set()),
        ],
    )
    def test_exact_input_routing(self, real_tools, path, etype, expected):
        inv = Inventory(evidence_list=[_evidence(path, etype)])
        selected = {s.tool_id for s in filter_by_evidence(inv, real_tools)}
        assert selected == expected

    def test_scanner_source_extensions_match_bandit_and_semgrep(self, real_tools):
        cases = {
            "/case/types.pyi": {"bandit", "semgrep", "gitleaks"},
            "/case/component.tsx": {"semgrep", "gitleaks"},
            "/case/header.hpp": {"semgrep", "gitleaks"},
            "/case/App.swift": {"semgrep", "gitleaks"},
        }
        for path, expected in cases.items():
            etype = (
                "source_code_python"
                if path.endswith(".pyi")
                else "source_code_javascript"
                if path.endswith(".tsx")
                else "source_code_generic"
            )
            inv = Inventory(evidence_list=[_evidence(path, etype)])
            selected = {s.tool_id for s in filter_by_evidence(inv, real_tools)}
            assert selected == expected

    def test_text_document_routes_to_gitleaks(self, real_tools):
        inv = Inventory(evidence_list=[_evidence("/case/notes.txt", "text_document")])
        assert {s.tool_id for s in filter_by_evidence(inv, real_tools)} == {"gitleaks"}

    def test_config_only_tree_routes_to_gitleaks(self, real_tools, tmp_path):
        env_file = tmp_path / ".env"
        settings_file = tmp_path / "settings.yaml"
        env_file.write_text("TOKEN=example\n", encoding="utf-8")
        settings_file.write_text("token: example\n", encoding="utf-8")

        selections = filter_by_evidence(scan(tmp_path), real_tools)

        assert {selection.tool_id for selection in selections} == {"gitleaks"}
        assert set(selections[0].target_evidence) == {
            str(env_file),
            str(settings_file),
        }

    def test_scan_root_tool_never_crosses_inventory_boundaries(
        self, real_tools, tmp_path
    ):
        env_file = tmp_path / ".env"
        unknown_file = tmp_path / "mystery.raw"
        ignored_file = tmp_path / ".git" / "ignored.env"
        depth_file = tmp_path / "deep" / "outside.env"
        env_file.write_text("TOKEN=example\n", encoding="utf-8")
        unknown_file.write_bytes(b"not a recognized artifact")
        ignored_file.parent.mkdir()
        ignored_file.write_text("TOKEN=ignored\n", encoding="utf-8")
        depth_file.parent.mkdir()
        depth_file.write_text("TOKEN=outside\n", encoding="utf-8")

        inventory = scan(tmp_path, max_depth=0, include_unknown=True)
        selection = next(
            item
            for item in filter_by_evidence(inventory, real_tools)
            if item.tool_id == "gitleaks"
        )

        assert inventory.depth_limit_hit is True
        assert any(
            evidence.path == str(unknown_file)
            and evidence.evidence_type == "unknown"
            for evidence in inventory.evidence_list
        )
        assert selection.target_evidence == [str(env_file)]
        assert str(ignored_file) not in selection.target_evidence
        assert str(depth_file) not in selection.target_evidence

    def test_gitleaks_writes_machine_readable_report_to_isolated_output(self, real_tools):
        template = real_tools["gitleaks"].command_templates[0].template
        assert "--report-path {output_dir}/gitleaks.csv" in template

    def test_code_tree_tools_use_only_inventoried_files(self, real_tools, tmp_path):
        first = tmp_path / "one.py"
        second = tmp_path / "pkg" / "two.py"
        second.parent.mkdir()
        first.write_text("pass\n", encoding="utf-8")
        second.write_text("pass\n", encoding="utf-8")
        inv = Inventory(
            scan_root=str(tmp_path),
            evidence_list=[
                _evidence(str(first), "source_code_python"),
                _evidence(str(second), "source_code_python"),
            ],
        )

        selections = filter_by_evidence(inv, real_tools)

        by_id = {selection.tool_id: selection for selection in selections}
        for tool_id in ("bandit", "semgrep", "gitleaks"):
            assert set(by_id[tool_id].target_evidence) == {str(first), str(second)}

    def test_root_aggregation_is_disabled_for_mixed_binary_case(
        self, real_tools, tmp_path
    ):
        source = tmp_path / "one.py"
        memory = tmp_path / "memory.raw"
        inv = Inventory(
            scan_root=str(tmp_path),
            evidence_list=[
                _evidence(str(source), "source_code_python"),
                _evidence(str(memory), "memory_dump"),
            ],
        )

        selections = filter_by_evidence(inv, real_tools)

        by_id = {selection.tool_id: selection for selection in selections}
        assert by_id["gitleaks"].target_evidence == [str(source)]

    def test_forced_root_scan_tool_keeps_inventory_boundary(
        self, real_tools, tmp_path
    ):
        first = tmp_path / "one.py"
        second = tmp_path / "two.py"
        inv = Inventory(
            scan_root=str(tmp_path),
            evidence_list=[
                _evidence(str(first), "source_code_python"),
                _evidence(str(second), "source_code_python"),
            ],
        )

        plan = select(
            inv,
            real_tools,
            force_tools=["bandit"],
            use_llm=False,
            use_rag=False,
        )

        assert len(plan.selected_tools) == 1
        assert plan.selected_tools[0].reason == "forced by --tools"
        assert plan.selected_tools[0].priority == 10
        assert set(plan.selected_tools[0].target_evidence) == {
            str(first),
            str(second),
        }

    def test_forced_tool_still_requires_compatible_input_format(self, real_tools):
        inv = Inventory(
            evidence_list=[_evidence("/case/not-python.txt", "source_code_python")]
        )

        plan = select(
            inv,
            real_tools,
            force_tools=["bandit"],
            use_llm=False,
            use_rag=False,
        )

        assert plan.selected_tools == []

    def test_unhandled_evidence_is_reported_and_serialized(self, real_tools):
        inv = Inventory(
            evidence_list=[
                _evidence("/case/disk.e01", "disk_image"),
                _evidence("/case/browser.sqlite", "sqlite_database"),
                _evidence("/case/Security.evtx", "evtx_log"),
                _evidence("/case/unclassified.bin", "unknown"),
            ]
        )

        expected = ["/case/browser.sqlite"]
        assert unhandled_evidence_paths(inv, real_tools) == expected

        plan = select(inv, real_tools, use_llm=False, use_rag=False)
        assert plan.unhandled_evidence == expected
        assert plan.to_dict()["unhandled_evidence"] == expected
