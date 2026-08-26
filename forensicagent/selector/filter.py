"""Stage 1 — 결정론 필터링.

증거의 evidence_type과 도구의 applicable_evidence_types를 먼저 맞추고,
input_format까지 검증해 실제로 소비 가능한 입력만 후보로 남긴다. LLM 호출 없음.
"""

from __future__ import annotations

import sys
from pathlib import Path

from forensicagent.scanner.types import Evidence, Inventory
from forensicagent.selector.types import ToolSelection
from forensicagent.tools.schema import ToolMetadata


def input_format_matches(evidence: Evidence, formats: list[str]) -> bool:
    """Match metadata input formats against an evidence filename.

    Canonical syntax is ``any``, ``name:<basename>`` and ``ext:<suffix>``.
    Empty lists remain wildcard-compatible for third-party metadata.  Legacy
    ``.suffix`` and bare basename tokens are accepted during migration.
    """
    if not formats:
        return True

    filename = (evidence.filename or Path(evidence.path).name).casefold()
    for raw in formats:
        token = raw.strip()
        folded = token.casefold()
        if folded == "any":
            return True
        if folded.startswith("name:"):
            if filename == token[5:].strip().casefold():
                return True
            continue
        if folded.startswith("ext:"):
            suffix = token[4:].strip().casefold()
            if suffix and not suffix.startswith("."):
                suffix = f".{suffix}"
            if suffix and filename.endswith(suffix):
                return True
            continue

        # Legacy compatibility: a leading dot denotes a suffix; otherwise it
        # is an exact basename such as NTUSER.DAT or $MFT.
        if folded.startswith("."):
            if filename.endswith(folded):
                return True
        elif filename == folded:
            return True
    return False


def _current_host_platform() -> str | None:
    if sys.platform == "win32":
        return "windows"
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "macos"
    return None


def _matching_evidence(
    inventory: Inventory,
    meta: ToolMetadata,
) -> list[Evidence]:
    host_platforms = set(meta.platform)
    if "any" not in host_platforms:
        current_host = _current_host_platform()
        if current_host is None or current_host not in host_platforms:
            return []

    applicable = set(meta.applicable_evidence_types)
    evidence_platforms = set(meta.applicable_evidence_platforms)
    return [
        evidence
        for evidence in inventory.evidence_list
        if evidence.evidence_type != "unknown"
        and evidence.evidence_type in applicable
        and (
            evidence.platform_hint == "unknown"
            or "any" in evidence_platforms
            or evidence.platform_hint in evidence_platforms
        )
        and input_format_matches(evidence, meta.input_format)
    ]


def _target_paths(
    matches: list[Evidence],
) -> list[str]:
    """Keep every external invocation inside the scanner inventory boundary."""
    return list(dict.fromkeys(evidence.path for evidence in matches))


def filter_by_evidence(
    inventory: Inventory,
    tools: dict[str, ToolMetadata],
) -> list[ToolSelection]:
    """Stage 1 결과를 ToolSelection list 로 반환.

    target_evidence 에는 evidence_type과 input_format이 모두 매칭된 path가 들어간다.
    command_template 은 첫 번째 템플릿을 기본으로 (Selector 가 LLM 으로 더
    구체화하면 덮어쓸 수 있게 둠).
    """
    selections: list[ToolSelection] = []
    for tool_id, meta in tools.items():
        matches = _matching_evidence(inventory, meta)
        targets = _target_paths(matches)
        if not targets:
            continue
        matched_types = list(dict.fromkeys(e.evidence_type for e in matches))

        reason = (
            f"{', '.join(matched_types)} 증거가 발견되어 "
            f"{meta.display_name} 적용 가능 ({meta.category})."
        )
        selections.append(
            ToolSelection(
                tool_id=tool_id,
                tool_version=meta.version_supported,
                reason=reason,
                target_evidence=targets,
                command_template=meta.command_templates[0].template,
                estimated_runtime=meta.estimated_runtime,
                priority=5,
            )
        )
    return selections


def skipped_by_evidence_gap(
    inventory: Inventory,
    tools: dict[str, ToolMetadata],
) -> list[str]:
    """Stage 1 에서 떨어진 도구 id 목록. UX 에 '왜 안 돌렸나' 표시 용."""
    return [
        tid
        for tid, m in tools.items()
        if not _matching_evidence(inventory, m)
    ]


def unhandled_evidence_paths(
    inventory: Inventory,
    tools: dict[str, ToolMetadata],
) -> list[str]:
    """Evidence paths that no configured tool can consume safely."""
    handled = {
        evidence.path
        for meta in tools.values()
        for evidence in _matching_evidence(inventory, meta)
    }
    return list(
        dict.fromkeys(
            evidence.path
            for evidence in inventory.evidence_list
            if evidence.evidence_type != "unknown" and evidence.path not in handled
        )
    )
