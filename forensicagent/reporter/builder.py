"""Report builder — Scanner / Selector / Executor / Analyzer 결과를 한 묶음으로."""

from __future__ import annotations

import os
import platform
from collections import defaultdict
from typing import Any

from forensicagent import __version__
from forensicagent.analyzer.types import (
    MAX_RETAINED_FINDINGS,
    SEVERITY_RANK,
    Finding,
    ToolAnalysis,
)
from forensicagent.executor.types import ExecutionBundle, ExecutionResult
from forensicagent.reporter.types import (
    Report,
    ReportMeta,
    Summary,
    ToolBundle,
    now_iso,
)
from forensicagent.scanner.types import Inventory
from forensicagent.selector.types import Plan

MAX_REPORT_TIMELINE_EVENTS = 2_000


def _host_info() -> dict[str, str]:
    return {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
    }


def _dedupe_and_cap(analysis: ToolAnalysis) -> None:
    unique: dict[str, Finding] = {}
    for finding in analysis.findings:
        key = finding.fingerprint or finding.refresh_fingerprint()
        previous = unique.get(key)
        if previous is None or (
            SEVERITY_RANK[finding.severity], finding.confidence
        ) > (SEVERITY_RANK[previous.severity], previous.confidence):
            unique[key] = finding
    retained = sorted(
        unique.values(),
        key=lambda finding: (
            SEVERITY_RANK[finding.severity],
            finding.confidence,
        ),
        reverse=True,
    )
    if len(retained) > MAX_RETAINED_FINDINGS:
        analysis.finding_limit_reached = True
    analysis.findings = retained[:MAX_RETAINED_FINDINGS]


def _path_key(value: str) -> str:
    return os.path.normcase(os.path.abspath(value))


def _planned_owners(plan: Plan) -> dict[str, str]:
    claimed: dict[str, tuple[int, str]] = {}
    for selection in plan.selected_tools:
        targets = (
            [spec.target_evidence for spec in selection.run_specs]
            if selection.run_specs
            else selection.target_evidence
        )
        for target in targets:
            key = _path_key(target)
            previous = claimed.get(key)
            if previous is None or selection.priority > previous[0]:
                claimed[key] = (selection.priority, selection.tool_id)
    return {key: owner for key, (_, owner) in claimed.items()}


def _has_analysis_input(result: ExecutionResult) -> bool:
    if result.parsed_output is not None or result.output_size_bytes > 0:
        return True
    return any(
        artifact.role in ("stdout", "generated") and artifact.size_bytes > 0
        for artifact in result.artifacts
    )


def _artifact_ledger(
    inventory: Inventory,
    plan: Plan,
    execution: ExecutionBundle,
    analyses: list[ToolAnalysis],
) -> list[dict[str, Any]]:
    owners = _planned_owners(plan)
    results_by_path: dict[str, list[ExecutionResult]] = defaultdict(list)
    for result in execution.results:
        if result.target_evidence:
            results_by_path[_path_key(result.target_evidence)].append(result)

    analyses_by_target: dict[tuple[str, str], list[ToolAnalysis]] = defaultdict(list)
    for analysis in analyses:
        if analysis.target_evidence:
            analyses_by_target[
                (analysis.tool_id, _path_key(analysis.target_evidence))
            ].append(analysis)

    ledger: list[dict[str, Any]] = []
    for evidence in inventory.evidence_list:
        key = _path_key(evidence.path)
        results = results_by_path.get(key, [])
        statuses = list(dict.fromkeys(result.status for result in results))
        executed_tool_ids = list(
            dict.fromkeys(result.tool_id for result in results)
        )
        target_analyses = [
            analysis
            for tool_id in executed_tool_ids
            for analysis in analyses_by_target.get((tool_id, key), [])
        ]
        analyzed = [
            analysis
            for analysis in target_analyses
            if analysis.status == "analyzed"
        ]
        if not analyzed:
            analysis_status = "not_analyzed"
            finding_count: int | None = None
        elif len(analyzed) == len(target_analyses) == len(results):
            analysis_status = "analyzed"
            finding_count = sum(len(analysis.findings) for analysis in analyzed)
        else:
            analysis_status = "partial"
            finding_count = sum(len(analysis.findings) for analysis in analyzed)

        ledger.append(
            {
                "path": evidence.path,
                "discovery_status": "included",
                "size_bytes": evidence.size_bytes,
                "mtime_ns": evidence.mtime_ns,
                "sha256": evidence.sha256,
                "detected_type": evidence.evidence_type,
                "detected_by": evidence.detected_by,
                "selected_tool_id": owners.get(key),
                "executed_tool_ids": executed_tool_ids,
                "preflight_status": (
                    "not_run"
                    if not results
                    else "failed"
                    if all(result.status == "skipped" for result in results)
                    else "mixed"
                    if any(result.status == "skipped" for result in results)
                    else "passed"
                ),
                "execution_status": (
                    "not_run"
                    if not statuses
                    else statuses[0]
                    if len(statuses) == 1
                    else "mixed"
                ),
                "executions": [
                    {
                        "executed_tool_id": result.tool_id,
                        "status": result.status,
                        "command_executed": result.command_executed,
                        "provenance": dict(result.provenance),
                    }
                    for result in results
                ],
                "analysis_status": analysis_status,
                "finding_count": finding_count,
            }
        )

    for item in inventory.oversized_files:
        ledger.append(
            {
                "path": str(item.get("path", "")),
                "discovery_status": "excluded_oversized",
                "exclusion_reason": str(
                    item.get(
                        "reason", "size is at or above the 1.5 GiB scan limit"
                    )
                ),
                "size_limit_bytes": int(item.get("limit_bytes", 0) or 0),
                "size_bytes": int(item.get("size_bytes", 0)),
                "mtime_ns": int(item.get("mtime_ns", 0) or 0),
                "sha256": None,
                "detected_type": None,
                "detected_by": None,
                "selected_tool_id": None,
                "executed_tool_ids": [],
                "preflight_status": "not_run",
                "execution_status": "not_run",
                "executions": [],
                "analysis_status": "not_analyzed",
                "finding_count": None,
            }
        )
    return ledger


def build(
    *,
    inventory: Inventory,
    plan: Plan,
    execution: ExecutionBundle,
    analyses: list[ToolAnalysis],
    started_at: str,
    working_directory: str,
    stage_ms: dict[str, int] | None = None,
) -> Report:
    """모든 단계 결과를 하나의 Report 로 묶는다."""
    finished_at = now_iso()
    meta = ReportMeta(
        version=__version__,
        started_at=started_at,
        finished_at=finished_at,
        working_directory=working_directory,
        host_info=_host_info(),
    )

    # tool_id → bundle 누적.
    bundle_map: dict[str, ToolBundle] = {}
    for r in execution.results:
        b = bundle_map.setdefault(r.tool_id, ToolBundle(tool_id=r.tool_id))
        b.execution.append(r)

    # 같은 tool_id 의 여러 ToolAnalysis 를 하나로 머지 (도구가 여러 evidence
    # 파일에 호출되면 analysis 도 N개씩 옴 — 단순히 마지막을 쓰면 다른 결과를
    # 덮어쓰게 됨). findings 는 누적, case/llm 플래그는 가장 상위 결과 유지.
    merged_analyses: dict[str, ToolAnalysis] = {}
    for a in analyses:
        existing = merged_analyses.get(a.tool_id)
        if existing is None:
            merged_analyses[a.tool_id] = ToolAnalysis(
                tool_id=a.tool_id,
                findings=list(a.findings),
                summary=a.summary,
                case_used=a.case_used,
                llm_invoked=a.llm_invoked,
                llm_failed=a.llm_failed,
                finding_limit_reached=a.finding_limit_reached,
                coverage_warnings=list(a.coverage_warnings),
                target_evidence=a.target_evidence,
                status=a.status,
                llm_route=a.llm_route,
                llm_input_chars=a.llm_input_chars,
                llm_input_estimated_tokens=a.llm_input_estimated_tokens,
                deterministic_coverage=a.deterministic_coverage,
                time_scope=dict(a.time_scope),
                scope_rows=dict(a.scope_rows),
                scope_context_truncated=a.scope_context_truncated,
                artifact_profiles=[dict(item) for item in a.artifact_profiles],
                timeline_events=[
                    dict(item)
                    for item in a.timeline_events[:MAX_REPORT_TIMELINE_EVENTS]
                ],
                timeline_event_count=a.timeline_event_count,
                timeline_events_truncated=(
                    a.timeline_events_truncated
                    or len(a.timeline_events) > MAX_REPORT_TIMELINE_EVENTS
                ),
            )
        else:
            existing.findings.extend(a.findings)
            existing.llm_invoked = existing.llm_invoked or a.llm_invoked
            existing.llm_failed = existing.llm_failed or a.llm_failed
            existing.finding_limit_reached = (
                existing.finding_limit_reached or a.finding_limit_reached
            )
            if existing.llm_route and a.llm_route != existing.llm_route:
                existing.llm_route = "mixed"
            elif not existing.llm_route:
                existing.llm_route = a.llm_route
            existing.llm_input_chars += a.llm_input_chars
            existing.llm_input_estimated_tokens += (
                a.llm_input_estimated_tokens
            )
            existing.deterministic_coverage = (
                existing.deterministic_coverage and a.deterministic_coverage
            )
            if not existing.time_scope:
                existing.time_scope = dict(a.time_scope)
            for name, count in a.scope_rows.items():
                existing.scope_rows[name] = existing.scope_rows.get(name, 0) + count
            existing.scope_context_truncated = (
                existing.scope_context_truncated or a.scope_context_truncated
            )
            existing.artifact_profiles.extend(
                dict(item) for item in a.artifact_profiles
            )
            existing.timeline_event_count += a.timeline_event_count
            available = max(
                0,
                MAX_REPORT_TIMELINE_EVENTS - len(existing.timeline_events),
            )
            existing.timeline_events.extend(
                dict(item) for item in a.timeline_events[:available]
            )
            existing.timeline_events_truncated = (
                existing.timeline_events_truncated
                or a.timeline_events_truncated
                or len(a.timeline_events) > available
            )
            existing.coverage_warnings = list(
                dict.fromkeys(existing.coverage_warnings + a.coverage_warnings)
            )
            if existing.target_evidence != a.target_evidence:
                existing.target_evidence = ""
            if a.status == "analyzed":
                existing.status = "analyzed"
            # case 는 더 보수적인 쪽 (A < B < C) 유지.
            order = {"A": 0, "B": 1, "C": 2}
            if order.get(a.case_used, 0) > order.get(existing.case_used, 0):
                existing.case_used = a.case_used
        _dedupe_and_cap(merged_analyses[a.tool_id])

    # 동일 규칙/증거가 여러 exporter 또는 LLM+rule 경로에서 반복되면 안정적인
    # fingerprint로 한 번만 보고한다. 더 높은 severity 결과를 유지한다.
    # summary 재생성 (머지 후 정확한 카운트). 실행 실패/skip은 무탐지와
    # 구분한다. 이것을 덮어쓰면 "도구가 안 돌았는데 0 findings"로 오해한다.
    for a in merged_analyses.values():
        executions = bundle_map.get(a.tool_id, ToolBundle(a.tool_id)).execution
        successful = [e for e in executions if e.status == "success"]
        if executions and not any(_has_analysis_input(e) for e in executions):
            a.status = "not_analyzed"
        if a.status == "not_analyzed":
            statuses: dict[str, int] = {}
            for result in executions:
                statuses[result.status] = statuses.get(result.status, 0) + 1
            status_text = ", ".join(
                f"{name}={count}" for name, count in sorted(statuses.items())
            )
            first_error = next(
                (e.error_message for e in executions if e.error_message), ""
            )
            reason = (
                "no successful execution"
                if executions and not successful
                else "no analyzable execution output"
            )
            a.summary = f"not analyzed: {reason} ({status_text or 'not_run'})"
            if first_error:
                a.summary += f"; {first_error[:240]}"
            continue
        from forensicagent.analyzer.types import by_severity_count
        cnt = by_severity_count(a.findings)
        sev = (
            f"critical={cnt['critical']} high={cnt['high']} "
            f"medium={cnt['medium']} low={cnt['low']} info={cnt['info']}"
        )
        cat: dict[str, int] = {}
        for f in a.findings:
            cat[f.category] = cat.get(f.category, 0) + 1
        top = ", ".join(f"{k}({v})" for k, v in sorted(cat.items(), key=lambda x: -x[1])[:3]) or "n/a"
        a.summary = f"{len(a.findings)} findings ({sev}); top: {top}"
        if a.llm_route:
            a.summary += (
                f"; route={a.llm_route}; llm_input_chars={a.llm_input_chars}; "
                f"llm_input_estimated_tokens={a.llm_input_estimated_tokens}; "
                f"deterministic_coverage={str(a.deterministic_coverage).lower()}"
            )
        if a.artifact_profiles:
            a.summary += (
                f"; parsed_artifacts={len(a.artifact_profiles)}; "
                f"timeline_events={a.timeline_event_count}; "
                f"parse_ms={sum(int(item.get('parse_ms', 0)) for item in a.artifact_profiles)}; "
                f"rules_ms={sum(int(item.get('rules_ms', 0)) for item in a.artifact_profiles)}"
            )
        if a.time_scope:
            a.summary += (
                f"; time_scope={a.time_scope.get('start_utc', '')}.."
                f"{a.time_scope.get('end_utc', '')}; scope_rows="
                f"selected:{a.scope_rows.get('selected', 0)},"
                f"outside:{a.scope_rows.get('outside', 0)},"
                f"undated:{a.scope_rows.get('undated', 0)},"
                f"retained:{a.scope_rows.get('retained', 0)},"
                f"selected_chars:{a.scope_rows.get('selected_chars', 0)}"
            )
        if a.scope_context_truncated:
            a.summary += "; scope_context_truncated=true"
        if a.finding_limit_reached:
            a.summary += "; finding_limit_reached=true"
        if a.coverage_warnings:
            a.summary += (
                f"; coverage_truncated=true; coverage_warnings="
                f"{len(a.coverage_warnings)}"
            )
        partial_statuses: dict[str, int] = {}
        for result in executions:
            if result.status != "success":
                partial_statuses[result.status] = (
                    partial_statuses.get(result.status, 0) + 1
                )
        if partial_statuses:
            status_text = ", ".join(
                f"{name}={count}"
                for name, count in sorted(partial_statuses.items())
            )
            a.summary += (
                "; partial_artifacts_analyzed=true; "
                f"execution_status={status_text}"
            )

    for a in merged_analyses.values():
        b = bundle_map.setdefault(a.tool_id, ToolBundle(tool_id=a.tool_id))
        b.analysis = a

    # plan 의 순서를 유지하면서 정렬, 미등장 도구는 뒤에 append.
    ordered: list[ToolBundle] = []
    seen: set[str] = set()
    for sel in plan.selected_tools:
        b = bundle_map.get(sel.tool_id)
        if b is not None:
            ordered.append(b)
            seen.add(sel.tool_id)
    for tid, b in bundle_map.items():
        if tid not in seen:
            ordered.append(b)

    # ---- summary aggregation ----
    by_sev: dict[str, int] = defaultdict(int)
    by_cat: dict[str, int] = defaultdict(int)
    total = 0
    for b in ordered:
        if b.analysis is None:
            continue
        for f in b.analysis.findings:
            by_sev[f.severity] += 1
            by_cat[f.category] += 1
            total += 1

    tools_run = sum(1 for b in ordered if any(e.status == "success" for e in b.execution))
    tools_failed = sum(
        1
        for b in ordered
        if any(
            e.status
            in ("failed", "timeout", "cancelled", "output_limit", "output_missing")
            for e in b.execution
        )
    )
    tools_skipped = sum(
        1 for b in ordered if all(e.status == "skipped" for e in b.execution)
    )
    total_ms = sum((stage_ms or {}).values())

    summary = Summary(
        total_findings=total,
        by_severity=dict(by_sev),
        by_category=dict(by_cat),
        tools_run=tools_run,
        tools_failed=tools_failed,
        tools_skipped=tools_skipped,
        total_ms=total_ms,
        finding_limit_reached=any(
            analysis.finding_limit_reached
            for analysis in merged_analyses.values()
        ),
        coverage_truncated=any(
            analysis.coverage_warnings for analysis in merged_analyses.values()
        ),
        depth_limit_hit=inventory.depth_limit_hit,
        unreadable_paths=inventory.unreadable_paths,
        reparse_paths=inventory.reparse_paths,
        oversized_files=len(inventory.oversized_files),
    )

    return Report(
        meta=meta,
        evidence_inventory=inventory,
        execution_plan=plan,
        tool_bundles=ordered,
        summary=summary,
        stage_ms=dict(stage_ms or {}),
        artifact_ledger=_artifact_ledger(inventory, plan, execution, analyses),
    )
