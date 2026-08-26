"""Reporter types — 명세 2.5 의 리포트 스키마."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from forensicagent.analyzer.time_scope import (
    parse_timestamp,
    timestamp_timezone_assumed,
)
from forensicagent.analyzer.types import Finding, ToolAnalysis, by_severity_count
from forensicagent.executor.types import ExecutionResult
from forensicagent.scanner.types import Inventory
from forensicagent.selector.types import Plan


def event_namespace(entry: dict[str, Any]) -> str:
    parts = [
        str(entry[key])
        for key in ("channel", "provider", "event_id")
        if entry.get(key) not in (None, "")
    ]
    return " / ".join(parts) or "-"


@dataclass
class ReportMeta:
    version: str = "0.0.1"
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    started_at: str = ""
    finished_at: str = ""
    working_directory: str = ""
    host_info: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "run_id": self.run_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "working_directory": self.working_directory,
            "host_info": dict(self.host_info),
        }


@dataclass
class ToolBundle:
    tool_id: str
    execution: list[ExecutionResult] = field(default_factory=list)
    analysis: ToolAnalysis | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "execution": [e.to_dict() for e in self.execution],
            "analysis": self.analysis.to_dict() if self.analysis else None,
        }


@dataclass
class Summary:
    total_findings: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)
    by_category: dict[str, int] = field(default_factory=dict)
    tools_run: int = 0
    tools_failed: int = 0
    tools_skipped: int = 0
    total_ms: int = 0
    finding_limit_reached: bool = False
    coverage_truncated: bool = False
    depth_limit_hit: bool = False
    unreadable_paths: int = 0
    reparse_paths: int = 0
    oversized_files: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "by_severity": dict(self.by_severity),
            "by_category": dict(self.by_category),
            "tools_run": self.tools_run,
            "tools_failed": self.tools_failed,
            "tools_skipped": self.tools_skipped,
            "total_ms": self.total_ms,
            "finding_limit_reached": self.finding_limit_reached,
            "coverage_truncated": self.coverage_truncated,
            "depth_limit_hit": self.depth_limit_hit,
            "unreadable_paths": self.unreadable_paths,
            "reparse_paths": self.reparse_paths,
            "oversized_files": self.oversized_files,
        }


@dataclass
class Report:
    meta: ReportMeta = field(default_factory=ReportMeta)
    evidence_inventory: Inventory | None = None
    execution_plan: Plan | None = None
    tool_bundles: list[ToolBundle] = field(default_factory=list)
    summary: Summary = field(default_factory=Summary)
    stage_ms: dict[str, int] = field(default_factory=dict)
    artifact_ledger: list[dict[str, Any]] = field(default_factory=list)
    analyst_annotations: dict[str, dict[str, str]] = field(default_factory=dict)

    def all_findings(self) -> list[Finding]:
        out: list[Finding] = []
        for b in self.tool_bundles:
            if b.analysis:
                out.extend(b.analysis.findings)
        return out

    def annotation_for(self, fingerprint: str) -> dict[str, str]:
        annotation = self.analyst_annotations.get(fingerprint)
        if annotation is not None:
            return dict(annotation)
        return {"status": "pending", "notes": "", "updated_at": ""}

    def current_annotations(self) -> dict[str, dict[str, str]]:
        fingerprints = sorted({item.fingerprint for item in self.all_findings()})
        return {
            fingerprint: self.annotation_for(fingerprint)
            for fingerprint in fingerprints
        }

    def correlations(self) -> list[dict[str, Any]]:
        """Derive non-causal links between findings sharing explicit entities."""
        type_order = {"user": 0, "ip": 1, "process": 2}
        grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for bundle in self.tool_bundles:
            if bundle.analysis is None:
                continue
            for finding in bundle.analysis.findings:
                reference = {
                    "fingerprint": finding.fingerprint,
                    "finding_id": finding.finding_id,
                    "tool_id": bundle.tool_id,
                    "severity": finding.severity,
                    "title": finding.title,
                    "annotation_status": self.annotation_for(finding.fingerprint)[
                        "status"
                    ],
                }
                for entity_type in type_order:
                    values = finding.entities.get(entity_type, [])
                    for value in sorted({item for item in values if item}):
                        grouped.setdefault((entity_type, value), []).append(reference)
        return [
            {
                "entity_type": entity_type,
                "entity_value": entity_value,
                "findings": references,
            }
            for (entity_type, entity_value), references in sorted(
                grouped.items(),
                key=lambda item: (
                    type_order[item[0][0]],
                    item[0][1].casefold(),
                    item[0][1],
                ),
            )
            if len(references) >= 2
        ]

    def timeline(self) -> dict[str, list[dict[str, Any]]]:
        """Return finding references ordered by normalized UTC timestamp."""
        dated: list[tuple[datetime, int, dict[str, Any]]] = []
        undated: list[dict[str, Any]] = []
        position = 0
        for bundle in self.tool_bundles:
            if not bundle.analysis:
                continue
            for finding in bundle.analysis.findings:
                original = finding.evidence_ref.timestamp.strip()
                parsed = parse_timestamp(original)
                entry = {
                    "finding_id": finding.finding_id,
                    "fingerprint": finding.fingerprint,
                    "timestamp_original": original,
                    "timestamp_utc": None,
                    "timezone_assumed": False,
                    "severity": finding.severity,
                    "tool_id": bundle.tool_id,
                    "event_id": finding.evidence_ref.event_id,
                    "channel": finding.evidence_ref.channel,
                    "provider": finding.evidence_ref.provider,
                    "title": finding.title,
                    "source_file": finding.evidence_ref.source_file,
                    "annotation_status": self.annotation_for(finding.fingerprint)[
                        "status"
                    ],
                }
                if parsed is None:
                    entry["reason"] = "missing" if not original else "unparseable"
                    undated.append(entry)
                else:
                    entry["timezone_assumed"] = timestamp_timezone_assumed(
                        original
                    )
                    try:
                        utc = parsed.astimezone(timezone.utc)
                        entry["timestamp_utc"] = utc.isoformat().replace(
                            "+00:00", "Z"
                        )
                    except (OverflowError, ValueError):
                        entry["reason"] = "unparseable"
                        undated.append(entry)
                    else:
                        dated.append((utc, position, entry))
                position += 1
        dated.sort(key=lambda item: (item[0], item[1]))
        return {
            "events": [entry for _, _, entry in dated],
            "undated": undated,
        }

    def artifact_timeline(self) -> dict[str, Any]:
        """Return the bounded normalized artifact-event preview in UTC order."""
        events: list[tuple[datetime, int, dict[str, Any]]] = []
        position = 0
        total_events = 0
        truncated = False
        for bundle in self.tool_bundles:
            analysis = bundle.analysis
            if analysis is None:
                continue
            total_events += analysis.timeline_event_count
            truncated = truncated or analysis.timeline_events_truncated
            for item in analysis.timeline_events:
                event = dict(item)
                parsed = parse_timestamp(event.get("timestamp_utc"))
                if parsed is None:
                    continue
                events.append((parsed, position, event))
                position += 1
        events.sort(key=lambda item: (item[0], item[1]))
        retained = [event for _, _, event in events]
        return {
            "events": retained,
            "total_events": total_events,
            "retained_events": len(retained),
            "truncated": truncated or total_events > len(retained),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "meta": self.meta.to_dict(),
            "evidence_inventory": self.evidence_inventory.to_dict()
            if self.evidence_inventory
            else None,
            "execution_plan": self.execution_plan.to_dict()
            if self.execution_plan
            else None,
            "tool_results": [b.to_dict() for b in self.tool_bundles],
            "summary": self.summary.to_dict(),
            "timeline": self.timeline(),
            "artifact_timeline": self.artifact_timeline(),
            "correlations": self.correlations(),
            "analyst_annotations": self.current_annotations(),
            "stage_ms": dict(self.stage_ms),
            "artifact_ledger": [dict(item) for item in self.artifact_ledger],
        }


def now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")
