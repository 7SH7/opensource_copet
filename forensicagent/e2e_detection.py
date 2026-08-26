"""Offline end-to-end rule-label detection benchmark.

This is deliberately separate from :mod:`bench`, which measures tool-selection
ranking.  Corpus files are supplied by the user; this module never downloads
them.  A case contributes to multiplicity-aware ``rule_id`` label metrics only
after the real scanner -> selector -> executor -> analyzer -> report pipeline
succeeds completely.  These metrics do not measure event-occurrence location.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from forensicagent.analyzer import analyze_all
from forensicagent.executor import execute
from forensicagent.reporter.builder import build
from forensicagent.scanner import scan
from forensicagent.selector import select
from forensicagent.tools.loader import load_all_tools

SCHEMA_VERSION = 1
BENCHMARK_KIND = "end_to_end_finding_detection"
SCOPE = "end-to-end finding detection accuracy; not tool-selection ranking"
METRIC_LABEL_SEMANTICS = (
    "multiplicity-aware rule_id label matching (unlabeled findings use unmatched "
    "fallback identities); not event-occurrence localization"
)
_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}\Z")
_SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")


def finding_metrics(gold_labels: Iterable[str], predicted_labels: Iterable[str]) -> dict[str, Any]:
    """Return multiplicity-aware rule-label counts and zero-safe metrics."""
    gold = Counter(gold_labels)
    predicted = Counter(predicted_labels)
    true_positives = sum((gold & predicted).values())
    false_positives = sum((predicted - gold).values())
    false_negatives = sum((gold - predicted).values())
    precision_denominator = true_positives + false_positives
    recall_denominator = true_positives + false_negatives
    precision = true_positives / precision_denominator if precision_denominator else 0.0
    recall = true_positives / recall_denominator if recall_denominator else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "finding_precision": precision,
        "finding_recall": recall,
        "finding_f1": f1,
    }


def _require_text(mapping: dict[str, Any], key: str, *, where: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{where}.{key} must be a non-empty string")
    return value.strip()


def _require_https(mapping: dict[str, Any], key: str, *, where: str) -> str:
    value = _require_text(mapping, key, where=where)
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError(f"{where}.{key} must be an https URL")
    return value


def load_manifest(path: str | Path) -> dict[str, Any]:
    """Load and validate a corpus manifest without fetching any URL."""
    manifest_path = Path(path)
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load manifest {manifest_path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError("manifest must be a JSON object")
    if raw.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"manifest.schema_version must be {SCHEMA_VERSION}")
    if raw.get("scope") != SCOPE:
        raise ValueError(f"manifest.scope must be {SCOPE!r}")
    cases = raw.get("cases")
    if not isinstance(cases, list):
        raise ValueError("manifest.cases must be a list")

    normalized_cases: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, value in enumerate(cases):
        where = f"manifest.cases[{index}]"
        if not isinstance(value, dict):
            raise ValueError(f"{where} must be an object")
        case = dict(value)
        case_id = _require_text(case, "id", where=where)
        if not _SAFE_ID.fullmatch(case_id):
            raise ValueError(f"{where}.id contains unsafe characters")
        if case_id in seen_ids:
            raise ValueError(f"duplicate case id: {case_id}")
        seen_ids.add(case_id)
        case["id"] = case_id
        case["source_url"] = _require_https(case, "source_url", where=where)
        case["download_url"] = _require_https(case, "download_url", where=where)
        case["license"] = _require_text(case, "license", where=where)
        case["license_url"] = _require_https(case, "license_url", where=where)

        evidence_path = Path(_require_text(case, "evidence_path", where=where))
        if evidence_path.is_absolute() or ".." in evidence_path.parts:
            raise ValueError(f"{where}.evidence_path must stay below the corpus directory")
        case["evidence_path"] = evidence_path.as_posix()

        sha256 = case.get("sha256")
        if sha256 is not None:
            if not isinstance(sha256, str) or not _SHA256.fullmatch(sha256):
                raise ValueError(f"{where}.sha256 must be null or 64 hexadecimal characters")
            case["sha256"] = sha256.lower()

        gold_labels = case.get("gold_labels")
        if not isinstance(gold_labels, list) or not all(
            isinstance(label, str) and label.strip() for label in gold_labels
        ):
            raise ValueError(f"{where}.gold_labels must be a list of non-empty strings")
        case["gold_labels"] = [label.strip() for label in gold_labels]

        required_tools = case.get("required_tools")
        if not isinstance(required_tools, list) or len(required_tools) != 1:
            raise ValueError(f"{where}.required_tools must contain exactly one tool id")
        tool_id = required_tools[0]
        if not isinstance(tool_id, str) or not _SAFE_ID.fullmatch(tool_id):
            raise ValueError(f"{where}.required_tools contains an invalid tool id")
        case["required_tools"] = [tool_id]
        normalized_cases.append(case)

    return {**raw, "cases": normalized_cases}


def _finding_label(finding: Any) -> str:
    rule_id = str(getattr(finding, "rule_id", "") or "").strip()
    if rule_id:
        return rule_id
    fingerprint = str(getattr(finding, "fingerprint", "") or "").strip()
    finding_id = str(getattr(finding, "finding_id", "") or "").strip()
    return f"unlabeled:{fingerprint or finding_id or 'unknown'}"


def _case_base(case: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": case["id"],
        "source_url": case["source_url"],
        "download_url": case["download_url"],
        "license": case["license"],
        "license_url": case["license_url"],
        "evidence_path": case["evidence_path"],
        "sha256": case.get("sha256"),
        "gold_labels": list(case["gold_labels"]),
        "required_tools": list(case["required_tools"]),
    }


def _not_measured(case: dict[str, Any], status: str, reason: str, detail: str = "") -> dict[str, Any]:
    result = {**_case_base(case), "status": status, "reason": reason}
    if detail:
        result["detail"] = detail
    return result


def _run_case(
    case: dict[str, Any],
    *,
    corpus_dir: Path,
    output_dir: Path,
    tools: dict[str, Any],
) -> dict[str, Any]:
    corpus_root = corpus_dir.resolve()
    evidence_path = (corpus_root / case["evidence_path"]).resolve()
    if not evidence_path.is_relative_to(corpus_root):
        return _not_measured(case, "skipped", "evidence_outside_corpus")
    if not evidence_path.is_file():
        return _not_measured(case, "skipped", "evidence_missing", str(evidence_path))

    expected_hash = case.get("sha256")
    if not expected_hash:
        return _not_measured(
            case,
            "skipped",
            "sha256_not_pinned",
            "pin an independently verified SHA-256 before measuring this case",
        )

    stage_ms: dict[str, int] = {}
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    inventory = scan(evidence_path, stage_ms=stage_ms)
    if len(inventory.evidence_list) != 1:
        return _not_measured(case, "skipped", "evidence_not_scanned")
    scanned_evidence = inventory.evidence_list[0]
    try:
        scanned_path = Path(scanned_evidence.path).resolve(strict=True)
    except OSError as exc:
        return _not_measured(case, "skipped", "evidence_unreadable", str(exc))
    if scanned_path != evidence_path:
        return _not_measured(case, "error", "scanned_evidence_mismatch")
    actual_hash = scanned_evidence.sha256
    if actual_hash != expected_hash:
        return _not_measured(
            case,
            "skipped",
            "sha256_mismatch",
            f"expected={expected_hash}; actual={actual_hash}",
        )
    tool_id = case["required_tools"][0]
    metadata = tools.get(tool_id)
    if metadata is None:
        return _not_measured(case, "skipped", "required_tool_metadata_missing", tool_id)
    case_tools = {tool_id: metadata}
    plan = select(
        inventory,
        case_tools,
        use_llm=False,
        use_rag=False,
        stage_ms=stage_ms,
    )
    if tool_id not in {selection.tool_id for selection in plan.selected_tools}:
        return _not_measured(case, "skipped", "required_tool_not_selected", tool_id)

    execution = execute(
        plan,
        case_tools,
        output_dir=output_dir / case["id"],
        max_parallel=1,
        inventory=inventory,
        stage_ms=stage_ms,
    )
    required_results = [result for result in execution.results if result.tool_id == tool_id]
    if not required_results:
        return _not_measured(case, "skipped", "required_tool_not_executed", tool_id)
    skipped = [result for result in required_results if result.status == "skipped"]
    if skipped:
        detail = "; ".join(result.error_message for result in skipped if result.error_message)
        return _not_measured(case, "skipped", "required_tool_unavailable", detail or tool_id)
    unsuccessful = [result for result in required_results if result.status != "success"]
    if unsuccessful:
        detail = "; ".join(
            f"{result.status}: {result.error_message}" for result in unsuccessful
        )
        return _not_measured(case, "error", "execution_failed", detail)

    analyses = analyze_all(
        execution.results,
        case_tools,
        use_llm=False,
        use_rag=False,
        stage_ms=stage_ms,
    )
    if len(analyses) != len(required_results):
        return _not_measured(
            case,
            "error",
            "analysis_incomplete",
            f"expected {len(required_results)} analysis results; got {len(analyses)}",
        )
    not_analyzed = [analysis.tool_id for analysis in analyses if analysis.status != "analyzed"]
    if not_analyzed:
        return _not_measured(
            case,
            "error",
            "analysis_incomplete",
            "not_analyzed: " + ", ".join(not_analyzed),
        )
    incomplete_coverage = [
        analysis
        for analysis in analyses
        if analysis.coverage_warnings or analysis.finding_limit_reached
    ]
    if incomplete_coverage:
        details = []
        for analysis in incomplete_coverage:
            warnings = "; ".join(analysis.coverage_warnings[:3])
            if analysis.finding_limit_reached:
                warnings = f"{warnings}; finding limit reached".strip("; ")
            details.append(f"{analysis.tool_id}: {warnings}")
        return _not_measured(
            case,
            "error",
            "analysis_incomplete",
            "coverage incomplete: " + " | ".join(details),
        )
    report = build(
        inventory=inventory,
        plan=plan,
        execution=execution,
        analyses=analyses,
        started_at=started_at,
        working_directory=str(corpus_root),
        stage_ms=stage_ms,
    )
    predicted_labels = [_finding_label(finding) for finding in report.all_findings()]
    metrics = finding_metrics(case["gold_labels"], predicted_labels)
    return {
        **_case_base(case),
        "status": "executed",
        "evidence_sha256": actual_hash,
        "predicted_labels": predicted_labels,
        "finding_metrics": metrics,
        "stage_ms": stage_ms,
    }


def run_detection_benchmark(
    manifest_path: str | Path,
    *,
    corpus_dir: str | Path | None = None,
    output_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Run manifest cases locally; absent prerequisites are explicit skips."""
    path = Path(manifest_path).resolve()
    manifest = load_manifest(path)
    corpus_root = Path(corpus_dir).resolve() if corpus_dir else path.parent / "corpus"
    output_root = Path(output_dir).resolve() if output_dir else path.parent / "runs"
    tools = load_all_tools()
    cases = [
        _run_case(
            case,
            corpus_dir=corpus_root,
            output_dir=output_root,
            tools=tools,
        )
        for case in manifest["cases"]
    ]
    executed = [case for case in cases if case["status"] == "executed"]
    totals = (
        finding_metrics(
            (
                label
                for case in executed
                for label in case["gold_labels"]
            ),
            (
                label
                for case in executed
                for label in case["predicted_labels"]
            ),
        )
        if executed
        else None
    )
    return {
        "config": {
            "benchmark_kind": BENCHMARK_KIND,
            "scope": SCOPE,
            "metric_label_semantics": METRIC_LABEL_SEMANTICS,
            "downloads": "disabled",
            "zero_division": 0,
            "total_cases": len(cases),
            "executed_cases": len(executed),
            "skipped_cases": sum(case["status"] == "skipped" for case in cases),
            "error_cases": sum(case["status"] == "error" for case in cases),
            "metrics_available": bool(executed),
        },
        "aggregate": {
            "finding_metrics": totals,
            "unmeasured_reason": None if executed else "no cases executed successfully",
        },
        "cases": cases,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=SCOPE)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--corpus-dir", type=Path)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args(argv)
    result = run_detection_benchmark(
        args.manifest,
        corpus_dir=args.corpus_dir,
        output_dir=args.output_dir,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return int(result["config"]["error_cases"] > 0)


if __name__ == "__main__":
    raise SystemExit(main())
