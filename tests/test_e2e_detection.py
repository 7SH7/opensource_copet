from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

from forensicagent import e2e_detection as detection
from forensicagent.analyzer.types import ToolAnalysis
from forensicagent.tools.schema import (
    CommandTemplate,
    InstallCheck,
    SuspiciousIndicator,
    ToolMetadata,
)


def _write_manifest(
    root: Path,
    *,
    evidence_path: str = "case.py",
    sha256: str | None = None,
    gold_labels: list[str] | None = None,
) -> Path:
    manifest = {
        "schema_version": 1,
        "scope": detection.SCOPE,
        "cases": [
            {
                "id": "fixture-case",
                "source_url": "https://example.invalid/case",
                "download_url": "https://example.invalid/case.raw",
                "license": "MIT",
                "license_url": "https://example.invalid/license",
                "sha256": sha256,
                "evidence_path": evidence_path,
                "gold_labels": gold_labels if gold_labels is not None else ["bandit:B506"],
                "required_tools": ["fixture_tool"],
            }
        ],
    }
    path = root / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def _fixture_metadata(*, available: bool = True) -> ToolMetadata:
    executable = str(Path(sys.executable).resolve())
    check = f'"{executable}" --version' if available else "missing-fixture-tool --version"
    return ToolMetadata(
        tool_id="fixture_tool",
        display_name="Fixture tool",
        category="code_security",
        applicable_evidence_types=["source_code_python"],
        platform=["any"],
        input_format=["ext:.py"],
        output_format="csv",
        install_check=InstallCheck(command=check, expected_pattern="Python"),
        command_templates=[
            CommandTemplate(
                name="fixture",
                template=f'"{executable}" {{evidence_path}} {{output_dir}}',
                when="test-only deterministic CSV producer",
            )
        ],
        usage_description="Test-only metadata exercising the production pipeline.",
        suspicious_indicators=[
            SuspiciousIndicator(
                id="bandit_issue",
                pattern="Bandit-compatible CSV row",
                severity_baseline="medium",
            )
        ],
    )


def test_finding_metrics_counts_tp_fp_fn_and_duplicate_findings() -> None:
    metrics = detection.finding_metrics(
        ["rule:a", "rule:a", "rule:b"],
        ["rule:a", "rule:b", "rule:extra"],
    )

    assert metrics["true_positives"] == 2
    assert metrics["false_positives"] == 1
    assert metrics["false_negatives"] == 1
    assert metrics["finding_precision"] == pytest.approx(2 / 3)
    assert metrics["finding_recall"] == pytest.approx(2 / 3)
    assert metrics["finding_f1"] == pytest.approx(2 / 3)


def test_finding_metrics_zero_denominators_are_zero() -> None:
    assert detection.finding_metrics([], []) == {
        "true_positives": 0,
        "false_positives": 0,
        "false_negatives": 0,
        "finding_precision": 0.0,
        "finding_recall": 0.0,
        "finding_f1": 0.0,
    }


def test_benchmark_runs_real_pipeline_and_uses_finding_metric_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    evidence = corpus / "case.py"
    evidence.write_text(
        """from pathlib import Path
import sys

Path(sys.argv[1], \"finding.csv\").write_text(
    \"filename,test_name,test_id,issue_severity,issue_confidence,issue_text,line_number\\n\"
    \"case.py,yaml_load,B506,MEDIUM,HIGH,Unsafe yaml load,7\\n\",
    encoding=\"utf-8\",
)
""",
        encoding="utf-8",
    )
    manifest = _write_manifest(
        tmp_path,
        sha256=hashlib.sha256(evidence.read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(
        detection,
        "load_all_tools",
        lambda: {"fixture_tool": _fixture_metadata()},
    )

    result = detection.run_detection_benchmark(
        manifest,
        corpus_dir=corpus,
        output_dir=tmp_path / "runs",
    )

    case = result["cases"][0]
    assert case["status"] == "executed"
    assert case["download_url"] == "https://example.invalid/case.raw"
    assert case["evidence_sha256"] == hashlib.sha256(evidence.read_bytes()).hexdigest()
    assert case["predicted_labels"] == ["bandit:B506"]
    assert case["finding_metrics"]["finding_precision"] == 1.0
    assert case["finding_metrics"]["finding_recall"] == 1.0
    assert case["finding_metrics"]["finding_f1"] == 1.0
    assert result["config"]["benchmark_kind"] == "end_to_end_finding_detection"
    assert result["config"]["metric_label_semantics"] == detection.METRIC_LABEL_SEMANTICS
    assert result["config"]["executed_cases"] == 1
    assert result["config"]["metrics_available"] is True
    assert set(result["aggregate"]["finding_metrics"]).isdisjoint(
        {"p@1", "r@1", "ndcg@1", "mrr", "core_mrr"}
    )


def test_manifest_requires_https_download_url(tmp_path: Path) -> None:
    manifest = _write_manifest(tmp_path)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["cases"][0]["download_url"] = "http://example.invalid/case.raw"
    manifest.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match=r"download_url must be an https URL"):
        detection.load_manifest(manifest)


def test_missing_corpus_file_is_skipped_and_not_in_metric_denominator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = _write_manifest(tmp_path)
    monkeypatch.setattr(detection, "load_all_tools", lambda: {})

    result = detection.run_detection_benchmark(manifest, corpus_dir=tmp_path / "corpus")

    assert result["cases"][0]["reason"] == "evidence_missing"
    assert result["config"]["executed_cases"] == 0
    assert result["config"]["skipped_cases"] == 1
    assert result["config"]["metrics_available"] is False
    assert result["aggregate"]["finding_metrics"] is None


def test_hash_mismatch_is_skipped_before_tool_lookup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "case.py").write_text("print('different')", encoding="utf-8")
    manifest = _write_manifest(tmp_path, sha256="0" * 64)
    monkeypatch.setattr(detection, "load_all_tools", lambda: {})

    result = detection.run_detection_benchmark(manifest, corpus_dir=corpus)

    assert result["cases"][0]["reason"] == "sha256_mismatch"
    assert result["config"]["executed_cases"] == 0


def test_manifest_hash_is_checked_against_the_scanned_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    evidence = corpus / "case.py"
    evidence.write_text("print('original')", encoding="utf-8")
    original_hash = hashlib.sha256(evidence.read_bytes()).hexdigest()
    manifest = _write_manifest(tmp_path, sha256=original_hash)
    original_scan = detection.scan

    def replace_then_scan(*args, **kwargs):
        evidence.write_text("print('replacement')", encoding="utf-8")
        return original_scan(*args, **kwargs)

    monkeypatch.setattr(detection, "scan", replace_then_scan)
    monkeypatch.setattr(
        detection,
        "load_all_tools",
        lambda: {"fixture_tool": _fixture_metadata()},
    )

    result = detection.run_detection_benchmark(manifest, corpus_dir=corpus)

    case = result["cases"][0]
    assert case["reason"] == "sha256_mismatch"
    assert original_hash in case["detail"]
    assert result["config"]["executed_cases"] == 0


def test_existing_evidence_without_pinned_hash_is_not_measured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "case.py").write_text("print('fixture')", encoding="utf-8")
    manifest = _write_manifest(tmp_path, sha256=None)
    monkeypatch.setattr(detection, "load_all_tools", lambda: {})

    result = detection.run_detection_benchmark(manifest, corpus_dir=corpus)

    assert result["cases"][0]["reason"] == "sha256_not_pinned"
    assert result["config"]["executed_cases"] == 0
    assert result["aggregate"]["finding_metrics"] is None


def test_missing_and_unavailable_required_tools_are_explicit_skips(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    evidence = corpus / "case.py"
    evidence.write_text("print('fixture')", encoding="utf-8")
    manifest = _write_manifest(
        tmp_path,
        sha256=hashlib.sha256(evidence.read_bytes()).hexdigest(),
    )

    monkeypatch.setattr(detection, "load_all_tools", lambda: {})
    missing = detection.run_detection_benchmark(manifest, corpus_dir=corpus)
    assert missing["cases"][0]["reason"] == "required_tool_metadata_missing"

    monkeypatch.setattr(
        detection,
        "load_all_tools",
        lambda: {"fixture_tool": _fixture_metadata(available=False)},
    )
    unavailable = detection.run_detection_benchmark(
        manifest,
        corpus_dir=corpus,
        output_dir=tmp_path / "runs",
    )
    assert unavailable["cases"][0]["reason"] == "required_tool_unavailable"
    assert unavailable["config"]["executed_cases"] == 0
    assert unavailable["aggregate"]["finding_metrics"] is None


@pytest.mark.parametrize(
    ("analysis", "detail_fragment"),
    [
        (ToolAnalysis(tool_id="fixture_tool", status="not_analyzed"), "not_analyzed"),
        (
            ToolAnalysis(
                tool_id="fixture_tool",
                coverage_warnings=["CSV record was truncated"],
            ),
            "coverage incomplete",
        ),
    ],
)
def test_incomplete_analysis_is_excluded_from_metrics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    analysis: ToolAnalysis,
    detail_fragment: str,
) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    evidence = corpus / "case.py"
    evidence.write_text(
        """from pathlib import Path
import sys

Path(sys.argv[1], "finding.csv").write_text(
    "filename,test_name,test_id,issue_severity,issue_confidence,issue_text,line_number\\n",
    encoding="utf-8",
)
""",
        encoding="utf-8",
    )
    manifest = _write_manifest(
        tmp_path,
        sha256=hashlib.sha256(evidence.read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(
        detection,
        "load_all_tools",
        lambda: {"fixture_tool": _fixture_metadata()},
    )
    monkeypatch.setattr(detection, "analyze_all", lambda *args, **kwargs: [analysis])

    result = detection.run_detection_benchmark(
        manifest,
        corpus_dir=corpus,
        output_dir=tmp_path / "runs",
    )

    case = result["cases"][0]
    assert case["status"] == "error"
    assert case["reason"] == "analysis_incomplete"
    assert detail_fragment in case["detail"]
    assert result["config"]["executed_cases"] == 0
    assert result["aggregate"]["finding_metrics"] is None
