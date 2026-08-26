"""Benchmark execution contract and reproducibility metadata."""

from __future__ import annotations

import math

import pytest

import bench.harness as harness
from bench.report import to_markdown


def test_benchmark_rejects_non_windows_before_loading_tools(monkeypatch):
    monkeypatch.setattr(harness.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        harness,
        "load_all_tools",
        lambda: pytest.fail("tool loading must not run on an unsupported host"),
    )

    with pytest.raises(RuntimeError, match="Windows-only"):
        harness.run_benchmark()


def test_tool_document_digest_is_stable_across_mapping_order(monkeypatch):
    from forensicagent.rag import tool_indexer

    monkeypatch.setattr(tool_indexer, "build_tool_document", lambda value: value)

    first = harness._tool_documents_sha256({"b": "doc-b", "a": "doc-a"})
    reordered = harness._tool_documents_sha256({"a": "doc-a", "b": "doc-b"})
    changed = harness._tool_documents_sha256({"a": "doc-a", "b": "changed"})

    assert first == reordered
    assert first != changed
    assert len(first) == 64


def test_no_rebuild_contract_verifies_digest_model_and_collection(
    tmp_path, monkeypatch
):
    from forensicagent.rag import tool_indexer

    monkeypatch.setattr(harness.settings, "CHROMA_PERSIST_DIR", str(tmp_path))
    monkeypatch.setattr(harness.settings, "TOOL_COLLECTION", "bench-tools")
    monkeypatch.setattr(harness.settings, "EMBEDDING_MODEL", "test/model")
    monkeypatch.setattr(
        tool_indexer,
        "tool_collection_status",
        lambda: (True, 2, "ok"),
    )
    contract = harness._index_contract("a" * 64, 2)
    harness._write_index_contract(contract)

    info = harness._verify_existing_index(contract)

    assert info["freshness_verified"] is True
    assert info["tools_indexed"] == 2
    assert info["tool_documents_sha256"] == "a" * 64


def test_no_rebuild_contract_rejects_stale_tool_documents(tmp_path, monkeypatch):
    monkeypatch.setattr(harness.settings, "CHROMA_PERSIST_DIR", str(tmp_path))
    monkeypatch.setattr(harness.settings, "TOOL_COLLECTION", "bench-tools")
    monkeypatch.setattr(harness.settings, "EMBEDDING_MODEL", "test/model")
    harness._write_index_contract(harness._index_contract("a" * 64, 2))

    with pytest.raises(RuntimeError, match="tool_documents_sha256"):
        harness._verify_existing_index(harness._index_contract("b" * 64, 2))


def test_result_keeps_metric_precision_and_reproducibility_metadata(monkeypatch):
    case = {
        "id": "precision",
        "evidence": [{"filename": "sample.evtx", "evidence_type": "evtx_log"}],
        "labels": {"secondary": 1, "core": 2},
    }
    monkeypatch.setattr(harness.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        harness, "load_all_tools", lambda: {"secondary": object(), "core": object()}
    )
    monkeypatch.setattr(harness, "_tool_documents_sha256", lambda tools: "d" * 64)
    monkeypatch.setattr(
        harness,
        "_verify_existing_index",
        lambda contract: {
            "rebuilt": False,
            "tools_indexed": 2,
            "freshness_verified": True,
            "freshness_contract": "tool-documents-sha256-v1",
            "tool_documents_sha256": "d" * 64,
        },
    )
    monkeypatch.setattr(harness, "load_cases", lambda: [case])
    monkeypatch.setattr(
        harness,
        "_run_mode",
        lambda *args, **kwargs: (["secondary", "core"], {}, kwargs["use_rag"]),
    )
    monkeypatch.setattr(harness, "_sha256_file", lambda path: "g" * 64)
    monkeypatch.setattr(
        harness, "_package_versions", lambda: {"forensicagent": "test"}
    )

    result = harness.run_benchmark(rebuild=False)

    raw_ndcg = (1.0 + 3.0 / math.log2(3)) / (3.0 + 1.0 / math.log2(3))
    stored = result["per_case"][0]["modes"]["deterministic"]["ndcg@3"]
    assert stored == round(raw_ndcg, 10)
    assert stored != round(raw_ndcg, 4)
    assert result["aggregate"]["deterministic"]["ndcg@3"] == round(
        raw_ndcg, 10
    )
    assert result["reproducibility"]["host"]["os"] == "Windows"
    assert result["reproducibility"]["golden_sha256"] == "g" * 64
    assert result["reproducibility"]["tool_documents_sha256"] == "d" * 64


def test_markdown_uses_runtime_model_and_four_decimal_metrics():
    metrics = {key: 0.123456789 for key in harness.METRIC_KEYS}
    rag_metrics = {key: 0.987654321 for key in harness.METRIC_KEYS}
    result = {
        "config": {
            "scope": "tool-selection ranking only; not end-to-end detection accuracy",
            "n_cases": 1,
            "n_tools": 2,
            "ks": [3, 5],
            "llm_note": "not requested",
            "rag_used_cases": 1,
        },
        "index": {
            "rebuilt": False,
            "freshness_verified": True,
            "freshness_contract": "tool-documents-sha256-v1",
            "tool_documents_sha256": "d" * 64,
        },
        "reproducibility": {
            "generated_at_utc": "2026-08-19T00:00:00Z",
            "host": {"os": "Windows", "release": "11", "machine": "AMD64"},
            "python": {"implementation": "CPython", "version": "3.12.0"},
            "embedding_model": "example/multilingual-model",
            "rag_top_k": 5,
            "rag_min_similarity": 0.25,
            "rag_min_score_margin": 0.1,
            "golden_sha256": "g" * 64,
            "tool_documents_sha256": "d" * 64,
            "package_versions": {"forensicagent": "0.0.1"},
        },
        "aggregate": {"deterministic": metrics, "rag": rag_metrics},
        "delta": {
            "rag_vs_deterministic": {
                key: rag_metrics[key] - metrics[key] for key in harness.METRIC_KEYS
            }
        },
        "timing_ms": {
            mode: {"select_filter": 1.0, "select_rag": 2.0, "select_rank": 3.0}
            for mode in ("deterministic", "rag")
        },
        "per_case": [
            {
                "id": "case-1",
                "n_eligible": 2,
                "scenario": True,
                "modes": {
                    "deterministic": {"ndcg@3": 0.123456789, "order": ["a", "b"]},
                    "rag": {"ndcg@3": 0.987654321, "order": ["b", "a"]},
                },
            }
        ],
    }

    markdown = to_markdown(result)

    assert "example/multilingual-model" in markdown
    assert "all-MiniLM-L6-v2" not in markdown
    assert "Korean scenarios would score worse" not in markdown
    assert "| case-1 | 2 | Y | 0.1235 | 0.9877 | +0.8642 |" in markdown
    assert "golden-set SHA-256" in markdown
