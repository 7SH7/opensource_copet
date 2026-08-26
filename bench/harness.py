"""RAG benchmark harness — deterministic baseline vs RAG reranking.

각 골든 케이스에 대해 Selector 를 여러 모드로 돌려 선택 도구/순서/타이밍을
캡처하고, golden relevance 라벨 대비 도구 선택 랭킹 지표(NDCG/MRR/P/R @k)를
계산한다. 실제 분석기를 실행하지 않으므로 end-to-end 탐지 정확도 지표가 아니다.

모드:
  * deterministic : use_rag=False, use_llm=False  (baseline — Stage1 필터 순서)
  * rag           : use_rag=True,  use_llm=False  (RAG 관련도 재정렬)
  * llm           : use_rag=False, use_llm=True    (opt-in, Ollama 필요)
  * rag_llm       : use_rag=True,  use_llm=True     (opt-in, Ollama 필요)

핵심 원칙: 자격 게이트(Stage1)는 모드 간 동일하므로 개선 신호는 순전히
순서 품질(NDCG/MRR/P/R)에 있다. LLM 모드는 로컬 CPU 추론이 느려 기본 off,
`--with-llm` 로만 켠다(Ollama 없으면 우아하게 skip). RAG 의존성이 없으면
select 가 결정론 순서로 폴백하므로 rag==deterministic 이 되고 delta=0.
"""

from __future__ import annotations

import hashlib
import json
import platform
import time
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version as package_version
from pathlib import Path
from typing import Any, Optional

from forensicagent import config as settings
from forensicagent.scanner.types import Evidence, Inventory
from forensicagent.selector import select
from forensicagent.tools import load_all_tools
from bench import metrics as M

BENCH_DIR = Path(__file__).resolve().parent
GOLDEN_PATH = BENCH_DIR / "goldenset.json"
KS = (3, 5)
METRIC_KEYS = [f"ndcg@{k}" for k in KS] + ["mrr", "core_mrr"] + \
    [f"p@{k}" for k in KS] + [f"r@{k}" for k in KS] + \
    [f"core_r@{k}" for k in KS]
_INDEX_CONTRACT_FILE = ".forensicagent-benchmark-index.json"
_INDEX_CONTRACT_SCHEMA = 1
_REPRO_PACKAGES = (
    "forensicagent",
    "chromadb",
    "sentence-transformers",
    "torch",
    "transformers",
    "tokenizers",
    "numpy",
    "PyYAML",
    "ollama",
)


def _require_windows_host() -> None:
    system = platform.system()
    if system != "Windows":
        raise RuntimeError(
            "Official benchmark results are Windows-only; "
            f"this host reports {system!r}. Run the benchmark on Windows so "
            "tool eligibility and timing use the published host contract."
        )


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tool_documents_sha256(tools: dict[str, Any]) -> str:
    """Digest exactly the sorted documents supplied to the embedding index."""
    from forensicagent.rag.tool_indexer import build_tool_document

    documents = [
        {"tool_id": tool_id, "document": build_tool_document(tools[tool_id])}
        for tool_id in sorted(tools)
    ]
    payload = json.dumps(
        documents,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _index_contract(tool_documents_sha256: str, n_tools: int) -> dict[str, Any]:
    return {
        "schema": _INDEX_CONTRACT_SCHEMA,
        "collection": settings.TOOL_COLLECTION,
        "embedding_model": settings.EMBEDDING_MODEL,
        "tool_documents_sha256": tool_documents_sha256,
        "n_tools": n_tools,
    }


def _index_contract_path() -> Path:
    return Path(settings.CHROMA_PERSIST_DIR) / _INDEX_CONTRACT_FILE


def _write_index_contract(contract: dict[str, Any]) -> None:
    path = _index_contract_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(contract, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _verify_existing_index(contract: dict[str, Any]) -> dict[str, Any]:
    """Fail closed when ``--no-rebuild`` cannot prove index freshness."""
    path = _index_contract_path()
    try:
        stored = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError(
            "Cannot reuse the tool index: benchmark freshness contract is "
            "missing. Run once without --no-rebuild."
        ) from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            "Cannot reuse the tool index: benchmark freshness contract is "
            "unreadable. Run once without --no-rebuild."
        ) from exc
    if not isinstance(stored, dict):
        raise RuntimeError(
            "Cannot reuse the tool index: benchmark freshness contract has "
            "an invalid shape. Run once without --no-rebuild."
        )

    if stored != contract:
        changed = sorted(
            key
            for key in set(stored) | set(contract)
            if stored.get(key) != contract.get(key)
        )
        raise RuntimeError(
            "Cannot reuse the tool index: freshness contract changed "
            f"({', '.join(changed)}). Run without --no-rebuild."
        )

    from forensicagent.rag.tool_indexer import tool_collection_status

    available, count, detail = tool_collection_status()
    if not available or count != contract["n_tools"]:
        raise RuntimeError(
            "Cannot reuse the tool index: collection count does not match "
            f"the freshness contract (expected {contract['n_tools']}, got "
            f"{count}; {detail}). Run without --no-rebuild."
        )
    return {
        "rebuilt": False,
        "tools_indexed": count,
        "freshness_verified": True,
        "freshness_contract": "tool-documents-sha256-v1",
        "tool_documents_sha256": contract["tool_documents_sha256"],
    }


def _package_versions() -> dict[str, str | None]:
    versions: dict[str, str | None] = {}
    for name in _REPRO_PACKAGES:
        try:
            versions[name] = package_version(name)
        except PackageNotFoundError:
            versions[name] = None
    return versions


def _reproducibility_metadata(
    *, golden_sha256: str, tool_documents_sha256: str
) -> dict[str, Any]:
    return {
        "generated_at_utc": datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "host": {
            "os": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "python": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
        },
        "embedding_model": settings.EMBEDDING_MODEL,
        "rag_top_k": settings.RAG_TOP_K,
        "rag_min_similarity": settings.RAG_MIN_SIMILARITY,
        "rag_min_score_margin": settings.RAG_MIN_SCORE_MARGIN,
        "golden_sha256": golden_sha256,
        "tool_documents_sha256": tool_documents_sha256,
        "package_versions": _package_versions(),
    }


# ---------------------------------------------------------------------------
# Golden set + inventory
# ---------------------------------------------------------------------------

def load_cases(path: Path = GOLDEN_PATH) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["cases"]


def _inventory(case: dict[str, Any]) -> Inventory:
    evs = [
        Evidence(
            path=e["filename"],
            filename=e["filename"],
            size_bytes=1,
            evidence_type=e["evidence_type"],
            detected_by="extension",
        )
        for e in case["evidence"]
    ]
    return Inventory(evidence_list=evs, scan_root="(bench synthetic)")


# ---------------------------------------------------------------------------
# One (case, mode) run + metrics
# ---------------------------------------------------------------------------

def _run_mode(
    inv: Inventory,
    tools: dict,
    scenario: Optional[str],
    *,
    use_rag: bool,
    use_llm: bool,
    client,
) -> tuple[list[str], dict[str, int], bool]:
    stage_ms: dict[str, int] = {}
    plan = select(
        inv, tools,
        use_llm=use_llm, use_rag=use_rag,
        client=client, scenario=scenario, stage_ms=stage_ms,
    )
    return [t.tool_id for t in plan.selected_tools], stage_ms, plan.rag_used


def _case_metrics(predicted_ids: list[str], labels: dict[str, int]) -> dict[str, float]:
    rels = [float(labels.get(t, 0)) for t in predicted_ids]
    gold_rels = [float(rel) for rel in labels.values()]
    out: dict[str, float] = {}
    for k in KS:
        out[f"ndcg@{k}"] = M.ndcg_at_k(rels, k, ideal_rels=gold_rels)
        out[f"p@{k}"] = M.precision_at_k(rels, k)
        out[f"r@{k}"] = M.recall_at_k(
            rels,
            k,
            total_relevant=sum(rel >= 1.0 for rel in gold_rels),
        )
    out["mrr"] = M.mrr(rels)
    # Grade 1 is useful context, but it made the previous MRR saturate at 1.0
    # for nearly every synthetic case. Track the first core (grade 2) tool and
    # core coverage separately so a primary-tool regression is visible.
    out["core_mrr"] = M.mrr(rels, threshold=2.0)
    for k in KS:
        out[f"core_r@{k}"] = M.recall_at_k(
            rels,
            k,
            threshold=2.0,
            total_relevant=sum(rel >= 2.0 for rel in gold_rels),
        )
    return out


# ---------------------------------------------------------------------------
# Full benchmark
# ---------------------------------------------------------------------------

def run_benchmark(*, with_llm: bool = False, rebuild: bool = True) -> dict[str, Any]:
    _require_windows_host()
    tools = load_all_tools()  # 공용 리졸버 (env -> ~/.forensicagent -> repo)
    n_tools = len(tools)
    tool_documents_sha256 = _tool_documents_sha256(tools)
    contract = _index_contract(tool_documents_sha256, n_tools)

    # ---- index build (timed) ----
    if rebuild:
        from forensicagent.rag.tool_indexer import index_tools

        stats = index_tools(tools, overwrite=True)
        if stats.errors or stats.tools_indexed != n_tools:
            detail = "; ".join(stats.errors) or (
                f"expected {n_tools} tools, indexed {stats.tools_indexed}"
            )
            raise RuntimeError(f"Tool-index rebuild was incomplete: {detail}")
        _write_index_contract(contract)
        index_info: dict[str, Any] = dict(
            rebuilt=True,
            tools_indexed=stats.tools_indexed,
            embedding_ms=stats.embedding_ms,
            chroma_ms=stats.chroma_ms,
            elapsed_s=round(stats.elapsed_s, 2),
            errors=stats.errors,
            freshness_verified=True,
            freshness_contract="tool-documents-sha256-v1",
            tool_documents_sha256=tool_documents_sha256,
        )
    else:
        index_info = _verify_existing_index(contract)

    # ---- modes (LLM opt-in + availability gated) ----
    modes: list[tuple[str, bool, bool]] = [
        ("deterministic", False, False),
        ("rag", True, False),
    ]
    client = None
    llm_note = "LLM modes not requested (--with-llm off)."
    if with_llm:
        from forensicagent.llm import OllamaClient
        c = OllamaClient()
        ok, detail = c.is_available()
        if ok:
            client = c
            modes += [("llm", False, True), ("rag_llm", True, True)]
            llm_note = f"LLM modes enabled ({c.model}: {detail})."
        else:
            llm_note = f"LLM modes SKIPPED - Ollama unavailable: {detail}"

    cases = load_cases()
    per_case: list[dict[str, Any]] = []
    # accumulators: mode -> metric -> [values]; mode -> timing lists
    agg: dict[str, dict[str, list[float]]] = {m[0]: {k: [] for k in METRIC_KEYS} for m in modes}
    timing: dict[str, dict[str, list[float]]] = {
        m[0]: {"select_filter": [], "select_rag": [], "select_rank": []} for m in modes
    }
    rag_used_count = 0

    for case in cases:
        inv = _inventory(case)
        scenario = case.get("scenario")
        labels = case.get("labels", {})
        row: dict[str, Any] = {
            "id": case["id"],
            "n_eligible": None,
            "scenario": bool(scenario),
            "modes": {},
        }
        for name, use_rag, use_llm in modes:
            ids, stage_ms, rag_used = _run_mode(
                inv, tools, scenario, use_rag=use_rag, use_llm=use_llm, client=client
            )
            row["n_eligible"] = len(ids)
            met = _case_metrics(ids, labels)
            row["modes"][name] = {
                "order": ids,
                **{k: round(v, 10) for k, v in met.items()},
            }
            for k in METRIC_KEYS:
                agg[name][k].append(met[k])
            for tkey in ("select_filter", "select_rag", "select_rank"):
                timing[name][tkey].append(float(stage_ms.get(tkey, 0)))
            if name == "rag" and rag_used:
                rag_used_count += 1
        per_case.append(row)

    # ---- aggregate means + delta ----
    aggregate_raw = {
        name: {k: M.mean(vals) for k, vals in mets.items()}
        for name, mets in agg.items()
    }
    aggregate = {
        name: {k: round(value, 10) for k, value in metrics.items()}
        for name, metrics in aggregate_raw.items()
    }
    timing_mean = {
        name: {tkey: round(M.mean(vals), 2) for tkey, vals in t.items()}
        for name, t in timing.items()
    }
    delta = {}
    if "deterministic" in aggregate and "rag" in aggregate:
        delta["rag_vs_deterministic"] = {
            k: round(
                aggregate_raw["rag"][k] - aggregate_raw["deterministic"][k],
                10,
            )
            for k in METRIC_KEYS
        }
    if "llm" in aggregate and "rag_llm" in aggregate:
        delta["rag_llm_vs_llm"] = {
            k: round(aggregate_raw["rag_llm"][k] - aggregate_raw["llm"][k], 10)
            for k in METRIC_KEYS
        }

    return {
        "config": {
            "scope": "tool-selection ranking only; not end-to-end detection accuracy",
            "host_contract": "Windows-only official benchmark",
            "n_cases": len(cases),
            "n_tools": n_tools,
            "ks": list(KS),
            "modes": [m[0] for m in modes],
            "llm_note": llm_note,
            "rag_used_cases": rag_used_count,
        },
        "index": index_info,
        "reproducibility": _reproducibility_metadata(
            golden_sha256=_sha256_file(GOLDEN_PATH),
            tool_documents_sha256=tool_documents_sha256,
        ),
        "aggregate": aggregate,
        "delta": delta,
        "timing_ms": timing_mean,
        "per_case": per_case,
    }
