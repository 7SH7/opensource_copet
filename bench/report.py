"""Render benchmark results — terminal (Rich) + JSON + Markdown.

주의(cp949): 터미널 출력 문자열은 ASCII 만 사용한다 (em-dash 등 금지).
JSON/MD 파일은 utf-8 로 저장.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from bench.harness import METRIC_KEYS

BENCH_DIR = Path(__file__).resolve().parent

_METHODOLOGY = """\
## Methodology

- **Goal**: quantify how much RAG reranking improves the Selector's tool
  *ordering* over a deterministic-only baseline.
- **Host contract**: official results are generated on Windows; the harness
  rejects other operating systems before loading tools or rebuilding an index.
- **Golden set**: {n_cases} SYNTHETIC, hand-labeled English cases (one labeler).
  Each case = an evidence inventory (evidence_type + filenames) + optional
  English scenario + per-tool relevance grades (2=core, 1=secondary,
  0=irrelevant-but-eligible). NOT real CTF data.
- **Qualification is identical across modes**: the deterministic evidence-type
  gate (Stage 1) admits the same tool set in every mode, so all differences
  below come purely from ORDERING, never from which tools qualify.
- **Baseline (deterministic)**: `use_rag=False, use_llm=False` -> Stage 1
  filter order (tool_metadata load order), which carries no semantic signal.
- **RAG**: `use_rag=True, use_llm=False` -> candidates reranked by cosine
  similarity of the tool-metadata corpus to an (evidence + scenario) query,
  embedded with `{embedding_model}`. Retrieval uses a minimum similarity of
  {rag_min_similarity}; reranking also requires a full eligible-set score
  spread of at least {rag_min_score_margin}.
- **Metrics**: NDCG@k uses exponential gain (2^rel - 1)/log2(rank+1); MRR,
  Precision@k, Recall@k use relevance >= 1 as the "relevant" threshold.
  NDCG's ideal ranking and Recall's denominator use every gold-labeled tool,
  including relevant tools omitted by the Selector.
  k in {ks}. Reported values are means across cases.

## Limitations (read before trusting the numbers)

- Small (n={n_cases}), synthetic, single-labeler golden set - indicative, not
  statistically robust. Labels encode one analyst's judgement.
- Only {n_tools} tools; several evidence types map to a single eligible tool,
  where ordering is trivial (metric == 1.0 regardless of mode) and dilutes the
  measured delta. The signal lives in multi-tool cases (registry_hive,
  evtx_log, source_code_*).
- The golden scenarios are English only. Korean and other multilingual
  performance is not measured by this benchmark.
- Ordering quality only. This does NOT measure end-to-end triage correctness,
  tool execution, or finding quality.
- RAG safety property (never promotes a tool outside Stage 1) and graceful
  fallback are covered by unit tests, not by this benchmark.
"""


def _fmt_delta(v: float) -> str:
    return f"+{v:.4f}" if v > 0 else f"{v:.4f}"


def render_terminal(result: dict[str, Any], console) -> None:
    from rich.table import Table

    cfg = result["config"]
    console.print(
        f"[bold]RAG tool-selection ranking benchmark[/] - "
        f"{cfg['n_cases']} cases, {cfg['n_tools']} tools"
    )
    console.print(f"[dim]{cfg['llm_note']}[/]")
    idx = result.get("index", {})
    if idx.get("rebuilt"):
        console.print(
            f"[dim]index build: {idx.get('tools_indexed')} tools, "
            f"embed {idx.get('embedding_ms')}ms, chroma {idx.get('chroma_ms')}ms, "
            f"total {idx.get('elapsed_s')}s[/]"
        )
    if "freshness_verified" in idx:
        state = "verified" if idx["freshness_verified"] else "unverified"
        console.print(
            f"[dim]index freshness: {state} "
            f"({idx.get('freshness_contract')}, "
            f"tool docs {idx.get('tool_documents_sha256')})[/]"
        )
    repro = result.get("reproducibility", {})
    if repro:
        host = repro.get("host", {})
        python = repro.get("python", {})
        console.print(
            f"[dim]repro: {repro.get('generated_at_utc')} | "
            f"{host.get('os')} {host.get('release')} {host.get('machine')} | "
            f"{python.get('implementation')} {python.get('version')}[/]"
        )
    console.print(f"[dim]RAG actually reranked {cfg['rag_used_cases']}/{cfg['n_cases']} cases[/]\n")

    # aggregate table
    agg = result["aggregate"]
    t = Table(title="Aggregate (mean over cases)")
    t.add_column("metric", style="bold")
    for mode in agg:
        t.add_column(mode, justify="right")
    for k in METRIC_KEYS:
        t.add_row(k, *[f"{agg[m][k]:.4f}" for m in agg])
    console.print(t)

    # delta table (headline)
    for dname, dvals in result["delta"].items():
        dt = Table(title=f"DELTA {dname} (positive = RAG better)")
        dt.add_column("metric", style="bold")
        dt.add_column("delta", justify="right")
        for k in METRIC_KEYS:
            v = dvals[k]
            style = "green" if v > 0 else ("red" if v < 0 else "dim")
            dt.add_row(k, f"[{style}]{_fmt_delta(v)}[/]")
        console.print(dt)

    # timing
    tm = result["timing_ms"]
    tt = Table(title="Timing (mean ms per case)")
    tt.add_column("mode", style="bold")
    tt.add_column("select_filter", justify="right")
    tt.add_column("select_rag", justify="right")
    tt.add_column("select_rank", justify="right")
    for mode, vals in tm.items():
        tt.add_row(mode, f"{vals['select_filter']:.1f}", f"{vals['select_rag']:.1f}", f"{vals['select_rank']:.1f}")
    console.print(tt)


def _md_table(headers: list[str], rows: list[list[str]]) -> str:
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for r in rows:
        out.append("| " + " | ".join(r) + " |")
    return "\n".join(out)


def to_markdown(result: dict[str, Any]) -> str:
    cfg = result["config"]
    agg = result["aggregate"]
    modes = list(agg.keys())

    parts = ["# forensicagent RAG tool-selection ranking benchmark\n"]
    parts.append(
        f"- cases: **{cfg['n_cases']}** | tools: **{cfg['n_tools']}** | "
        f"k: {cfg['ks']} | RAG reranked {cfg['rag_used_cases']}/{cfg['n_cases']} cases"
    )
    parts.append(f"- scope: **{cfg.get('scope', 'tool-selection ranking only')}**")
    parts.append(f"- host contract: **{cfg.get('host_contract', 'not recorded')}**")
    parts.append(f"- {cfg['llm_note']}")
    idx = result.get("index", {})
    if idx.get("rebuilt"):
        parts.append(
            f"- index build: {idx.get('tools_indexed')} tools, "
            f"embed {idx.get('embedding_ms')}ms, chroma {idx.get('chroma_ms')}ms, "
            f"total {idx.get('elapsed_s')}s"
        )
    if "freshness_verified" in idx:
        state = "verified" if idx["freshness_verified"] else "unverified"
        parts.append(
            f"- index freshness: **{state}** "
            f"({idx.get('freshness_contract')}); tool-documents SHA-256: "
            f"`{idx.get('tool_documents_sha256')}`"
        )
    parts.append("")

    # reproducibility
    repro = result.get("reproducibility", {})
    if repro:
        host = repro.get("host", {})
        python = repro.get("python", {})
        packages = repro.get("package_versions", {})
        package_text = ", ".join(
            f"{name}={version if version is not None else 'not installed'}"
            for name, version in packages.items()
        )
        parts.append("## Reproducibility metadata\n")
        parts.append(f"- generated (UTC): `{repro.get('generated_at_utc')}`")
        parts.append(
            f"- host: `{host.get('os')} {host.get('release')} "
            f"{host.get('machine')}`; Python: "
            f"`{python.get('implementation')} {python.get('version')}`"
        )
        parts.append(
            f"- embedding: `{repro.get('embedding_model')}`; "
            f"top-k: `{repro.get('rag_top_k')}`; minimum similarity: "
            f"`{repro.get('rag_min_similarity')}`; minimum score spread: "
            f"`{repro.get('rag_min_score_margin')}`"
        )
        parts.append(f"- golden-set SHA-256: `{repro.get('golden_sha256')}`")
        parts.append(
            "- tool-documents SHA-256: "
            f"`{repro.get('tool_documents_sha256')}`"
        )
        parts.append(f"- packages: {package_text}")
        parts.append("")

    # aggregate
    parts.append("## Aggregate (mean over cases)\n")
    parts.append(_md_table(
        ["metric"] + modes,
        [[k] + [f"{agg[m][k]:.4f}" for m in modes] for k in METRIC_KEYS],
    ))
    parts.append("")

    # delta
    for dname, dvals in result["delta"].items():
        parts.append(f"## Delta: {dname} (positive = RAG better)\n")
        parts.append(_md_table(
            ["metric", "delta"],
            [[k, _fmt_delta(dvals[k])] for k in METRIC_KEYS],
        ))
        parts.append("")

    # timing
    parts.append("## Timing (mean ms per case)\n")
    tm = result["timing_ms"]
    parts.append(_md_table(
        ["mode", "select_filter", "select_rag", "select_rank"],
        [[m, f"{tm[m]['select_filter']:.1f}", f"{tm[m]['select_rag']:.1f}", f"{tm[m]['select_rank']:.1f}"] for m in tm],
    ))
    parts.append("")

    # per-case (ndcg@3 + order for det vs rag)
    parts.append("## Per-case (deterministic vs rag)\n")
    rows = []
    for row in result["per_case"]:
        det = row["modes"].get("deterministic", {})
        rag = row["modes"].get("rag", {})
        rows.append([
            row["id"],
            str(row["n_eligible"]),
            "Y" if row["scenario"] else "-",
            f"{det.get('ndcg@3', 0):.4f}",
            f"{rag.get('ndcg@3', 0):.4f}",
            f"{rag.get('ndcg@3', 0) - det.get('ndcg@3', 0):+.4f}",
            " > ".join(rag.get("order", [])[:4]),
        ])
    parts.append(_md_table(
        ["case", "elig", "scen", "det ndcg@3", "rag ndcg@3", "delta", "rag order (top4)"],
        rows,
    ))
    parts.append("")

    parts.append(_METHODOLOGY.format(
        n_cases=cfg["n_cases"],
        n_tools=cfg["n_tools"],
        ks=cfg["ks"],
        embedding_model=repro.get("embedding_model", "not recorded"),
        rag_min_similarity=repro.get("rag_min_similarity", "not recorded"),
        rag_min_score_margin=repro.get("rag_min_score_margin", "not recorded"),
    ))
    return "\n".join(parts)


def save(result: dict[str, Any], *, out_dir: Path = BENCH_DIR) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "bench_result.json"
    md_path = out_dir / "bench_report.md"
    json_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(to_markdown(result), encoding="utf-8")
    return {"json": json_path, "md": md_path}
