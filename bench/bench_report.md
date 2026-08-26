# forensicagent RAG tool-selection ranking benchmark

- cases: **14** | tools: **11** | k: [3, 5] | RAG reranked 3/14 cases
- scope: **tool-selection ranking only; not end-to-end detection accuracy**
- host contract: **Windows-only official benchmark**
- LLM modes not requested (--with-llm off).
- index build: 11 tools, embed 43094ms, chroma 716ms, total 48.26s
- index freshness: **verified** (tool-documents-sha256-v1); tool-documents SHA-256: `291b124da08be965087aaebcd2ace4d27da328d74aeb023254179b0e94344a4a`

## Reproducibility metadata

- generated (UTC): `2026-08-19T11:58:52Z`
- host: `Windows 11 AMD64`; Python: `CPython 3.12.4`
- embedding: `sentence-transformers/all-MiniLM-L6-v2`; top-k: `5`; minimum similarity: `0.25`; minimum score spread: `0.1`
- golden-set SHA-256: `ece2e16d43a9cbcd0f44cf5885cafd891b46fb2aba37fc5d58f40e0dd1aefe9e`
- tool-documents SHA-256: `291b124da08be965087aaebcd2ace4d27da328d74aeb023254179b0e94344a4a`
- packages: forensicagent=0.0.1, chromadb=1.5.9, sentence-transformers=6.0.0, torch=2.13.0, transformers=5.15.0, tokenizers=0.22.2, numpy=2.5.2, PyYAML=6.0.3, ollama=0.6.2

## Aggregate (mean over cases)

| metric | deterministic | rag |
|---|---|---|
| ndcg@3 | 0.9295 | 0.9242 |
| ndcg@5 | 0.9485 | 0.9442 |
| mrr | 1.0000 | 1.0000 |
| core_mrr | 0.8929 | 0.8571 |
| p@3 | 0.6429 | 0.6429 |
| p@5 | 0.4143 | 0.4143 |
| r@3 | 0.9714 | 0.9714 |
| r@5 | 1.0000 | 1.0000 |
| core_r@3 | 0.9524 | 0.9524 |
| core_r@5 | 1.0000 | 1.0000 |

## Delta: rag_vs_deterministic (positive = RAG better)

| metric | delta |
|---|---|
| ndcg@3 | -0.0053 |
| ndcg@5 | -0.0043 |
| mrr | 0.0000 |
| core_mrr | -0.0357 |
| p@3 | 0.0000 |
| p@5 | 0.0000 |
| r@3 | 0.0000 |
| r@5 | 0.0000 |
| core_r@3 | 0.0000 |
| core_r@5 | 0.0000 |

## Timing (mean ms per case)

| mode | select_filter | select_rag | select_rank |
|---|---|---|---|
| deterministic | 0.0 | 0.0 | 0.0 |
| rag | 0.0 | 220.7 | 0.0 |

## Per-case (deterministic vs rag)

| case | elig | scen | det ndcg@3 | rag ndcg@3 | delta | rag order (top4) |
|---|---|---|---|---|---|---|
| logon-bruteforce-evtx | 2 | Y | 1.0000 | 1.0000 | +0.0000 | chainsaw > evtxecmd |
| powershell-scriptblock | 2 | Y | 1.0000 | 1.0000 | +0.0000 | chainsaw > evtxecmd |
| evtx-service-install | 2 | Y | 1.0000 | 1.0000 | +0.0000 | chainsaw > evtxecmd |
| evtx-no-scenario | 2 | - | 1.0000 | 1.0000 | +0.0000 | chainsaw > evtxecmd |
| registry-runkey-persistence | 2 | Y | 1.0000 | 1.0000 | +0.0000 | recmd > regripper |
| amcache-program-execution | 1 | Y | 1.0000 | 1.0000 | +0.0000 | amcacheparser |
| registry-usb-history | 2 | Y | 0.7967 | 0.7967 | +0.0000 | recmd > regripper |
| memory-implant-triage | 1 | Y | 1.0000 | 1.0000 | +0.0000 | volatility3 |
| prefetch-execution-timeline | 1 | Y | 1.0000 | 1.0000 | +0.0000 | pecmd |
| disk-mft-timeline | 1 | Y | 1.0000 | 1.0000 | +0.0000 | mftecmd |
| python-vuln-scan | 3 | Y | 0.9514 | 0.8146 | -0.1369 | gitleaks > semgrep > bandit |
| secrets-leak-scan | 3 | Y | 0.8213 | 1.0000 | +0.1787 | gitleaks > semgrep > bandit |
| js-security-audit | 2 | Y | 0.7967 | 0.7967 | +0.0000 | gitleaks > semgrep |
| mixed-intrusion-triage | 5 | Y | 0.6462 | 0.5307 | -0.1155 | recmd > regripper > evtxecmd > chainsaw |

## Methodology

- **Goal**: quantify how much RAG reranking improves the Selector's tool
  *ordering* over a deterministic-only baseline.
- **Host contract**: official results are generated on Windows; the harness
  rejects other operating systems before loading tools or rebuilding an index.
- **Golden set**: 14 SYNTHETIC, hand-labeled English cases (one labeler).
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
  embedded with `sentence-transformers/all-MiniLM-L6-v2`. Retrieval uses a minimum similarity of
  0.25; reranking also requires a full eligible-set score
  spread of at least 0.1.
- **Metrics**: NDCG@k uses exponential gain (2^rel - 1)/log2(rank+1); MRR,
  Precision@k, Recall@k use relevance >= 1 as the "relevant" threshold.
  NDCG's ideal ranking and Recall's denominator use every gold-labeled tool,
  including relevant tools omitted by the Selector.
  k in [3, 5]. Reported values are means across cases.

## Limitations (read before trusting the numbers)

- Small (n=14), synthetic, single-labeler golden set - indicative, not
  statistically robust. Labels encode one analyst's judgement.
- Only 11 tools; several evidence types map to a single eligible tool,
  where ordering is trivial (metric == 1.0 regardless of mode) and dilutes the
  measured delta. The signal lives in multi-tool cases (registry_hive,
  evtx_log, source_code_*).
- The golden scenarios are English only. Korean and other multilingual
  performance is not measured by this benchmark.
- Ordering quality only. This does NOT measure end-to-end triage correctness,
  tool execution, or finding quality.
- RAG safety property (never promotes a tool outside Stage 1) and graceful
  fallback are covered by unit tests, not by this benchmark.
