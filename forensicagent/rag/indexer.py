"""Index crawled seed_docs/<domain>/*.json into a ChromaDB collection.

Stage 3 of the sample.txt 인제스션 파이프라인. 도메인별로 별도 컬렉션을
유지해 검색 시 도메인 필터를 결정론적으로 적용할 수 있게 한다.

청킹 규칙
  * 800 chars / 80 overlap (포렌식 문서는 명령 한 줄이 길어 200~400 자
    청크는 명령이 잘림. 800 정도가 안정적).
  * 빈 줄 두 개 (\n\n) 를 우선 경계로 사용하고, 그 안에서 800 자 초과면
    추가 슬라이스.
  * 메타데이터: {url, title, domain, chunk_index, total_chunks}.
  * doc_id (= sha8(url) + "_" + chunk_index) 가 중복이면 add 안 함.

호출 위치
  scripts/ingest_sample.py 다음 단계로 직접 호출, 또는
  python -m forensicagent.rag.indexer <domain> ...
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from forensicagent import config as settings

logger = logging.getLogger("rag.indexer")

# Lazy: VectorStore / embedder import inside functions so this module is
# cheap to import (e.g. from CLI --help).


SEED_ROOT = settings.SEED_DOCS_DIR


# ---------------------------------------------------------------------------
# Chunking
# ---------------------------------------------------------------------------

_PARA_SPLIT = re.compile(r"\n\s*\n+")


def _chunks(text: str, *, target: int = 800, overlap: int = 80) -> list[str]:
    """단순 sliding window 청커. 경계가 단어 중간에 떨어지지 않도록 보정."""
    text = text.strip()
    if not text:
        return []
    if len(text) <= target:
        return [text]

    # Step 1: try paragraph-first grouping.
    paragraphs = [p.strip() for p in _PARA_SPLIT.split(text) if p.strip()]
    out: list[str] = []
    buf = ""
    for p in paragraphs:
        if not buf:
            buf = p
            continue
        if len(buf) + 2 + len(p) <= target:
            buf = f"{buf}\n\n{p}"
        else:
            out.append(buf)
            buf = p
    if buf:
        out.append(buf)

    # Step 2: if any single chunk is still much larger than target, slice it.
    final: list[str] = []
    for c in out:
        if len(c) <= target * 1.5:
            final.append(c)
            continue
        i = 0
        while i < len(c):
            end = min(i + target, len(c))
            # Avoid splitting inside a word.
            if end < len(c):
                while end > i and not c[end - 1].isspace():
                    end -= 1
                if end == i:
                    end = min(i + target, len(c))
            final.append(c[i:end].strip())
            if end >= len(c):
                break
            i = max(end - overlap, i + 1)
    return [c for c in final if c]


def _doc_id(url: str, chunk_index: int) -> str:
    h = hashlib.sha1(url.encode()).hexdigest()[:10]
    return f"{h}_{chunk_index}"


# ---------------------------------------------------------------------------
# Collection naming
# ---------------------------------------------------------------------------

def collection_name(domain: str) -> str:
    """Per-domain collection. Keep them separate so retrieval can filter at
    the collection level (cheaper than metadata filter for large corpora)."""
    return f"seed_{domain}"


# ---------------------------------------------------------------------------
# Index a single domain
# ---------------------------------------------------------------------------

@dataclass
class IndexStats:
    domain: str
    docs_seen: int = 0
    docs_indexed: int = 0
    docs_skipped: int = 0      # cached / empty
    chunks_written: int = 0
    embedding_ms: int = 0
    chroma_ms: int = 0
    elapsed_s: float = 0.0
    errors: list[str] = field(default_factory=list)


def _existing_ids(store) -> set[str]:
    """이미 컬렉션에 있는 모든 id 의 set. 재실행 idempotent 용."""
    try:
        # ChromaDB 0.5+ has .get() that returns all if no filter.
        got = store._collection.get(limit=None, include=[])  # type: ignore[attr-defined]
        ids = got.get("ids") or []
        return set(ids)
    except Exception as e:  # noqa: BLE001
        logger.warning("could not enumerate existing ids: %s", e)
        return set()


def _iter_doc_files(domain: str) -> Iterable[Path]:
    d = SEED_ROOT / domain
    if not d.exists():
        return []
    return sorted(d.glob("*.json"))


def index_domain(
    domain: str,
    *,
    target_chunk_chars: int = 800,
    overlap: int = 80,
    batch_size: int = 64,
    overwrite: bool = False,
) -> IndexStats:
    """Read every seed_docs/<domain>/*.json → chunk → embed → store."""
    from forensicagent.rag.embedder import embed_texts
    from forensicagent.rag.vector_store import VectorStore

    stats = IndexStats(domain=domain)
    start = time.perf_counter()

    files = list(_iter_doc_files(domain))
    if not files:
        logger.warning("no docs in seed_docs/%s/", domain)
        stats.elapsed_s = time.perf_counter() - start
        return stats

    store = VectorStore(
        persist_dir=settings.CHROMA_PERSIST_DIR,
        collection_name=collection_name(domain),
    )
    if overwrite:
        store.reset()
        existing: set[str] = set()
    else:
        existing = _existing_ids(store)

    # Collect chunks until batch_size, then embed+write.
    pending_texts: list[str] = []
    pending_ids: list[str] = []
    pending_metas: list[dict] = []

    def flush() -> None:
        nonlocal pending_texts, pending_ids, pending_metas
        if not pending_texts:
            return
        t0 = time.perf_counter()
        vectors = embed_texts(pending_texts)
        stats.embedding_ms += int((time.perf_counter() - t0) * 1000)

        t0 = time.perf_counter()
        store.add(
            contents=pending_texts,
            embeddings=vectors,
            metadatas=pending_metas,
            ids=pending_ids,
        )
        stats.chroma_ms += int((time.perf_counter() - t0) * 1000)
        stats.chunks_written += len(pending_texts)
        pending_texts, pending_ids, pending_metas = [], [], []

    for f in files:
        stats.docs_seen += 1
        try:
            doc = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            stats.errors.append(f"{f.name}: {e}")
            continue
        url = doc.get("url") or f.stem
        title = doc.get("title") or ""
        content = doc.get("content") or ""

        chunks = _chunks(content, target=target_chunk_chars, overlap=overlap)
        if not chunks:
            stats.docs_skipped += 1
            continue

        new_chunks = 0
        for i, chunk in enumerate(chunks):
            cid = _doc_id(url, i)
            if cid in existing:
                continue
            pending_texts.append(chunk)
            pending_ids.append(cid)
            pending_metas.append({
                "url": url,
                "title": title,
                "domain": domain,
                "chunk_index": i,
                "total_chunks": len(chunks),
                "source_file": str(f),
            })
            new_chunks += 1
            if len(pending_texts) >= batch_size:
                flush()
        if new_chunks > 0:
            stats.docs_indexed += 1
        else:
            stats.docs_skipped += 1

    flush()
    stats.elapsed_s = time.perf_counter() - start
    return stats


def index_all_domains(
    domains: list[str],
    **kwargs,
) -> dict[str, IndexStats]:
    out: dict[str, IndexStats] = {}
    for d in domains:
        logger.info("indexing %s ...", d)
        out[d] = index_domain(d, **kwargs)
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="RAG-index crawled seed_docs.")
    ap.add_argument(
        "--domains",
        default="cyberdefenders,dfirreport,hacktricks,eztools",
        help="Comma-separated domain tags to index.",
    )
    ap.add_argument("--chunk-chars", type=int, default=800)
    ap.add_argument("--overlap", type=int, default=80)
    ap.add_argument("--batch", type=int, default=64)
    ap.add_argument("--overwrite", action="store_true")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    domains = [d.strip() for d in args.domains.split(",") if d.strip()]
    print(f"[rag] indexing {len(domains)} domains: {', '.join(domains)}")
    results = index_all_domains(
        domains,
        target_chunk_chars=args.chunk_chars,
        overlap=args.overlap,
        batch_size=args.batch,
        overwrite=args.overwrite,
    )
    print("\n=== RAG summary ===")
    for d, s in results.items():
        print(
            f"  {d}: docs_seen={s.docs_seen} indexed={s.docs_indexed} "
            f"skipped={s.docs_skipped} chunks={s.chunks_written} "
            f"embed_ms={s.embedding_ms} chroma_ms={s.chroma_ms} "
            f"elapsed={s.elapsed_s:.1f}s"
        )
        if s.errors:
            print(f"    errors: {len(s.errors)} (first: {s.errors[0][:120]})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
