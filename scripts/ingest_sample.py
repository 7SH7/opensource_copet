"""sample.txt 의 URL 들을 도메인별로 분류 + 병렬 크롤 + 캐시.

이 스크립트는 forensicagent 의 *입력 데이터 인제스션* 진입점이다.
sample.txt 한 줄당 URL 하나 → 도메인 식별 → 도메인별 크롤러로 위임 →
`seed_docs/<domain>/<slug>.json` 으로 저장.

병렬성:
  * 4 도메인 각각의 워커 풀 (asyncio + httpx 대신 ThreadPoolExecutor +
    requests 로 가됨 — Windows 친화 + 의존성 적음).
  * 도메인별 max_workers 로 호스트 부하 제어.
  * 캐시 (slug.json 존재) 면 즉시 스킵 → 재실행 idempotent.

사용:
    python scripts/ingest_sample.py sample.txt
    python scripts/ingest_sample.py sample.txt --domains cyberdefenders,dfirreport
    python scripts/ingest_sample.py sample.txt --max-workers 6 --limit 20
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

# Top-level imports kept light. bs4 / requests are lazy-imported in fetch.
logger = logging.getLogger("ingest_sample")


SEED_ROOT = Path("seed_docs")


# --------------------------------------------------------------------------
# Domain classification
# --------------------------------------------------------------------------

DOMAIN_RULES: list[tuple[str, str]] = [
    # (substring match in netloc, domain_tag)
    ("cyberdefenders.org", "cyberdefenders"),
    ("thedfirreport.com", "dfirreport"),
    ("book.hacktricks.xyz", "hacktricks"),
    ("github.com/EZToolsManuals", "eztools"),
    # Generic github fallback only if path matches EZTools.
    ("github.com", "eztools"),  # narrowed below in classify()
]


def classify(url: str) -> str | None:
    """URL → domain tag, 모르면 None."""
    p = urlparse(url)
    netloc = p.netloc.lower()
    path = p.path

    if "cyberdefenders.org" in netloc:
        return "cyberdefenders"
    if "thedfirreport.com" in netloc:
        return "dfirreport"
    if "book.hacktricks.xyz" in netloc:
        return "hacktricks"
    if "github.com" in netloc and "EZToolsManuals" in path:
        return "eztools"
    return None


# --------------------------------------------------------------------------
# URL → filename slug
# --------------------------------------------------------------------------

_SAFE_SLUG = re.compile(r"[^A-Za-z0-9._-]+")


def slug_for(url: str) -> str:
    """파일명으로 안전한 slug. 너무 길면 sha8 로 보충."""
    p = urlparse(url)
    # path 의 마지막 의미 있는 segment.
    parts = [s for s in p.path.split("/") if s]
    if not parts:
        return hashlib.sha1(url.encode()).hexdigest()[:12]
    last = parts[-1].lower()
    # github raw text file 은 .txt 로 끝남 → 확장자 제거.
    if last.endswith(".txt"):
        last = last[:-4]
    slug = _SAFE_SLUG.sub("-", last).strip("-")
    if not slug:
        slug = hashlib.sha1(url.encode()).hexdigest()[:12]
    if len(slug) > 80:
        slug = slug[:60] + "-" + hashlib.sha1(url.encode()).hexdigest()[:8]
    return slug


# --------------------------------------------------------------------------
# HTTP fetch + per-domain parsers
# --------------------------------------------------------------------------

DEFAULT_HEADERS = {
    "User-Agent": (
        "forensicagent-ingest/0.1 (+https://example.local) "
        "PythonRequests"
    ),
    "Accept": "text/html,application/xhtml+xml,text/plain,*/*;q=0.8",
}


def _fetch(url: str, *, timeout: float, retries: int) -> str | None:
    import requests

    backoff = 1.0
    for attempt in range(retries + 1):
        try:
            r = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout)
            if r.status_code == 200:
                # GitHub raw redirect path
                return r.text
            if r.status_code in (429, 500, 502, 503, 504):
                logger.warning("retry %s %s on %s", r.status_code, attempt, url)
                time.sleep(backoff)
                backoff *= 2
                continue
            logger.info("non-200 %s for %s", r.status_code, url)
            return None
        except requests.RequestException as e:
            logger.warning("fetch error %s attempt=%d: %s", url, attempt, e)
            time.sleep(backoff)
            backoff *= 2
    return None


def _strip_html(html: str) -> tuple[str, str]:
    """(title, text). bs4 lazy import.

    선택자 우선순위 (WordPress / GitBook / generic 순):
      1. div.entry-content-wrapper, div.entry-content (WordPress, DFIR Report 등)
      2. article.post / div.post-content (WP 변형)
      3. <article> / <main> / <body> (semantic fallback)
    """
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html, "html.parser")
    title = soup.title.text.strip() if soup.title else ""

    main = (
        soup.find("div", class_="entry-content-wrapper")
        or soup.find("div", class_="entry-content")
        or soup.find("article", class_="post")
        or soup.find("div", class_="post-content")
        or soup.find("article")
        or soup.find("main")
        or soup.find("body")
        or soup
    )
    for s in main(["script", "style", "noscript", "nav", "footer", "header"]):
        s.decompose()
    text = main.get_text(separator="\n", strip=True)
    return title, text


def _parse_html(url: str, html: str) -> dict:
    title, text = _strip_html(html)
    return {"url": url, "title": title, "content": text}


def _parse_eztools(url: str, raw: str) -> dict:
    """github.com/EZToolsManuals 의 blob URL → raw URL 로 바꾸고 받은 텍스트.

    blob URL 그대로 받으면 HTML 이라 본문만 추출하기 까다로워서
    raw.githubusercontent.com 으로 변환된 결과를 받는다 (caller 가 변환).
    """
    return {"url": url, "title": Path(urlparse(url).path).stem, "content": raw}


def _eztools_raw_url(blob_url: str) -> str:
    """github.com/<owner>/<repo>/blob/<branch>/<path> → raw URL."""
    p = urlparse(blob_url)
    path = p.path
    # /EZToolsManuals/EZToolsManuals/blob/main/manuscript/xxx.txt
    parts = path.split("/")
    if "blob" in parts:
        i = parts.index("blob")
        owner, repo = parts[1], parts[2]
        branch = parts[i + 1]
        rest = "/".join(parts[i + 2 :])
        return f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{rest}"
    return blob_url


# Live URL rewrites for sites that moved hosts. Keys are substring matches.
URL_REWRITES: list[tuple[str, str]] = [
    # HackTricks: book.hacktricks.xyz/src/X → book.hacktricks.wiki/en/X.html
    # 도메인 이전 + path 재구조화 (/src/ → /en/) + 끝 .html 보강이 모두 필요.
    # 단순 호스트 rewrite 만 했던 1차 실행에서 828 페이지 전부 404 반환되어
    # placeholder (105 chars) 만 RAG 에 들어갔던 문제 해결.
    ("book.hacktricks.xyz/src/", "book.hacktricks.wiki/en/"),
]


def _rewrite_url(url: str) -> str:
    out = url
    for old, new in URL_REWRITES:
        out = out.replace(old, new)
    # HackTricks wiki 는 mdBook 기반이라 .html 확장자가 있어야 본문이 렌더된다.
    if "book.hacktricks.wiki/" in out and not out.endswith(".html"):
        # 경로의 마지막 segment 가 확장자 없으면 .html 추가.
        # (예: /en/AI/AI-Deep-Learning → /en/AI/AI-Deep-Learning.html)
        from urllib.parse import urlparse
        p = urlparse(out)
        last = p.path.rsplit("/", 1)[-1] if p.path else ""
        if "." not in last:
            out = out + ".html"
    return out


def parse_for(domain: str, url: str, body: str) -> dict:
    if domain == "eztools":
        return _parse_eztools(url, body)
    return _parse_html(url, body)


def fetch_url_for(domain: str, url: str, *, timeout: float, retries: int) -> dict | None:
    """도메인 규칙 따라 fetch + parse. None 이면 실패."""
    if domain == "eztools":
        real_url = _eztools_raw_url(url)
    else:
        real_url = _rewrite_url(url)
    body = _fetch(real_url, timeout=timeout, retries=retries)
    if body is None:
        return None
    return parse_for(domain, url, body)


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

@dataclass
class DomainStats:
    domain: str
    total: int = 0
    cached: int = 0
    fetched: int = 0
    failed: int = 0
    skipped: int = 0
    elapsed_s: float = 0.0
    failed_urls: list[str] = field(default_factory=list)


def _output_path(domain: str, url: str) -> Path:
    return SEED_ROOT / domain / f"{slug_for(url)}.json"


def _crawl_one(
    domain: str,
    url: str,
    *,
    timeout: float,
    retries: int,
    overwrite: bool,
) -> tuple[str, str]:
    """단일 URL 크롤. (url, status) 반환. status ∈ {cached, fetched, failed}."""
    out = _output_path(domain, url)
    if out.exists() and not overwrite:
        return url, "cached"
    out.parent.mkdir(parents=True, exist_ok=True)
    doc = fetch_url_for(domain, url, timeout=timeout, retries=retries)
    if doc is None or not doc.get("content"):
        return url, "failed"
    out.write_text(
        json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return url, "fetched"


def crawl_domain(
    domain: str,
    urls: list[str],
    *,
    max_workers: int,
    timeout: float,
    retries: int,
    overwrite: bool,
    on_progress: Callable[[str, str, str], None] | None = None,
) -> DomainStats:
    """도메인 1개를 max_workers thread 로 크롤."""
    stats = DomainStats(domain=domain, total=len(urls))
    if not urls:
        return stats

    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(
                _crawl_one,
                domain,
                u,
                timeout=timeout,
                retries=retries,
                overwrite=overwrite,
            ): u
            for u in urls
        }
        for fut in as_completed(futures):
            u = futures[fut]
            try:
                url, status = fut.result()
            except Exception as e:  # noqa: BLE001
                logger.exception("crawl crashed for %s: %s", u, e)
                status = "failed"
                url = u
            if status == "cached":
                stats.cached += 1
            elif status == "fetched":
                stats.fetched += 1
            else:
                stats.failed += 1
                stats.failed_urls.append(url)
            if on_progress:
                on_progress(domain, url, status)
    stats.elapsed_s = time.perf_counter() - start
    return stats


def read_urls(path: Path) -> dict[str, list[str]]:
    """sample.txt 읽고 도메인 분류 후 dict 반환."""
    out: dict[str, list[str]] = {}
    skipped: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        u = raw.strip()
        if not u or u.startswith("#"):
            continue
        tag = classify(u)
        if tag is None:
            skipped.append(u)
            continue
        out.setdefault(tag, []).append(u)
    if skipped:
        logger.info("skipped %d unclassified URLs", len(skipped))
    return out


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Crawl sample.txt URLs in parallel.")
    ap.add_argument("input", help="Path to sample.txt with one URL per line.")
    ap.add_argument(
        "--domains",
        default="cyberdefenders,dfirreport,hacktricks,eztools",
        help="Comma-separated domain tags to crawl (default: all).",
    )
    ap.add_argument("--max-workers", type=int, default=4,
                    help="Threads per domain (rate-limit per host).")
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--limit", type=int, default=0,
                    help="If >0, cap URLs per domain (for smoke tests).")
    ap.add_argument("--overwrite", action="store_true",
                    help="Re-fetch even if cached file exists.")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    requested = {d.strip() for d in args.domains.split(",") if d.strip()}
    urls_by_domain = read_urls(Path(args.input))
    targets = {d: us for d, us in urls_by_domain.items() if d in requested}
    if args.limit > 0:
        targets = {d: us[: args.limit] for d, us in targets.items()}

    total_urls = sum(len(us) for us in targets.values())
    print(f"[ingest] {total_urls} URLs across {len(targets)} domains")
    for d, us in targets.items():
        print(f"  - {d}: {len(us)}")

    # Run each domain in its own outer thread so domain pools overlap fully.
    # Inside crawl_domain, max_workers threads handle that domain's URLs.
    domain_stats: dict[str, DomainStats] = {}
    with ThreadPoolExecutor(max_workers=len(targets) or 1) as outer:
        futures = {
            outer.submit(
                crawl_domain,
                d,
                us,
                max_workers=args.max_workers,
                timeout=args.timeout,
                retries=args.retries,
                overwrite=args.overwrite,
            ): d
            for d, us in targets.items()
        }
        for fut in as_completed(futures):
            d = futures[fut]
            stats = fut.result()
            domain_stats[d] = stats
            print(
                f"[done] {d}: total={stats.total} cached={stats.cached} "
                f"fetched={stats.fetched} failed={stats.failed} "
                f"({stats.elapsed_s:.1f}s)"
            )

    # Summary
    print("\n=== summary ===")
    grand_total = grand_cached = grand_fetched = grand_failed = 0
    for d, s in domain_stats.items():
        grand_total += s.total
        grand_cached += s.cached
        grand_fetched += s.fetched
        grand_failed += s.failed
    print(
        f"total={grand_total} cached={grand_cached} "
        f"fetched={grand_fetched} failed={grand_failed}"
    )

    # write a manifest
    manifest = SEED_ROOT / "ingest_manifest.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(
        json.dumps(
            {
                "input": args.input,
                "stats": {
                    d: {
                        "total": s.total,
                        "cached": s.cached,
                        "fetched": s.fetched,
                        "failed": s.failed,
                        "elapsed_s": s.elapsed_s,
                        "failed_urls": s.failed_urls[:50],
                    }
                    for d, s in domain_stats.items()
                },
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"manifest: {manifest}")
    return 0 if grand_failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
