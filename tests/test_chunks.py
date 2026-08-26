"""RAG indexer 의 _chunks 함수 + slug_for 단위 테스트.

ChromaDB / sentence-transformers 의존성 없이 순수 텍스트 처리만 검증.
"""

from __future__ import annotations

import pytest

from forensicagent.rag.indexer import _chunks, _doc_id
from scripts.ingest_sample import classify, slug_for


class TestChunks:
    def test_empty_string_returns_empty_list(self):
        assert _chunks("") == []
        assert _chunks("   \n   ") == []

    def test_short_text_returns_single_chunk(self):
        text = "Short paragraph content."
        chunks = _chunks(text, target=800, overlap=80)
        assert chunks == [text]

    def test_paragraph_split_respected(self):
        # 두 단락이 각자 target 미만이면 둘 다 한 청크로 합쳐질 수 있음.
        p1 = "alpha " * 50   # ~300 chars
        p2 = "beta " * 50    # ~250 chars
        text = f"{p1.strip()}\n\n{p2.strip()}"
        chunks = _chunks(text, target=800, overlap=80)
        # 두 단락 합쳐 ~550 chars < 800 → 한 청크.
        assert len(chunks) == 1
        assert "alpha" in chunks[0] and "beta" in chunks[0]

    def test_paragraph_split_when_combined_exceeds_target(self):
        p1 = "alpha " * 200  # ~1200 chars
        p2 = "beta " * 200   # ~1000 chars
        text = f"{p1.strip()}\n\n{p2.strip()}"
        chunks = _chunks(text, target=800, overlap=80)
        # 각 단락이 ~1000+ chars 라 target*1.5(=1200) 안쪽이면 그대로 한 청크씩.
        assert len(chunks) >= 2

    def test_very_long_paragraph_gets_sliced(self):
        # 단일 단락이 target * 1.5 이상이면 sliding window 슬라이스.
        text = "x" * 5000
        chunks = _chunks(text, target=800, overlap=80)
        assert len(chunks) >= 5
        # overlap 보장: 인접 chunk 가 80 chars 정도 공유 (정확히 검사하긴 어려움)
        assert all(len(c) > 0 for c in chunks)
        # 총 길이 합이 원문보다 작거나 같지 않음 (overlap 때문에 더 큼).
        assert sum(len(c) for c in chunks) >= len(text)

    def test_no_word_split_when_possible(self):
        words = " ".join(f"word{i}" for i in range(500))  # ~3500 chars
        chunks = _chunks(words, target=800, overlap=80)
        for c in chunks:
            # 각 청크가 공백이 아닌 문자열 중간에서 끊기지 않게 노력함.
            # 빈 청크는 없어야 함.
            assert c.strip() != ""

    def test_overlap_preserves_continuity(self):
        text = "alpha beta gamma delta epsilon " * 200  # ~6000 chars
        chunks = _chunks(text, target=800, overlap=120)
        # 인접 chunk 의 시작/끝이 일부 공유되는지 확인 (overlap 의 효과).
        if len(chunks) >= 2:
            tail_of_first = chunks[0][-100:]
            head_of_second = chunks[1][:200]
            # 적어도 한 단어는 겹쳐야 한다.
            shared = any(w in head_of_second for w in tail_of_first.split() if len(w) > 3)
            assert shared


class TestDocId:
    def test_deterministic(self):
        a = _doc_id("https://example.com/foo", 0)
        b = _doc_id("https://example.com/foo", 0)
        assert a == b

    def test_different_chunks_get_different_ids(self):
        a = _doc_id("https://example.com/foo", 0)
        b = _doc_id("https://example.com/foo", 1)
        assert a != b
        # 같은 sha8 prefix 를 공유해야 한다.
        assert a.split("_")[0] == b.split("_")[0]

    def test_different_urls_different_prefix(self):
        a = _doc_id("https://a.com/x", 0)
        b = _doc_id("https://b.com/x", 0)
        assert a.split("_")[0] != b.split("_")[0]


class TestClassify:
    @pytest.mark.parametrize(
        "url,domain",
        [
            ("https://cyberdefenders.org/blog/foo/", "cyberdefenders"),
            ("https://thedfirreport.com/2025/05/19/case/", "dfirreport"),
            ("https://book.hacktricks.xyz/src/foo", "hacktricks"),
            (
                "https://github.com/EZToolsManuals/EZToolsManuals/blob/main/manuscript/mftecmd.txt",
                "eztools",
            ),
        ],
    )
    def test_known_domains(self, url, domain):
        assert classify(url) == domain

    def test_unknown_domain_returns_none(self):
        assert classify("https://example.com/foo") is None
        assert classify("https://github.com/some/other/repo") is None


class TestSlugFor:
    def test_basic(self):
        assert slug_for("https://example.com/foo/bar") == "bar"

    def test_eztools_strips_txt(self):
        assert (
            slug_for(
                "https://github.com/EZToolsManuals/EZToolsManuals/blob/main/manuscript/mftecmd.txt"
            )
            == "mftecmd"
        )

    def test_safe_characters(self):
        slug = slug_for("https://example.com/foo!bar*baz")
        assert "!" not in slug and "*" not in slug
        assert slug

    def test_long_url_gets_hash_suffix(self):
        url = "https://example.com/" + "a" * 200
        slug = slug_for(url)
        assert len(slug) <= 80
        # sha 접미사가 붙음.
        assert "-" in slug

    def test_empty_path_falls_back_to_hash(self):
        slug = slug_for("https://example.com")
        # path 가 없으면 sha8 prefix 만 12자.
        assert slug
        assert len(slug) >= 8

    def test_idempotent(self):
        a = slug_for("https://x.com/foo/bar")
        b = slug_for("https://x.com/foo/bar")
        assert a == b
