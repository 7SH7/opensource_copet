"""Ranking-quality metrics — pure functions, no I/O, unit-tested.

입력 규약: `ranked_rels` 는 **예측 순서**대로 나열한 golden relevance 등급
리스트다 (예: 예측 1 위 도구의 등급, 2 위 도구의 등급, ...). 등급은
2=핵심 / 1=보조 / 0=무관.
`ideal_rels`/`total_relevant`를 주면 선택 결과에서 빠진 gold 도구도 NDCG 이상
정렬과 Recall 분모에 포함한다.

  * NDCG@k : 지수 gain (2^rel - 1) / log2(rank+1). 이상 정렬 대비 정규화.
  * MRR    : 첫 relevant(등급>=threshold) 의 역순위.
  * P@k    : 상위 k 중 relevant 비율.
  * R@k    : 상위 k 안의 relevant 수 / 전체 relevant 수.
"""

from __future__ import annotations

import math


def dcg_at_k(rels: list[float], k: int) -> float:
    """Discounted Cumulative Gain, 지수 gain 방식."""
    total = 0.0
    for i, rel in enumerate(rels[:k]):
        # rank = i + 1 → discount = log2(rank + 1)
        total += (2.0 ** rel - 1.0) / math.log2(i + 2)
    return total


def ndcg_at_k(
    ranked_rels: list[float],
    k: int,
    *,
    ideal_rels: list[float] | None = None,
) -> float:
    """Normalized DCG@k against the complete gold relevance set when supplied."""
    idcg = dcg_at_k(sorted(ideal_rels if ideal_rels is not None else ranked_rels, reverse=True), k)
    if idcg == 0.0:
        return 0.0
    return dcg_at_k(ranked_rels, k) / idcg


def mrr(ranked_rels: list[float], *, threshold: float = 1.0) -> float:
    """Mean Reciprocal Rank (단일 쿼리 = reciprocal rank). 첫 relevant 의 1/rank."""
    for i, rel in enumerate(ranked_rels):
        if rel >= threshold:
            return 1.0 / (i + 1)
    return 0.0


def precision_at_k(ranked_rels: list[float], k: int, *, threshold: float = 1.0) -> float:
    """상위 k 중 relevant 비율. k<=0 이면 0."""
    if k <= 0:
        return 0.0
    hits = sum(1 for rel in ranked_rels[:k] if rel >= threshold)
    return hits / k


def recall_at_k(
    ranked_rels: list[float],
    k: int,
    *,
    threshold: float = 1.0,
    total_relevant: int | None = None,
) -> float:
    """상위 k 안의 relevant 수 / 전체 relevant 수. relevant 0 이면 0."""
    if total_relevant is None:
        total_relevant = sum(1 for rel in ranked_rels if rel >= threshold)
    if total_relevant == 0:
        return 0.0
    hits = sum(1 for rel in ranked_rels[:k] if rel >= threshold)
    return hits / total_relevant


def mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0
