"""bench.metrics — 알려진 입력으로 랭킹 지표 검증."""

from __future__ import annotations

import math

import pytest

from bench.metrics import (
    dcg_at_k,
    mean,
    mrr,
    ndcg_at_k,
    precision_at_k,
    recall_at_k,
)
from bench.harness import _case_metrics


# ---- DCG / NDCG ----

def test_dcg_known_value():
    # rels=[2,1,0]: 3/log2(2) + 1/log2(3) + 0 = 3 + 0.63093 = 3.63093
    assert dcg_at_k([2, 1, 0], 3) == pytest.approx(3.0 + 1.0 / math.log2(3), rel=1e-9)


def test_ndcg_perfect_order_is_one():
    assert ndcg_at_k([2, 1, 0], 3) == pytest.approx(1.0)


def test_ndcg_worst_order_below_one():
    # reversed relevance is suboptimal
    val = ndcg_at_k([0, 1, 2], 3)
    assert 0.0 < val < 1.0
    # explicit: DCG=[0 + 1/log2(3) + 3/log2(4)] / IDCG(3.63093)
    dcg = 1.0 / math.log2(3) + 3.0 / math.log2(4)
    idcg = 3.0 + 1.0 / math.log2(3)
    assert val == pytest.approx(dcg / idcg)


def test_ndcg_all_zero_is_zero():
    assert ndcg_at_k([0, 0, 0], 3) == 0.0


def test_ndcg_k_truncation():
    # only top-1 counts at k=1; [1,2] -> dcg=1, idcg from sorted[2,1]=3 -> 1/3
    assert ndcg_at_k([1, 2], 1) == pytest.approx(1.0 / 3.0)


def test_case_metrics_penalize_missing_gold_tool():
    metrics = _case_metrics(["found"], {"found": 2, "missed": 1})

    ideal = 3.0 + 1.0 / math.log2(3)
    assert metrics["ndcg@3"] == pytest.approx(3.0 / ideal)
    assert metrics["r@3"] == pytest.approx(0.5)


# ---- MRR ----

def test_mrr_first_relevant_rank():
    assert mrr([0, 0, 2, 1]) == pytest.approx(1.0 / 3.0)
    assert mrr([2, 0, 0]) == pytest.approx(1.0)
    assert mrr([0, 0, 0]) == 0.0


def test_mrr_threshold_core_only():
    # threshold=2 → only grade-2 counts; first grade-2 at rank 2
    assert mrr([1, 2, 1], threshold=2.0) == pytest.approx(0.5)


# ---- Precision@k ----

def test_precision_at_k():
    assert precision_at_k([2, 1, 0], 2) == pytest.approx(1.0)
    assert precision_at_k([2, 0, 1], 2) == pytest.approx(0.5)
    assert precision_at_k([0, 0, 0], 3) == 0.0
    assert precision_at_k([2, 1], 0) == 0.0


# ---- Recall@k ----

def test_recall_at_k():
    # total relevant = 2 (grades 2 and 1); top-2 captures both
    assert recall_at_k([2, 1, 0], 2) == pytest.approx(1.0)
    # top-1 captures 1 of 2 relevant
    assert recall_at_k([2, 0, 1], 1) == pytest.approx(0.5)
    assert recall_at_k([0, 0, 0], 3) == 0.0


def test_recall_full_list_is_one_when_relevant_exist():
    assert recall_at_k([0, 1, 2], 3) == pytest.approx(1.0)


# ---- mean ----

def test_mean():
    assert mean([1.0, 2.0, 3.0]) == pytest.approx(2.0)
    assert mean([]) == 0.0
