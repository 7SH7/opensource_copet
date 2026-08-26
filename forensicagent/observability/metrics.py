"""Measurement primitives for forensicagent.

Per the "measure everything end-to-end" rule: every stage of every module
records elapsed time + counts, and all values round-trip through JSON so
they can be persisted in the run report and aggregated later.

What lives here:
  * Stopwatch / StageTimings — timing
  * ScoreStats / LengthStats — distributions
  * percentile — p50/p95/p99 helper

Domain-specific metric dataclasses (ScanMetrics, SelectMetrics, ExecuteMetrics,
AnalyzeMetrics, ...) belong in each module — not here.
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass
from typing import Any


# ---------- timing ----------

class Stopwatch:
    """Context manager that records a single elapsed-ms measurement.

        with Stopwatch() as sw:
            do_work()
        elapsed = sw.elapsed_ms
    """

    __slots__ = ("_start", "elapsed_ms")

    def __init__(self) -> None:
        self._start = 0.0
        self.elapsed_ms = 0

    def __enter__(self) -> "Stopwatch":
        self._start = time.perf_counter()
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.elapsed_ms = int((time.perf_counter() - self._start) * 1000)


class StageTimings(dict):
    """Mapping of stage name -> elapsed milliseconds.

    Subclasses dict so it serializes naturally to JSON.
    """

    def time(self, name: str) -> "_StageContext":
        return _StageContext(self, name)


class _StageContext:
    __slots__ = ("_timings", "_name", "_start")

    def __init__(self, timings: StageTimings, name: str) -> None:
        self._timings = timings
        self._name = name
        self._start = 0.0

    def __enter__(self) -> "_StageContext":
        self._start = time.perf_counter()
        return self

    def __exit__(self, *_exc: Any) -> None:
        elapsed = int((time.perf_counter() - self._start) * 1000)
        self._timings[self._name] = self._timings.get(self._name, 0) + elapsed


# ---------- aggregate stats ----------

@dataclass
class ScoreStats:
    count: int = 0
    top: float = 0.0
    mean: float = 0.0
    median: float = 0.0
    min: float = 0.0
    max: float = 0.0
    stdev: float = 0.0

    @classmethod
    def from_values(cls, values: list[float]) -> "ScoreStats":
        if not values:
            return cls()
        return cls(
            count=len(values),
            top=max(values),
            mean=float(statistics.fmean(values)),
            median=float(statistics.median(values)),
            min=min(values),
            max=max(values),
            stdev=float(statistics.pstdev(values)) if len(values) > 1 else 0.0,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "count": self.count,
            "top": self.top,
            "mean": self.mean,
            "median": self.median,
            "min": self.min,
            "max": self.max,
            "stdev": self.stdev,
        }


@dataclass
class LengthStats:
    """Char-length distribution across a list of strings."""

    count: int = 0
    total_chars: int = 0
    mean_chars: float = 0.0
    min_chars: int = 0
    max_chars: int = 0

    @classmethod
    def from_strings(cls, strings: list[str]) -> "LengthStats":
        if not strings:
            return cls()
        lens = [len(s) for s in strings]
        return cls(
            count=len(lens),
            total_chars=sum(lens),
            mean_chars=sum(lens) / len(lens),
            min_chars=min(lens),
            max_chars=max(lens),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "count": self.count,
            "total_chars": self.total_chars,
            "mean_chars": self.mean_chars,
            "min_chars": self.min_chars,
            "max_chars": self.max_chars,
        }


# ---------- percentile helpers (for analytics) ----------

def percentile(values: list[float], p: float) -> float:
    """Linear-interpolation percentile, matching numpy default. p in [0, 100]."""
    if not values:
        return 0.0
    if len(values) == 1:
        return float(values[0])
    s = sorted(values)
    rank = (p / 100.0) * (len(s) - 1)
    lo = int(rank)
    hi = min(lo + 1, len(s) - 1)
    frac = rank - lo
    return float(s[lo] + (s[hi] - s[lo]) * frac)
