"""Executor — Layer 4 도구 실행 (subprocess 격리)."""

from forensicagent.executor.adapter import GenericAdapter, get_adapter, register_adapter
from forensicagent.executor.browser_sqlite_adapter import BrowserSQLiteAdapter
from forensicagent.executor.chainsaw_adapter import ChainsawAdapter
from forensicagent.executor.executor import execute
from forensicagent.executor.recmd_adapter import RECmdAdapter
from forensicagent.executor.types import (
    ExecStatus,
    ExecutionBundle,
    ExecutionResult,
    OutputArtifact,
    ProducedArtifact,
)

# 도구별 specialized 어댑터 등록 (미등록 도구는 GenericAdapter 로 폴백).
register_adapter("chainsaw", ChainsawAdapter)
register_adapter("recmd", RECmdAdapter)
register_adapter("browser_sqlite", BrowserSQLiteAdapter)

__all__ = [
    "execute",
    "ExecutionResult",
    "ExecutionBundle",
    "ExecStatus",
    "OutputArtifact",
    "ProducedArtifact",
    "GenericAdapter",
    "get_adapter",
    "register_adapter",
]
