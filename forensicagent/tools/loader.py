"""Load YAML tool metadata from disk.

규약: 한 파일 = 한 ToolMetadata. 파일 이름 stem 이 tool_id 와 다르면 경고
출력하지만 거부하지는 않는다 (사용자 디렉토리 구조에 유연하게).
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml
from pydantic import ValidationError

from forensicagent import config as settings
from forensicagent.tools.schema import ToolMetadata

logger = logging.getLogger(__name__)


def load_tool(path: str | Path) -> ToolMetadata:
    """단일 YAML 파일 로드 + 검증."""
    p = Path(path)
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{p}: top-level YAML must be a mapping, got {type(raw).__name__}")
    try:
        meta = ToolMetadata(**raw)
    except ValidationError as e:
        raise ValueError(f"{p}: schema validation failed:\n{e}") from e
    if meta.tool_id != p.stem:
        logger.warning(
            "%s: tool_id=%r does not match filename stem %r",
            p, meta.tool_id, p.stem,
        )
    return meta


def load_all_tools(directory: str | Path | None = None) -> dict[str, ToolMetadata]:
    """디렉토리의 모든 *.yaml/*.yml 을 로드. tool_id → ToolMetadata.

    잘못된 파일이 있어도 다른 파일 로드는 계속하고, stderr 로 보고한다.
    directory 를 생략하면 config.resolve_tools_dir() 의 공용 fallback 사슬
    (env → ~/.forensicagent/tools → repo tools_metadata → cwd) 을 따른다.
    """
    base = Path(directory) if directory is not None else settings.resolve_tools_dir()
    out: dict[str, ToolMetadata] = {}
    if not base.exists():
        logger.warning("tool metadata dir not found: %s", base)
        return out

    files = sorted(list(base.glob("*.yaml")) + list(base.glob("*.yml")))
    for f in files:
        try:
            meta = load_tool(f)
        except (ValueError, yaml.YAMLError) as e:
            logger.error("skip %s: %s", f, e)
            continue
        if meta.tool_id in out:
            logger.warning(
                "duplicate tool_id %r (already loaded from %s, skipping %s)",
                meta.tool_id, out[meta.tool_id], f,
            )
            continue
        out[meta.tool_id] = meta
    return out
