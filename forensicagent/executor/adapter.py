"""ToolAdapter — 도구별 커스터마이즈 포인트.

명세 2.3 의 어댑터 패턴 구현. 도구마다 출력 형식과 검증 방법이 다르므로
이 인터페이스를 통해 캡슐화한다.

기본 구현 (GenericAdapter) 은 YAML 메타데이터만으로 작동:
  * validate_prerequisites: install_check 의 command 를 실행, expected_pattern 매칭
  * build_command: command_template 의 {evidence_path} placeholder 치환,
    shlex 로 안전하게 토큰화
  * parse_output: output_format 이 json 이면 json.loads, 아니면 raw text
  * get_metadata: ToolMetadata 그대로 반환

도구마다 더 정교한 로직이 필요하면 GenericAdapter 를 상속해서 register_adapter 로 등록.
"""

from __future__ import annotations

import json
import logging
import shlex
import string
import subprocess
from pathlib import Path
from typing import Any, Optional, Protocol

from forensicagent import config as settings
from forensicagent.executor.types import MAX_INLINE_JSON_BYTES
from forensicagent.tools.executables import resolve_executable
from forensicagent.tools.schema import ToolMetadata

logger = logging.getLogger(__name__)

_FMT = string.Formatter()


def _placeholder_names(template: str) -> set[str]:
    """Extract `{name}` placeholders from a format string without raising."""
    return {field for _, field, _, _ in _FMT.parse(template) if field}


class ToolAdapter(Protocol):
    def validate_prerequisites(self) -> tuple[bool, str]: ...
    def build_command(self, evidence_path: str, **vars: str) -> list[str]: ...
    def parse_output(self, stdout_path: str) -> Optional[dict[str, Any]]: ...
    def get_metadata(self) -> ToolMetadata: ...


class GenericAdapter:
    """YAML 메타데이터만으로 동작하는 기본 어댑터."""

    def __init__(self, metadata: ToolMetadata) -> None:
        self._meta = metadata
        self.selected_template: str = ""

    # ---- prerequisites ----

    def validate_prerequisites(self) -> tuple[bool, str]:
        check = self._meta.install_check
        if check is None:
            # check 가 없으면 공용 resolver 로 tool_id 를 확인 (best effort).
            resolved = resolve_executable(self._meta.tool_id)
            if resolved is None:
                return False, f"{self._meta.tool_id} not on PATH or tools_bin"
            return True, f"{self._meta.tool_id} found at {resolved}"

        try:
            argv = shlex.split(check.command, posix=False)
        except ValueError as e:
            return False, f"invalid install_check.command: {e}"

        # 명령의 첫 토큰이 PATH/tools_bin 에 없으면 즉시 실패. 실제 resolved
        # path 로 실행해 doctor 와 executor 의 탐색 정책을 동일하게 유지한다.
        resolved = resolve_executable(argv[0]) if argv else None
        if resolved is None:
            missing = argv[0] if argv else "(empty command)"
            return False, f"{missing} not on PATH or tools_bin"
        argv[0] = str(resolved)

        try:
            # Version checks must not inherit an evidence-controlled CWD.  The
            # package/project root is stable for both source and wheel installs.
            trusted_cwd = Path(settings.PROJECT_ROOT).resolve(strict=True)
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                cwd=trusted_cwd,
                shell=False,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError, RuntimeError) as e:
            return False, f"install_check failed to run: {e}"

        haystack = (proc.stdout or "") + (proc.stderr or "")
        if check.expected_pattern in haystack:
            version = " ".join(haystack.split())
            version = "".join(
                char if char.isprintable() else "\N{REPLACEMENT CHARACTER}"
                for char in version
            )
            return True, version[:240] or (
                f"{self._meta.tool_id} {check.expected_pattern} found"
            )
        return False, (
            f"install_check stdout/stderr did not contain "
            f"{check.expected_pattern!r}"
        )

    # ---- command building ----

    def build_command(
        self,
        evidence_path: str,
        *,
        preferred_template: str | None = None,
        **vars: str,
    ) -> list[str]:
        """Pick the preferred satisfiable template, then fall back in order.

        Tokenization happens BEFORE substitution so values containing spaces
        (Windows paths like `C:\\path with spaces\\evt.pf`) stay a single
        argv element regardless of the caller.
        """
        available: dict[str, str] = {"evidence_path": evidence_path, **vars}
        last_missing: set[str] | None = None
        templates = list(self._meta.command_templates)
        if preferred_template:
            preferred = [ct for ct in templates if ct.template == preferred_template]
            templates = preferred + [ct for ct in templates if ct.template != preferred_template]

        for ct in templates:
            needed = _placeholder_names(ct.template)
            missing = needed - available.keys()
            if missing:
                last_missing = missing
                continue
            tokens = shlex.split(ct.template, posix=False)
            argv = [t.format(**available) for t in tokens]
            if not argv:
                raise ValueError(f"empty command template for {self._meta.tool_id}")
            resolved = resolve_executable(argv[0])
            if resolved is not None:
                argv[0] = str(resolved)
            self.selected_template = ct.template
            return argv
        raise KeyError(
            f"no command_template can be satisfied for {self._meta.tool_id}; "
            f"last template missing vars: {sorted(last_missing or set())}"
        )

    # ---- output parsing ----

    def parse_output(self, stdout_path: str) -> Optional[dict[str, Any]]:
        p = Path(stdout_path)
        try:
            size = p.stat().st_size
        except OSError as e:
            logger.warning("parse_output: cannot stat %s: %s", p, e)
            return None
        if size == 0:
            return None
        if self._meta.output_format != "json":
            return None
        # Metadata is only an estimate.  The completed stdout byte size is the
        # availability boundary for eager parsing and report embedding.
        if size > MAX_INLINE_JSON_BYTES:
            return None
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.warning("parse_output: cannot read %s: %s", p, e)
            return None
        try:
            return _parse_json_or_ndjson(text)
        except json.JSONDecodeError as e:
            logger.warning("parse_output: JSON decode failed for %s: %s", p, e)
            return None

    def get_metadata(self) -> ToolMetadata:
        return self._meta


def _parse_json_or_ndjson(text: str) -> dict[str, Any]:
    """JSON object/array 단일 문서, 또는 NDJSON 을 dict 로 정규화."""
    stripped = text.strip()
    if not stripped:
        return {"items": []}

    # NDJSON: 첫 char 가 '{' 이고 줄마다 '{' 로 시작하면 줄별 파싱.
    if "\n" in stripped and all(
        ln.lstrip().startswith(("{", "["))
        for ln in stripped.splitlines()
        if ln.strip()
    ):
        items: list[Any] = []
        for ln in stripped.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                items.append(json.loads(ln))
            except json.JSONDecodeError:
                # 단일 문서 시도로 폴백.
                break
        else:
            return {"items": items}

    parsed = json.loads(stripped)
    if isinstance(parsed, list):
        return {"items": parsed}
    if isinstance(parsed, dict):
        return parsed
    return {"value": parsed}


# ---------- registry ----------

# 도구별 커스텀 어댑터를 등록할 수 있다. 미등록이면 GenericAdapter.
_REGISTRY: dict[str, type] = {}


def register_adapter(tool_id: str, adapter_cls: type) -> None:
    _REGISTRY[tool_id] = adapter_cls


def get_adapter(metadata: ToolMetadata) -> GenericAdapter:
    cls = _REGISTRY.get(metadata.tool_id, GenericAdapter)
    return cls(metadata)
