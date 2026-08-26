"""Tool metadata Pydantic schema.

YAML 한 파일이 하나의 ToolMetadata 인스턴스로 검증된다. 새 필드를 추가할
때는 명세 2.6 의 의도 (Selector 결정론 필터 + Analyzer suspicious_indicators
lookup) 를 깨지 않게 신중히.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

# 명세 2.1 의 evidence_type literal 과 동기화 (scanner/types.py).
EvidenceTypeStr = Literal[
    "memory_dump",
    "evtx_log",
    "registry_hive",
    "pcap",
    "disk_image",
    "ntfs_metadata",
    "sqlite_database",
    "browser_artifact",
    "prefetch",
    "text_log",
    "text_document",
    "source_code_python",
    "source_code_javascript",
    "source_code_generic",
    "unknown",
]

OutputFormat = Literal["json", "jsonl", "csv", "text", "binary"]
OutputSize = Literal["small", "medium", "large"]
Runtime = Literal["short", "medium", "long"]
PlatformStr = Literal["windows", "linux", "macos", "any"]
TargetMode = Literal["per_file", "scan_root"]


class CommandTemplate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    template: str = Field(
        ...,
        description=(
            "Shell-safe command template with placeholders: "
            "{evidence_path}, {output_path}, {sigma_path} ..."
        ),
    )
    when: str = Field(
        ...,
        description="자연어 설명 — 이 템플릿을 선택할 휴리스틱.",
    )


class InstallCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command: str = Field(..., description="설치 확인용 명령 (예: 'chainsaw --version')")
    expected_pattern: str = Field(
        ...,
        description="stdout 또는 stderr 에 포함되어야 하는 패턴 (substring).",
    )


# severity 의 baseline. Analyzer 가 컨텍스트 따라 한 단계 가감할 수 있음.
SeverityBaseline = Literal["info", "low", "medium", "high", "critical"]


class SuspiciousIndicator(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(
        ...,
        description="indicator slug. analyzer/rules.py 에서 dispatch 키로 사용.",
    )
    pattern: str = Field(
        ...,
        description=(
            "패턴 설명. 자연어 또는 단순 정규식 / JSON path 표현. 룰 엔진은 "
            "id 기반 dispatch 가 우선이고 pattern 은 LLM 컨텍스트용 보조."
        ),
    )
    severity_baseline: SeverityBaseline = "medium"
    description: str = ""


class ToolMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # ---------- identity ----------
    tool_id: str = Field(..., description="고유 식별자. YAML 파일명 stem 과 일치 권장.")
    display_name: str
    version_supported: str = Field(
        "",
        description="SemVer range 표현 (예: '>=2.0, <3.0').",
    )

    # ---------- classification ----------
    category: str = Field(
        ...,
        description=(
            "상위 카테고리 (memory_analysis | log_analysis | registry_analysis | "
            "disk_analysis | network_analysis | timeline | string_extraction | ...)"
        ),
    )
    subcategory: str = ""

    # ---------- routing ----------
    applicable_evidence_types: list[EvidenceTypeStr] = Field(
        ...,
        min_length=1,
        description="Selector 결정론 필터의 핵심.",
    )
    platform: list[PlatformStr] = Field(
        default_factory=lambda: ["any"],
        description="Host operating systems on which the tool can run.",
    )
    applicable_evidence_platforms: list[PlatformStr] = Field(
        default_factory=lambda: ["any"],
        min_length=1,
        description=(
            "Target operating systems supported by the declared commands. "
            "Evidence with an unknown platform remains eligible."
        ),
    )
    input_format: list[str] = Field(
        default_factory=list,
        description=(
            "Selector 입력 게이트. any, name:<basename>, ext:<suffix> 문법을 "
            "지원하며 기존 basename/.suffix 토큰도 호환한다. 빈 목록은 any."
        ),
    )
    target_mode: TargetMode = Field(
        "per_file",
        description=(
            "Legacy scheduling hint. External invocations remain scoped to "
            "scanner-inventoried matching files, including scan_root tools."
        ),
    )

    # ---------- runtime characteristics ----------
    output_format: OutputFormat = "text"
    output_size_estimate: OutputSize = "small"
    parallelizable: bool = True
    estimated_runtime: Runtime = "short"

    # ---------- ops ----------
    install_check: Optional[InstallCheck] = None
    command_templates: list[CommandTemplate] = Field(..., min_length=1)

    # ---------- analyzer hints ----------
    usage_description: str = Field(
        ...,
        description="LLM 컨텍스트에 들어갈 자연어 설명.",
    )
    suspicious_indicators: list[SuspiciousIndicator] = Field(default_factory=list)
    known_false_positives: list[str] = Field(default_factory=list)

    # ---------- bookkeeping ----------
    reference_urls: list[str] = Field(default_factory=list)
