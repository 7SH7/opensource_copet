"""Tool metadata schema + loader.

50+ 개 포렌식 도구를 표현하는 YAML 의 스키마 정의 (Pydantic) 와 디스크
디렉토리에서 일괄 로드하는 헬퍼.

forensicagent 의 모든 모듈은 이 패키지에서 정의된 ToolMetadata 만을
도구의 진실 원천으로 사용한다.
"""

from forensicagent.tools.loader import load_all_tools, load_tool
from forensicagent.tools.schema import (
    CommandTemplate,
    InstallCheck,
    SuspiciousIndicator,
    ToolMetadata,
)

__all__ = [
    "CommandTemplate",
    "InstallCheck",
    "SuspiciousIndicator",
    "ToolMetadata",
    "load_all_tools",
    "load_tool",
]
