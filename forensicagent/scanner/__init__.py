"""Scanner — Layer 1 모듈.

CWD 의 파일을 magic bytes + 확장자 + 파일명 + 부모 디렉토리 힌트로 식별해
Evidence 인벤토리를 만든다.
"""

from forensicagent.scanner.scanner import scan
from forensicagent.scanner.types import (
    DetectionMethod,
    Evidence,
    EvidenceType,
    Inventory,
    Platform,
)

__all__ = [
    "scan",
    "Evidence",
    "EvidenceType",
    "DetectionMethod",
    "Platform",
    "Inventory",
]
