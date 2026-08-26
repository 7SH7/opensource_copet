"""Chainsaw 전용 어댑터 — EVTX 채널별 정확한 Event ID 검색.

Chainsaw의 ``-e``는 직렬화된 레코드 전체에 적용되는 정규식이다. 따라서
``4624|4625`` 같은 패턴은 EventID가 아닌 다른 필드의 숫자에도 걸릴 수 있고,
한 자리 Sysmon ID는 특히 오탐이 많다. 이 어댑터는 필드를 지정하는 Tau
표현식(``Event.System.EventID: =4624``)을 사용하고 여러 식은
``--match-any``로 결합한다.
"""

from __future__ import annotations

import logging
from pathlib import Path

from forensicagent.executor.adapter import GenericAdapter

logger = logging.getLogger(__name__)


# 채널(파일) → 그 채널에서 의미 있는 Event ID 목록.
# 새 채널을 지원하려면 여기에 (판별 토큰, ID 리스트) 한 줄만 추가하면 된다.
CHANNEL_EVENT_IDS: dict[str, list[str]] = {
    # 인증, 프로세스 생성, 서비스 설치, 계정/그룹 변경, 감사 로그 삭제.
    "security": [
        "4624", "4625", "4648", "4672", "4688", "4697",
        "4720", "4728", "4732", "4740", "1102",
    ],
    # PowerShell 모듈/스크립트 블록 로깅.
    "powershell": ["4103", "4104"],
    # Windows System 로그 삭제 및 서비스 설치.
    "system": ["104", "7045"],
    # 정확한 필드 비교이므로 한 자리 ID도 안전하게 사용할 수 있다.
    "sysmon": ["1", "3", "7", "8", "10", "11", "12", "13", "22"],
}

# 채널을 특정하지 못한 경우 여러 로그에 공통적으로 조사 가치가 높은 ID만 본다.
DEFAULT_EVENT_IDS: list[str] = [
    "104",
    "1102",
    "4104",
    "4624",
    "4625",
    "4697",
    "4720",
    "4732",
    "7045",
]


def event_ids_for_file(filename: str) -> list[str]:
    """파일명으로 채널을 추정해 검색할 Event ID 목록을 돌려준다."""
    f = filename.lower()
    if f == "microsoft-windows-powershell%4operational.evtx":
        return CHANNEL_EVENT_IDS["powershell"]
    if f == "microsoft-windows-sysmon%4operational.evtx":
        return CHANNEL_EVENT_IDS["sysmon"]
    if f == "security.evtx":
        return CHANNEL_EVENT_IDS["security"]
    if f == "system.evtx":
        return CHANNEL_EVENT_IDS["system"]
    return DEFAULT_EVENT_IDS


class ChainsawAdapter(GenericAdapter):
    """파일별 Event ID를 Tau 식으로 만들어 Chainsaw 검색 명령을 만든다."""

    def build_command(
        self,
        evidence_path: str,
        *,
        preferred_template: str | None = None,
        **vars: str,
    ) -> list[str]:
        output_dir = vars.get("output_dir")
        if not output_dir:
            raise ValueError("ChainsawAdapter requires an isolated output_dir")
        template = preferred_template or next(
            (
                command.template
                for command in self._meta.command_templates
                if "chainsaw search" in command.template.casefold()
            ),
            "",
        )
        if "chainsaw search" not in template.casefold():
            raise ValueError(
                "ChainsawAdapter supports deterministic Event-ID search only; "
                "Sigma hunt requires caller-supplied rules and mapping paths"
            )

        ids = event_ids_for_file(Path(evidence_path).name)
        argv = ["chainsaw", "search"]
        for event_id in ids:
            argv.extend(["-t", f"Event.System.EventID: ={event_id}"])
        if len(ids) > 1:
            argv.append("--match-any")
        output_path = Path(output_dir) / "chainsaw.jsonl"
        argv.extend(["--jsonl", "--output", str(output_path), evidence_path])
        self.selected_template = template
        logger.info("chainsaw: %s -> Tau IDs %s", Path(evidence_path).name, ids)
        return argv
