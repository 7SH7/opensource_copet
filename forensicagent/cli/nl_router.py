"""자연어 -> 슬래시 액션 시퀀스 라우터 (Phase B).

REPL 의 슬래시 명령은 그대로 두고, 그 위에 얹는 얇은 계층:
  user text  -> Ollama json_chat -> {"actions": [...], "message": "..."}
              -> repl.do_* 함수들을 순차 실행

LLM 실패/Ollama 부재/no_llm 모드에서는 사용자에게 안내하고 즉시 복귀
(슬래시 명령은 여전히 사용 가능).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from forensicagent.cli import repl as repl_mod
from forensicagent.cli.session import SessionState
from forensicagent.llm.ollama_client import JsonRetryFailed, OllamaUnavailable
from forensicagent.ui_text import safe_text

ROUTER_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "message": {"type": "string"},
        "actions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "enum": [
                            "scan", "scenario", "plan", "run", "analyze",
                            "report", "auto", "show", "status", "set", "cd",
                            "tools", "clear",
                        ],
                    },
                    "args": {"type": "object"},
                },
                "required": ["name"],
            },
        },
    },
    "required": ["message", "actions"],
}


def _system_prompt(state: SessionState) -> str:
    tool_ids = ",".join(sorted(state.tool_metas.keys()))
    return f"""You are the request router for the `forensicagent` CLI (a Korean-language forensic triage agent).

Convert the user's natural-language request (Korean or English) into a JSON object describing a short sequence of slash-command actions to execute. Reply in Korean.

Output JSON shape (strict):
{{
  "message": "<1-2 sentence Korean explanation of what will run>",
  "actions": [ {{"name": "<action>", "args": {{...}} }}, ... ]
}}

Available actions:
- scan       args: {{ "path"?: string, "scenario"?: string }}  - 증거 인벤토리 작성 (path 생략시 현재 target; scenario 있으면 함께 설정)
- scenario   args: {{ "text": string }}          - 조사 시나리오 설정 (selector/analyzer LLM 컨텍스트). "clear" 면 해제
- plan       args: {{}}                          - selector 실행
- run        args: {{}}                          - 선별 도구 실행
- analyze    args: {{}}                          - 의심항목 추출
- report     args: {{}}                          - JSON+MD 리포트 저장
- auto       args: {{}}                          - scan->plan->run->analyze->report 전체
- show       args: {{ "what": "inventory"|"plan"|"findings"|"report" }}
- status     args: {{}}                          - 세션 상태
- set        args: {{ "key": string, "value": string }}  - no_llm/quick/max_depth/timeout/max_job_output_mib/max_total_output_mib/min_free_disk_mib/tools/path/output_dir (MiB values are positive integers; total must be >= job)
- cd         args: {{ "path": string }}          - target_path 변경
- tools      args: {{ "arg"?: string }}          - "" 또는 "list" 또는 "info <id>"
- clear      args: {{}}                          - 실행 상태 초기화

Rules:
1. 사용자가 단순 인사/질문만 한 경우 actions=[] 로 두고 message 만 채워라.
2. 여러 단계 요청 ("스캔하고 도구 돌려줘") 은 actions 에 순서대로 모두 포함하라.
3. 모호하면 actions=[] 로 두고 message 에서 무엇이 필요한지 짧게 되물어라.
4. message 는 항상 한국어로, 1-2 문장.
5. JSON 외의 어떤 텍스트도 출력하지 마라.

Context:
- 현재 target_path: {state.target_path}
- 로드된 도구: {tool_ids}
- no_llm: {state.options.no_llm}, quick: {state.options.quick}
- 진행 상태: inv={'Y' if state.inventory else '-'} plan={'Y' if state.plan else '-'} run={'Y' if state.bundle else '-'} analyze={'Y' if state.analyses else '-'} report={'Y' if state.last_report else '-'}
"""


_DISPATCH = {
    "scan": lambda s, c, a: repl_mod.do_scan(
        s, c,
        path=Path(a["path"]) if a.get("path") else None,
        scenario=a.get("scenario"),
    ),
    "scenario": lambda s, c, a: repl_mod.do_scenario(
        s, c, str(a.get("text", ""))
    ),
    "plan": lambda s, c, a: repl_mod.do_plan(s, c),
    "run": lambda s, c, a: repl_mod.do_run(s, c),
    "analyze": lambda s, c, a: repl_mod.do_analyze(s, c),
    "report": lambda s, c, a: repl_mod.do_report(s, c),
    "auto": lambda s, c, a: repl_mod.do_auto(s, c),
    "show": lambda s, c, a: repl_mod.do_show(s, c, a.get("what", "")),
    "status": lambda s, c, a: repl_mod.do_status(s, c),
    "set": lambda s, c, a: repl_mod.do_set(
        s, c, a.get("key", ""), a.get("value", "")
    ),
    "cd": lambda s, c, a: repl_mod.do_cd(s, c, a.get("path", "")),
    "tools": lambda s, c, a: repl_mod.do_tools(s, c, a.get("arg", "")),
    "clear": lambda s, c, a: repl_mod.do_clear(s, c),
}


def _strip_surrogates(s: str) -> str:
    """UTF-8 인코딩 불가능한 surrogate (U+D800-U+DFFF) 제거.

    Windows 콘솔/파이프 + cp949 stdin 경계에서 한글이 mojibake 로 들어오면
    파이썬이 surrogateescape 로 마킹한다. 그대로 ollama HTTP body 에 실으면
    'surrogates not allowed' 로 죽으니, LLM 에 보내기 전에 흘려보낸다.
    """
    return s.encode("utf-8", errors="replace").decode("utf-8")


def handle(state: SessionState, c, text: str) -> None:
    """자연어 입력 한 줄을 처리. 슬래시 명령이 아닌 입력 전용."""
    if state.options.no_llm:
        c.print("[yellow]no_llm 모드: /help 의 슬래시 명령만 사용하세요.[/]")
        return
    client = state.client()
    if client is None:
        c.print("[yellow]LLM 미가용. /help 의 슬래시 명령만 사용하세요.[/]")
        return

    safe_input = _strip_surrogates(text)
    safe_system = _strip_surrogates(_system_prompt(state))
    messages = [
        {"role": "system", "content": safe_system},
        {"role": "user", "content": safe_input},
    ]
    c.print("[dim](LLM 라우팅 중...)[/]")
    try:
        with c.status("[dim]thinking...[/]", spinner="dots"):
            payload = client.json_chat(messages, format_schema=ROUTER_SCHEMA)
    except OllamaUnavailable as e:
        c.print("[red]Ollama 사용 불가:[/]", safe_text(e))
        return
    except JsonRetryFailed as e:
        c.print("[red]LLM JSON 파싱 실패:[/]", safe_text(e))
        return

    if not isinstance(payload, dict):
        c.print(f"[red]예상하지 못한 LLM 응답 형태:[/] {type(payload).__name__}")
        return

    msg = payload.get("message", "")
    actions = payload.get("actions", [])
    if msg:
        c.print(safe_text(msg, style="cyan"))

    if not isinstance(actions, list) or not actions:
        return

    for idx, act in enumerate(actions, 1):
        if not isinstance(act, dict):
            c.print(f"[red]action[{idx}] 형식 오류:[/]", safe_text(act))
            continue
        name = str(act.get("name", "")).lower().strip()
        args = act.get("args") or {}
        if not isinstance(args, dict):
            args = {}
        handler = _DISPATCH.get(name)
        if handler is None:
            c.print("[red]알 수 없는 action:[/]", safe_text(name))
            continue
        c.print(safe_text(f"-> /{name} {args if args else ''}", style="dim"))
        try:
            handler(state, c, args)
        except Exception as e:  # noqa: BLE001
            c.print("[red]action 에러:[/]", safe_text(f"/{name}: {e}"))
