"""Typer 진입점 — `forensicagent` 명령.

전 파이프라인 흐름 (명세 0.2):
  Scanner → Selector → (사용자 승인) → Executor → Analyzer → Reporter
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Optional

import typer

from forensicagent import __version__
from forensicagent import config as settings
from forensicagent.analyzer import analyze_all
from forensicagent.cli.doctor import run_doctor
from forensicagent.cli.repl import run as run_repl
from forensicagent.cli.session import SessionOptions, make_session
from forensicagent.cli.ui import console, render_inventory, render_oversized_exclusions
from forensicagent.executor import execute
from forensicagent.llm import OllamaClient
from forensicagent.reporter import write as write_report
from forensicagent.reporter.types import now_iso
from forensicagent.scanner import scan
from forensicagent.selector import select
from forensicagent.tools import load_all_tools
from forensicagent.ui_text import safe_text

app = typer.Typer(
    name="forensicagent",
    help="Forensic auto-triage CLI agent.",
    no_args_is_help=False,
    add_completion=False,
    rich_markup_mode="rich",
)

tools_app = typer.Typer(help="Tool metadata management.")
app.add_typer(tools_app, name="tools")

rag_app = typer.Typer(help="RAG index management (tool-metadata corpus).")
app.add_typer(rag_app, name="rag")

_MIB = 1024**2


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"forensicagent {__version__}")
        raise typer.Exit(0)


def _approve(c, *, auto: bool, prompt: str) -> bool:
    """interactive approval. --auto 면 항상 True."""
    if auto:
        return True
    if not sys.stdin.isatty():
        # CI/IDE/pipe 환경에서 외부 분석 도구를 묵시적으로 실행하지 않는다.
        # 자동화를 원하면 호출자가 의도를 명시하는 --auto 가 필요하다.
        c.print(
            "[yellow]비대화형 입력에서는 실행 승인을 받을 수 없습니다. "
            "자동 실행하려면 --auto 를 명시하세요.[/]"
        )
        return False
    answer = c.input(prompt).strip().lower()
    return answer in ("", "y", "yes")


def _load_tools_or_exit(c) -> tuple[Path, list]:
    tools_dir = settings.resolve_tools_dir()
    tool_metas = load_all_tools(tools_dir)
    if not tool_metas:
        c.print(
            f"[yellow]경고: 도구 메타데이터가 없습니다 ({tools_dir}). "
            "tools_metadata/*.yaml 을 추가하세요.[/]"
        )
        raise typer.Exit(2)
    return tools_dir, tool_metas


@app.callback(invoke_without_command=True)
def root(
    ctx: typer.Context,
    auto: bool = typer.Option(False, "--auto", help="Skip approval prompts."),
    quick: bool = typer.Option(
        False, "--quick", help="Run only short-runtime tools."
    ),
    tools: Optional[str] = typer.Option(
        None,
        "--tools",
        help=(
            "Force listed tool choices after host/evidence/input safety checks; "
            "skips RAG/LLM ranking."
        ),
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Stop after planning; do not execute tools."
    ),
    max_depth: int = typer.Option(
        5, "--max-depth", help="Recursive scan depth limit.", min=1
    ),
    path: Optional[Path] = typer.Option(
        None, "--path",
        help="File or directory to analyze (default: CWD).",
        exists=False, file_okay=True, dir_okay=True,
    ),
    no_llm: bool = typer.Option(
        False, "--no-llm",
        help="Disable Selector/Analyzer LLM; RAG remains unless --no-rag is set.",
    ),
    no_rag: bool = typer.Option(
        False, "--no-rag",
        help="Disable RAG reranking/context; LLM remains unless --no-llm is set.",
    ),
    scenario: Optional[str] = typer.Option(
        None, "--scenario",
        help=(
            "Include a scenario in RAG/LLM context; absolute timestamps also "
            "scope structured Analyzer LLM input."
        ),
    ),
    output_dir: Optional[Path] = typer.Option(
        None, "--output-dir",
        help="Where to write outputs (default: ~/.forensicagent/output/<case>).",
    ),
    timeout: int = typer.Option(
        0, "--timeout",
        help="Per-tool timeout seconds (0 = use config default).",
    ),
    max_job_output_mib: Optional[int] = typer.Option(
        None,
        "--max-job-output-mib",
        "--max-job-output-mb",
        min=1,
        help="Maximum output per tool job in MiB (default: configured value).",
    ),
    max_total_output_mib: Optional[int] = typer.Option(
        None,
        "--max-total-output-mib",
        "--max-total-output-mb",
        min=1,
        help="Maximum total raw tool output in MiB (default: configured value).",
    ),
    min_free_disk_mib: Optional[int] = typer.Option(
        None,
        "--min-free-disk-mib",
        "--min-free-disk-mb",
        min=1,
        help="Free disk space to preserve in MiB (default: configured value).",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True,
        help="Print version and exit.",
    ),
) -> None:
    """Default flow when no subcommand is given."""
    if ctx.invoked_subcommand is not None:
        return

    if verbose:
        logging.basicConfig(
            level=logging.INFO, format="%(levelname)s %(name)s: %(message)s"
        )

    c = console()

    max_job_output_bytes = (
        max_job_output_mib * _MIB
        if max_job_output_mib is not None
        else settings.MAX_JOB_OUTPUT_BYTES
    )
    max_total_output_bytes = (
        max_total_output_mib * _MIB
        if max_total_output_mib is not None
        else settings.MAX_TOTAL_OUTPUT_BYTES
    )
    min_free_disk_bytes = (
        min_free_disk_mib * _MIB
        if min_free_disk_mib is not None
        else settings.MIN_FREE_DISK_BYTES
    )
    if max_total_output_bytes < max_job_output_bytes:
        c.print(
            "[red]--max-total-output-mib must be greater than or equal to "
            "--max-job-output-mib.[/]"
        )
        raise typer.Exit(2)

    # 인자 없이 호출 + TTY 면 인터랙티브 REPL 로 진입.
    one_shot_signals = (
        auto or quick or dry_run or no_llm or no_rag
        or tools is not None or path is not None
        or output_dir is not None or timeout != 0
        or scenario is not None
        or max_job_output_mib is not None
        or max_total_output_mib is not None
        or min_free_disk_mib is not None
    )
    if not one_shot_signals and sys.stdin.isatty():
        _, tool_metas = _load_tools_or_exit(c)
        state = make_session(
            path=None,
            output_dir=None,
            tool_metas=tool_metas,
            options=SessionOptions(no_llm=False),
        )
        raise typer.Exit(run_repl(state))

    target = (path or Path(os.getcwd())).resolve()
    out_dir = output_dir.resolve() if output_dir else settings.default_output_dir(target)
    if not target.exists():
        c.print("[red]분석 경로가 없습니다:[/]", safe_text(target))
        raise typer.Exit(2)
    c.print(f"[bold]forensicagent[/] {__version__}")
    c.print(safe_text(f"[*] 작업 디렉토리: {target}"))

    started_at = now_iso()
    stage_ms: dict[str, int] = {}

    # ---------- 1. Scanner ----------
    c.print("[*] 증거 스캔 중...")
    inv = scan(
        target,
        max_depth=max_depth,
        include_unknown=False,
        exclude_paths=[out_dir],
        stage_ms=stage_ms,
    )
    if inv.depth_limit_hit or inv.unreadable_paths or inv.reparse_paths:
        c.print(
            "[yellow]Scan coverage incomplete: "
            f"depth_limit_hit={str(inv.depth_limit_hit).lower()}, "
            f"unreadable_paths={inv.unreadable_paths}, "
            f"reparse_paths={inv.reparse_paths}.[/]"
        )
    if inv.oversized_files:
        c.print(render_oversized_exclusions(inv))
        c.print(
            "[yellow]위 파일들은 1.5 GiB 이상이기 때문에 scan 작업에서 "
            "제외되었습니다. 나머지 파일로 계속 진행합니다.[/]"
        )
    if not inv.evidence_list:
        suffix = (
            f" (미식별 파일 {inv.unidentified_files}개)"
            if inv.unidentified_files else ""
        )
        c.print(f"[yellow]지원되는 증거가 없습니다{suffix}.[/]")
        raise typer.Exit(0)
    c.print(render_inventory(inv))
    c.print(
        f"[*] 스캔 완료: {inv.scanned_files} 파일 검사, "
        f"{len(inv.evidence_list)} 증거 식별 "
        f"(미식별 {inv.unidentified_files}, "
        f"소요 {stage_ms.get('scan_walk', 0) + stage_ms.get('scan_detect', 0)} ms)."
    )

    # ---------- 2. Selector ----------
    tools_dir, tool_metas = _load_tools_or_exit(c)

    forced = [t.strip() for t in tools.split(",") if t.strip()] if tools else []
    c.print(
        f"[*] 도구 풀: {len(tool_metas)} 개 ({tools_dir}). "
        f"증거 기반 선별 시작..."
    )
    client = None if no_llm else OllamaClient()
    plan = select(
        inv,
        tool_metas,
        quick=quick,
        force_tools=forced or None,
        use_llm=not no_llm,
        use_rag=not no_rag,
        client=client,
        scenario=scenario,
        stage_ms=stage_ms,
    )

    if not plan.selected_tools:
        c.print(
            "[yellow]적용 가능한 도구가 없습니다. 식별된 증거의 형식과 "
            "tools_metadata 입력 규칙을 확인하세요.[/]"
        )
        raise typer.Exit(2)

    c.print(f"\n[*] 적용 가능한 도구 {len(plan.selected_tools)} 개 선별됨:")
    for i, sel in enumerate(plan.selected_tools, 1):
        c.print(
            safe_text(
                f"  {i}. {sel.tool_id} (prio={sel.priority}, "
                f"runtime={sel.estimated_runtime}, targets={len(sel.target_evidence)})"
            )
        )
        c.print(safe_text(f"     {sel.reason}", style="dim"))
    if plan.llm_used:
        msg = "LLM 우선순위 보강 ok" if not plan.llm_fallback else "LLM 실패 → 기본 우선순위 fallback"
        c.print(f"[dim]({msg})[/]")
    if plan.unhandled_evidence:
        c.print(
            f"[yellow]주의: 식별됐지만 지원 도구가 없는 증거 "
            f"{len(plan.unhandled_evidence)}개가 있습니다.[/]"
        )

    if dry_run:
        c.print("\n[dim]--dry-run: stopping after plan.[/]")
        raise typer.Exit(0)

    if not _approve(c, auto=auto, prompt="\n계속 진행할까요? [Y/n] "):
        if not sys.stdin.isatty():
            raise typer.Exit(2)
        c.print("[yellow]사용자 취소.[/]")
        raise typer.Exit(0)

    # ---------- 3. Executor ----------
    raw_out_dir = out_dir / "raw"
    c.print(safe_text(f"\n[*] 도구 실행 중 (output → {out_dir})..."))
    bundle = execute(
        plan,
        tool_metas,
        output_dir=raw_out_dir,
        timeout_sec=(timeout or None),
        max_job_output_bytes=max_job_output_bytes,
        max_total_output_bytes=max_total_output_bytes,
        min_free_disk_bytes=min_free_disk_bytes,
        inventory=inv,
        console=c,
        stage_ms=stage_ms,
    )

    counts = {
        status: sum(1 for r in bundle.results if r.status == status)
        for status in (
            "success",
            "failed",
            "timeout",
            "cancelled",
            "output_limit",
            "output_missing",
            "skipped",
        )
    }
    reused_n = sum(
        1
        for result in bundle.results
        if isinstance(result.provenance.get("resume"), dict)
        and result.provenance["resume"].get("reused") is True
    )
    c.print(
        "[*] 실행 완료: "
        + ", ".join(f"{status}={count}" for status, count in counts.items())
        + f", reused={reused_n}"
    )

    # ---------- 4. Analyzer ----------
    c.print("[*] 의심항목 추출 중...")
    analyses = analyze_all(
        bundle.results,
        tool_metas,
        use_llm=not no_llm,
        use_rag=not no_rag,
        client=client,
        scenario=scenario,
        stage_ms=stage_ms,
    )

    # ---------- 5. Reporter ----------
    c.print("[*] 리포트 생성 중...\n")
    report, paths = write_report(
        inventory=inv,
        plan=plan,
        execution=bundle,
        analyses=analyses,
        started_at=started_at,
        working_directory=str(target),
        output_dir=out_dir,
        console=c,
        stage_ms=stage_ms,
    )

    if paths:
        c.print("")
        for fmt, p in paths.items():
            c.print(f"[green]리포트 저장됨 ({fmt}):[/]", safe_text(p))
    if counts["cancelled"]:
        raise typer.Exit(130)
    if counts["output_limit"]:
        raise typer.Exit(3)
    if plan.selected_tools and counts["success"] == 0:
        c.print(
            "[red]실행 가능한 도구가 하나도 성공하지 않았습니다. "
            "리포트의 skipped/failed 원인과 `forensicagent doctor` 결과를 "
            "확인하세요.[/]"
        )
        raise typer.Exit(3)


@app.command("shell")
def shell_cmd(
    path: Optional[Path] = typer.Option(
        None, "--path",
        help="Initial target file or directory (default: CWD).",
        exists=False, file_okay=True, dir_okay=True,
    ),
    output_dir: Optional[Path] = typer.Option(
        None, "--output-dir",
        help="Where to write outputs (default: ~/.forensicagent/output/<case>).",
    ),
    no_llm: bool = typer.Option(
        False, "--no-llm",
        help="Disable LLM (Selector stage-2 + Analyzer LLM extract off).",
    ),
    quick: bool = typer.Option(
        False, "--quick", help="Only short-runtime tools when planning.",
    ),
) -> None:
    """Launch the interactive REPL (forensic> prompt)."""
    c = console()
    _, tool_metas = _load_tools_or_exit(c)
    state = make_session(
        path=path,
        output_dir=output_dir,
        tool_metas=tool_metas,
        options=SessionOptions(no_llm=no_llm, quick=quick),
    )
    raise typer.Exit(run_repl(state))


@app.command("doctor")
def doctor_cmd(
    skip_optional: bool = typer.Option(
        False, "--skip-optional", help="Skip optional forensic-tool PATH checks."
    ),
) -> None:
    """Check environment readiness."""
    failed = run_doctor(console=console(), show_optional=not skip_optional)
    raise typer.Exit(failed)


@app.command("install")
def install_cmd(
    tools: Optional[list[str]] = typer.Argument(
        None,
        help="설치할 도구 이름들 (생략시 missing 인 도구를 모두 인터랙티브 순회).",
    ),
    all_auto: bool = typer.Option(
        False, "--all",
        help="자동 설치 가능한 (pip/zip) missing 도구를 모두 한 번에. manual 은 안내만.",
    ),
) -> None:
    """Install missing forensic tools (pip + zip auto, manual just gets a URL hint)."""
    from forensicagent.cli.tool_install import (
        install_all_auto,
        install_interactive,
        TOOL_SPECS,
    )
    c = console()
    failures: list[str] = []
    if tools:
        # 사용자가 명시. registry 검증은 install_interactive 가 함.
        n, failures = install_interactive(c, names=tools)
    elif all_auto:
        n, failures = install_all_auto(c)
    else:
        n, failures = install_interactive(c, names=None)
    c.print(f"\n[bold]설치 완료:[/] {n}개")
    c.print(f"[dim]registry 전체: {len(set(s.name for s in TOOL_SPECS.values()))} 도구[/]")
    c.print("[dim]다시 `forensicagent doctor` 로 확인하세요.[/]")
    if failures:
        c.print(f"[red]설치 실패:[/] {', '.join(failures)}")
        raise typer.Exit(1)


@tools_app.command("list")
def tools_list() -> None:
    """List tool metadata YAMLs found in the resolved tools dir."""
    c = console()
    tdir = settings.resolve_tools_dir()
    yamls = (
        sorted(list(tdir.glob("*.yaml")) + list(tdir.glob("*.yml")))
        if tdir.exists() else []
    )
    if yamls:
        c.print(f"[bold]tool metadata in {tdir}:[/]")
        for y in yamls:
            c.print(f"  - {y.name}")
        return
    c.print(f"[yellow]no YAMLs found in: {tdir}[/]")


@tools_app.command("info")
def tools_info(
    tool_id: str = typer.Argument(..., help="Tool ID (matches YAML filename stem).")
) -> None:
    """Print contents of tool metadata YAML."""
    tdir = settings.resolve_tools_dir()
    for ext in (".yaml", ".yml"):
        f = tdir / f"{tool_id}{ext}"
        if f.exists():
            console().print(f.read_text(encoding="utf-8"))
            return
    console().print(f"[red]not found:[/] {tool_id} (in {tdir})")
    raise typer.Exit(1)


@rag_app.command("index-tools")
def rag_index_tools(
    keep: bool = typer.Option(
        False, "--keep",
        help="Add without resetting the collection first (default: overwrite).",
    ),
) -> None:
    """Index tools_metadata/*.yaml into the runtime tool-selection collection."""
    c = console()
    tools_dir, tool_metas = _load_tools_or_exit(c)
    c.print(f"[*] 도구 {len(tool_metas)} 개 인덱싱 중 ({tools_dir}) ...")
    try:
        from forensicagent.rag.tool_indexer import index_tools
    except ImportError as e:  # pragma: no cover
        c.print(f"[red]RAG 의존성 없음:[/] {e}")
        raise typer.Exit(2)
    try:
        stats = index_tools(tool_metas, overwrite=not keep)
    except Exception as e:  # noqa: BLE001
        c.print(
            f"[red]인덱싱 실패:[/] {type(e).__name__}: {e}\n"
            "[dim]chromadb / sentence-transformers 설치 여부를 확인하세요 "
            "(forensicagent doctor).[/]"
        )
        raise typer.Exit(2)
    if stats.errors:
        for err in stats.errors:
            c.print(f"[yellow]  ! {err}[/]")
    c.print(
        f"[green]완료:[/] collection={stats.collection} "
        f"tools_indexed={stats.tools_indexed} "
        f"(embed {stats.embedding_ms}ms, chroma {stats.chroma_ms}ms, "
        f"total {stats.elapsed_s:.1f}s)"
    )


@app.command("bench")
def bench_cmd(
    with_llm: bool = typer.Option(
        False, "--with-llm",
        help="Also run +LLM / +RAG+LLM modes (needs Ollama; slow on CPU).",
    ),
    no_rebuild: bool = typer.Option(
        False, "--no-rebuild", help="Reuse existing tool index instead of rebuilding.",
    ),
) -> None:
    """Benchmark RAG reranking vs the deterministic baseline (writes bench/)."""
    c = console()
    # bench/ 는 패키지 밖(리포 루트)이라 PROJECT_ROOT 를 path 에 얹고 import.
    root = str(settings.PROJECT_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)
    try:
        from bench.harness import run_benchmark
        from bench.report import render_terminal, save
    except ImportError as e:
        c.print(f"[red]bench/ 를 찾을 수 없습니다 ({e}). 리포 루트에서 실행하세요.[/]")
        raise typer.Exit(2)
    result = run_benchmark(with_llm=with_llm, rebuild=not no_rebuild)
    render_terminal(result, c)
    paths = save(result)
    c.print(f"\n[green]saved:[/] {paths['json']}")
    c.print(f"[green]saved:[/] {paths['md']}")


@rag_app.command("status")
def rag_status() -> None:
    """Show whether the runtime tool-selection index is present and populated."""
    from forensicagent.rag.tool_indexer import tool_collection_status

    c = console()
    ok, n, detail = tool_collection_status()
    status = "[green]OK[/]" if ok and n > 0 else "[yellow]miss[/]"
    c.print(f"{status} collection=[bold]{settings.TOOL_COLLECTION}[/] count={n}")
    c.print(f"[dim]{detail}[/]")
    c.print(f"[dim]USE_RAG={settings.USE_RAG}, TOP_K={settings.RAG_TOP_K}, "
            f"persist={settings.CHROMA_PERSIST_DIR}[/]")


if __name__ == "__main__":
    app()
