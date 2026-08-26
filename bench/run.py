"""Runnable entry: `python -m bench.run [--with-llm] [--no-rebuild]`.

`forensicagent bench` CLI 명령과 동일한 로직을 얇게 감싼다.
"""

from __future__ import annotations

import argparse
import sys

from rich.console import Console

from bench.harness import run_benchmark
from bench.report import render_terminal, save


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="forensicagent RAG benchmark.")
    ap.add_argument("--with-llm", action="store_true",
                    help="Also run +LLM / +RAG+LLM modes (needs Ollama; slow on CPU).")
    ap.add_argument("--no-rebuild", action="store_true",
                    help="Reuse the existing tool index instead of rebuilding.")
    args = ap.parse_args(argv)

    console = Console()
    result = run_benchmark(with_llm=args.with_llm, rebuild=not args.no_rebuild)
    render_terminal(result, console)
    paths = save(result)
    console.print(f"\n[green]saved:[/] {paths['json']}")
    console.print(f"[green]saved:[/] {paths['md']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
