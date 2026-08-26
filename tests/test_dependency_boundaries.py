from __future__ import annotations

import subprocess
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 support
    import tomli as tomllib


ROOT = Path(__file__).resolve().parents[1]


def _project_table() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]


def test_heavy_runtime_stacks_are_explicit_extras() -> None:
    project = _project_table()
    base = project["dependencies"]
    extras = project["optional-dependencies"]

    assert not any(
        dependency.startswith(("ollama", "chromadb", "sentence-transformers"))
        for dependency in base
    )
    assert extras["llm"] == ["ollama>=0.3.0"]
    assert extras["rag"] == [
        "chromadb>=0.5.0",
        "sentence-transformers>=3.0.0",
    ]


def test_forensic_tools_extra_does_not_reference_legacy_binwalk() -> None:
    extras = _project_table()["optional-dependencies"]

    assert extras["forensic-tools"] == ["volatility3==2.28.0"]
    assert not any(
        dependency.casefold().startswith("binwalk")
        for dependencies in extras.values()
        for dependency in dependencies
    )


def test_distribution_includes_only_runtime_tool_metadata() -> None:
    build = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "tool"
    ]["hatch"]["build"]["targets"]

    assert build["wheel"]["force-include"] == {
        f"tools_metadata/{tool_id}.yaml": (
            f"forensicagent/builtin_tools/{tool_id}.yaml"
        )
        for tool_id in (
            "amcacheparser",
            "appcompatcacheparser",
            "bandit",
            "browser_sqlite",
            "chainsaw",
            "evtxecmd",
            "fls",
            "gitleaks",
            "mftecmd",
            "pecmd",
            "recmd",
            "regripper",
            "semgrep",
            "tshark",
            "volatility3",
        )
    } | {"bench/goldenset.json": "bench/goldenset.json"}
    assert {
        "/.claude/**",
        "/CLAUDE.md",
        "/GUIDELINE.md",
        "/PROJECT_TOUR.md",
        "/reference_parser/**",
        "/submit/**",
        "/test_evi/**",
        "/tools_metadata/_failures/**",
    } <= set(build["sdist"]["exclude"])


def test_core_cli_import_and_help_do_not_load_optional_stacks() -> None:
    script = r'''
import importlib.abc
import sys

blocked = {"chromadb", "ollama", "openai", "sentence_transformers"}


class BlockOptional(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.partition(".")[0] in blocked:
            raise ModuleNotFoundError(f"blocked optional dependency: {fullname}")
        return None


sys.meta_path.insert(0, BlockOptional())

from typer.testing import CliRunner
from forensicagent.cli.main import app

result = CliRunner().invoke(app, ["--help"])
if result.exit_code != 0:
    raise SystemExit(result.output or repr(result.exception))
'''
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
