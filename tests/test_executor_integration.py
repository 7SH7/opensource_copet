from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from forensicagent import config as settings
from forensicagent.analyzer import analyze_one
from forensicagent.executor.adapter import GenericAdapter
from forensicagent.executor.executor import _build_jobs, _command_dependencies, execute
from forensicagent.executor.runner import collect_generated_artifacts, run_tool
from forensicagent.executor.state import (
    load_state,
    new_state,
    record_result,
    reusable_result,
)
from forensicagent.executor.types import MAX_INLINE_JSON_BYTES, ExecutionResult
from forensicagent.scanner import scan
from forensicagent.selector.types import Plan, RunSpec, ToolSelection
from forensicagent.tools.schema import CommandTemplate, InstallCheck, ToolMetadata


def _script(path: Path, *, create_output: bool = True) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    write_output = (
        "(out / 'result.csv').write_text('kind,value\\nrow,1\\n', encoding='utf-8')"
        if create_output
        else "pass"
    )
    path.write_text(
        "from pathlib import Path\n"
        "import sys\n"
        "out = Path(sys.argv[1])\n"
        "out.mkdir(parents=True, exist_ok=True)\n"
        f"{write_output}\n"
        "print('done')\n",
        encoding="utf-8",
    )
    return path


def _metadata(
    tool_id: str,
    template: str,
    *,
    parallelizable: bool = True,
    output_format: str = "csv",
) -> ToolMetadata:
    return ToolMetadata(
        tool_id=tool_id,
        display_name=tool_id,
        category="test",
        applicable_evidence_types=["text_log"],  # type: ignore[list-item]
        parallelizable=parallelizable,
        output_format=output_format,  # type: ignore[arg-type]
        install_check=InstallCheck(
            command=f"{sys.executable} --version",
            expected_pattern="Python",
        ),
        command_templates=[
            CommandTemplate(name="fake", template=template, when="test")
        ],
        usage_description="executor integration fixture",
    )


def _selection(tool_id: str, template: str, targets: list[str], priority: int = 5):
    return ToolSelection(
        tool_id=tool_id,
        target_evidence=targets,
        command_template=template,
        priority=priority,
    )


def test_generated_file_argument_is_never_hashed_as_a_tool_dependency(tmp_path):
    evidence = tmp_path / "evidence.evtx"
    dependency = tmp_path / "rules.yml"
    generated = tmp_path / "job" / "generated"
    output = generated / "result.jsonl"
    evidence.write_bytes(b"evidence")
    dependency.write_bytes(b"rules")
    generated.mkdir(parents=True)
    argv = ["tool", str(dependency), str(output), str(evidence)]

    before = _command_dependencies(
        argv,
        evidence_path=evidence,
        generated_dir=generated,
    )
    output.write_bytes(b"result")
    after = _command_dependencies(
        argv,
        evidence_path=evidence,
        generated_dir=generated,
    )

    assert before == after
    assert [item["path"] for item in after] == [str(dependency.resolve())]


def test_generated_output_manifest_and_stdout_compatibility(tmp_path):
    fake = _script(tmp_path / "fake.py")
    template = f"{sys.executable} {{evidence_path}} {{output_dir}}"
    metadata = _metadata("fakecsv", template)
    plan = Plan(selected_tools=[_selection("fakecsv", template, [str(fake)])])

    bundle = execute(
        plan,
        {"fakecsv": metadata},
        output_dir=tmp_path / "runs",
        max_parallel=2,
    )

    assert len(bundle.results) == 1
    result = bundle.results[0]
    assert result.status == "success"
    assert Path(result.stdout_path).read_text(encoding="utf-8").strip() == "done"
    assert result.command_template_used == template
    assert {artifact.role for artifact in result.artifacts} == {
        "stdout",
        "stderr",
        "generated",
    }
    generated = next(a for a in result.artifacts if a.role == "generated")
    assert generated.format == "csv"
    assert generated.size_bytes > 0
    assert generated.sha256 == hashlib.sha256(Path(generated.path).read_bytes()).hexdigest()
    payload = result.to_dict()
    assert payload["artifacts"][0]["sha256"]
    assert payload["warnings"] == []
    provenance = payload["provenance"]
    assert provenance["app_version"]
    assert provenance["tool_version"].startswith("Python ")
    assert Path(provenance["executable_path"]) == Path(sys.executable).resolve()
    assert provenance["executable_sha256"] == hashlib.sha256(
        Path(sys.executable).read_bytes()
    ).hexdigest()
    assert provenance["tool_metadata"]["tool_id"] == "fakecsv"
    assert len(provenance["tool_metadata_sha256"]) == 64
    assert len(provenance["rule_definition_sha256"]) == 64
    rules_path = Path(__file__).resolve().parents[1] / "forensicagent/analyzer/rules.py"
    assert provenance["analyzer_rules_sha256"] == hashlib.sha256(
        rules_path.read_bytes()
    ).hexdigest()
    assert provenance["input_integrity"]["status"] == "verified"
    assert provenance["preflight"]["status"] == "passed"


def test_generated_reparse_point_is_not_followed(tmp_path, monkeypatch):
    generated = tmp_path / "generated"
    generated.mkdir()

    class ReparseEntry:
        path = str(generated / "junction")

        def stat(self, *, follow_symlinks):
            assert follow_symlinks is False
            return SimpleNamespace(st_file_attributes=0x400)

        def is_symlink(self):
            return False

    monkeypatch.setattr(
        "forensicagent.executor.runner.os.scandir",
        lambda directory: [ReparseEntry()],
    )

    artifacts, warnings = collect_generated_artifacts(
        generated,
        default_format="text",
    )

    assert artifacts == []
    assert any("link/reparse point" in warning for warning in warnings)


def test_generated_root_reparse_point_is_rejected(tmp_path, monkeypatch):
    generated = (tmp_path / "generated").resolve()
    generated.mkdir()
    original_lstat = Path.lstat

    def fake_lstat(path):
        value = original_lstat(path)
        if path == generated:
            return SimpleNamespace(
                st_mode=value.st_mode,
                st_file_attributes=0x400,
            )
        return value

    monkeypatch.setattr(Path, "lstat", fake_lstat)

    artifacts, warnings = collect_generated_artifacts(
        generated,
        default_format="text",
        containment_root=tmp_path,
    )

    assert artifacts == []
    assert any("unsafe generated output root" in warning for warning in warnings)


def test_large_json_stdout_stays_artifact_and_is_not_embedded(tmp_path):
    script = tmp_path / "large_json.py"
    script.write_text(
        "import json\n"
        "print(json.dumps({'items': [{'EventID': 4624, "
        f"'padding': 'x' * {MAX_INLINE_JSON_BYTES}}}]}}))\n",
        encoding="utf-8",
    )
    template = f"{sys.executable} {{evidence_path}}"
    metadata = _metadata("largejson", template, output_format="json")

    result = execute(
        Plan(selected_tools=[_selection("largejson", template, [str(script)])]),
        {"largejson": metadata},
        output_dir=tmp_path / "runs",
    ).results[0]

    assert result.status == "success"
    assert result.output_size_bytes > MAX_INLINE_JSON_BYTES
    assert result.parsed_output is None
    assert any("eager parse/report embedding skipped" in item for item in result.warnings)
    stdout = next(item for item in result.artifacts if item.role == "stdout")
    assert Path(stdout.path).is_file()
    assert stdout.size_bytes == result.output_size_bytes
    assert result.to_dict()["parsed_output"] is None


def test_same_evidence_filename_jobs_are_isolated(tmp_path):
    first = _script(tmp_path / "one" / "same.py")
    second = _script(tmp_path / "two" / "same.py")
    template = f"{sys.executable} {{evidence_path}} {{output_dir}}"
    metadata = _metadata("isolated", template)
    plan = Plan(
        selected_tools=[
            _selection("isolated", template, [str(first), str(second)])
        ]
    )

    results = execute(
        plan,
        {"isolated": metadata},
        output_dir=tmp_path / "runs",
        max_parallel=2,
    ).results

    assert [r.status for r in results] == ["success", "success"]
    job_dirs = {Path(r.stdout_path).parent for r in results}
    assert len(job_dirs) == 2
    generated_paths = {
        a.path for r in results for a in r.artifacts if a.role == "generated"
    }
    assert len(generated_paths) == 2


def test_run_specs_expand_one_target_into_multiple_isolated_jobs(tmp_path):
    fake = _script(tmp_path / "multi.py")
    first = f"{sys.executable} {{evidence_path}} {{output_dir}} first"
    second = f"{sys.executable} {{evidence_path}} {{output_dir}} second"
    metadata = _metadata("multi", first)
    metadata.command_templates.append(
        CommandTemplate(name="second", template=second, when="second pass")
    )
    selection = _selection("multi", first, [str(fake)])
    selection.run_specs = [
        RunSpec(str(fake), first, label="first"),
        RunSpec(str(fake), second, label="second"),
    ]

    results = execute(
        Plan(selected_tools=[selection]),
        {"multi": metadata},
        output_dir=tmp_path / "runs",
        max_parallel=2,
    ).results

    assert [result.command_template_used for result in results] == [first, second]
    assert all(result.status == "success" for result in results)
    assert len({Path(result.stdout_path).parent for result in results}) == 2


def test_expected_generated_output_missing_is_explicit(tmp_path):
    fake = _script(tmp_path / "no_output.py", create_output=False)
    template = f"{sys.executable} {{evidence_path}} {{output_dir}}"
    metadata = _metadata("missing", template)
    plan = Plan(selected_tools=[_selection("missing", template, [str(fake)])])

    result = execute(
        plan,
        {"missing": metadata},
        output_dir=tmp_path / "runs",
    ).results[0]

    assert result.status == "output_missing"
    assert "no files were produced" in result.error_message
    assert result.warnings
    assert not [a for a in result.artifacts if a.role == "generated"]
    assert not (Path(result.stdout_path).parent / "generated").exists()


def test_silent_success_leaves_no_empty_job_but_keeps_resume_state(tmp_path):
    script = tmp_path / "silent.py"
    script.write_text("pass\n", encoding="utf-8")
    template = f"{sys.executable} {{evidence_path}}"
    metadata = _metadata("silent", template, output_format="text")
    raw_dir = tmp_path / "runs"

    result = execute(
        Plan(selected_tools=[_selection("silent", template, [str(script)])]),
        {"silent": metadata},
        output_dir=raw_dir,
    ).results[0]

    assert result.status == "success"
    assert result.stdout_path == ""
    assert result.stderr_path == ""
    assert result.artifacts == []
    assert (raw_dir / ".execution-state.json").is_file()
    assert not [path for path in raw_dir.iterdir() if path.is_dir()]


def test_successful_stderr_diagnostic_keeps_job_directory(tmp_path):
    script = tmp_path / "warn.py"
    script.write_text(
        "import sys\nsys.stderr.write('nonfatal warning')\n",
        encoding="utf-8",
    )
    template = f"{sys.executable} {{evidence_path}}"
    metadata = _metadata("warn", template, output_format="text")

    result = execute(
        Plan(selected_tools=[_selection("warn", template, [str(script)])]),
        {"warn": metadata},
        output_dir=tmp_path / "runs",
    ).results[0]

    assert result.status == "success"
    assert Path(result.stderr_path).is_file()
    assert "nonfatal warning" in Path(result.stderr_path).read_text(encoding="utf-8")


def test_successful_implicit_cwd_output_is_never_deleted(tmp_path):
    script = tmp_path / "implicit.py"
    script.write_text(
        "from pathlib import Path\n"
        "Path('implicit.csv').write_text('kind,value\\nrow,1\\n', encoding='utf-8')\n",
        encoding="utf-8",
    )
    template = f"{sys.executable} {{evidence_path}}"
    metadata = _metadata("implicit", template, output_format="text")

    result = execute(
        Plan(selected_tools=[_selection("implicit", template, [str(script)])]),
        {"implicit": metadata},
        output_dir=tmp_path / "runs",
    ).results[0]

    implicit = Path(result.stdout_path).parent / "implicit.csv"
    assert result.status == "success"
    assert implicit.read_text(encoding="utf-8") == "kind,value\nrow,1\n"


def test_zero_byte_generated_file_is_output_missing(tmp_path):
    script = tmp_path / "empty_output.py"
    script.write_text(
        "from pathlib import Path\n"
        "import sys\n"
        "out = Path(sys.argv[1])\n"
        "out.mkdir(parents=True, exist_ok=True)\n"
        "(out / 'empty.csv').touch()\n",
        encoding="utf-8",
    )
    template = f"{sys.executable} {{evidence_path}} {{output_dir}}"
    metadata = _metadata("empty", template)

    result = execute(
        Plan(selected_tools=[_selection("empty", template, [str(script)])]),
        {"empty": metadata},
        output_dir=tmp_path / "runs",
    ).results[0]

    assert result.status == "output_missing"
    assert [item.size_bytes for item in result.artifacts if item.role == "generated"] == [0]


def test_empty_chainsaw_jsonl_is_excluded_from_results(tmp_path, monkeypatch):
    script = tmp_path / "empty_chainsaw.py"
    script.write_text(
        "from pathlib import Path\n"
        "import sys\n"
        "out = Path(sys.argv[1])\n"
        "out.mkdir(parents=True, exist_ok=True)\n"
        "(out / 'chainsaw.jsonl').touch()\n"
        "print('Chainsaw completed with 0 hits')\n",
        encoding="utf-8",
    )
    template = f"{sys.executable} {{evidence_path}} {{output_dir}}"
    metadata = _metadata("chainsaw", template, output_format="jsonl")
    monkeypatch.setattr(
        "forensicagent.executor.executor.get_adapter",
        lambda meta: GenericAdapter(meta),
    )
    raw_dir = tmp_path / "runs"

    result = execute(
        Plan(selected_tools=[_selection("chainsaw", template, [str(script)])]),
        {"chainsaw": metadata},
        output_dir=raw_dir,
    ).results[0]

    assert result.status == "success"
    assert result.parsed_output == {"items": []}
    assert result.stdout_path == ""
    assert result.stderr_path == ""
    assert result.artifacts == []
    assert not [path for path in raw_dir.iterdir() if path.is_dir()]
    assert not any(
        item.get("path", "").casefold().endswith("chainsaw.jsonl")
        for item in result.to_dict()["artifacts"]
    )
    analysis = analyze_one(result, metadata, use_llm=False, use_rag=False)
    assert analysis.status == "analyzed"
    assert analysis.findings == []

    reused = execute(
        Plan(selected_tools=[_selection("chainsaw", template, [str(script)])]),
        {"chainsaw": metadata},
        output_dir=raw_dir,
    ).results[0]
    assert reused.provenance["resume"]["reused"] is False
    assert reused.provenance["chainsaw_no_matches"] is True
    assert reused.parsed_output == {"items": []}
    assert not [path for path in raw_dir.iterdir() if path.is_dir()]


def test_nonempty_chainsaw_jsonl_remains_a_generated_result(tmp_path, monkeypatch):
    script = tmp_path / "chainsaw_hit.py"
    script.write_text(
        "from pathlib import Path\n"
        "import sys\n"
        "out = Path(sys.argv[1])\n"
        "out.mkdir(parents=True, exist_ok=True)\n"
        "(out / 'chainsaw.jsonl').write_text('{\"EventID\": 4624}\\n', encoding='utf-8')\n",
        encoding="utf-8",
    )
    template = f"{sys.executable} {{evidence_path}} {{output_dir}}"
    metadata = _metadata("chainsaw", template, output_format="jsonl")
    monkeypatch.setattr(
        "forensicagent.executor.executor.get_adapter",
        lambda meta: GenericAdapter(meta),
    )

    result = execute(
        Plan(selected_tools=[_selection("chainsaw", template, [str(script)])]),
        {"chainsaw": metadata},
        output_dir=tmp_path / "runs",
    ).results[0]

    generated = [item for item in result.artifacts if item.role == "generated"]
    assert result.status == "success"
    assert [Path(item.path).name for item in generated] == ["chainsaw.jsonl"]
    assert generated[0].size_bytes > 0
    assert "chainsaw_no_matches" not in result.provenance


def test_other_empty_chainsaw_filename_keeps_missing_output_policy(
    tmp_path, monkeypatch
):
    script = tmp_path / "other_empty.py"
    script.write_text(
        "from pathlib import Path\n"
        "import sys\n"
        "out = Path(sys.argv[1])\n"
        "out.mkdir(parents=True, exist_ok=True)\n"
        "(out / 'other.jsonl').touch()\n",
        encoding="utf-8",
    )
    template = f"{sys.executable} {{evidence_path}} {{output_dir}}"
    metadata = _metadata("chainsaw", template, output_format="jsonl")
    monkeypatch.setattr(
        "forensicagent.executor.executor.get_adapter",
        lambda meta: GenericAdapter(meta),
    )

    result = execute(
        Plan(selected_tools=[_selection("chainsaw", template, [str(script)])]),
        {"chainsaw": metadata},
        output_dir=tmp_path / "runs",
    ).results[0]

    assert result.status == "output_missing"
    assert [
        Path(item.path).name
        for item in result.artifacts
        if item.role == "generated"
    ] == ["other.jsonl"]
    assert "chainsaw_no_matches" not in result.provenance


def test_generic_adapter_honors_preferred_template():
    preferred = "preferred {evidence_path}"
    metadata = ToolMetadata(
        tool_id="chooser",
        display_name="chooser",
        category="test",
        applicable_evidence_types=["text_log"],  # type: ignore[list-item]
        command_templates=[
            CommandTemplate(
                name="default", template="default {evidence_path}", when="default"
            ),
            CommandTemplate(name="preferred", template=preferred, when="preferred"),
        ],
        usage_description="template chooser",
    )
    adapter = GenericAdapter(metadata)

    argv = adapter.build_command("evidence.txt", preferred_template=preferred)

    assert argv == ["preferred", "evidence.txt"]
    assert adapter.selected_template == preferred


def test_prerequisite_validation_runs_once_per_tool(tmp_path, monkeypatch):
    calls = 0
    original = GenericAdapter.validate_prerequisites

    def counted(self):
        nonlocal calls
        calls += 1
        return original(self)

    monkeypatch.setattr(GenericAdapter, "validate_prerequisites", counted)
    first = _script(tmp_path / "one.py")
    second = _script(tmp_path / "two.py")
    template = f"{sys.executable} {{evidence_path}} {{output_dir}}"
    metadata = _metadata("preflight", template)
    plan = Plan(
        selected_tools=[_selection("preflight", template, [str(first), str(second)])]
    )

    execute(plan, {"preflight": metadata}, output_dir=tmp_path / "runs")

    assert calls == 1


def test_prerequisite_output_is_decoded_as_utf8_on_windows(monkeypatch):
    metadata = _metadata("utf8-preflight", f"{sys.executable} {{evidence_path}}")
    metadata.install_check = InstallCheck(
        command="tool --version", expected_pattern="tool"
    )
    seen = {}

    def fake_run(_argv, **kwargs):
        seen.update(kwargs)
        return SimpleNamespace(stdout="tool \u2713", stderr="", returncode=0)

    monkeypatch.setattr(
        "forensicagent.executor.adapter.resolve_executable", lambda _name: Path("tool")
    )
    monkeypatch.setattr("forensicagent.executor.adapter.subprocess.run", fake_run)

    ok, detail = GenericAdapter(metadata).validate_prerequisites()

    assert ok, detail
    assert seen["encoding"] == "utf-8"
    assert seen["errors"] == "replace"


def test_prerequisite_check_uses_trusted_project_cwd(tmp_path, monkeypatch):
    trusted = tmp_path / "trusted-project"
    hostile = tmp_path / "attacker-evidence"
    trusted.mkdir()
    hostile.mkdir()
    (hostile / "rogue-config").write_text("attacker-controlled", encoding="utf-8")
    probe = trusted / "show_cwd.py"
    probe.write_text("from pathlib import Path\nprint(Path.cwd())\n", encoding="utf-8")
    metadata = _metadata("cwd-preflight", f"{sys.executable} {{evidence_path}}")
    metadata.install_check = InstallCheck(
        command=f"{sys.executable} {probe}",
        expected_pattern=str(trusted.resolve()),
    )
    monkeypatch.setattr(settings, "PROJECT_ROOT", trusted)
    monkeypatch.chdir(hostile)

    ok, detail = GenericAdapter(metadata).validate_prerequisites()

    assert ok, detail


def test_jobs_and_single_worker_execution_are_priority_ordered(tmp_path, monkeypatch):
    template = f"{sys.executable} {{evidence_path}}"
    high_evidence = tmp_path / "high.txt"
    low_evidence = tmp_path / "low.txt"
    high_evidence.write_text("high", encoding="utf-8")
    low_evidence.write_text("low", encoding="utf-8")
    low_meta = _metadata("low", template, output_format="text")
    high_meta = _metadata("high", template, output_format="text")
    plan = Plan(
        selected_tools=[
            _selection("low", template, [str(low_evidence)], priority=1),
            _selection("high", template, [str(high_evidence)], priority=10),
        ]
    )
    tools = {"low": low_meta, "high": high_meta}
    assert [job.metadata.tool_id for job in _build_jobs(plan, tools)] == ["high", "low"]

    starts: list[str] = []
    starts_lock = threading.Lock()

    def fake_execute(prepared, output_dir, timeout_sec, budget, cancel_event):
        job = prepared.job
        with starts_lock:
            starts.append(job.metadata.tool_id)
        return ExecutionResult(tool_id=job.metadata.tool_id, status="success")

    monkeypatch.setattr(
        "forensicagent.executor.executor._execute_one", fake_execute
    )
    monkeypatch.setattr(
        "forensicagent.executor.executor._preflight_tools",
        lambda jobs: {job.metadata.tool_id: (True, "ok") for job in jobs},
    )

    execute(plan, tools, output_dir=tmp_path / "runs", max_parallel=1)

    assert starts == ["high", "low"]


def test_each_artifact_is_owned_by_only_one_tool(tmp_path):
    shared = str(tmp_path / "shared.evtx")
    unique = str(tmp_path / "unique.evtx")
    template = f"{sys.executable} {{evidence_path}}"
    low = _metadata("low", template, output_format="text")
    high = _metadata("high", template, output_format="text")
    plan = Plan(
        selected_tools=[
            _selection("low", template, [shared, unique], priority=1),
            _selection("high", template, [shared], priority=10),
        ]
    )

    jobs = _build_jobs(plan, {"low": low, "high": high})

    assert [(job.metadata.tool_id, job.evidence) for job in jobs] == [
        ("high", shared),
        ("low", unique),
    ]


def test_unavailable_owner_does_not_fall_back_to_lower_priority_tool(tmp_path):
    evidence_path = tmp_path / "shared.evtx"
    evidence_path.write_text("evidence", encoding="utf-8")
    evidence = str(evidence_path)
    template = f"{sys.executable} {{evidence_path}}"
    high = _metadata("high", template, output_format="text")
    high.install_check = InstallCheck(
        command="forensicagent-definitely-missing --version",
        expected_pattern="never",
    )
    low = _metadata("low", template, output_format="text")
    plan = Plan(
        selected_tools=[
            _selection("low", template, [evidence], priority=1),
            _selection("high", template, [evidence], priority=10),
        ]
    )

    bundle = execute(plan, {"low": low, "high": high}, output_dir=tmp_path / "runs")

    assert [(item.tool_id, item.status) for item in bundle.results] == [
        ("high", "skipped")
    ]


def test_unknown_high_priority_owner_does_not_fall_back(tmp_path, monkeypatch):
    evidence = tmp_path / "shared.log"
    evidence.write_text("evidence", encoding="utf-8")
    template = f"{sys.executable} {{evidence_path}}"
    low = _metadata("low", template, output_format="text")
    plan = Plan(
        selected_tools=[
            _selection("low", template, [str(evidence)], priority=1),
            _selection("unknown", template, [str(evidence)], priority=10),
        ]
    )
    monkeypatch.setattr(
        "forensicagent.executor.executor.run_tool",
        lambda *_args, **_kwargs: pytest.fail("lower-priority fallback executed"),
    )

    bundle = execute(plan, {"low": low}, output_dir=tmp_path / "runs")

    assert bundle.results == []


def test_changed_scan_identity_is_refused_before_tool_run(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence.log"
    evidence.write_text("AAAA", encoding="utf-8")
    inventory = scan(evidence)
    template = f"{sys.executable} {{evidence_path}}"
    metadata = _metadata("integrity", template, output_format="text")
    plan = Plan(
        selected_tools=[
            _selection("integrity", template, [str(evidence)], priority=10)
        ]
    )
    evidence.write_text("BBBB", encoding="utf-8")
    monkeypatch.setattr(
        GenericAdapter,
        "validate_prerequisites",
        lambda *_args, **_kwargs: pytest.fail(
            "tool preflight ran before evidence verification"
        ),
    )
    monkeypatch.setattr(
        "forensicagent.executor.executor.run_tool",
        lambda *_args, **_kwargs: pytest.fail("tool executed on changed evidence"),
    )

    result = execute(
        plan,
        {"integrity": metadata},
        output_dir=tmp_path / "runs",
        inventory=inventory,
    ).results[0]

    assert result.status == "failed"
    assert "no longer matches scan inventory" in result.error_message


def test_touch_only_change_after_scan_is_refused(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence.log"
    evidence.write_text("same", encoding="utf-8")
    inventory = scan(evidence)
    scanned_mtime = inventory.evidence_list[0].mtime_ns
    value = evidence.stat()
    os.utime(evidence, ns=(value.st_atime_ns, scanned_mtime + 1_000_000_000))
    template = f"{sys.executable} {{evidence_path}}"
    metadata = _metadata("integrity", template, output_format="text")
    plan = Plan(
        selected_tools=[
            _selection("integrity", template, [str(evidence)], priority=10)
        ]
    )
    monkeypatch.setattr(
        "forensicagent.executor.executor.run_tool",
        lambda *_args, **_kwargs: pytest.fail("tool executed after evidence touch"),
    )

    result = execute(
        plan,
        {"integrity": metadata},
        output_dir=tmp_path / "runs",
        inventory=inventory,
    ).results[0]

    assert evidence.stat().st_mtime_ns != scanned_mtime
    assert result.status == "failed"
    assert "mtime changed" in result.error_message


def test_direct_caller_touch_only_change_creates_new_attempt(tmp_path):
    evidence = _script(tmp_path / "tool.py")
    template = f"{sys.executable} {{evidence_path}} {{output_dir}}"
    metadata = _metadata("touch", template)
    plan = Plan(
        selected_tools=[_selection("touch", template, [str(evidence)], priority=10)]
    )
    raw = tmp_path / "runs"

    first = execute(plan, {"touch": metadata}, output_dir=raw).results[0]
    value = evidence.stat()
    os.utime(
        evidence,
        ns=(value.st_atime_ns, value.st_mtime_ns + 1_000_000_000),
    )
    second = execute(plan, {"touch": metadata}, output_dir=raw).results[0]

    assert first.provenance["input"]["mtime_ns"] != second.provenance["input"][
        "mtime_ns"
    ]
    assert second.provenance["resume"]["reused"] is False
    assert Path(first.stdout_path).parent != Path(second.stdout_path).parent


def test_multiple_runs_share_start_and_final_input_hash(tmp_path, monkeypatch):
    import forensicagent.executor.executor as executor_module

    evidence = _script(tmp_path / "multi-hash.py")
    template = f"{sys.executable} {{evidence_path}} {{output_dir}}"
    metadata = _metadata("multi-hash", template)
    selection = _selection("multi-hash", template, [str(evidence)], priority=10)
    selection.run_specs = [
        RunSpec(str(evidence), template, label="first"),
        RunSpec(str(evidence), template, label="second"),
    ]
    original_hash = executor_module.hash_file
    evidence_hashes = 0

    def counted_hash(path):
        nonlocal evidence_hashes
        if Path(path).resolve() == evidence.resolve():
            evidence_hashes += 1
        return original_hash(path)

    monkeypatch.setattr(executor_module, "hash_file", counted_hash)

    results = execute(
        Plan(selected_tools=[selection]),
        {"multi-hash": metadata},
        output_dir=tmp_path / "runs",
        max_parallel=1,
    ).results

    assert [result.status for result in results] == ["success", "success"]
    assert evidence_hashes == 2


def test_final_input_mismatch_invalidates_siblings_and_blocks_analysis(tmp_path):
    evidence = tmp_path / "evidence.log"
    evidence.write_text("AAAA", encoding="utf-8")
    inventory = scan(evidence)
    mutator = tmp_path / "mutator.py"
    mutator.write_text(
        "from pathlib import Path\n"
        "import sys\n"
        "Path(sys.argv[1]).write_text('BBBB', encoding='utf-8')\n"
        "print('partial output retained')\n",
        encoding="utf-8",
    )
    template = f"{sys.executable} {mutator} {{evidence_path}}"
    metadata = _metadata("mutator", template, output_format="text")
    selection = _selection("mutator", template, [str(evidence)], priority=10)
    selection.run_specs = [
        RunSpec(str(evidence), template, label="first"),
        RunSpec(str(evidence), template, label="second"),
    ]
    raw = tmp_path / "runs"

    results = execute(
        Plan(selected_tools=[selection]),
        {"mutator": metadata},
        output_dir=raw,
        inventory=inventory,
        max_parallel=1,
    ).results

    assert [result.status for result in results] == ["failed", "failed"]
    assert all(
        result.provenance["input_integrity"]["status"] == "failed"
        for result in results
    )
    retained = results[0].artifacts
    assert retained and all(Path(artifact.path).is_file() for artifact in retained)
    state, _ = load_state(raw)
    for result in results:
        job_key = result.provenance["resume"]["job_key"]
        assert state["jobs"][job_key]["result"]["status"] == "failed"
        assert reusable_result(state, job_key, raw)[0] is None

    analysis = analyze_one(results[0], metadata, use_llm=False, use_rag=False)

    assert analysis.status == "not_analyzed"
    assert analysis.findings == []
    assert any("input integrity failure" in item for item in analysis.coverage_warnings)


def test_pending_input_verification_is_never_reused(tmp_path):
    job_key = "a" * 64
    result = ExecutionResult(
        tool_id="pending",
        status="success",
        provenance={
            "resume": {"job_key": job_key, "reused": False},
            "input_integrity": {"status": "pending_final_verification"},
        },
    )
    state = new_state()
    record_result(state, result)

    reused, warning = reusable_result(state, job_key, tmp_path)

    assert reused is None
    assert "lacks verified input integrity" in warning


def test_fingerprint_rejects_path_replacement_after_hash(tmp_path, monkeypatch):
    import forensicagent.executor.executor as executor_module

    evidence = tmp_path / "evidence.log"
    replacement = tmp_path / "replacement.log"
    evidence.write_text("AAAA", encoding="utf-8")
    original_stat = evidence.stat()
    original_hash = executor_module.hash_file

    def replacing_hash(path):
        result = original_hash(path)
        replacement.write_text("BBBB", encoding="utf-8")
        os.utime(
            replacement,
            ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
        )
        os.replace(replacement, evidence)
        return result

    monkeypatch.setattr(executor_module, "hash_file", replacing_hash)

    with pytest.raises(OSError, match="changed while it was fingerprinted"):
        executor_module._input_fingerprint(evidence)


def test_nonparallel_tool_is_serialized_without_blocking_other_tools(
    tmp_path, monkeypatch
):
    template = f"{sys.executable} {{evidence_path}}"
    evidence = [tmp_path / name for name in ("one", "two", "three")]
    for path in evidence:
        path.write_text(path.name, encoding="utf-8")
    serial_meta = _metadata(
        "serial", template, parallelizable=False, output_format="text"
    )
    other_meta = _metadata(
        "other", template, parallelizable=False, output_format="text"
    )
    plan = Plan(
        selected_tools=[
            _selection(
                "serial", template, [str(evidence[0]), str(evidence[1])], priority=10
            ),
            _selection("other", template, [str(evidence[2])], priority=1),
        ]
    )
    tools = {"serial": serial_meta, "other": other_meta}
    guard = threading.Lock()
    active: dict[str, int] = {"serial": 0, "other": 0}
    max_serial = 0
    max_total = 0

    def fake_execute(prepared, output_dir, timeout_sec, budget, cancel_event):
        nonlocal max_serial, max_total
        job = prepared.job
        with guard:
            active[job.metadata.tool_id] += 1
            max_serial = max(max_serial, active["serial"])
            max_total = max(max_total, sum(active.values()))
        time.sleep(0.08)
        with guard:
            active[job.metadata.tool_id] -= 1
        return ExecutionResult(tool_id=job.metadata.tool_id, status="success")

    monkeypatch.setattr(
        "forensicagent.executor.executor._execute_one", fake_execute
    )
    monkeypatch.setattr(
        "forensicagent.executor.executor._preflight_tools",
        lambda jobs: {job.metadata.tool_id: (True, "ok") for job in jobs},
    )

    execute(plan, tools, output_dir=tmp_path / "runs", max_parallel=2)

    assert max_serial == 1
    assert max_total == 2


def test_max_parallel_must_be_positive(tmp_path):
    with pytest.raises(ValueError, match="max_parallel must be >= 1"):
        execute(Plan(), {}, output_dir=tmp_path, max_parallel=0)


def test_runner_timeout_returns_manifested_streams(tmp_path):
    sleeper = tmp_path / "sleeper.py"
    sleeper.write_text(
        "import time\nprint('started', flush=True)\ntime.sleep(30)\n",
        encoding="utf-8",
    )
    template = f"{sys.executable} {{evidence_path}}"
    metadata = _metadata("sleeper", template, output_format="text")

    result = run_tool(
        metadata,
        [sys.executable, str(sleeper)],
        str(sleeper),
        tmp_path / "job",
        timeout_sec=1,
    )

    assert result.status == "timeout"
    assert result.exit_code == -1
    assert {artifact.role for artifact in result.artifacts} == {"stdout", "stderr"}
    assert Path(result.stdout_path).read_text(encoding="utf-8").strip() in {
        "",
        "started",
    }
