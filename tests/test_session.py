from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

from forensicagent import config as settings
from forensicagent.cli.repl import do_set, do_status
from forensicagent.cli.session import SessionOptions, SessionState, make_session


_MIB = 1024**2


def _state(tmp_path: Path) -> SessionState:
    return make_session(path=tmp_path, output_dir=None, tool_metas={})


def test_stage_invalidation_is_downstream_only(tmp_path):
    state = _state(tmp_path)
    state.inventory = object()  # type: ignore[assignment]
    state.plan = object()  # type: ignore[assignment]
    state.bundle = object()  # type: ignore[assignment]
    state.analyses = []
    state.last_report = object()  # type: ignore[assignment]
    state.last_report_paths = {"json": tmp_path / "old.json"}

    state.invalidate_after_plan()

    assert state.inventory is not None
    assert state.plan is not None
    assert state.bundle is None
    assert state.analyses is None
    assert state.last_report is None
    assert state.last_report_paths == {}


def test_target_change_resets_state_and_moves_default_output(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    state = make_session(path=first, output_dir=None, tool_metas={})
    old_output = state.output_dir
    state.inventory = object()  # type: ignore[assignment]

    state.set_target(second)

    assert state.target_path == second.resolve()
    assert state.output_dir != old_output
    assert state.inventory is None


def test_explicit_output_stays_pinned_when_target_changes(tmp_path):
    explicit = tmp_path / "reports"
    state = make_session(path=tmp_path, output_dir=explicit, tool_metas={})
    other = tmp_path / "other"
    other.mkdir()

    state.set_target(other)

    assert state.output_dir == explicit.resolve()


def test_resource_options_default_to_config():
    options = SessionOptions()

    assert options.max_job_output_bytes == settings.MAX_JOB_OUTPUT_BYTES
    assert options.max_total_output_bytes == settings.MAX_TOTAL_OUTPUT_BYTES
    assert options.min_free_disk_bytes == settings.MIN_FREE_DISK_BYTES


def test_resource_limits_set_in_mib_and_enforce_total_invariant(tmp_path):
    state = _state(tmp_path)
    sink = Console(file=StringIO(), force_terminal=False)
    total_mib = (state.options.max_job_output_bytes + _MIB - 1) // _MIB + 1

    do_set(state, sink, "max_total_output_mib", str(total_mib))
    do_set(state, sink, "max_job_output_mib", str(total_mib))
    do_set(state, sink, "min_free_disk_mib", "7")

    assert state.options.max_job_output_bytes == total_mib * _MIB
    assert state.options.max_total_output_bytes == total_mib * _MIB
    assert state.options.min_free_disk_bytes == 7 * _MIB
    with pytest.raises(ValueError, match="positive integer"):
        do_set(state, sink, "min_free_disk_mib", "0")
    with pytest.raises(ValueError, match="must be >="):
        do_set(state, sink, "max_total_output_mib", str(total_mib - 1))


def test_status_displays_resource_limits(tmp_path):
    state = _state(tmp_path)
    output = StringIO()

    do_status(state, Console(file=output, force_terminal=False, width=120))

    rendered = output.getvalue()
    assert "max_job_output_mib" in rendered
    assert "max_total_output_mib" in rendered
    assert "min_free_disk_mib" in rendered
