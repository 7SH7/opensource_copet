"""Configuration path safety invariants."""

from __future__ import annotations

from forensicagent import config


def test_default_output_directory_is_outside_evidence_tree(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "OUTPUT_DIR", None)
    monkeypatch.setattr(config, "USER_HOME", tmp_path.parent / "state-home")
    evidence = tmp_path / "case"
    evidence.mkdir()

    output = config.default_output_dir(evidence)

    assert output.is_relative_to(config.USER_HOME)
    assert not output.is_relative_to(evidence)


def test_default_output_directory_is_stable_and_case_specific(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "OUTPUT_DIR", None)
    monkeypatch.setattr(config, "USER_HOME", tmp_path / "state-home")
    first = tmp_path / "a" / "case"
    second = tmp_path / "b" / "case"
    first.mkdir(parents=True)
    second.mkdir(parents=True)

    assert config.default_output_dir(first) == config.default_output_dir(first)
    assert config.default_output_dir(first) != config.default_output_dir(second)
