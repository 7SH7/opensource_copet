"""Deterministic per-target command expansion for multi-pass tools.

Most tools need one command per evidence file.  Memory and registry analysis
are different: useful coverage requires selecting a plugin as well as a tool.
Memory keeps the complete declared detector set, while the safe registry plugin
depends on the hive basename.  This module keeps that decision in the selector
layer instead of hard-coding tool behavior inside the subprocess executor.
"""

from __future__ import annotations

from pathlib import Path, PureWindowsPath

from forensicagent.selector.types import RunSpec, ToolSelection
from forensicagent.tools.schema import ToolMetadata


_VOLATILITY_MARKERS = {
    "pslist": "windows.pslist.",
    "cmdline": "windows.cmdline.",
    "netscan": "windows.netscan.",
    "malfind": "windows.malfind.",
    "pstree": "windows.pstree.",
}

_REGRIPPER_MARKERS = {
    "system": ("services", "-p services"),
    "software": ("run", "-p run"),
}


def populate_run_specs(
    selections: list[ToolSelection],
    tools: dict[str, ToolMetadata],
    scenario: str | None,
) -> None:
    """Attach concrete run specs in place, preserving explicit caller specs."""
    for selection in selections:
        if selection.run_specs:
            continue
        metadata = tools.get(selection.tool_id)
        if metadata is None:
            selection.run_specs = _legacy_specs(selection)
        elif selection.tool_id == "volatility3":
            selection.run_specs = _volatility_specs(selection, metadata, scenario)
        elif selection.tool_id == "regripper":
            selection.run_specs = _regripper_specs(selection, metadata)
        else:
            selection.run_specs = _legacy_specs(selection)


def _legacy_specs(selection: ToolSelection) -> list[RunSpec]:
    return [
        RunSpec(
            target_evidence=target,
            command_template=selection.command_template,
        )
        for target in dict.fromkeys(selection.target_evidence)
    ]


def _volatility_specs(
    selection: ToolSelection,
    metadata: ToolMetadata,
    scenario: str | None,
) -> list[RunSpec]:
    # Scenario text may prioritize a case, but must never disable a detector
    # advertised by the built-in metadata.
    del scenario
    plugins = list(_VOLATILITY_MARKERS)
    templates: list[tuple[str, str]] = []
    for plugin in dict.fromkeys(plugins):
        template = _template_containing(metadata, _VOLATILITY_MARKERS[plugin])
        if template is None and plugin == "pslist":
            template = selection.command_template
        if template:
            templates.append((plugin, template))

    return [
        RunSpec(
            target_evidence=target,
            command_template=template,
            label=plugin,
        )
        for target in dict.fromkeys(selection.target_evidence)
        for plugin, template in templates
    ]
def _regripper_specs(
    selection: ToolSelection,
    metadata: ToolMetadata,
) -> list[RunSpec]:
    specs: list[RunSpec] = []
    profile_template = _template_containing(metadata, "{profile}")
    for target in dict.fromkeys(selection.target_evidence):
        hive = _basename(target).casefold()
        if hive == "ntuser.dat":
            for label, marker in (
                ("userassist", "-p userassist"),
                ("run", "-p run"),
            ):
                template = _template_containing(metadata, marker)
                if template:
                    specs.append(
                        RunSpec(
                            target_evidence=target,
                            command_template=template,
                            label=label,
                        )
                    )
            continue
        mapped = _REGRIPPER_MARKERS.get(hive)
        if mapped is not None:
            label, marker = mapped
            template = _template_containing(metadata, marker)
            specs.append(
                RunSpec(
                    target_evidence=target,
                    command_template=template or selection.command_template,
                    label=label,
                )
            )
            continue

        # SECURITY and SAM are supported by RegRipper profiles but do not map
        # to the three focused plugins above.  Use the metadata-declared full
        # profile template when present instead of applying userassist blindly.
        if hive in {"security", "sam"} and profile_template:
            specs.append(
                RunSpec(
                    target_evidence=target,
                    command_template=profile_template,
                    variables={"profile": hive},
                    label=f"{hive}-profile",
                )
            )
            continue

        specs.append(
            RunSpec(
                target_evidence=target,
                command_template=selection.command_template,
            )
        )
    return specs


def _template_containing(metadata: ToolMetadata, marker: str) -> str | None:
    folded = marker.casefold()
    for command in metadata.command_templates:
        if folded in command.template.casefold():
            return command.template
    return None


def _basename(path: str) -> str:
    name = Path(path).name
    if "\\" in name:
        return PureWindowsPath(path).name
    return name


__all__ = ["populate_run_specs"]
