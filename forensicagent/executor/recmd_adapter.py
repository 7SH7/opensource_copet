"""RECmd adapter with executable-relative batch resource discovery."""

from __future__ import annotations

from pathlib import Path

from forensicagent.executor.adapter import GenericAdapter
from forensicagent.tools.executables import resolve_executable


_DEFAULT_BATCH = "RECmd_Batch_MC.reb"


def find_default_batch(executable: Path) -> Path | None:
    """Find the official batch file near an installed RECmd executable.

    ZimmermanTools archives are commonly extracted with ``BatchExamples``
    either beside RECmd.exe or one/two archive levels above it. Searching only
    these bounded locations avoids depending on the caller's current directory.
    """
    roots = [executable.parent, *list(executable.parents)[:3]]
    seen: set[Path] = set()
    for root in roots:
        if root in seen:
            continue
        seen.add(root)
        candidate = root / "BatchExamples" / _DEFAULT_BATCH
        if candidate.is_file():
            return candidate.resolve()
    return None


class RECmdAdapter(GenericAdapter):
    """Build the default single-hive batch invocation without CWD assumptions."""

    def build_command(
        self,
        evidence_path: str,
        *,
        preferred_template: str | None = None,
        **vars: str,
    ) -> list[str]:
        default_template = self._meta.command_templates[0].template
        chosen = preferred_template or default_template
        if chosen != default_template:
            return super().build_command(
                evidence_path,
                preferred_template=preferred_template,
                **vars,
            )

        output_dir = vars.get("output_dir")
        if not output_dir:
            raise KeyError("RECmd default command requires output_dir")
        executable = resolve_executable("RECmd.exe")
        if executable is None:
            raise FileNotFoundError("RECmd.exe not found on PATH or tools_bin")
        batch = find_default_batch(executable)
        if batch is None:
            raise FileNotFoundError(
                f"{_DEFAULT_BATCH} not found in BatchExamples near {executable}; "
                "install the complete RECmd archive"
            )

        self.selected_template = default_template
        return [
            str(executable),
            "-f",
            evidence_path,
            "--bn",
            str(batch),
            "--csv",
            output_dir,
        ]


__all__ = ["RECmdAdapter", "find_default_batch"]
