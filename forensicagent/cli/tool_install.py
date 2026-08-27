"""포렌식 도구 설치 도우미 — pip / zip 다운 / manual 안내.

doctor 가 "miss" 라고 잡은 도구를 자동(가능한 경우) 또는 안내(URL+curl
예시) 로 채워 준다.

Registry 한 곳에 모든 메타데이터:
- kind="pip"     : `pip install <package>` 로 해결
- kind="zip"     : URL 에서 zip 받아 ~/.forensicagent/tools_bin/<name>/ 로 풂
- kind="manual"  : 자동 설치 불가, URL 만 안내 (라이선스/설치 마법사/큰 의존성)

설치된 zip 도구의 실행파일은 ~/.forensicagent/tools_bin/<name>/<exe> 에 있고,
doctor 의 PATH 검사가 이 디렉토리들도 자동으로 본다.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from importlib import metadata as importlib_metadata
from pathlib import Path, PurePosixPath
from typing import Literal, Optional
from urllib.parse import urlsplit

from rich.console import Console

from forensicagent import config as settings
from forensicagent.tools.executables import (
    find_executable,
    installed_bin_dirs,
    tools_bin_root,
)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


@dataclass
class ToolSpec:
    name: str                          # shutil.which 가 찾을 실행파일명
    kind: Literal["pip", "venv", "zip", "manual"]
    description: str
    homepage: str
    # pip
    pip_package: Optional[str] = None
    # zip
    zip_url: Optional[str] = None
    zip_executable: Optional[str] = None  # zip 안에서 찾을 .exe 파일명
    zip_sha256: Optional[str] = None
    # manual
    manual_hint: str = ""
    # platform restriction
    only_on: Optional[str] = None      # "win32" | "linux" | "darwin"


# Windows 가 1순위, Linux/macOS 는 차차 보강.
TOOL_SPECS: dict[str, ToolSpec] = {
    # ---- pip 으로 설치 가능 ----
    "vol": ToolSpec(
        name="vol",
        kind="pip",
        description="Volatility3 - memory forensics framework",
        homepage="https://github.com/volatilityfoundation/volatility3",
        pip_package="volatility3==2.28.0",
    ),
    "volatility3": ToolSpec(
        name="volatility3",
        kind="pip",
        description="(alias) installed alongside vol",
        homepage="https://github.com/volatilityfoundation/volatility3",
        pip_package="volatility3==2.28.0",
    ),
    "binwalk": ToolSpec(
        name="binwalk",
        kind="manual",
        description="Firmware/embedded object extraction",
        homepage="https://github.com/ReFirmLabs/binwalk/releases/tag/v3.1.0",
        manual_hint=(
            "Install the official Rust-based Binwalk v3.1.0 release or build it "
            "from source. Do not use the unrelated legacy `pip install binwalk` "
            "package (PyPI 2.1.0 from 2015)."
        ),
    ),
    "bandit": ToolSpec(
        name="bandit",
        kind="pip",
        description="Python SAST - OWASP/CWE 패턴 탐지",
        homepage="https://bandit.readthedocs.io/",
        pip_package="bandit==1.9.4",
    ),
    "semgrep": ToolSpec(
        name="semgrep",
        kind="venv",
        description="Multi-language SAST - auto ruleset",
        homepage="https://semgrep.dev/",
        pip_package="semgrep==1.173.0",
    ),

    # ---- zip 다운로드 가능 (GitHub releases) ----
    # 재현성과 무결성 검증을 위해 버전 URL과 게시된 SHA-256을 함께 고정한다.
    "chainsaw": ToolSpec(
        name="chainsaw",
        kind="zip",
        description="Channel-aware deterministic EVTX Event-ID search",
        homepage="https://github.com/WithSecureLabs/chainsaw",
        zip_url="https://github.com/WithSecureLabs/chainsaw/releases/download/v2.16.3/chainsaw_x86_64-pc-windows-msvc.zip",
        zip_executable="chainsaw.exe",
        zip_sha256="3623ddbd71b32623692db563f3d78f9359c484330a983f9e5e480b624984d338",
        only_on="win32",
    ),
    "gitleaks": ToolSpec(
        # v8.30.1 silently misses default-rule secrets (upstream #2170).
        name="gitleaks",
        kind="zip",
        description="Secret scanner - API keys / credentials in code",
        homepage="https://github.com/gitleaks/gitleaks/releases/tag/v8.30.0",
        zip_url="https://github.com/gitleaks/gitleaks/releases/download/v8.30.0/gitleaks_8.30.0_windows_x64.zip",
        zip_executable="gitleaks.exe",
        zip_sha256="54fe94f644b832dd08e8c3a5915efb3bfa862386d59fb27ca0792cb687a83573",
        only_on="win32",
    ),

    # Eric Zimmerman's Windows forensic utilities are distributed as signed
    # release binaries and via the official Get-ZimmermanTools script rather
    # than PyPI. Keep them manual so the installer never guesses an asset URL.
    "amcacheparser": ToolSpec(
        name="AmcacheParser.exe",
        kind="manual",
        description="Eric Zimmerman Amcache parser",
        homepage="https://github.com/EricZimmerman/AmcacheParser",
        manual_hint="Install with the official Get-ZimmermanTools script or place the complete release under ~/.forensicagent/tools_bin/.",
        only_on="win32",
    ),
    "appcompatcacheparser": ToolSpec(
        name="AppCompatCacheParser.exe",
        kind="manual",
        description="Eric Zimmerman Shimcache/AppCompatCache parser",
        homepage="https://github.com/EricZimmerman/AppCompatCacheParser",
        manual_hint=(
            "Install with the official Get-ZimmermanTools script or place the "
            "complete release under this project's .forensicagent/tools_bin/."
        ),
        only_on="win32",
    ),
    "evtxecmd": ToolSpec(
        name="EvtxECmd.exe",
        kind="manual",
        description="Eric Zimmerman EVTX parser",
        homepage="https://github.com/EricZimmerman/evtx",
        manual_hint="Install with the official Get-ZimmermanTools script or place the complete release under ~/.forensicagent/tools_bin/.",
        only_on="win32",
    ),
    "mftecmd": ToolSpec(
        name="MFTECmd.exe",
        kind="manual",
        description="Eric Zimmerman NTFS metadata parser",
        homepage="https://github.com/EricZimmerman/MFTECmd",
        manual_hint="Install with the official Get-ZimmermanTools script or place the complete release under ~/.forensicagent/tools_bin/.",
        only_on="win32",
    ),
    "pecmd": ToolSpec(
        name="PECmd.exe",
        kind="manual",
        description="Eric Zimmerman Prefetch parser",
        homepage="https://github.com/EricZimmerman/PECmd",
        manual_hint="Install with the official Get-ZimmermanTools script or place the complete release under ~/.forensicagent/tools_bin/.",
        only_on="win32",
    ),
    "recmd": ToolSpec(
        name="RECmd.exe",
        kind="manual",
        description="Eric Zimmerman Registry parser",
        homepage="https://github.com/EricZimmerman/RECmd",
        manual_hint="Install the complete release, including BatchExamples, with the official Get-ZimmermanTools script or under ~/.forensicagent/tools_bin/.",
        only_on="win32",
    ),

    # ---- manual (라이선스/설치 마법사/MSVC 빌드 필요/버전 변동 큰 URL) ----
    "plaso": ToolSpec(
        name="plaso",
        kind="manual",
        description="log2timeline super-timeline",
        homepage="https://plaso.readthedocs.io/en/latest/sources/user/Users-Guide.html",
        manual_hint=(
            "Windows: needs MSVC Build Tools first "
            "(https://visualstudio.microsoft.com/visual-cpp-build-tools/), "
            "then `pip install plaso`. Or use the Docker image."
        ),
    ),
    "log2timeline.py": ToolSpec(
        name="log2timeline.py",
        kind="manual",
        description="part of plaso",
        homepage="https://plaso.readthedocs.io/",
        manual_hint="installed alongside plaso",
    ),
    "psort.py": ToolSpec(
        name="psort.py",
        kind="manual",
        description="part of plaso",
        homepage="https://plaso.readthedocs.io/",
        manual_hint="installed alongside plaso",
    ),
    "yara": ToolSpec(
        name="yara",
        kind="manual",
        description="Pattern matching for malware classification",
        homepage="https://github.com/VirusTotal/yara/releases",
        manual_hint=(
            "Download the latest yara-vX.Y.Z-*-win64.zip from GitHub releases, "
            "extract yara.exe to a directory on PATH (or to "
            "~/.forensicagent/tools_bin/yara/)."
        ),
    ),
    "exiftool": ToolSpec(
        name="exiftool",
        kind="manual",
        description="File metadata reader",
        homepage="https://exiftool.org/",
        manual_hint=(
            "Windows: download exiftool-XX.XX_64.zip from exiftool.org, "
            "rename the .exe to exiftool.exe, move to ~/.forensicagent/tools_bin/exiftool/."
        ),
    ),
    "tshark": ToolSpec(
        name="tshark",
        kind="manual",
        description="Wireshark CLI - pcap analysis",
        homepage="https://www.wireshark.org/download.html",
        manual_hint="Install full Wireshark (.exe installer); tshark.exe goes to C:\\Program Files\\Wireshark\\.",
    ),
    "fls": ToolSpec(
        name="fls",
        kind="manual",
        description="The Sleuth Kit filesystem image lister",
        homepage="https://sleuthkit.org/sleuthkit/download.php",
        manual_hint=(
            "Install The Sleuth Kit Windows binaries, then place the complete "
            "release under the project-local tools_bin directory or expose fls "
            "through an existing absolute PATH entry."
        ),
    ),
    "tcpdump": ToolSpec(
        name="tcpdump",
        kind="manual",
        description="(Linux/macOS only)",
        homepage="https://www.tcpdump.org/",
        manual_hint="Linux: `apt install tcpdump`. macOS: bundled. Not native on Windows (use tshark).",
        only_on="linux",
    ),
    "rip": ToolSpec(
        name="rip",
        kind="manual",
        description="RegRipper",
        homepage="https://github.com/keydet89/RegRipper3.0",
        manual_hint=(
            "git clone https://github.com/keydet89/RegRipper3.0 into "
            "~/.forensicagent/tools_bin/regripper/, then add to PATH."
        ),
    ),
    "strings": ToolSpec(
        name="strings",
        kind="manual",
        description="Binary string extraction",
        homepage="https://learn.microsoft.com/en-us/sysinternals/downloads/strings",
        manual_hint="Windows: Sysinternals Strings or use Git Bash's strings.exe. Linux/macOS: usually bundled.",
    ),
}


# ---------------------------------------------------------------------------
# Installers
# ---------------------------------------------------------------------------


_DOWNLOAD_TIMEOUT_SECONDS = 60
_MAX_ZIP_DOWNLOAD_BYTES = 100 * 1024 * 1024
_MAX_ZIP_MEMBERS = 10_000
_MAX_ZIP_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
_ISOLATED_PIP_VERSION = "26.2.1"


def _download_verified_zip(url: str, expected_sha256: str, destination: Path) -> None:
    expected = expected_sha256.strip().lower()
    if urlsplit(url).scheme.lower() != "https":
        raise ValueError("automatic ZIP installs require HTTPS")
    if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
        raise ValueError("automatic ZIP installs require a valid SHA-256 digest")

    digest = hashlib.sha256()
    downloaded = 0
    with urllib.request.urlopen(url, timeout=_DOWNLOAD_TIMEOUT_SECONDS) as response:
        final_url = str(response.geturl())
        if urlsplit(final_url).scheme.lower() != "https":
            raise ValueError("download redirected away from HTTPS")
        with destination.open("wb") as output:
            while chunk := response.read(1024 * 1024):
                downloaded += len(chunk)
                if downloaded > _MAX_ZIP_DOWNLOAD_BYTES:
                    raise ValueError("ZIP download exceeds the 100 MiB safety limit")
                output.write(chunk)
                digest.update(chunk)

    actual = digest.hexdigest()
    if actual != expected:
        raise ValueError(f"SHA-256 mismatch (expected {expected}, got {actual})")


def _zip_member_parts(info: zipfile.ZipInfo) -> tuple[str, ...]:
    name = info.filename.replace("\\", "/")
    path = PurePosixPath(name)
    if not name or path.is_absolute() or not path.parts:
        raise ValueError(f"unsafe ZIP member path: {info.filename!r}")
    if any(part in {"", ".."} for part in path.parts):
        raise ValueError(f"unsafe ZIP member path: {info.filename!r}")
    if any("\x00" in part or ":" in part or part.endswith((" ", ".")) for part in path.parts):
        raise ValueError(f"unsafe ZIP member path: {info.filename!r}")

    mode = info.external_attr >> 16
    if stat.S_IFMT(mode) not in {0, stat.S_IFREG, stat.S_IFDIR}:
        raise ValueError(f"unsupported ZIP member type: {info.filename!r}")
    return path.parts


def _extract_zip_safely(archive: zipfile.ZipFile, destination: Path) -> None:
    members = archive.infolist()
    if len(members) > _MAX_ZIP_MEMBERS:
        raise ValueError(f"ZIP contains more than {_MAX_ZIP_MEMBERS} members")
    if sum(member.file_size for member in members) > _MAX_ZIP_UNCOMPRESSED_BYTES:
        raise ValueError("ZIP expands beyond the 512 MiB safety limit")

    plans: list[tuple[zipfile.ZipInfo, Path]] = []
    seen: set[tuple[str, ...]] = set()
    root = destination.resolve()
    for member in members:
        parts = _zip_member_parts(member)
        collision_key = tuple(part.casefold() for part in parts)
        if collision_key in seen:
            raise ValueError(f"duplicate ZIP member path: {member.filename!r}")
        seen.add(collision_key)
        target = root.joinpath(*parts).resolve()
        if not target.is_relative_to(root):
            raise ValueError(f"unsafe ZIP member path: {member.filename!r}")
        plans.append((member, target))

    for member, target in plans:
        if member.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(member) as source, target.open("xb") as output:
            shutil.copyfileobj(source, output, length=1024 * 1024)


def _packaged_executable(root: Path, name: str) -> Path | None:
    for candidate in sorted(root.rglob("*"), key=lambda path: str(path).casefold()):
        if candidate.is_file() and candidate.name.casefold() == name.casefold():
            relative = candidate.relative_to(root)
            if len(relative.parts) <= 2:
                return relative
    return None


def _promote_install(staged: Path, target: Path, backup: Path) -> None:
    had_previous = target.exists() or target.is_symlink()
    if had_previous:
        target.replace(backup)
    try:
        staged.replace(target)
    except BaseException:
        if had_previous and backup.exists() and not target.exists():
            backup.replace(target)
        raise


def _platform_ok(spec: ToolSpec) -> bool:
    if spec.only_on is None:
        return True
    return sys.platform == spec.only_on or (
        spec.only_on == "linux" and sys.platform.startswith("linux")
    )


def _spec_installed(spec: ToolSpec) -> bool:
    if spec.kind == "venv":
        importlib_metadata.MetadataPathFinder.invalidate_caches()
        root = tools_bin_root() / spec.name
        return (
            _venv_executable(root, spec.name).is_file()
            and spec.pip_package is not None
            and _venv_requirement_installed(root, spec.pip_package)
            and _venv_requirement_installed(
                root, f"pip=={_ISOLATED_PIP_VERSION}"
            )
        )
    return find_executable(spec.name) is not None


def _exact_pip_requirement(spec: ToolSpec, c: Console) -> str | None:
    package = spec.pip_package
    if not package:
        c.print(f"[red]{spec.name}: pip_package not set in registry[/]")
        return None
    if re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9_,.-]+\])?"
        r"==[A-Za-z0-9][A-Za-z0-9.!+_-]*",
        package,
    ) is None:
        c.print(
            f"[red]{spec.name}: exact pip version required; refusing "
            f"{package!r}[/]"
        )
        return None
    return package


def install_pip(spec: ToolSpec, c: Console) -> bool:
    package = _exact_pip_requirement(spec, c)
    if package is None:
        return False
    c.print(f"[*] pip install {package} ...")
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", package],
            check=True,
            cwd=settings.PROJECT_ROOT,
        )
        return True
    except subprocess.CalledProcessError as e:
        c.print(f"[red]pip install 실패 (exit {e.returncode}). {spec.manual_hint or ''}[/]")
        if spec.homepage:
            c.print(f"[dim]참고: {spec.homepage}[/]")
        return False


def _venv_python(root: Path) -> Path:
    return root / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")


def _venv_executable(root: Path, name: str) -> Path:
    suffix = ".exe" if sys.platform == "win32" else ""
    directory = "Scripts" if sys.platform == "win32" else "bin"
    return root / directory / f"{name}{suffix}"


def _venv_site_packages(root: Path) -> Path:
    if sys.platform == "win32":
        return root / "Lib" / "site-packages"
    version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    return root / "lib" / version / "site-packages"


def _venv_requirement_installed(root: Path, requirement: str) -> bool:
    distribution, separator, expected = requirement.partition("==")
    if not separator:
        return False
    distribution = distribution.split("[", 1)[0]
    normalized = re.sub(r"[-_.]+", "-", distribution).casefold()
    try:
        for installed in importlib_metadata.distributions(
            path=[str(_venv_site_packages(root))]
        ):
            name = installed.metadata.get("Name", "")
            if re.sub(r"[-_.]+", "-", name).casefold() == normalized:
                return installed.version == expected
    except (OSError, ValueError):
        return False
    return False


def install_venv(spec: ToolSpec, c: Console) -> bool:
    """Install a dependency-heavy CLI into its own project-local venv."""
    package = _exact_pip_requirement(spec, c)
    if package is None:
        return False
    try:
        tools_root = tools_bin_root().resolve()
        tools_root.mkdir(parents=True, exist_ok=True)
        target = tools_root / spec.name
        if target.parent != tools_root or target.resolve() != target:
            c.print(f"[red]{spec.name}: unsafe isolated venv target[/]")
            return False
        had_previous = target.exists() or target.is_symlink()
        work_dir = Path(tempfile.mkdtemp(prefix=f".{spec.name}-", dir=tools_root))
    except (OSError, RuntimeError, ValueError) as e:
        c.print(f"[red]{spec.name}: isolated venv setup failed: {e}[/]")
        return False

    backup = work_dir / "previous"
    previous_moved = False
    try:
        if had_previous:
            target.replace(backup)
            previous_moved = True
        subprocess.run(
            [sys.executable, "-m", "venv", str(target)],
            check=True,
            cwd=settings.PROJECT_ROOT,
        )
        subprocess.run(
            [
                str(_venv_python(target)),
                "-m",
                "pip",
                "install",
                f"pip=={_ISOLATED_PIP_VERSION}",
                package,
            ],
            check=True,
            cwd=settings.PROJECT_ROOT,
        )
        executable = _venv_executable(target, spec.name)
        if not executable.is_file():
            raise ValueError(f"install completed without {executable}")
    except BaseException as e:
        rollback_error: OSError | None = None
        try:
            if not had_previous or previous_moved:
                if target.is_dir() and not target.is_symlink():
                    shutil.rmtree(target)
                elif target.exists() or target.is_symlink():
                    target.unlink()
            if previous_moved and backup.exists():
                backup.replace(target)
        except OSError as cleanup_error:
            rollback_error = cleanup_error
        if rollback_error is None:
            shutil.rmtree(work_dir, ignore_errors=True)
        else:
            c.print(
                f"[yellow]rollback incomplete: {rollback_error}; "
                f"backup retained at {backup}[/]"
            )
        c.print(f"[red]{spec.name} isolated install failed: {e}[/]")
        if not isinstance(
            e, (OSError, subprocess.CalledProcessError, ValueError)
        ):
            raise
        return False

    try:
        shutil.rmtree(work_dir)
    except OSError as cleanup_error:
        c.print(f"[yellow]previous venv cleanup failed: {cleanup_error}[/]")
    c.print(f"[green]ok[/] {spec.name} -> {executable}")
    return True


def install_zip(spec: ToolSpec, c: Console) -> bool:
    if not spec.zip_url:
        c.print(f"[red]{spec.name}: zip_url not set[/]")
        return False
    if not spec.zip_sha256:
        c.print(f"[red]{spec.name}: zip_sha256 not set; refusing unverified download[/]")
        return False
    executable_name = spec.zip_executable or spec.name
    tools_root = tools_bin_root()
    target_dir = tools_root / spec.name
    tools_root.mkdir(parents=True, exist_ok=True)

    c.print(f"[*] 다운로드: {spec.zip_url}")
    try:
        with tempfile.TemporaryDirectory(prefix=f".{spec.name}-", dir=tools_root) as tmp:
            work_dir = Path(tmp)
            archive_path = work_dir / "download.zip"
            staged_dir = work_dir / "payload"
            staged_dir.mkdir()
            _download_verified_zip(spec.zip_url, spec.zip_sha256, archive_path)
            c.print(f"[*] 검증 후 풀기: {archive_path} -> {target_dir}")
            with zipfile.ZipFile(archive_path) as archive:
                _extract_zip_safely(archive, staged_dir)
            executable = _packaged_executable(staged_dir, executable_name)
            if executable is None:
                raise ValueError(f"archive does not contain a discoverable {executable_name}")
            _promote_install(staged_dir, target_dir, work_dir / "previous")
    except (urllib.error.URLError, OSError, ValueError, zipfile.BadZipFile) as e:
        c.print(f"[red]다운/풀기 실패:[/] {e}")
        c.print(f"[dim]수동 다운: {spec.zip_url}[/]")
        return False

    installed = target_dir / executable
    if installed.is_file():
        c.print(f"[green]ok[/] {spec.name} -> {installed}")
        return True
    else:
        c.print(
            f"[yellow]풀었지만 {executable_name} 을 못 찾음. "
            f"{target_dir} 안을 직접 확인하세요.[/]"
        )
        return False


def show_manual(spec: ToolSpec, c: Console) -> None:
    c.print(f"[bold yellow]수동 설치 필요:[/] {spec.name}")
    c.print(f"  설명: {spec.description}")
    c.print(f"  안내: {spec.manual_hint or '(없음)'}")
    c.print(f"  URL : {spec.homepage}")
    # curl 예시 - 다운만이라도 도와줌
    if spec.zip_url:
        c.print(f"  [dim]curl -L -o {spec.name}.zip {spec.zip_url}[/]")


def install_one(spec: ToolSpec, c: Console) -> bool:
    """단일 도구 설치 시도. 성공/실패 bool."""
    if not _platform_ok(spec):
        c.print(f"[dim]{spec.name}: {sys.platform} 플랫폼 비대상 (only_on={spec.only_on})[/]")
        return False
    if _spec_installed(spec):
        c.print(f"[green]이미 설치됨:[/] {spec.name}")
        return True
    if spec.kind == "pip":
        return install_pip(spec, c)
    elif spec.kind == "venv":
        return install_venv(spec, c)
    elif spec.kind == "zip":
        return install_zip(spec, c)
    else:  # manual
        show_manual(spec, c)
        return False


# ---------------------------------------------------------------------------
# Interactive flow
# ---------------------------------------------------------------------------


def _ask_yn(c: Console, prompt: str, default: bool = True) -> bool:
    if not sys.stdin.isatty():
        c.print(f"[dim]{prompt} (non-tty, default={'y' if default else 'n'})[/]")
        return default
    suffix = "[Y/n]" if default else "[y/N]"
    try:
        ans = c.input(f"{prompt} {suffix} ").strip().lower()
    except EOFError:
        c.print(f"[dim](EOF, default={'y' if default else 'n'})[/]")
        return default
    if not ans:
        return default
    return ans in ("y", "yes")


def install_interactive(
    c: Console, names: Optional[list[str]] = None
) -> tuple[int, list[str]]:
    """missing 도구를 하나씩 순회하며 y/n 으로 설치.

    names 가 주어지면 그것만, 아니면 registry 전체 중 missing 만.
    반환: (설치 성공 개수, 자동 설치 실패 도구).
    """
    failures: list[str] = []
    if names:
        # 별칭 정리 + registry 검증.
        targets = []
        for n in names:
            if n in TOOL_SPECS:
                targets.append(TOOL_SPECS[n])
            else:
                c.print(f"[red]registry 에 없는 도구:[/] {n}")
                failures.append(n)
        if not targets:
            return 0, failures
    else:
        # vol 과 volatility3 같은 별칭 중복 제거 — pip_package 기준.
        seen_pkg: set[str] = set()
        targets = []
        for spec in TOOL_SPECS.values():
            key = spec.pip_package or spec.zip_url or spec.name
            if key in seen_pkg:
                continue
            seen_pkg.add(key)
            if not _spec_installed(spec) and _platform_ok(spec):
                targets.append(spec)
        if not targets:
            c.print("[green]모두 설치되어 있거나 현재 플랫폼 비대상입니다.[/]")
            return 0, failures

    c.print(f"[bold]설치 후보 {len(targets)} 개[/]")
    for s in targets:
        kind_label = {
            "pip": "pip",
            "venv": "isolated venv",
            "zip": "zip 다운",
            "manual": "수동",
        }[s.kind]
        c.print(f"  - [bold]{s.name}[/] ({kind_label}) - {s.description}")
    c.print("")

    installed = 0
    for spec in targets:
        c.print(f"\n--- {spec.name} ---")
        c.print(f"  {spec.description}")
        c.print(f"  homepage: {spec.homepage}")
        if spec.kind in {"pip", "venv"}:
            prompt = f"pip install {spec.pip_package} 진행할까요?"
        elif spec.kind == "zip":
            prompt = f"{spec.zip_url} 다운로드할까요?"
        else:
            prompt = "수동 설치 안내만 보시겠어요?"
        if _ask_yn(c, prompt, default=True):
            if install_one(spec, c):
                installed += 1
            elif spec.kind != "manual":
                failures.append(spec.name)
        else:
            c.print("[dim]건너뜀.[/]")
    return installed, failures


def install_all_auto(c: Console) -> tuple[int, list[str]]:
    """pip/zip 으로 자동 설치 가능한 모든 미설치 도구를 install. manual 은 안내만."""
    installed = 0
    failures: list[str] = []
    seen_pkg: set[str] = set()
    for spec in TOOL_SPECS.values():
        key = spec.pip_package or spec.zip_url or spec.name
        if key in seen_pkg:
            continue
        seen_pkg.add(key)
        if _spec_installed(spec):
            continue
        if not _platform_ok(spec):
            continue
        c.print(f"\n--- {spec.name} ---")
        if spec.kind == "manual":
            show_manual(spec, c)
            continue
        if install_one(spec, c):
            installed += 1
        else:
            failures.append(spec.name)
    return installed, failures
