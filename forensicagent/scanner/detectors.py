"""Evidence-type detectors.

명세 2.1 의 우선순위 그대로:
  1. magic bytes (가장 신뢰)
  2. 확장자
  3. 파일명 패턴 (NTUSER.DAT 같이 확장자 없는 레지스트리 하이브 등)
  4. 부모 디렉토리 (Windows/System32/winevt/Logs 등)

각 detector 는 (evidence_type, platform_hint, confidence) 또는 None 을 반환.
None 이면 다음 우선순위 detector 가 시도된다.
"""

from __future__ import annotations

import re
from pathlib import Path

from forensicagent.scanner.types import DetectionMethod, EvidenceType, Platform

# (header_bytes, evidence_type, platform_hint, confidence)
_MAGIC_SIGNATURES: list[tuple[bytes, EvidenceType, Platform, float]] = [
    # Windows EVTX: "ElfFile\x00"
    (b"ElfFile\x00", "evtx_log", "windows", 0.99),
    # pcap (libpcap classic, both endians) + pcapng
    (b"\xa1\xb2\xc3\xd4", "pcap", "unknown", 0.98),
    (b"\xd4\xc3\xb2\xa1", "pcap", "unknown", 0.98),
    (b"\x4d\x3c\xb2\xa1", "pcap", "unknown", 0.98),  # nanosecond pcap
    (b"\xa1\xb2\x3c\x4d", "pcap", "unknown", 0.98),  # nanosecond pcap, other endian
    (b"\x0a\x0d\x0d\x0a", "pcap", "unknown", 0.95),  # pcapng SHB
    # Registry hive (regf): "regf"
    (b"regf", "registry_hive", "windows", 0.98),
    # Prefetch (Windows 10+): "MAM\x04" compressed or "SCCA" plain
    (b"MAM\x04", "prefetch", "windows", 0.95),
    (b"SCCA", "prefetch", "windows", 0.95),
    # EWF / E01 disk image: "EVF\x09\x0d\x0a\xff\x00"
    (b"EVF\x09\x0d\x0a\xff\x00", "disk_image", "unknown", 0.99),
    # Raw VMDK descriptor magic (KDMV) is binary; just pcap-style hint.
    (b"KDMV", "disk_image", "unknown", 0.90),
    # SQLite is a storage format, not necessarily a browser artifact.  Browser
    # context is applied in detect_by_magic() using filename/parent hints.
    (b"SQLite format 3\x00", "sqlite_database", "unknown", 0.90),
]

_EXTENSION_MAP: dict[str, tuple[EvidenceType, Platform, float]] = {
    ".evtx": ("evtx_log", "windows", 0.85),
    ".pcap": ("pcap", "unknown", 0.85),
    ".pcapng": ("pcap", "unknown", 0.85),
    ".cap": ("pcap", "unknown", 0.70),
    ".mem": ("memory_dump", "unknown", 0.75),
    ".dmp": ("memory_dump", "windows", 0.70),
    ".vmem": ("memory_dump", "unknown", 0.80),
    ".lime": ("memory_dump", "linux", 0.90),
    ".dd": ("disk_image", "unknown", 0.75),
    ".e01": ("disk_image", "unknown", 0.90),
    ".aff": ("disk_image", "unknown", 0.85),
    ".vhd": ("disk_image", "unknown", 0.80),
    ".vhdx": ("disk_image", "unknown", 0.80),
    ".vmdk": ("disk_image", "unknown", 0.75),
    ".mft": ("ntfs_metadata", "windows", 0.90),
    ".pf": ("prefetch", "windows", 0.90),
    ".sqlite": ("sqlite_database", "unknown", 0.70),
    ".sqlite3": ("sqlite_database", "unknown", 0.70),
    ".db": ("sqlite_database", "unknown", 0.45),
    ".log": ("text_log", "unknown", 0.55),
    ".txt": ("text_document", "unknown", 0.60),
    # Secret-bearing configuration files are text evidence for Gitleaks.  If
    # they remain ``unknown``, an otherwise config-only tree is never scanned.
    ".yaml": ("text_document", "unknown", 0.70),
    ".yml": ("text_document", "unknown", 0.70),
    ".json": ("text_document", "unknown", 0.70),
    ".toml": ("text_document", "unknown", 0.70),
    ".ini": ("text_document", "unknown", 0.65),
    ".cfg": ("text_document", "unknown", 0.65),
    ".conf": ("text_document", "unknown", 0.65),
    ".properties": ("text_document", "unknown", 0.65),
    ".sh": ("text_document", "unknown", 0.70),
    ".ps1": ("text_document", "unknown", 0.75),
    ".bat": ("text_document", "unknown", 0.70),
    ".cmd": ("text_document", "unknown", 0.70),
    ".xml": ("text_document", "unknown", 0.65),
    ".tf": ("text_document", "unknown", 0.75),
    ".tfvars": ("text_document", "unknown", 0.80),
    ".pem": ("text_document", "unknown", 0.75),
    ".key": ("text_document", "unknown", 0.75),
    # --- source code (bandit / semgrep / gitleaks 의 입력) ---
    ".py": ("source_code_python", "unknown", 0.85),
    ".pyi": ("source_code_python", "unknown", 0.80),
    ".js": ("source_code_javascript", "unknown", 0.80),
    ".jsx": ("source_code_javascript", "unknown", 0.80),
    ".ts": ("source_code_javascript", "unknown", 0.85),
    ".tsx": ("source_code_javascript", "unknown", 0.85),
    ".mjs": ("source_code_javascript", "unknown", 0.80),
    ".cjs": ("source_code_javascript", "unknown", 0.80),
    ".java": ("source_code_generic", "unknown", 0.80),
    ".go": ("source_code_generic", "unknown", 0.80),
    ".rb": ("source_code_generic", "unknown", 0.80),
    ".php": ("source_code_generic", "unknown", 0.80),
    ".c": ("source_code_generic", "unknown", 0.70),
    ".h": ("source_code_generic", "unknown", 0.55),
    ".cpp": ("source_code_generic", "unknown", 0.75),
    ".hpp": ("source_code_generic", "unknown", 0.70),
    ".rs": ("source_code_generic", "unknown", 0.80),
    ".cs": ("source_code_generic", "unknown", 0.75),
    ".kt": ("source_code_generic", "unknown", 0.75),
    ".swift": ("source_code_generic", "unknown", 0.75),
}

# (regex, evidence_type, platform_hint, confidence)
_FILENAME_PATTERNS: list[tuple[re.Pattern[str], EvidenceType, Platform, float]] = [
    # Dotfiles have no useful Path.suffix (``.env``) or a misleading one
    # (``.env.local``), so classify the common credential/config names first.
    (re.compile(r"^\.env(?:\..+)?$", re.IGNORECASE),
     "text_document", "unknown", 0.85),
    (re.compile(r"^\.(npmrc|pypirc|netrc|envrc|git-credentials)$", re.IGNORECASE),
     "text_document", "unknown", 0.85),
    (re.compile(r"^(Dockerfile|Makefile|Jenkinsfile)$", re.IGNORECASE),
     "text_document", "unknown", 0.80),
    # Registry hives (extension-less)
    (re.compile(r"^NTUSER\.DAT$", re.IGNORECASE), "registry_hive", "windows", 0.95),
    (re.compile(r"^UsrClass\.dat$", re.IGNORECASE), "registry_hive", "windows", 0.95),
    (re.compile(r"^(SYSTEM|SOFTWARE|SAM|SECURITY|DEFAULT)$"), "registry_hive", "windows", 0.90),
    (re.compile(r"^Amcache\.hve$", re.IGNORECASE), "registry_hive", "windows", 0.98),
    # Extracted NTFS metadata files consumed by MFTECmd.
    (re.compile(r"^\$(MFT|J|Boot|SDS|I30)$", re.IGNORECASE),
     "ntfs_metadata", "windows", 0.98),
    # Common memory dump names
    (re.compile(
        r"^(?:.*[-_.])?(?:memory|memdump|ram|physmem|winpmem)"
        r"(?:[-_.].*)?\.(raw|mem|dmp|bin|vmem)$",
        re.IGNORECASE,
    ), "memory_dump", "unknown", 0.88),
    # Browser artifacts (typical filenames)
    (re.compile(r"^(History|Cookies|Web Data|Places\.sqlite|formhistory\.sqlite)$",
                re.IGNORECASE), "browser_artifact", "unknown", 0.85),
    # Linux syslog-style
    (re.compile(r"^(syslog|messages|auth\.log|secure)(\.\d+)?$"),
     "text_log", "linux", 0.85),
]

_BROWSER_PARENT_PATHS: list[tuple[str, Platform]] = [
    ("appdata/local/google/chrome/user data", "windows"),
    ("appdata/local/microsoft/edge/user data", "windows"),
    ("appdata/roaming/mozilla/firefox/profiles", "windows"),
    (".config/google-chrome", "linux"),
    (".config/chromium", "linux"),
    (".mozilla/firefox", "linux"),
    ("library/application support/google/chrome", "macos"),
    ("library/application support/firefox/profiles", "macos"),
]

# parent-dir keywords (case-insensitive substring matches in the normalized path)
_PARENT_DIR_HINTS: list[tuple[str, EvidenceType, Platform, float]] = [
    ("windows/prefetch", "prefetch", "windows", 0.85),
    ("windows/system32/config", "registry_hive", "windows", 0.80),
    *[
        (needle, "browser_artifact", platform, 0.70)
        for needle, platform in _BROWSER_PARENT_PATHS
    ],
    ("var/log", "text_log", "linux", 0.75),
]

# How many bytes to read from each file's head for magic detection.
HEADER_READ_BYTES = 32

_BROWSER_FILENAMES = {
    "history",
    "cookies",
    "web data",
    "places.sqlite",
    "formhistory.sqlite",
}

_PREFETCH_VERSIONS = {17, 23, 26, 30, 31}


def _has_browser_context(path: Path) -> bool:
    """Return True only when SQLite is located/named like a browser DB."""
    if path.name.casefold() in _BROWSER_FILENAMES:
        return True
    norm = str(path).replace("\\", "/").casefold()
    return any(needle in norm for needle, _ in _BROWSER_PARENT_PATHS)


def detect_by_magic(path: Path) -> tuple[EvidenceType, Platform, float] | None:
    """헤더 N 바이트만 읽어 시그니처 매칭. 못 읽으면 None."""
    try:
        with open(path, "rb") as f:
            head = f.read(HEADER_READ_BYTES)
    except (OSError, PermissionError):
        return None
    if not head:
        return None
    # Uncompressed Prefetch begins with a version DWORD; SCCA is at offset 4.
    # Retain the legacy offset-0 signature below for already-collected fixtures.
    if (
        len(head) >= 8
        and head[4:8] == b"SCCA"
        and int.from_bytes(head[:4], "little") in _PREFETCH_VERSIONS
    ):
        return "prefetch", "windows", 0.98
    for sig, etype, plat, conf in _MAGIC_SIGNATURES:
        if head.startswith(sig):
            if etype == "sqlite_database" and _has_browser_context(path):
                return "browser_artifact", plat, 0.95
            return etype, plat, conf
    return None


def detect_by_extension(path: Path) -> tuple[EvidenceType, Platform, float] | None:
    ext = path.suffix.lower()
    if not ext:
        return None
    hit = _EXTENSION_MAP.get(ext)
    if hit and hit[0] == "sqlite_database" and _has_browser_context(path):
        return "browser_artifact", hit[1], max(hit[2], 0.85)
    return hit


def detect_by_filename(path: Path) -> tuple[EvidenceType, Platform, float] | None:
    name = path.name
    for pat, etype, plat, conf in _FILENAME_PATTERNS:
        if pat.match(name):
            return etype, plat, conf
    return None


def detect_by_parent_dir(path: Path) -> tuple[EvidenceType, Platform, float] | None:
    # Normalize separators for cross-platform matching.
    norm = str(path).replace("\\", "/").lower()
    for needle, etype, plat, conf in _PARENT_DIR_HINTS:
        if needle in norm:
            return etype, plat, conf
    return None


def detect(path: Path) -> tuple[EvidenceType, Platform, float, DetectionMethod] | None:
    """우선순위에 따라 단일 결과를 반환. 어느 detector 도 못 잡으면 None."""
    if hit := detect_by_magic(path):
        et, pl, cf = hit
        return et, pl, cf, "magic_bytes"
    if hit := detect_by_extension(path):
        et, pl, cf = hit
        return et, pl, cf, "extension"
    if hit := detect_by_filename(path):
        et, pl, cf = hit
        return et, pl, cf, "filename_pattern"
    if hit := detect_by_parent_dir(path):
        et, pl, cf = hit
        return et, pl, cf, "parent_dir"
    return None
