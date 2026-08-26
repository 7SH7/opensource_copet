"""Deterministic, structured finding extraction.

Only indicator IDs with a concrete parser are executed.  In particular there
is deliberately no natural-language/substring fallback: prose in a YAML
``pattern`` is documentation, not executable detection logic.
"""

from __future__ import annotations

import ipaddress
import heapq
import json
import logging
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from itertools import chain
from typing import Any, Callable, Iterable

from forensicagent import config as settings
from forensicagent.analyzer.time_scope import parse_timestamp as _parse_timestamp
from forensicagent.analyzer.types import (
    MAX_RETAINED_FINDINGS,
    SEVERITY_RANK,
    EvidenceRef,
    Finding,
    Severity,
)
from forensicagent.tools.schema import SuspiciousIndicator, ToolMetadata

logger = logging.getLogger(__name__)

Matcher = Callable[[Any, str, ToolMetadata, SuspiciousIndicator], list[Finding]]
MAX_RULE_FINDINGS = MAX_RETAINED_FINDINGS


# ---------------------------------------------------------------------------
# Output normalization
# ---------------------------------------------------------------------------

_KEY_RE = re.compile(r"[^a-z0-9]+")
_TEMP_MARKERS = (
    "%temp%",
    "%appdata%",
    "\\temp\\",
    "/temp/",
    "\\appdata\\roaming\\",
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
    "/users/public/",
    "\\downloads\\",
    "/downloads/",
)
_CREDENTIAL_TOOLS = (
    "mimikatz",
    "lazagne",
    "nanodump",
    "sekurlsa",
    "lsassy",
)
_CREDENTIAL_TOOL_RE = re.compile(
    rf"(?i)(?<![a-z0-9])(?:{'|'.join(_CREDENTIAL_TOOLS)})(?:\.exe)?(?![a-z0-9])"
)
_PRIVILEGED_LOCAL_GROUP_SIDS = {
    "s-1-5-32-544",  # Administrators
    "s-1-5-32-548",  # Account Operators
    "s-1-5-32-549",  # Server Operators
    "s-1-5-32-550",  # Print Operators
    "s-1-5-32-551",  # Backup Operators
    "s-1-5-32-555",  # Remote Desktop Users
    "s-1-5-32-556",  # Network Configuration Operators
    "s-1-5-32-569",  # Cryptographic Operators
    "s-1-5-32-578",  # Hyper-V Administrators
    "s-1-5-32-580",  # Remote Management Users
}
_PRIVILEGED_LOCAL_GROUP_NAMES = {
    "administrators",
    "account operators",
    "server operators",
    "print operators",
    "backup operators",
    "remote desktop users",
    "network configuration operators",
    "cryptographic operators",
    "hyper-v administrators",
    "remote management users",
}
_ACCOUNT_PRIVILEGE_WINDOW_SECONDS = 60 * 60
_RUN_KEY_RE = re.compile(
    r"(?i)(?:^|[\\/\s])run(?:once|services)?(?:$|[\\/\s:=])"
)


def normalize_field_name(name: Any) -> str:
    """Normalize vendor-specific CSV/JSON headers for robust lookup."""
    return _KEY_RE.sub("", str(name).strip().casefold())


def normalize_row(row: dict[str, Any]) -> dict[str, Any]:
    """Flatten nested dictionaries while retaining leaf and qualified keys."""
    out: dict[str, Any] = {}

    def walk(obj: Any, prefix: str = "") -> None:
        if not isinstance(obj, dict):
            return
        for raw_key, value in obj.items():
            key = normalize_field_name(raw_key)
            qualified = f"{prefix}{key}" if prefix else key
            if isinstance(value, dict):
                walk(value, qualified)
                continue
            out.setdefault(key, value)
            out.setdefault(qualified, value)

    walk(row)
    return out


def _rows(parsed: Any) -> list[dict[str, Any]]:
    if isinstance(parsed, list):
        return [x for x in parsed if isinstance(x, dict)]
    if not isinstance(parsed, dict):
        return []
    normalized = normalize_row(parsed)
    for name in ("items", "results", "rows", "events", "records"):
        value = normalized.get(name)
        if isinstance(value, list):
            return [x for x in value if isinstance(x, dict)]
    # A single structured row is useful for streamed artifact batches.
    if parsed and any(not isinstance(v, (dict, list)) for v in parsed.values()):
        return [parsed]
    return []


def _value(row: dict[str, Any], *aliases: str, default: Any = "") -> Any:
    normalized = normalize_row(row)
    for alias in aliases:
        key = normalize_field_name(alias)
        if key in normalized and normalized[key] not in (None, ""):
            return normalized[key]
    # Nested exporters often prefix keys with Event/System/EventData.  A leaf
    # suffix is unambiguous enough after exact aliases have been attempted.
    for alias in aliases:
        key = normalize_field_name(alias)
        # Generic leaf names such as ``path``, ``name``, ``line`` and ``id``
        # are not suffix-safe (for example ParentPath is not FullPath).
        if len(key) < 5:
            continue
        for candidate, value in normalized.items():
            if candidate.endswith(key) and value not in (None, ""):
                return value
    return default


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return " ".join(_text(v) for v in value)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, default=str)
    return str(value)


def _qualified_value(
    row: dict[str, Any],
    *,
    qualified_aliases: tuple[str, ...],
    flat_aliases: tuple[str, ...],
) -> Any:
    """Prefer an unambiguous structured field over same-named payload leaves."""
    normalized = normalize_row(row)
    qualified = tuple(normalize_field_name(alias) for alias in qualified_aliases)
    matches = [
        value
        for key, value in normalized.items()
        if any(key == alias or key.endswith(alias) for alias in qualified)
        and value not in (None, "")
    ]
    if matches:
        distinct = {_text(value).strip().casefold() for value in matches}
        return matches[0] if len(distinct) == 1 else None
    flat = [
        normalized[key]
        for alias in flat_aliases
        if (key := normalize_field_name(alias)) in normalized
        and normalized[key] not in (None, "")
    ]
    if not flat:
        return None
    distinct = {_text(value).strip().casefold() for value in flat}
    return flat[0] if len(distinct) == 1 else None


def _row_text(row: dict[str, Any]) -> str:
    return " ".join(_text(v) for v in row.values())


def _excerpt(row: Any, max_chars: int = 700) -> str:
    try:
        rendered = json.dumps(row, ensure_ascii=False, default=str, sort_keys=True)
    except (TypeError, ValueError):
        rendered = str(row)
    return rendered[:max_chars]


def _is_header_row(row: dict[str, Any]) -> bool:
    normalized = normalize_row(row)
    comparable = 0
    same = 0
    for key, value in normalized.items():
        if isinstance(value, (dict, list, tuple)):
            continue
        val_key = normalize_field_name(value)
        if not val_key:
            continue
        comparable += 1
        if val_key == key or key.endswith(val_key):
            same += 1
    return comparable >= 2 and same >= max(2, comparable // 2)


def _int_value(value: Any) -> int | None:
    match = re.search(r"-?\d+", _text(value))
    if not match:
        return None
    try:
        return int(match.group(0))
    except ValueError:
        return None


def _event_id(row: dict[str, Any]) -> int | None:
    return _int_value(
        _qualified_value(
            row,
            qualified_aliases=("event_system_event_id",),
            flat_aliases=("event_id", "eventid"),
        )
    )


def _event_channel(row: dict[str, Any]) -> str:
    return _text(
        _qualified_value(
            row,
            qualified_aliases=("event_system_channel",),
            flat_aliases=("channel", "channel_name", "log_name"),
        )
    ).strip()


def _event_provider(row: dict[str, Any]) -> str:
    return _text(
        _qualified_value(
            row,
            qualified_aliases=(
                "event_system_provider_attributes_name",
                "event_system_provider_name",
            ),
            flat_aliases=("provider_name", "provider"),
        )
    ).strip()


def _event_context_is(
    row: dict[str, Any],
    *,
    channel: str,
    providers: set[str],
) -> bool:
    """Require the namespace that gives a Windows Event ID its meaning."""
    actual_channel = _event_channel(row).casefold()
    actual_provider = _event_provider(row).casefold()
    return actual_channel == channel.casefold() and actual_provider in providers


def _is_security_audit_event(row: dict[str, Any], *event_ids: int) -> bool:
    return _event_id(row) in event_ids and _event_context_is(
        row,
        channel="Security",
        providers={"microsoft-windows-security-auditing"},
    )


def cross_batch_correlation_family(row: dict[str, Any]) -> str | None:
    """Return the bounded carry family for cross-row event correlations."""
    event_id = _event_id(row)
    if event_id in {4624, 4625} and _is_security_audit_event(row, event_id):
        return "logon"
    if event_id in {4720, 4732} and _is_security_audit_event(row, event_id):
        return "account"
    return None


def _timestamp_text(row: dict[str, Any]) -> str:
    return _text(
        _value(
            row,
            "timestamp",
            "time_created",
            "timecreated",
            "system_time",
            "datetime",
            "date_time",
            "last_run",
        )
    ).strip()


def _source_file(row: dict[str, Any]) -> str:
    return _text(
        _value(
            row,
            "source_file",
            "sourcefile",
            "filename",
            "file_name",
            "full_path",
            "fullpath",
            "path",
        )
    ).strip()


def _make_finding(
    *,
    rule_id: str,
    severity: Severity,
    category: str,
    title: str,
    description: str,
    row: dict[str, Any] | None = None,
    raw_excerpt: str = "",
    source_file: str = "",
    event_id: int | None = None,
    timestamp: str = "",
    followup: str = "",
    alternative_explanation: str = "",
    confidence: float = 0.9,
    entities: dict[str, list[str]] | None = None,
) -> Finding:
    row = row or {}
    finding = Finding(
        severity=severity,
        category=category,
        title=title,
        description=description,
        evidence_ref=EvidenceRef(
            source_file=source_file or _source_file(row),
            event_id=event_id if event_id is not None else _event_id(row),
            channel=_event_channel(row),
            provider=_event_provider(row),
            timestamp=timestamp or _timestamp_text(row),
            raw_excerpt=(raw_excerpt or _excerpt(row))[:700],
        ),
        suggested_followup=followup,
        alternative_explanation=alternative_explanation,
        source="rule",
        rule_id=rule_id,
        confidence=confidence,
        entities=entities or {},
    )
    finding.refresh_fingerprint()
    return finding


def _path_is_suspicious(path: str) -> bool:
    normalized = path.replace("/", "\\").casefold()
    return any(marker.replace("/", "\\") in normalized for marker in _TEMP_MARKERS)


def _contains_credential_tool(text: str) -> bool:
    return _CREDENTIAL_TOOL_RE.search(text) is not None


def _canonical_ip(value: Any) -> str:
    """Return stdlib-canonical IP text, accepting common host:port wrappers."""
    candidate = _text(value).strip()
    if candidate.startswith("[") and "]" in candidate:
        closing = candidate.find("]")
        suffix = candidate[closing + 1 :]
        if not suffix or (suffix.startswith(":") and suffix[1:].isdigit()):
            candidate = candidate[1:closing]
    elif candidate.count(":") == 1 and "." in candidate:
        host, port = candidate.rsplit(":", 1)
        if port.isdigit():
            candidate = host
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return ""
    return "" if address.is_unspecified else address.compressed.casefold()


def _global_ip(value: str) -> bool:
    candidate = _canonical_ip(value)
    return bool(candidate and ipaddress.ip_address(candidate).is_global)


def _account(value: Any) -> str:
    text = _text(value).strip().casefold()
    if not text:
        return ""
    cn = re.search(r"(?:^|,)cn=([^,]+)", text, re.IGNORECASE)
    if cn:
        text = cn.group(1)
    if "\\" in text:
        text = text.rsplit("\\", 1)[-1]
    return text.strip().strip('"')


def _logon_user(row: dict[str, Any]) -> str:
    return _account(
        _value(
            row,
            "target_user_name",
            "targetusername",
            "account_name",
            "username",
        )
    )


def _logon_ip(row: dict[str, Any]) -> str:
    return _canonical_ip(
        _value(
            row,
            "ip_address",
            "ipaddress",
            "source_ip",
            "sourceip",
            "remote_address",
        )
    )


def _basename(value: Any) -> str:
    """Return a Windows/POSIX basename independent of the host platform."""
    return _text(value).replace("/", "\\").rsplit("\\", 1)[-1].strip()


_EMPTY_ENTITIES = {"", "-", "?", "n/a", "none", "null", "unknown"}


def _entity_map(
    *,
    users: Iterable[Any] = (),
    ips: Iterable[Any] = (),
    processes: Iterable[Any] = (),
) -> dict[str, list[str]]:
    """Canonicalize only entities whose meaning is known by the caller."""
    normalized = {
        "user": {_account(value) for value in users},
        "ip": {_canonical_ip(value) for value in ips},
        "process": {_basename(value).casefold() for value in processes},
    }
    return {
        kind: sorted(value for value in values if value not in _EMPTY_ENTITIES)
        for kind, values in normalized.items()
        if any(value not in _EMPTY_ENTITIES for value in values)
    }


def _principal_entities(key: str) -> dict[str, list[str]]:
    kind, separator, value = key.partition(":")
    if not separator:
        return {}
    if kind == "ip":
        return _entity_map(ips=(value,))
    if kind == "account":
        return _entity_map(users=(value,))
    return {}


# ---------------------------------------------------------------------------
# General structured-tool matchers
# ---------------------------------------------------------------------------

def _match_sigma_rule_hit(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    out: list[Finding] = []
    for row in _rows(parsed):
        if _is_header_row(row):
            continue
        rule = _text(_value(row, "rule_name", "rulename", "rule", "name"))
        if not rule:
            continue
        slug = re.sub(r"[^a-z0-9]+", "-", rule.casefold()).strip("-")[:80]
        out.append(
            _make_finding(
                rule_id=f"sigma:{slug or 'match'}",
                severity=ind.severity_baseline,
                category="threat_intel",
                title=f"Sigma rule match: {rule[:160]}",
                description=f"{meta.display_name} matched Sigma rule {rule}.",
                row=row,
                followup="Validate the rule context against the original event.",
            )
        )
    return out


def _registry_temp_rows(parsed: Any, raw: str) -> Iterable[tuple[dict[str, Any], str]]:
    rows = _rows(parsed)
    if rows:
        for row in rows:
            key = _text(_value(row, "key_path", "keypath", "registry_path", "path"))
            value = _text(
                _value(row, "value", "data", "value_data", "image_path", "command")
            )
            blob = f"{key} {value} {_row_text(row)}"
            if _path_is_suspicious(blob) and _RUN_KEY_RE.search(blob):
                yield row, blob
        return

    context = ""
    for line in raw.splitlines():
        if _RUN_KEY_RE.search(line):
            context = line
        if _path_is_suspicious(line) and _RUN_KEY_RE.search(f"{context} {line}"):
            yield {}, line.strip()


def _match_registry_temp_persistence(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    out: list[Finding] = []
    for row, text in _registry_temp_rows(parsed, raw):
        out.append(
            _make_finding(
                rule_id=ind.id,
                severity=ind.severity_baseline,
                category="persistence",
                title="Run-key persistence from a user-writable path",
                description=text[:300],
                row=row,
                raw_excerpt=text,
                followup="Hash and verify the referenced executable, then inspect its autorun owner.",
                confidence=0.94,
            )
        )
    return out


def _registry_rows_or_lines(
    parsed: Any, raw: str,
) -> Iterable[tuple[dict[str, Any], str]]:
    rows = _rows(parsed)
    if rows:
        for row in rows:
            if not _is_header_row(row):
                yield row, _row_text(row)
        return
    context = ""
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        key_context = _RUN_KEY_RE.search(stripped) or re.search(
            r"(?i)(?:^HK[A-Z]+\\|^software\\|^system\\|services\\|winlogon|"
            r"image file execution options|appinit|userassist)",
            stripped,
        )
        if "\\" in stripped and key_context:
            context = stripped
        yield {}, f"{context} {stripped}".strip()


def _match_registry_service_image(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    out: list[Finding] = []
    for row, blob in _registry_rows_or_lines(parsed, raw):
        key_path = _text(_value(row, "key_path", "keypath", "registry_path"))
        service_name = _text(_value(row, "service_name", "servicename"))
        image_path = _text(
            _value(row, "image_path", "imagepath", "value_data", "data", "value")
        )
        searchable = f"{key_path} {service_name} {image_path} {blob}"
        if not re.search(r"(?i)services?\\", searchable) or not re.search(
            r"(?i)image\s*path", searchable
        ):
            continue
        if not _path_is_suspicious(image_path or blob):
            continue
        if not service_name and key_path:
            match = re.search(r"(?i)services?\\([^\\\s]+)", key_path)
            service_name = match.group(1) if match else ""
        if not service_name:
            match = re.search(r"(?i)services?\\([^\\\s]+)", blob)
            service_name = match.group(1) if match else ""
        # Requiring a compact alphanumeric service name implements the
        # metadata's random/short-name predicate and avoids generic Temp hits.
        if not re.fullmatch(r"[a-z0-9]{4,8}", service_name.strip(), re.IGNORECASE):
            continue
        out.append(
            _make_finding(
                rule_id=ind.id,
                severity=ind.severity_baseline,
                category="persistence",
                title="Short-name service points to a user-writable path",
                description=(image_path or blob)[:300],
                row=row,
                raw_excerpt=blob,
                followup="Inspect the service creation time, binary, owner, and signature.",
                confidence=0.94,
            )
        )
    return out


def _match_registry_ifeo_debugger(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    out: list[Finding] = []
    accessibility_targets = (
        "sethc.exe",
        "utilman.exe",
        "osk.exe",
        "magnify.exe",
        "narrator.exe",
        "displayswitch.exe",
        "atbroker.exe",
    )
    command_interpreters = (
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "rundll32.exe",
        "mshta.exe",
        "wscript.exe",
        "cscript.exe",
    )
    for row, blob in _registry_rows_or_lines(parsed, raw):
        lowered = blob.casefold()
        if "image file execution options" not in lowered or "debugger" not in lowered:
            continue
        debugger = _text(_value(row, "debugger", "value_data", "data", "value"))
        if row and not debugger:
            continue
        candidate = f"{lowered} {debugger.casefold()}"
        if not any(target in candidate for target in accessibility_targets) or not any(
            interpreter in candidate for interpreter in command_interpreters
        ):
            continue
        out.append(
            _make_finding(
                rule_id=ind.id,
                severity=ind.severity_baseline,
                category="persistence",
                title="Accessibility IFEO debugger points to a command interpreter",
                description=(debugger or blob)[:300],
                row=row,
                raw_excerpt=blob,
                followup="Validate the IFEO target and debugger binary and remove unauthorized persistence.",
                alternative_explanation=(
                    "A debugger may be configured for authorized testing, but this "
                    "accessibility-target combination is a high-risk persistence setting."
                ),
                confidence=0.95,
            )
        )
    return out


def _nonstandard_binary_path(text: str) -> bool:
    normalized = text.replace("/", "\\").casefold()
    if _path_is_suspicious(normalized):
        return True
    return bool(re.search(r"(?i)[a-z]:\\", text)) and not any(
        root in normalized
        for root in ("\\windows\\", "\\program files\\", "\\program files (x86)\\")
    )


def _match_registry_appinit(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    out: list[Finding] = []
    for row, blob in _registry_rows_or_lines(parsed, raw):
        if "appinit_dlls" not in blob.casefold():
            continue
        data = _text(_value(row, "value_data", "data", "value", "appinit_dlls"))
        candidate = data or blob
        if not _nonstandard_binary_path(candidate):
            continue
        out.append(
            _make_finding(
                rule_id=ind.id,
                severity=ind.severity_baseline,
                category="persistence",
                title="AppInit DLL configured from a non-standard path",
                description=candidate[:300],
                row=row,
                raw_excerpt=blob,
                followup="Inspect the DLL signature and every process into which it may load.",
                alternative_explanation=(
                    "Legacy or vendor software may legitimately configure AppInit DLLs; "
                    "the setting alone does not prove a malicious load."
                ),
                confidence=0.94,
            )
        )
    return out


def _match_registry_winlogon_shell(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    out: list[Finding] = []
    for row, blob in _registry_rows_or_lines(parsed, raw):
        lowered = blob.casefold()
        if "winlogon" not in lowered or not re.search(r"(?i)\bshell\b", blob):
            continue
        data = _text(_value(row, "value_data", "data", "value", "shell"))
        if not data:
            match = re.search(r"(?i)\bshell\s*[:=]\s*(.+)$", blob)
            data = match.group(1).strip() if match else ""
        normalized = data.strip().strip('"').casefold()
        if not normalized or normalized == "explorer.exe":
            continue
        out.append(
            _make_finding(
                rule_id=ind.id,
                severity=ind.severity_baseline,
                category="persistence",
                title="Winlogon shell differs from Explorer",
                description=data[:300],
                row=row,
                raw_excerpt=blob,
                followup="Validate the configured shell and inspect its binary and launch chain.",
                alternative_explanation=(
                    "Kiosk software or a managed custom desktop can intentionally replace "
                    "Explorer; the setting alone does not prove malicious execution."
                ),
                confidence=0.98,
            )
        )
    return out


def _match_userassist_temp(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    out: list[Finding] = []
    for row, blob in _registry_rows_or_lines(parsed, raw):
        lowered = blob.casefold()
        if "userassist" not in lowered or not _path_is_suspicious(blob):
            continue
        if not re.search(r"(?i)\.(?:exe|dll|scr|com)\b", blob):
            continue
        if ind.id == "userassist_unsigned_in_temp":
            status = _text(
                _value(row, "signature_status", "signing_status", "is_signed", "signed")
            ).casefold()
            if status not in {"false", "no", "unsigned", "invalid", "untrusted"}:
                continue
        out.append(
            _make_finding(
                rule_id=ind.id,
                severity=ind.severity_baseline,
                category="execution",
                title="UserAssist execution from a user-writable path",
                description=blob[:300],
                row=row,
                raw_excerpt=blob,
                followup="Recover and hash the executable and correlate its last-run timestamp.",
                confidence=0.9 if ind.id == "userassist_unsigned_in_temp" else 0.82,
            )
        )
    return out


def _volatility_process_rows(parsed: Any, raw: str) -> list[dict[str, Any]]:
    rows = _rows(parsed)
    if rows:
        return rows
    out: list[dict[str, Any]] = []
    process_line = re.compile(
        r"^\s*[*.`|+\- ]*(?P<pid>\d+)\s+(?P<ppid>\d+)\s+(?P<name>[^\s]+)(?P<rest>.*)$"
    )
    for line in raw.splitlines():
        match = process_line.match(line)
        if not match:
            continue
        rest = match.group("rest")
        path_match = re.search(
            r"(?i)(?:[a-z]:\\|\\device\\harddiskvolume\d+\\)[^\r\n]*?\.exe\b",
            rest,
        )
        out.append(
            {
                "PID": match.group("pid"),
                "PPID": match.group("ppid"),
                "ImageFileName": match.group("name"),
                "Path": path_match.group(0) if path_match else "",
                "raw_line": line.strip(),
            }
        )
    return out


def _match_volatility_parent_child(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    rows = _volatility_process_rows(parsed, raw)
    by_pid: dict[int, str] = {}
    for row in rows:
        pid = _int_value(_value(row, "pid", "process_id", "processid"))
        name = _text(
            _value(
                row,
                "image_file_name",
                "imagefilename",
                "process_name",
                "process",
                "name",
            )
        ).casefold()
        if pid is not None and name:
            by_pid[pid] = _basename(name).casefold()

    expected = {
        "lsass.exe": {"wininit.exe"},
        "services.exe": {"wininit.exe"},
        "winlogon.exe": {"smss.exe", "wininit.exe"},
    }
    out: list[Finding] = []
    for row in rows:
        child = _basename(
            _value(
                row,
                "image_file_name",
                "imagefilename",
                "process_name",
                "process",
                "name",
            )
        ).casefold()
        allowed = expected.get(child)
        if not allowed:
            continue
        parent = _basename(
            _value(
                row,
                "parent_process_name",
                "parentprocessname",
                "parent_image_file_name",
                "parentimagefilename",
                "parent_name",
                "parentname",
            )
        ).casefold()
        if not parent:
            ppid = _int_value(_value(row, "ppid", "parent_pid", "parentpid"))
            parent = by_pid.get(ppid or -1, "")
        # A numeric PPID without a resolvable process name is insufficient
        # evidence; the parent may simply have exited before acquisition.
        if not parent or parent in allowed:
            continue
        out.append(
            _make_finding(
                rule_id=ind.id,
                severity=ind.severity_baseline,
                category="process_anomaly",
                title="Critical Windows process has an unexpected parent",
                description=f"{child} parent is {parent}; expected {', '.join(sorted(allowed))}.",
                row=row,
                raw_excerpt=_text(_value(row, "raw_line")) or _excerpt(row),
                followup="Validate the process objects, creation times, tokens, and executable mappings.",
                confidence=0.96,
                entities=_entity_map(processes=(child, parent)),
            )
        )
    return out


def _match_volatility_unusual_path(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    out: list[Finding] = []
    for row in _volatility_process_rows(parsed, raw):
        path = _text(
            _value(
                row,
                "image_path",
                "imagepath",
                "process_path",
                "processpath",
                "full_path",
                "fullpath",
                "path",
                "command_line",
                "commandline",
                "args",
            )
        )
        if not _path_is_suspicious(path):
            continue
        process_name = _text(
            _value(
                row,
                "image_file_name",
                "imagefilename",
                "process_name",
                "process",
                "name",
            )
        )
        out.append(
            _make_finding(
                rule_id=ind.id,
                severity=ind.severity_baseline,
                category="process_anomaly",
                title="Process image in a user-writable path",
                description=f"{process_name or 'process'}: {path}"[:300],
                row=row,
                raw_excerpt=_text(_value(row, "raw_line")) or _excerpt(row),
                source_file=path,
                followup="Dump and hash the process image and inspect its parent, token, and network activity.",
                confidence=0.91,
                entities=_entity_map(processes=(process_name,)),
            )
        )
    return out


def _volatility_network_rows(parsed: Any, raw: str) -> list[dict[str, Any]]:
    rows = _rows(parsed)
    if rows:
        return rows
    out: list[dict[str, Any]] = []
    network_line = re.compile(
        r"^\s*(?:0x[0-9a-f]+|\d+)\s+"
        r"(?P<proto>TCPv[46])\s+"
        r"(?P<local>\S+)\s+(?P<local_port>\d+)\s+"
        r"(?P<foreign>\S+)\s+(?P<foreign_port>\d+)\s+"
        r"(?P<state>\S+)(?P<rest>.*)$",
        re.IGNORECASE,
    )
    for line in raw.splitlines():
        match = network_line.match(line)
        if not match:
            continue
        out.append(
            {
                "Proto": match.group("proto"),
                "LocalAddr": match.group("local"),
                "LocalPort": match.group("local_port"),
                "ForeignAddr": match.group("foreign"),
                "ForeignPort": match.group("foreign_port"),
                "State": match.group("state"),
                "raw_line": line.strip(),
            }
        )
    return out


def _match_volatility_rare_network(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    common_remote_ports = {
        20, 21, 22, 25, 53, 80, 110, 123, 135, 139, 143, 389, 443,
        445, 465, 587, 636, 993, 995, 1433, 3306, 3389, 5432, 5985, 5986,
    }
    out: list[Finding] = []
    for row in _volatility_network_rows(parsed, raw):
        state = _text(_value(row, "state")).strip().casefold()
        remote_ip = _text(
            _value(
                row,
                "foreign_addr",
                "foreignaddr",
                "remote_address",
                "remoteaddress",
                "remote_ip",
                "remoteip",
            )
        ).strip()
        remote_port = _int_value(
            _value(row, "foreign_port", "foreignport", "remote_port", "remoteport")
        )
        if state != "established" or not _global_ip(remote_ip):
            continue
        if remote_port is None or remote_port <= 0 or remote_port in common_remote_ports:
            continue
        owner = _text(_value(row, "owner", "process_name", "image_file_name"))
        out.append(
            _make_finding(
                rule_id=ind.id,
                severity=ind.severity_baseline,
                category="network_anomaly",
                title="Process connected to a global IP on an uncommon port",
                description=f"{owner or 'process'} -> {remote_ip}:{remote_port} ({state}).",
                row=row,
                raw_excerpt=_text(_value(row, "raw_line")) or _excerpt(row),
                followup="Validate the destination with approved services and threat intelligence, then inspect the owning process.",
                confidence=0.84,
                entities=_entity_map(ips=(remote_ip,), processes=(owner,)),
            )
        )
    return out


def _match_malfind_pe_unbacked(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    out: list[Finding] = []
    rows = _rows(parsed)
    for row in rows:
        if _is_header_row(row):
            continue
        hexdump = _text(
            _value(row, "hexdump", "hex_dump", "hex", "data", "disasm")
        )
        protection = _text(
            _value(row, "protection", "vad_protection", "vadprotection")
        )
        private_memory = _text(
            _value(row, "private_memory", "privatememory", "private")
        ).strip().casefold()
        tag = _text(_value(row, "tag", "vad_tag", "vadtag")).strip().casefold()
        file_output = _text(
            _value(row, "file_output", "fileoutput", "mapped_file", "mappedfile")
        ).strip()
        has_pe = bool(re.search(r"(?i)(?:\b4d\s+5a\b|\bMZ\b)", hexdump))
        executable = "execute" in protection.casefold() or bool(
            re.search(r"(?i)\b(?:r-x|rwx|rx)\b", protection)
        )
        private = private_memory in {"true", "1", "yes", "y"}
        unbacked = (
            private
            or tag == "vads"
            or not file_output
            or file_output.casefold() in {"-", "n/a", "none"}
        )
        if not (has_pe and executable and unbacked):
            continue
        process = _text(_value(row, "process", "process_name", "image_file_name"))
        pid = _int_value(_value(row, "pid", "process_id", "processid"))
        out.append(
            _make_finding(
                rule_id=ind.id,
                severity=ind.severity_baseline,
                category="defense_evasion",
                title="Unbacked executable memory region",
                description=(
                    f"Malfind found a PE header in executable memory for "
                    f"{process or 'process'} (PID {pid if pid is not None else '?'})."
                ),
                row=row,
                raw_excerpt=_excerpt(
                    {
                        "PID": pid,
                        "Process": process,
                        "Protection": protection,
                        "PrivateMemory": private_memory,
                        "Tag": tag,
                        "FileOutput": file_output,
                        "Hexdump": hexdump[:240],
                    }
                ),
                followup="Dump the region and validate it with static analysis and YARA.",
                confidence=0.98,
                entities=_entity_map(processes=(process,)),
            )
        )
    if rows:
        return out

    has_pe = re.compile(r"\bMZ\b|^\s*4d\s+5a", re.MULTILINE | re.IGNORECASE)
    has_unbacked = re.compile(r"(?i)(unbacked|RX\b.*MZ|No mapped path)")
    for block in re.split(r"\n\s*\n", raw):
        if has_pe.search(block) and has_unbacked.search(block):
            out.append(
                _make_finding(
                    rule_id=ind.id,
                    severity=ind.severity_baseline,
                    category="defense_evasion",
                    title="Unbacked executable memory region",
                    description="Malfind reported a PE header in an unbacked executable region.",
                    raw_excerpt=block.strip(),
                    followup="Dump the region and validate it with static analysis and YARA.",
                    confidence=0.96,
                )
            )
    return out


def _match_bandit_issue(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    severity_map: dict[str, Severity] = {
        "low": "low",
        "medium": "medium",
        "high": "high",
    }
    out: list[Finding] = []
    for row in _rows(parsed):
        if _is_header_row(row):
            continue
        test_id = _text(_value(row, "test_id", "testid")) or "unknown"
        issue = _text(_value(row, "issue_text", "issuetext", "message"))
        if test_id == "unknown" and not issue:
            continue
        severity = severity_map.get(
            _text(_value(row, "issue_severity", "severity")).casefold(),
            ind.severity_baseline,
        )
        filename = _text(_value(row, "filename", "path"))
        line = _int_value(_value(row, "line_number", "line"))
        confidence = {
            "high": 0.95,
            "medium": 0.8,
            "low": 0.65,
        }.get(_text(_value(row, "issue_confidence", "confidence")).casefold(), 0.75)
        out.append(
            _make_finding(
                rule_id=f"bandit:{test_id}",
                severity=severity,
                category="code_security",
                title=f"[bandit:{test_id}] finding",
                description=(
                    f"{filename}:{line or '?'} - Bandit reported rule {test_id}."
                ),
                row=row,
                raw_excerpt=f"{filename}:{line or '?'}; test_id={test_id}",
                source_file=filename,
                followup="Review the Bandit rule and the complete data flow at this location.",
                confidence=confidence,
            )
        )
    return out


def _match_semgrep_issue(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    severity_map: dict[str, Severity] = {
        "info": "low",
        "warning": "medium",
        "error": "high",
    }
    out: list[Finding] = []
    for row in _rows(parsed):
        if _is_header_row(row):
            continue
        check_id = _text(_value(row, "check_id", "checkid")) or "unknown"
        severity = severity_map.get(
            _text(_value(row, "severity")).casefold(), ind.severity_baseline
        )
        path = _text(_value(row, "path", "filename"))
        line = _int_value(_value(row, "line", "start_line", "startline"))
        message = _text(_value(row, "message"))
        if check_id == "unknown" and not message:
            continue
        fix = _text(_value(row, "fix"))
        out.append(
            _make_finding(
                rule_id=f"semgrep:{check_id}",
                severity=severity,
                category="code_security",
                title=f"[semgrep:{check_id}]",
                description=f"{path}:{line or '?'} - Semgrep reported rule {check_id}.",
                row=row,
                raw_excerpt=f"{path}:{line or '?'}; check_id={check_id}",
                source_file=path,
                followup="Review the Semgrep rule and validate exploitability.",
                confidence=0.85,
            )
        )
    return out


_SENSITIVE_KEYS = {
    "secret",
    "match",
    "token",
    "password",
    "apikey",
    "privatekey",
}


def _placeholder_secret(path: str, secret: str) -> bool:
    del path  # Placeholder status is value-based; example files can leak real keys.
    compact = re.sub(r"[\s_\-]+", "", secret).casefold()
    if not compact:
        return True
    if any(
        marker in compact
        for marker in (
            "placeholder",
            "changeme",
            "replacewith",
            "yourapikey",
            "yoursecret",
            "exampleonly",
            "dummyvalue",
        )
    ):
        return True
    return bool(re.fullmatch(r"(?:x{6,}|0{8,}|a{12,}|test|dummy|example)", compact))


def _redacted_row(row: dict[str, Any], secret: str) -> str:
    safe: dict[str, Any] = {}
    for key, value in row.items():
        normalized = normalize_field_name(key)
        if normalized in _SENSITIVE_KEYS or any(
            normalized.endswith(suffix) for suffix in _SENSITIVE_KEYS
        ):
            safe[str(key)] = "[REDACTED]"
            continue
        rendered = _text(value)
        if secret and secret in rendered:
            rendered = rendered.replace(secret, "[REDACTED]")
        safe[str(key)] = rendered
    return _excerpt(safe)


def _match_gitleaks_secret(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    out: list[Finding] = []
    for row in _rows(parsed):
        rule = _text(_value(row, "rule_id", "ruleid")) or "unknown"
        description = _text(_value(row, "description"))
        path = _text(_value(row, "file", "path", "filename"))
        line = _int_value(_value(row, "start_line", "startline", "line"))
        secret = _text(_value(row, "secret", "match"))
        if _placeholder_secret(path, secret):
            continue
        safe_description = (
            description.replace(secret, "[REDACTED]") if secret else description
        )
        is_aws = "aws" in rule.casefold() or secret.startswith("AKIA")
        severity: Severity = "critical" if is_aws else ind.severity_baseline
        out.append(
            _make_finding(
                rule_id=f"gitleaks:{rule}",
                severity=severity,
                category="secret_exposure",
                title=f"[gitleaks:{rule}] {safe_description[:140]}",
                description=(
                    f"Potential secret at {path}:{line or '?'}; detected value redacted."
                ),
                row=row,
                raw_excerpt=_redacted_row(row, secret),
                source_file=path,
                followup="Revoke or rotate the credential, then inspect access logs.",
                confidence=0.94,
            )
        )
    return out


def _no_duplicate_supplement(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    """Severity-specific YAML helpers are handled by the general parser."""
    return []


# ---------------------------------------------------------------------------
# Concrete forensic row matchers
# ---------------------------------------------------------------------------

def _amcache_identifier(row: dict[str, Any]) -> str:
    return " ".join(
        (
            _text(_value(row, "application_name", "applicationname")),
            _text(_value(row, "full_path", "fullpath", "application_path")),
        )
    ).strip()


def _match_amcache_temp(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    out: list[Finding] = []
    for row in _rows(parsed):
        if _is_header_row(row):
            continue
        path = _text(
            _value(row, "full_path", "fullpath", "path", "application_path")
        )
        if _contains_credential_tool(_amcache_identifier(row)):
            continue  # owned by the higher-confidence credential-tool rule
        normalized = normalize_row(row)
        association_fields = {
            normalize_field_name(name)
            for name in ("associated", "is_associated", "entry_type", "program_id")
        }
        if not any(field in normalized for field in association_fields):
            continue
        association = _text(
            _value(row, "associated", "is_associated", "entry_type", "program_id")
        ).casefold()
        unassociated = not association or association in {
            "0",
            "false",
            "no",
            "none",
            "unknown",
            "unassociated",
            "not associated",
        }
        if _path_is_suspicious(path) and unassociated:
            out.append(
                _make_finding(
                    rule_id=ind.id,
                    severity=ind.severity_baseline,
                    category="artifact_anomaly",
                    title="Unassociated Amcache executable in a user-writable path",
                    description=path,
                    row=row,
                    followup="Recover and hash the file, then seek independent execution evidence.",
                    alternative_explanation=(
                        "Portable applications and installers can create unassociated "
                        "Amcache entries in user-writable paths."
                    ),
                    confidence=0.78,
                )
            )
    return out


def _match_amcache_credential_tool(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    out: list[Finding] = []
    for row in _rows(parsed):
        candidate = _amcache_identifier(row)
        if _is_header_row(row) or not _contains_credential_tool(candidate):
            continue
        out.append(
            _make_finding(
                rule_id=ind.id,
                severity=ind.severity_baseline,
                category="credential_access",
                title="Credential-access utility name recorded in Amcache",
                description=_text(
                    _value(row, "full_path", "fullpath", "application_name", "name")
                ),
                row=row,
                followup="Confirm execution with Prefetch, UserAssist, or process events and validate authorization.",
                alternative_explanation=(
                    "The entry may be stale or belong to authorized security testing; "
                    "Amcache alone does not prove execution or credential access."
                ),
                confidence=0.88,
            )
        )
    return out


def _match_amcache_invalid_signature(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    out: list[Finding] = []
    invalid_tokens = {"false", "no", "invalid", "unsigned", "untrusted", "not signed"}
    for row in _rows(parsed):
        if _is_header_row(row):
            continue
        path = _text(_value(row, "full_path", "fullpath", "path"))
        status = _text(
            _value(
                row,
                "signature_status",
                "signaturestatus",
                "signing_status",
                "is_signed",
                "issigned",
                "signed",
            )
        ).strip().casefold()
        normalized_path = path.replace("/", "\\").casefold()
        standard = any(
            root in normalized_path
            for root in ("\\program files\\", "\\windows\\system32\\", "\\windows\\syswow64\\")
        )
        if not path or standard or not any(token in status for token in invalid_tokens):
            continue
        out.append(
            _make_finding(
                rule_id=ind.id,
                severity=ind.severity_baseline,
                category="execution",
                title="Unsigned or invalidly signed Amcache executable",
                description=f"{path} has signing status {status or 'unknown'}.",
                row=row,
                followup="Verify the file signature and hash, then correlate its execution context.",
                confidence=0.88,
            )
        )
    return out


def _match_rdp_external(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    out: list[Finding] = []
    for row in _rows(parsed):
        if not _is_security_audit_event(row, 4624):
            continue
        logon_type = _int_value(_value(row, "logon_type", "logontype"))
        source_ip = _logon_ip(row)
        user = _logon_user(row)
        if logon_type == 10 and _global_ip(source_ip):
            out.append(
                _make_finding(
                    rule_id=ind.id,
                    severity=ind.severity_baseline,
                    category="initial_access",
                    title="Successful RDP logon from a globally routable IP",
                    description=f"LogonType 10 from {source_ip}",
                    row=row,
                    event_id=4624,
                    followup="Validate the source IP, account, and remote-access authorization.",
                    alternative_explanation=(
                        "This may be approved remote administration or traffic observed "
                        "through an organization-controlled VPN or jump host."
                    ),
                    confidence=0.98,
                    entities=_entity_map(users=(user,), ips=(source_ip,)),
                )
            )
    return out


def _match_rdp_offhours(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    """Detect RemoteInteractive logons outside the configured local work window."""
    out: list[Finding] = []
    for row in _rows(parsed):
        if not _is_security_audit_event(row, 4624):
            continue
        if _int_value(_value(row, "logon_type", "logontype")) != 10:
            continue
        timestamp = _parse_timestamp(_timestamp_text(row))
        if timestamp is None:
            continue
        local_time = timestamp.astimezone(
            timezone(timedelta(minutes=settings.RDP_UTC_OFFSET_MINUTES))
        )
        start = settings.RDP_BUSINESS_START_HOUR
        end = settings.RDP_BUSINESS_END_HOUR
        in_business_hours = (
            True
            if start == end
            else start <= local_time.hour < end
            if start < end
            else local_time.hour >= start or local_time.hour < end
        )
        if in_business_hours:
            continue
        user = _logon_user(row)
        source_ip = _logon_ip(row)
        out.append(
            _make_finding(
                rule_id=ind.id,
                severity=ind.severity_baseline,
                category="initial_access",
                title="RDP logon outside business hours",
                description=(
                    "Event ID 4624 LogonType 10 occurred at "
                    f"{local_time.isoformat()}, outside the configured "
                    f"{start:02d}:00-{end:02d}:00 business window."
                ),
                row=row,
                event_id=4624,
                timestamp=timestamp.isoformat(),
                followup="Validate the account, source host, and approved remote-access schedule.",
                alternative_explanation=(
                    "This may be approved after-hours support, scheduled work, or a "
                    "mismatch between the configured and host time zones."
                ),
                confidence=0.78,
                entities=_entity_map(users=(user,), ips=(source_ip,)),
            )
        )
    return out


def _match_service_install_temp(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    out: list[Finding] = []
    for row in _rows(parsed):
        event = _event_id(row)
        if event not in {4697, 7045}:
            continue
        if event == 4697 and not _is_security_audit_event(row, 4697):
            continue
        if event == 7045 and not _event_context_is(
            row,
            channel="System",
            providers={"service control manager"},
        ):
            continue
        image_path = _text(
            _value(
                row,
                "service_file_name",
                "servicefilename",
                "service_path",
                "servicepath",
                "image_path",
                "imagepath",
                "binary_path_name",
            )
        )
        if not _path_is_suspicious(image_path):
            continue
        out.append(
            _make_finding(
                rule_id=ind.id,
                severity=ind.severity_baseline,
                category="persistence",
                title="Service installed from a user-writable path",
                description=image_path,
                row=row,
                raw_excerpt=image_path,
                event_id=event,
                followup="Inspect the service binary, creator account, signature, and process tree.",
                alternative_explanation=(
                    "A legitimate installer may stage a service binary in a writable "
                    "directory before moving or removing it."
                ),
                confidence=0.97,
            )
        )
    return out


def _failed_logon_key(row: dict[str, Any]) -> str:
    source_ip = _logon_ip(row)
    if source_ip:
        return f"ip:{source_ip}"
    account = _logon_user(row)
    return f"account:{account}" if account else ""


def _match_failed_logon_burst(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    groups: dict[str, list[tuple[datetime | None, dict[str, Any]]]] = defaultdict(list)
    for row in _rows(parsed):
        if not _is_security_audit_event(row, 4625):
            continue
        key = _failed_logon_key(row)
        if key:
            groups[key].append((_parse_timestamp(_timestamp_text(row)), row))

    out: list[Finding] = []
    for key, entries in groups.items():
        if len(entries) < 10:
            continue
        timed = sorted(
            ((ts, row) for ts, row in entries if ts is not None),
            key=lambda item: item[0],
        )
        matched: list[tuple[datetime | None, dict[str, Any]]] = []
        if len(timed) >= 10:
            left = 0
            for right, (end, _) in enumerate(timed):
                while left <= right and (end - timed[left][0]).total_seconds() > 300:
                    left += 1
                if right - left + 1 >= 10:
                    matched = [(ts, row) for ts, row in timed[left : right + 1]]
                    break
        elif len(entries) >= 10:
            # Exporters without timestamps still provide useful burst evidence,
            # but confidence is reduced because the five-minute window is unknown.
            matched = entries[:10]
        if not matched:
            continue
        first_ts, first_row = matched[0]
        window_text = (
            " within five minutes" if first_ts else " (time window unavailable)"
        )
        out.append(
            _make_finding(
                rule_id=ind.id,
                severity=ind.severity_baseline,
                category="credential_access",
                title="Failed-logon burst",
                description=(
                    f"{len(matched)} Event ID 4625 records for {key}{window_text}."
                ),
                row=first_row,
                raw_excerpt=f"failed-logon-burst key={key} count={len(matched)}",
                event_id=4625,
                timestamp=first_ts.isoformat() if first_ts else "",
                followup="Correlate the source/account with a subsequent successful logon.",
                alternative_explanation=(
                    "Repeated failures may come from stale credentials, a misconfigured "
                    "service, or an unavailable domain controller."
                ),
                confidence=0.96 if first_ts else 0.75,
                entities=_principal_entities(key),
            )
        )
    return out


def _match_bruteforce_then_success(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    """Correlate ten rapid failures with a later success for the same principal."""
    failures: dict[str, list[tuple[datetime | None, int, dict[str, Any]]]] = defaultdict(list)
    emitted: set[str] = set()
    out: list[Finding] = []
    for index, row in enumerate(_rows(parsed)):
        event = _event_id(row)
        if event in {4624, 4625} and not _is_security_audit_event(row, event):
            continue
        key = _failed_logon_key(row)
        if not key:
            continue
        timestamp = _parse_timestamp(_timestamp_text(row))
        if event == 4625:
            failures[key].append((timestamp, index, row))
            continue
        if event != 4624 or key in emitted:
            continue
        prior = failures.get(key, [])
        if len(prior) < 10:
            continue

        correlated: list[tuple[datetime | None, int, dict[str, Any]]] = []
        if timestamp is not None:
            candidates = [
                item
                for item in prior
                if item[0] is not None
                and 0 <= (timestamp - item[0]).total_seconds() <= 600
            ]
            candidates.sort(key=lambda item: item[0])
            if len(candidates) >= 10:
                last_ten = candidates[-10:]
                if (last_ten[-1][0] - last_ten[0][0]).total_seconds() <= 300:
                    correlated = last_ten
        else:
            # Row order still establishes failure-before-success, but without
            # timestamps the time-window confidence is necessarily lower.
            correlated = prior[-10:]
        if len(correlated) < 10:
            continue

        emitted.add(key)
        out.append(
            _make_finding(
                rule_id=ind.id,
                severity=ind.severity_baseline,
                category="credential_access",
                title="Failed-logon burst followed by success",
                description=f"Ten Event ID 4625 failures for {key} preceded Event ID 4624.",
                row=row,
                raw_excerpt=f"brute-force-success key={key}; failures=10; events=4625->4624",
                event_id=4624,
                timestamp=timestamp.isoformat() if timestamp else "",
                followup="Treat the account as potentially compromised and inspect its subsequent activity.",
                alternative_explanation=(
                    "A user or service may have corrected stale credentials after "
                    "repeated authentication failures."
                ),
                confidence=0.98 if timestamp else 0.8,
                entities=_principal_entities(key),
            )
        )
    return out


def _event_account(row: dict[str, Any], event_id: int) -> str:
    if event_id == 4732:
        return _account(
            _value(row, "member_name", "membername", "target_user_name", "targetusername")
        )
    return _account(
        _value(row, "target_user_name", "targetusername", "account_name", "sam_account_name")
    )


def _is_privileged_local_group(row: dict[str, Any]) -> bool:
    group_sid = _text(
        _value(row, "target_sid", "targetsid", "group_sid", "groupsid")
    ).strip().casefold()
    group_name = _account(
        _value(row, "target_user_name", "targetusername", "group_name", "groupname")
    )
    return (
        group_sid in _PRIVILEGED_LOCAL_GROUP_SIDS
        or group_name in _PRIVILEGED_LOCAL_GROUP_NAMES
    )


def _match_account_created_then_grouped(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    created: dict[str, tuple[int, datetime | None, dict[str, Any]]] = {}
    emitted: set[str] = set()
    out: list[Finding] = []
    for index, row in enumerate(_rows(parsed)):
        event = _event_id(row)
        if event not in {4720, 4732}:
            continue
        if not _is_security_audit_event(row, event):
            continue
        account = _event_account(row, event)
        if not account:
            continue
        if event == 4720:
            created[account] = (index, _parse_timestamp(_timestamp_text(row)), row)
            continue
        if (
            account not in created
            or account in emitted
            or created[account][0] >= index
            or not _is_privileged_local_group(row)
        ):
            continue
        created_timestamp = created[account][1]
        grouped_timestamp = _parse_timestamp(_timestamp_text(row))
        if created_timestamp is not None and grouped_timestamp is not None:
            elapsed = (grouped_timestamp - created_timestamp).total_seconds()
            if not 0 <= elapsed <= _ACCOUNT_PRIVILEGE_WINDOW_SECONDS:
                continue
        emitted.add(account)
        out.append(
            _make_finding(
                rule_id=ind.id,
                severity=ind.severity_baseline,
                category="persistence",
                title="New account added to a privileged local group",
                description=(
                    f"Account {account} was created (4720) and then added to a "
                    "privileged local group (4732)."
                ),
                row=row,
                raw_excerpt=f"account={account}; events=4720->4732",
                event_id=4732,
                followup="Validate the account owner and inspect all activity by the new account.",
                alternative_explanation=(
                    "This may be authorized account provisioning by an administrator "
                    "or identity-management workflow."
                ),
                confidence=(
                    0.97
                    if created_timestamp is not None and grouped_timestamp is not None
                    else 0.72
                ),
                entities=_entity_map(users=(account,)),
            )
        )
    return out


def _match_log_clear(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    out: list[Finding] = []
    for row in _rows(parsed):
        event = _event_id(row)
        if event == 1102:
            valid_context = _event_context_is(
                row,
                channel="Security",
                providers={"microsoft-windows-eventlog"},
            )
        elif event == 104:
            valid_context = _event_context_is(
                row,
                channel="System",
                providers={"microsoft-windows-eventlog"},
            )
        else:
            continue
        if not valid_context:
            continue
        user = _account(
            _value(
                row,
                "subject_user_name",
                "subjectusername",
                "user_name",
                "username",
            )
        )
        out.append(
            _make_finding(
                rule_id=f"{ind.id}:{event}",
                severity=ind.severity_baseline,
                category="defense_evasion",
                title="Windows event log cleared",
                description=f"Event ID {event} records log clearing.",
                row=row,
                event_id=event,
                followup="Preserve remaining logs and identify the account/process that cleared them.",
                alternative_explanation=(
                    "An administrator or maintenance task may have intentionally cleared "
                    "the log, but the resulting loss of visibility still requires review."
                ),
                confidence=0.99,
                entities=_entity_map(users=(user,)),
            )
        )
    return out


_ENCODED_PS_RE = re.compile(
    r"(?i)(?:-(?:enc|encodedcommand)\b|frombase64string\s*\(|[A-Za-z0-9+/]{80,}={0,2})"
)


def _match_powershell_encoded(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    out: list[Finding] = []
    for row in _rows(parsed):
        if _event_id(row) != 4104 or not _event_context_is(
            row,
            channel="Microsoft-Windows-PowerShell/Operational",
            providers={"microsoft-windows-powershell"},
        ):
            continue
        script = _text(
            _value(row, "script_block_text", "scriptblocktext", "message", "command_line")
        )
        if not _ENCODED_PS_RE.search(script):
            continue
        out.append(
            _make_finding(
                rule_id=ind.id,
                severity=ind.severity_baseline,
                category="execution",
                title="Encoded PowerShell command",
                description="Event ID 4104 contains encoded or Base64-decoding PowerShell.",
                row=row,
                raw_excerpt=script,
                event_id=4104,
                followup="Decode the command in an isolated environment and trace its parent process.",
                alternative_explanation=(
                    "Encoded PowerShell is also used by legitimate deployment, "
                    "configuration-management, and administration tooling."
                ),
                confidence=0.96,
            )
        )
    return out


def _bool_false(value: Any) -> bool:
    return _text(value).strip().casefold() in {"false", "0", "no", "n", "deleted"}


def _match_mft_deleted_temp_exe(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    out: list[Finding] = []
    for row in _rows(parsed):
        filename = _text(_value(row, "file_name", "filename", "name"))
        parent = _text(_value(row, "parent_path", "parentpath", "directory"))
        full_path = _text(_value(row, "full_path", "fullpath", "path"))
        path = full_path or f"{parent}\\{filename}".strip("\\")
        extension = _text(_value(row, "extension", "file_extension")).casefold().lstrip(".")
        is_exe = extension in {"exe", "dll"} or filename.casefold().endswith((".exe", ".dll"))
        deleted = _bool_false(_value(row, "in_use", "inuse")) or _text(
            _value(row, "deleted", "is_deleted")
        ).casefold() in {"true", "1", "yes"}
        if is_exe and deleted and _path_is_suspicious(path):
            out.append(
                _make_finding(
                    rule_id=ind.id,
                    severity=ind.severity_baseline,
                    category="file_activity",
                    title="Deleted executable in a temporary path",
                    description=path,
                    row=row,
                    source_file=path,
                    followup="Recover the file from disk/unallocated space and correlate execution artifacts.",
                    alternative_explanation=(
                        "Installers, updaters, and application cleanup commonly delete "
                        "temporary executables and libraries."
                    ),
                    confidence=0.78,
                )
            )
    return out


def _match_mft_timestomp(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    out: list[Finding] = []
    for row in _rows(parsed):
        si_created = _parse_timestamp(
            _text(
                _value(
                    row,
                    "created0x10",
                    "si_created",
                    "sicreated",
                    "standard_information_created",
                )
            )
        )
        fn_created = _parse_timestamp(
            _text(
                _value(
                    row,
                    "created0x30",
                    "fn_created",
                    "fncreated",
                    "file_name_created",
                )
            )
        )
        si_modified = _parse_timestamp(
            _text(
                _value(
                    row,
                    "lastmodified0x10",
                    "modified0x10",
                    "si_modified",
                    "simodified",
                )
            )
        )
        anomaly = (
            si_created is not None
            and fn_created is not None
            and (si_created - fn_created).total_seconds() > 1
        ) or (
            si_created is not None
            and si_modified is not None
            and (si_created - si_modified).total_seconds() > 1
        )
        if not anomaly:
            continue
        out.append(
            _make_finding(
                rule_id=ind.id,
                severity=ind.severity_baseline,
                category="defense_evasion",
                title="MFT timestamp inconsistency",
                description="$STANDARD_INFORMATION and $FILE_NAME timestamps have an implausible order.",
                row=row,
                followup="Compare all SI/FN timestamps with USN journal and adjacent MFT records.",
                confidence=0.86,
            )
        )
    return out


def _match_mft_ads(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    out: list[Finding] = []
    for row in _rows(parsed):
        filename = _text(_value(row, "file_name", "filename", "name"))
        if not filename:
            path = _text(_value(row, "full_path", "fullpath", "path"))
            filename = path.replace("/", "\\").rsplit("\\", 1)[-1]
        if ":" not in filename:
            continue
        stream = filename.split(":", 1)[1].strip().casefold()
        if not stream or stream in {"$data", "zone.identifier", "zone.identifier:$data"}:
            continue
        out.append(
            _make_finding(
                rule_id=ind.id,
                severity=ind.severity_baseline,
                category="defense_evasion",
                title="Alternate Data Stream recorded in MFT",
                description=filename,
                row=row,
                followup="Extract and inspect the named stream; verify whether it contains executable content.",
                confidence=0.9,
            )
        )
    return out


def _prefetch_executable(row: dict[str, Any]) -> str:
    return " ".join(
        (
            _text(_value(row, "executable_name", "executablename", "file_name", "filename")),
            _text(_value(row, "executable_path", "executablepath", "full_path", "path")),
        )
    )


def _match_prefetch_unusual_path(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    out: list[Finding] = []
    for row in _rows(parsed):
        executable = _prefetch_executable(row)
        if _path_is_suspicious(executable) and not _contains_credential_tool(executable):
            out.append(
                _make_finding(
                    rule_id=ind.id,
                    severity=ind.severity_baseline,
                    category="execution",
                    title="Prefetch executable in a user-writable path",
                    description=executable[:300],
                    row=row,
                    followup="Recover and hash the executable and inspect its launch context.",
                    confidence=0.9,
                )
            )
    return out


def _match_prefetch_credential_tool(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    out: list[Finding] = []
    for row in _rows(parsed):
        executable = _prefetch_executable(row)
        if _contains_credential_tool(executable):
            out.append(
                _make_finding(
                    rule_id=ind.id,
                    severity=ind.severity_baseline,
                    category="credential_access",
                    title="Credential-access utility in Prefetch",
                    description=executable[:300],
                    row=row,
                    followup="Inspect the process tree and credential-access telemetry at this run time.",
                    alternative_explanation=(
                        "The tool may have been run during authorized security testing; "
                        "Prefetch proves execution, not successful credential extraction."
                    ),
                    confidence=0.93,
                )
            )
    return out


def _match_prefetch_lsass_reference(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    out: list[Finding] = []
    for row in _rows(parsed):
        loaded = _text(
            _value(row, "files_loaded", "filesloaded", "referenced_files", "directories")
        )
        # FilesLoaded containing LSASS.EXE proves only a file reference
        # (Task Manager does this), not process-memory access. Require a dump
        # filename before raising a credential-access finding.
        if re.search(r"(?i)\blsass[^\\/:]*\.dmp\b", loaded):
            out.append(
                _make_finding(
                    rule_id=ind.id,
                    severity=ind.severity_baseline,
                    category="credential_access",
                    title="Prefetch references an LSASS dump file",
                    description=loaded[:300],
                    row=row,
                    followup="Determine whether the executable opened or dumped LSASS memory.",
                    alternative_explanation=(
                        "The dump may come from authorized incident response or crash "
                        "diagnostics; Prefetch alone does not prove credential extraction."
                    ),
                    confidence=0.92,
                )
            )
    return out


def _packet_timestamp(row: dict[str, Any]) -> str:
    value = _text(_value(row, "frame.time_epoch", "frame_time_epoch")).strip()
    try:
        parsed = datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (OSError, OverflowError, TypeError, ValueError):
        return ""
    return parsed.isoformat().replace("+00:00", "Z")


def _match_pcap_suspicious_remote_port(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    suspicious_ports = {1337, 4444, 5555, 6667, 9001, 9050}
    out: list[Finding] = []
    for row in _rows(parsed):
        destination = _text(_value(row, "ip.dst", "ipv6.dst", "destination_ip")).strip()
        port = _int_value(_value(row, "tcp.dstport", "udp.dstport", "destination_port"))
        if port not in suspicious_ports or not _global_ip(destination):
            continue
        out.append(
            _make_finding(
                rule_id=ind.id,
                severity=ind.severity_baseline,
                category="network_anomaly",
                title="Network traffic to a global address on a suspicious port",
                description=f"{destination}:{port} appeared in the packet capture.",
                row=row,
                timestamp=_packet_timestamp(row),
                followup="Validate the endpoint and owning process against approved remote-access services.",
                alternative_explanation=(
                    "Developer tunnels or approved remote-access software can use the same port."
                ),
                confidence=0.82,
                entities=_entity_map(ips=(destination,)),
            )
        )
    return out


def _match_pcap_long_dns_query(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    out: list[Finding] = []
    for row in _rows(parsed):
        query = _text(_value(row, "dns.qry.name", "dns_query_name")).strip().rstrip(".")
        txt = _text(_value(row, "dns.txt", "dns_txt")).strip()
        labels = query.split(".") if query else []
        encoded_label = any(
            len(label) >= 40
            and len(set(label.casefold())) >= 12
            and re.fullmatch(r"[A-Za-z0-9_-]+", label) is not None
            for label in labels
        )
        long_query = len(query) >= 150 and encoded_label
        long_txt = len(txt) >= 300 and re.fullmatch(r"[A-Za-z0-9+/=_ -]+", txt) is not None
        if not long_query and not long_txt:
            continue
        value = query if long_query else txt
        out.append(
            _make_finding(
                rule_id=ind.id,
                severity=ind.severity_baseline,
                category="network_anomaly",
                title="Unusually long encoded-looking DNS data",
                description=value[:300],
                row=row,
                timestamp=_packet_timestamp(row),
                followup="Compare repeated DNS payloads and query volume with approved DNS-based services.",
                alternative_explanation=(
                    "CDNs and approved DNS-based services can produce long encoded records."
                ),
                confidence=0.76,
            )
        )
    return out


def _match_browser_suspicious_download(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    suspicious_suffixes = (
        ".bat",
        ".cmd",
        ".com",
        ".dll",
        ".exe",
        ".hta",
        ".js",
        ".msi",
        ".ps1",
        ".scr",
        ".vbs",
    )
    out: list[Finding] = []
    for row in _rows(parsed):
        record_type = _text(_value(row, "record_type")).strip().casefold()
        if record_type != "browser_download":
            continue
        path = _text(_value(row, "target_path", "current_path")).strip()
        if not _basename(path).casefold().endswith(suspicious_suffixes):
            continue
        url = _text(_value(row, "url")).strip()
        out.append(
            _make_finding(
                rule_id=ind.id,
                severity=ind.severity_baseline,
                category="file_acquisition",
                title="Browser downloaded executable or script content",
                description=f"{path or '(unknown path)'} from {url or '(unknown URL)'}"[:300],
                row=row,
                followup="Hash the downloaded file and validate its signature, source, and subsequent execution.",
                alternative_explanation=(
                    "The download may be an approved installer or administrator-supplied script; "
                    "download history does not prove execution."
                ),
                confidence=0.86,
            )
        )
    return out


def _match_fls_deleted_suspicious_file(
    parsed: Any, raw: str, meta: ToolMetadata, ind: SuspiciousIndicator
) -> list[Finding]:
    suspicious_suffixes = (
        ".bat",
        ".cmd",
        ".com",
        ".dll",
        ".exe",
        ".hta",
        ".js",
        ".ps1",
        ".scr",
        ".vbs",
    )
    out: list[Finding] = []
    for line in raw.splitlines():
        match = re.match(r"^\S+\s+\*\s+[^:]+:\s*(?P<path>.+)$", line.strip())
        if match is None:
            continue
        path = match.group("path").split("\t", 1)[0].strip()
        if not _basename(path).casefold().endswith(suspicious_suffixes):
            continue
        if not _path_is_suspicious(path):
            continue
        out.append(
            _make_finding(
                rule_id=ind.id,
                severity=ind.severity_baseline,
                category="defense_evasion",
                title="Deleted executable or script in a commonly abused path",
                description=path[:300],
                raw_excerpt=line,
                followup="Recover the deleted entry where possible, hash it, and correlate execution artifacts.",
                confidence=0.88,
            )
        )
    return out


_SPECIFIC_MATCHERS: dict[str, Matcher] = {
    "sigma_rule_hit": _match_sigma_rule_hit,
    "run_key_unusual_binary": _match_registry_temp_persistence,
    "run_key_in_temp_path": _match_registry_temp_persistence,
    "service_imagepath_random": _match_registry_service_image,
    "service_imagepath_suspicious": _match_registry_service_image,
    "image_file_execution_debugger": _match_registry_ifeo_debugger,
    "applnit_dlls": _match_registry_appinit,
    "winlogon_shell_modified": _match_registry_winlogon_shell,
    "userassist_temp_execution": _match_userassist_temp,
    "userassist_unsigned_in_temp": _match_userassist_temp,
    "abnormal_parent_child": _match_volatility_parent_child,
    "process_in_unusual_path": _match_volatility_unusual_path,
    "netscan_to_known_bad_or_rare_ip": _match_volatility_rare_network,
    "malfind_pe_in_unbacked_region": _match_malfind_pe_unbacked,
    "bandit_issue": _match_bandit_issue,
    "bandit_high": _no_duplicate_supplement,
    "semgrep_issue": _match_semgrep_issue,
    "semgrep_high": _no_duplicate_supplement,
    "gitleaks_secret": _match_gitleaks_secret,
    "gitleaks_aws_key": _no_duplicate_supplement,
    "amcache_unassociated_in_temp": _match_amcache_temp,
    "amcache_signing_status_invalid": _match_amcache_invalid_signature,
    "amcache_credential_dump_tool": _match_amcache_credential_tool,
    "rdp_logon_external_ip": _match_rdp_external,
    "rdp_logon_offhours": _match_rdp_offhours,
    "failed_logon_burst": _match_failed_logon_burst,
    "brute_force_followed_by_success": _match_bruteforce_then_success,
    "service_install_4697": _match_service_install_temp,
    "account_creation_4720": _match_account_created_then_grouped,
    "clear_log_event": _match_log_clear,
    "powershell_encoded_command": _match_powershell_encoded,
    "deleted_executable_in_temp": _match_mft_deleted_temp_exe,
    "timestomp_inconsistency": _match_mft_timestomp,
    "ads_alternate_data_stream": _match_mft_ads,
    "prefetch_unusual_path": _match_prefetch_unusual_path,
    "prefetch_with_credential_tools": _match_prefetch_credential_tool,
    "prefetch_referenced_lsass_dump": _match_prefetch_lsass_reference,
    "pcap_suspicious_remote_port": _match_pcap_suspicious_remote_port,
    "pcap_long_dns_query": _match_pcap_long_dns_query,
    "browser_suspicious_download": _match_browser_suspicious_download,
    "fls_deleted_suspicious_file": _match_fls_deleted_suspicious_file,
}

_EVTX_EVENT_IDS: dict[str, tuple[int, ...]] = {
    "rdp_logon_external_ip": (4624,),
    "rdp_logon_offhours": (4624,),
    "brute_force_followed_by_success": (4624, 4625),
    "failed_logon_burst": (4625,),
    "service_install_4697": (4697, 7045),
    "account_creation_4720": (4720, 4732),
    "clear_log_event": (104, 1102),
    "powershell_encoded_command": (4104,),
}


def supported_indicator_ids() -> frozenset[str]:
    """Return IDs backed by concrete deterministic implementations."""
    return frozenset(_SPECIFIC_MATCHERS)


def apply_rules_with_status(
    parsed: Any,
    raw: str,
    metadata: ToolMetadata,
    *,
    evidence_path: str = "",
    failed_rule_ids: list[str] | None = None,
) -> tuple[list[Finding], bool]:
    """Return retained findings and whether any candidate was dropped."""
    out: list[Finding] = []
    limit_reached = False
    event_index: dict[int, list[tuple[int, dict[str, Any]]]] | None = None
    if "evtx_log" in metadata.applicable_evidence_types and any(
        indicator.id in _EVTX_EVENT_IDS
        for indicator in metadata.suspicious_indicators
    ):
        event_index = defaultdict(list)
        for position, row in enumerate(_rows(parsed)):
            event_id = _event_id(row)
            if event_id is not None:
                event_index[event_id].append((position, row))

    for indicator in metadata.suspicious_indicators:
        matcher = _SPECIFIC_MATCHERS.get(indicator.id)
        if matcher is None:
            logger.warning(
                "unsupported suspicious indicator id=%r for tool=%s; no finding emitted",
                indicator.id,
                metadata.tool_id,
            )
            continue
        matcher_input = parsed
        event_ids = _EVTX_EVENT_IDS.get(indicator.id)
        if event_index is not None and event_ids is not None:
            ordered = heapq.merge(
                *(event_index.get(event_id, ()) for event_id in event_ids),
                key=lambda item: item[0],
            )
            matcher_input = {"items": [row for _, row in ordered]}
        try:
            findings = matcher(matcher_input, raw, metadata, indicator)
        except Exception as exc:  # noqa: BLE001 - isolate individual rules
            logger.warning(
                "rule %s for tool %s raised: %s",
                indicator.id,
                metadata.tool_id,
                exc,
            )
            if failed_rule_ids is not None:
                failed_rule_ids.append(indicator.id)
            continue
        for finding in findings:
            if not finding.evidence_ref.source_file and evidence_path:
                finding.evidence_ref.source_file = evidence_path
            finding.refresh_fingerprint()
        candidate_count = len(out) + len(findings)
        if candidate_count <= MAX_RULE_FINDINGS:
            out.extend(findings)
            continue
        limit_reached = True
        out = heapq.nlargest(
            MAX_RULE_FINDINGS,
            chain(out, findings),
            key=lambda finding: (
                SEVERITY_RANK[finding.severity],
                finding.confidence,
            ),
        )
    if limit_reached:
        logger.warning(
            "finding cap reached for tool=%s (%d); retained by severity",
            metadata.tool_id,
            MAX_RULE_FINDINGS,
        )
    return out, limit_reached


def apply_rules(
    parsed: Any,
    raw: str,
    metadata: ToolMetadata,
    *,
    evidence_path: str = "",
) -> list[Finding]:
    """Apply only explicitly implemented indicators from ``metadata``."""
    findings, _ = apply_rules_with_status(
        parsed,
        raw,
        metadata,
        evidence_path=evidence_path,
    )
    return findings


def severity_at_least(severity: Severity, threshold: Severity) -> bool:
    from forensicagent.analyzer.types import SEVERITY_RANK

    return SEVERITY_RANK[severity] >= SEVERITY_RANK[threshold]
