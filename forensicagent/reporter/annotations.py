"""Bounded, strict persistence for analyst finding annotations."""

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal

AnnotationStatus = Literal["pending", "confirmed", "false_positive"]

ANNOTATION_FILENAME = "analyst_annotations.json"
ANNOTATION_SCHEMA_VERSION = 1
ANNOTATION_STATUSES = frozenset({"pending", "confirmed", "false_positive"})
MAX_ANNOTATION_FILE_BYTES = 5 * 1024 * 1024
MAX_ANNOTATIONS = 10_000
MAX_ANNOTATION_NOTES = 4_096

_FINGERPRINT_RE = re.compile(r"[0-9a-f]{64}\Z")


class AnnotationStoreError(ValueError):
    """The existing annotation store is unsafe or incompatible."""


def annotation_path(output_dir: str | Path) -> Path:
    return Path(output_dir) / ANNOTATION_FILENAME


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_non_json_constant(value: str) -> None:
    raise ValueError(f"non-JSON numeric constant: {value}")


def _validate_updated_at(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise AnnotationStoreError("updated_at must be a non-empty UTC timestamp")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise AnnotationStoreError("updated_at is not an ISO timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise AnnotationStoreError("updated_at must include the UTC offset")
    return value


def _validate_annotation(fingerprint: Any, value: Any) -> dict[str, str]:
    if not isinstance(fingerprint, str) or _FINGERPRINT_RE.fullmatch(fingerprint) is None:
        raise AnnotationStoreError("annotation keys must be lowercase SHA-256 fingerprints")
    if not isinstance(value, dict) or set(value) != {"status", "notes", "updated_at"}:
        raise AnnotationStoreError("annotation entries have an unknown schema")
    status = value["status"]
    notes = value["notes"]
    if not isinstance(status, str) or status not in ANNOTATION_STATUSES:
        raise AnnotationStoreError(f"unknown annotation status for {fingerprint}")
    if not isinstance(notes, str) or len(notes) > MAX_ANNOTATION_NOTES:
        raise AnnotationStoreError(f"annotation notes are invalid for {fingerprint}")
    try:
        notes.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise AnnotationStoreError(
            f"annotation notes are not valid Unicode for {fingerprint}"
        ) from exc
    return {
        "status": status,
        "notes": notes,
        "updated_at": _validate_updated_at(value["updated_at"]),
    }


def load_annotations(output_dir: str | Path) -> dict[str, dict[str, str]]:
    """Load a case store without accepting unbounded or unknown input."""
    path = annotation_path(output_dir)
    if not path.exists():
        return {}
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_ANNOTATION_FILE_BYTES + 1)
    except OSError as exc:
        raise AnnotationStoreError(f"cannot read annotation store: {exc}") from exc
    if len(raw) > MAX_ANNOTATION_FILE_BYTES:
        raise AnnotationStoreError("annotation store exceeds the size limit")
    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_non_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise AnnotationStoreError("annotation store is not valid strict JSON") from exc
    if not isinstance(payload, dict) or set(payload) != {"schema_version", "annotations"}:
        raise AnnotationStoreError("annotation store has an unknown schema")
    if (
        type(payload["schema_version"]) is not int
        or payload["schema_version"] != ANNOTATION_SCHEMA_VERSION
    ):
        raise AnnotationStoreError("annotation store has an unsupported schema version")
    annotations = payload["annotations"]
    if not isinstance(annotations, dict) or len(annotations) > MAX_ANNOTATIONS:
        raise AnnotationStoreError("annotation collection is invalid or too large")
    return {
        fingerprint: _validate_annotation(fingerprint, value)
        for fingerprint, value in annotations.items()
    }


def save_annotation(
    output_dir: str | Path,
    fingerprint: str,
    status: str,
    notes: str | None = None,
) -> dict[str, str]:
    """Atomically update one fingerprint, refusing unsafe existing stores."""
    if _FINGERPRINT_RE.fullmatch(fingerprint) is None:
        raise AnnotationStoreError("fingerprint must be a lowercase SHA-256 value")
    if status not in ANNOTATION_STATUSES:
        raise AnnotationStoreError(f"unknown annotation status: {status}")
    if notes is not None and len(notes) > MAX_ANNOTATION_NOTES:
        raise AnnotationStoreError(
            f"annotation notes exceed {MAX_ANNOTATION_NOTES} characters"
        )
    if notes is not None:
        try:
            notes.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise AnnotationStoreError("annotation notes are not valid Unicode") from exc

    annotations = load_annotations(output_dir)
    if len(annotations) >= MAX_ANNOTATIONS and fingerprint not in annotations:
        raise AnnotationStoreError("annotation store reached its entry limit")
    previous = annotations.get(fingerprint, {})
    annotation = {
        "status": status,
        "notes": previous.get("notes", "") if notes is None else notes,
        "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    annotations[fingerprint] = annotation
    payload = {
        "schema_version": ANNOTATION_SCHEMA_VERSION,
        "annotations": annotations,
    }
    encoded = json.dumps(
        payload, ensure_ascii=False, indent=2, sort_keys=True
    ).encode("utf-8")
    if len(encoded) > MAX_ANNOTATION_FILE_BYTES:
        raise AnnotationStoreError("annotation store would exceed the size limit")

    path = annotation_path(output_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        # ponytail: this local case store assumes one analyst writer at a time.
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise AnnotationStoreError(f"cannot save annotation store: {exc}") from exc
    return dict(annotation)
