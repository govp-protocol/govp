"""GOVP-STATUS-1 online status and key-lifecycle evaluation."""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from os import PathLike
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .core import (
    GOVP_ID_PATTERN,
    _rfc3339_utc_datetime,
    _valid_absolute_url,
    _valid_base64_length,
    _valid_rfc3339_utc,
    normalize_canonical,
    sha256,
    verify,
)

KEY_STATES = frozenset({"active", "retired", "revoked"})
REVOCATION_REASONS = frozenset(
    {"compromised", "superseded", "withdrawn", "cessation", "other"}
)
STATUS_FIELDS = frozenset(
    {
        "format",
        "canonical",
        "publisher",
        "authority",
        "generated_at",
        "keys",
        "revoked_records",
    }
)
KEY_FIELDS = frozenset({"key_id", "public_key", "state", "changed_at"})
REVOCATION_FIELDS = frozenset({"govp_id", "revoked_at", "reason"})
DEFAULT_STATUS_MAX_AGE_SECONDS = 300
DEFAULT_STATUS_MAX_FUTURE_SKEW_SECONDS = 60


@dataclass(frozen=True)
class StatusResult:
    """Result of applying a GOVP-STATUS-1 snapshot to one GOVP-1 record."""

    currently_trusted: bool | None
    snapshot_trusted: bool
    checks: dict[str, bool | None]
    reasons: tuple[str, ...] = ()

    @property
    def snapshot_valid(self) -> bool:
        """Whether the saved snapshot is internally valid, not proof of liveness."""
        return self.snapshot_trusted


def derive_key_id(public_key: str) -> str:
    """Derive the collision-resistant identifier for a raw Ed25519 key."""
    try:
        raw = base64.b64decode(public_key, validate=True)
    except (TypeError, ValueError) as error:
        raise ValueError("public key must be base64") from error
    if len(raw) != 32:
        raise ValueError("public key must contain 32 raw Ed25519 bytes")
    return f"sha256:{sha256(raw)}"


def parse_status(text: str) -> dict[str, Any]:
    """Parse a GOVP-STATUS-1 JSON document without performing trust policy."""
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise TypeError("status document must be a JSON object")
    return payload


def load_status(path: str | PathLike[str]) -> dict[str, Any]:
    """Load a GOVP-STATUS-1 JSON document from any path-like value."""
    return parse_status(Path(path).read_text(encoding="utf-8"))


def _origin(value: str) -> tuple[str, str, int] | None:
    if not _valid_absolute_url(value, https_only=True):
        return None
    try:
        parsed = urlsplit(value)
        port = parsed.port if parsed.port is not None else 443
    except ValueError:
        return None
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), port


def _status_format_ok(status: Mapping[str, Any]) -> bool:
    if (
        set(status) != STATUS_FIELDS
        or status.get("format") != "GOVP-STATUS-1"
        or status.get("authority") != "https-origin"
        or not isinstance(status.get("publisher"), str)
        or not status["publisher"]
        or not isinstance(status.get("canonical"), str)
        or not _valid_absolute_url(status["canonical"], https_only=True)
        or not isinstance(status.get("generated_at"), str)
        or not _valid_rfc3339_utc(status["generated_at"])
        or not isinstance(status.get("keys"), list)
        or not status["keys"]
        or not isinstance(status.get("revoked_records"), list)
    ):
        return False

    key_ids: set[str] = set()
    public_keys: set[str] = set()
    for entry in status["keys"]:
        if not isinstance(entry, dict) or set(entry) != KEY_FIELDS:
            return False
        key_id = entry.get("key_id")
        public_key = entry.get("public_key")
        if (
            not isinstance(key_id, str)
            or not isinstance(public_key, str)
            or not _valid_base64_length(public_key, 32)
            or entry.get("state") not in KEY_STATES
            or not isinstance(entry.get("changed_at"), str)
            or not _valid_rfc3339_utc(entry["changed_at"])
        ):
            return False
        try:
            expected_key_id = derive_key_id(public_key)
        except ValueError:
            return False
        if key_id != expected_key_id or key_id in key_ids or public_key in public_keys:
            return False
        key_ids.add(key_id)
        public_keys.add(public_key)

    revoked_ids: set[str] = set()
    for entry in status["revoked_records"]:
        if not isinstance(entry, dict) or set(entry) != REVOCATION_FIELDS:
            return False
        govp_id = entry.get("govp_id")
        if (
            not isinstance(govp_id, str)
            or GOVP_ID_PATTERN.fullmatch(govp_id) is None
            or govp_id in revoked_ids
            or not isinstance(entry.get("revoked_at"), str)
            or not _valid_rfc3339_utc(entry["revoked_at"])
            or entry.get("reason") not in REVOCATION_REASONS
        ):
            return False
        revoked_ids.add(govp_id)
    return True


def status_format_ok(status: Mapping[str, Any]) -> bool:
    """Return whether a decoded object satisfies the GOVP-STATUS-1 shape."""
    return _status_format_ok(status)


def _status_fresh(
    status: Mapping[str, Any],
    *,
    now: datetime,
    max_age_seconds: int,
    max_future_skew_seconds: int,
) -> bool:
    generated_at = status.get("generated_at")
    if not isinstance(generated_at, str):
        return False
    generated = _rfc3339_utc_datetime(generated_at)
    if generated is None:
        return False
    return (
        now - timedelta(seconds=max_age_seconds)
        <= generated
        <= now + timedelta(seconds=max_future_skew_seconds)
    )


def evaluate_status(
    fields: dict[str, str],
    status: Mapping[str, Any],
    *,
    fetched_url: str | None = None,
    record_fetched_url: str | None = None,
    now: datetime | None = None,
    max_age_seconds: int = DEFAULT_STATUS_MAX_AGE_SECONDS,
    max_future_skew_seconds: int = DEFAULT_STATUS_MAX_FUTURE_SKEW_SECONDS,
) -> StatusResult:
    """Apply a status snapshot; live trust requires its canonical HTTPS fetch.

    Offline evaluation can validate the snapshot but deliberately returns
    ``currently_trusted=None`` because a saved file cannot prove current
    liveness.
    """
    if max_age_seconds < 0 or max_future_skew_seconds < 0:
        raise ValueError("status freshness windows must be non-negative")
    evaluation_time = now or datetime.now(timezone.utc)
    if evaluation_time.utcoffset() is None:
        raise ValueError("status evaluation time must be timezone-aware")
    evaluation_time = evaluation_time.astimezone(timezone.utc)

    core_result = verify(fields, fetched_url=record_fetched_url)
    normalized_fields = core_result.fields
    core_valid = core_result.ok
    format_ok = _status_format_ok(status)
    status_fresh = bool(
        format_ok
        and _status_fresh(
            status,
            now=evaluation_time,
            max_age_seconds=max_age_seconds,
            max_future_skew_seconds=max_future_skew_seconds,
        )
    )
    status_canonical = status.get("canonical")
    canonical_ok: bool | None = None
    if fetched_url is not None:
        canonical_ok = bool(
            format_ok
            and isinstance(status_canonical, str)
            and normalize_canonical(status_canonical)
            == normalize_canonical(fetched_url)
        )
    same_origin = bool(
        format_ok
        and isinstance(status_canonical, str)
        and _origin(normalized_fields.get("canonical", "")) == _origin(status_canonical)
    )
    key_authorized = False
    if format_ok:
        key_authorized = any(
            entry["public_key"] == normalized_fields.get("public-key")
            and entry["state"] == "active"
            for entry in status["keys"]
        )
    record_not_revoked = False
    if format_ok:
        govp_id = normalized_fields.get("govp-id")
        record_not_revoked = bool(govp_id) and govp_id not in {
            entry["govp_id"] for entry in status["revoked_records"]
        }
    checks: dict[str, bool | None] = {
        "core": core_valid,
        "status-format": format_ok,
        "status-fresh": status_fresh,
        "status-canonical": canonical_ok,
        "same-origin": same_origin,
        "key-active": key_authorized,
        "record-not-revoked": record_not_revoked,
    }
    snapshot_trusted = all(
        (core_valid, format_ok, same_origin, key_authorized, record_not_revoked)
    )
    online = fetched_url is not None and record_fetched_url is not None
    currently_trusted = (
        snapshot_trusted and status_fresh and canonical_ok is True if online else None
    )
    reasons = tuple(name for name, value in checks.items() if value is False)
    return StatusResult(currently_trusted, snapshot_trusted, checks, reasons)
