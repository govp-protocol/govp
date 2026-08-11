"""Reference GOVP-EXT-1 evidence-envelope primitives."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .core import _ED25519_L, _valid_ed25519_subgroup_encoding

ENVELOPE_DOMAIN = b"GOVP::extension-envelope.v1\x00"
MAX_SAFE_INTEGER = 2**53 - 1
ENVELOPE_KEYS = frozenset(
    {
        "govp",
        "extension",
        "type",
        "id",
        "issuer",
        "subject",
        "created_at",
        "hash",
        "payload",
        "references",
        "evidence",
        "origin",
        "signature",
    }
)
UNSIGNED_ENVELOPE_KEYS = ENVELOPE_KEYS - {"signature"}
ORIGINS = frozenset(
    {"system_observed", "artifact_derived", "human_asserted", "upstream_attested"}
)
EXTERNAL_ATTESTATION_FORMATS = frozenset(
    {
        "application/vnd.in-toto+json",
        "application/vnd.dev.sigstore.bundle+json;version=0.3",
        "application/vnd.rekor.entry+json",
        "application/timestamp-reply",
    }
)
TYPE_PATTERN = re.compile(r"^[a-z0-9]+(?:\.[a-z0-9-]+)+/[1-9][0-9]*$")
EXTENSION_PATTERN = re.compile(r"^[a-z0-9]+(?:\.[a-z0-9-]+)+$")
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
TIMESTAMP_PATTERN = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$"
)
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_ENVELOPE_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class EnvelopeVerification:
    ok: bool
    checks: dict[str, bool | None]
    signing_input_sha256: str | None
    warnings: tuple[str, ...] = ()


def _object_without_duplicate_names(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError(f"duplicate JSON object name: {name}")
        result[name] = value
    return result


def parse_envelope(text: str) -> dict[str, Any]:
    """Parse a bounded GOVP-EXT-1 JSON envelope without losing duplicates."""
    if not isinstance(text, str):
        raise TypeError("envelope must be JSON text")
    if len(text.encode("utf-8")) > MAX_ENVELOPE_BYTES:
        raise ValueError("envelope exceeds the 4 MiB limit")
    value = json.loads(text, object_pairs_hook=_object_without_duplicate_names)
    if not isinstance(value, dict):
        raise TypeError("envelope must be a JSON object")
    return value


def load_envelope(path: str | Path) -> dict[str, Any]:
    """Load a bounded UTF-8 GOVP-EXT-1 envelope from disk."""
    raw = Path(path).read_bytes()
    if len(raw) > MAX_ENVELOPE_BYTES:
        raise ValueError("envelope exceeds the 4 MiB limit")
    try:
        return parse_envelope(raw.decode("utf-8", errors="strict"))
    except UnicodeDecodeError as error:
        raise ValueError("envelope is not valid UTF-8") from error


def _valid_scalar_string(value: Any, *, maximum: int = 200) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= maximum
        and "\x00" not in value
        and "\r" not in value
        and "\n" not in value
        and not any(0xD800 <= ord(character) <= 0xDFFF for character in value)
    )


def _valid_https_url(value: Any, *, canonical_identity: bool = False) -> bool:
    if not isinstance(value, str) or len(value) > 2048:
        return False
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    valid = (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
        and not parsed.fragment
    )
    if canonical_identity:
        valid = valid and parsed.path == "/.well-known/govp.txt" and not parsed.query
    return valid


def _validate_json_value(value: Any, *, depth: int = 0) -> None:
    if depth > 64:
        raise ValueError("envelope JSON exceeds the maximum depth")
    if value is None or isinstance(value, (bool, str)):
        if isinstance(value, str) and any(
            0xD800 <= ord(character) <= 0xDFFF for character in value
        ):
            raise ValueError("envelope strings must contain Unicode scalar values")
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ValueError("envelope integers must be interoperable safe integers")
        return
    if isinstance(value, float):
        raise TypeError("envelope canonical JSON does not accept floating-point values")
    if isinstance(value, list):
        for item in value:
            _validate_json_value(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("envelope object names must be strings")
            _validate_json_value(key, depth=depth + 1)
            _validate_json_value(item, depth=depth + 1)
        return
    raise TypeError(f"unsupported envelope JSON value: {type(value).__name__}")


def _utf16_sort_key(value: str) -> bytes:
    return value.encode("utf-16-be")


def canonical_json(value: Any) -> str:
    """Serialize the constrained GOVP-EXT-1 canonical JSON profile."""
    _validate_json_value(value)
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    if isinstance(value, dict):
        parts = []
        for key in sorted(value, key=_utf16_sort_key):
            parts.append(f"{canonical_json(key)}:{canonical_json(value[key])}")
        return "{" + ",".join(parts) + "}"
    raise TypeError(f"unsupported envelope JSON value: {type(value).__name__}")


def envelope_signing_input(envelope: Mapping[str, Any]) -> bytes:
    if not isinstance(envelope, Mapping):
        raise TypeError("envelope must be an object")
    unsigned = {key: value for key, value in envelope.items() if key != "signature"}
    return ENVELOPE_DOMAIN + canonical_json(unsigned).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _key_id(public_key: bytes) -> str:
    return f"sha256:{_sha256(public_key)}"


def sign_envelope(
    unsigned_envelope: Mapping[str, Any], private_key: Ed25519PrivateKey
) -> dict[str, Any]:
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("private_key must be an Ed25519PrivateKey")
    if "signature" in unsigned_envelope:
        raise ValueError("unsigned envelope cannot contain signature")
    candidate = dict(unsigned_envelope)
    if set(candidate) != UNSIGNED_ENVELOPE_KEYS:
        raise ValueError("unsigned envelope has missing or unknown core members")
    shape_ok, _ = _validate_shape({**candidate, "signature": _placeholder_signature()})
    if not shape_ok:
        raise ValueError("unsigned envelope shape is invalid")
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signing_input = envelope_signing_input(candidate)
    candidate["signature"] = {
        "alg": "Ed25519",
        "key_id": _key_id(public_key),
        "public_key": base64.b64encode(public_key).decode("ascii"),
        "signing_input_sha256": _sha256(signing_input),
        "value": base64.b64encode(private_key.sign(signing_input)).decode("ascii"),
    }
    return candidate


def _placeholder_signature() -> dict[str, str]:
    return {
        "alg": "Ed25519",
        "key_id": "sha256:" + "0" * 64,
        "public_key": base64.b64encode(bytes(32)).decode("ascii"),
        "signing_input_sha256": "0" * 64,
        "value": base64.b64encode(bytes(64)).decode("ascii"),
    }


def _valid_reference(reference: Any) -> bool:
    if not isinstance(reference, dict):
        return False
    if reference.get("type") == "govp":
        if set(reference) - {"type", "id", "digest", "locator"}:
            return False
        if not {"type", "id", "digest"}.issubset(reference):
            return False
        return (
            _valid_scalar_string(reference.get("id"))
            and bool(DIGEST_PATTERN.fullmatch(str(reference.get("digest", ""))))
            and (
                "locator" not in reference
                or _valid_https_url(reference.get("locator"))
            )
        )
    if reference.get("type") == "external_attestation":
        return (
            set(reference) == {"type", "format", "digest", "locator"}
            and reference.get("format") in EXTERNAL_ATTESTATION_FORMATS
            and bool(DIGEST_PATTERN.fullmatch(str(reference.get("digest", ""))))
            and _valid_https_url(reference.get("locator"))
        )
    return False


def _valid_evidence(item: Any) -> bool:
    if not isinstance(item, dict) or set(item) - {"type", "id", "digest", "locator"}:
        return False
    if not {"type", "id", "digest"}.issubset(item):
        return False
    return (
        bool(TYPE_PATTERN.fullmatch(str(item.get("type", ""))))
        and _valid_scalar_string(item.get("id"))
        and bool(DIGEST_PATTERN.fullmatch(str(item.get("digest", ""))))
        and ("locator" not in item or _valid_https_url(item.get("locator")))
    )


def _valid_origin(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "origin",
        "observed_by",
        "observation",
    }:
        return False
    origin = value.get("origin")
    if origin not in ORIGINS or not _valid_scalar_string(value.get("observed_by")):
        return False
    observation = value.get("observation")
    return observation is None if origin == "human_asserted" else isinstance(observation, dict)


def _valid_signature_shape(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "alg",
        "key_id",
        "public_key",
        "signing_input_sha256",
        "value",
    }:
        return False
    try:
        public_key = base64.b64decode(value.get("public_key", ""), validate=True)
        signature = base64.b64decode(value.get("value", ""), validate=True)
    except (ValueError, TypeError):
        return False
    return (
        value.get("alg") == "Ed25519"
        and len(public_key) == 32
        and len(signature) == 64
        and bool(DIGEST_PATTERN.fullmatch(str(value.get("key_id", ""))))
        and bool(SHA256_PATTERN.fullmatch(str(value.get("signing_input_sha256", ""))))
    )


def _validate_shape(envelope: Any) -> tuple[bool, tuple[str, ...]]:
    warnings: list[str] = []
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_KEYS:
        return False, ()
    try:
        _validate_json_value(envelope)
    except (TypeError, ValueError):
        return False, ()
    extension = envelope.get("extension")
    issuer = envelope.get("issuer")
    subject = envelope.get("subject")
    digest = envelope.get("hash")
    if not (
        envelope.get("govp") == "GOVP-EXT-1"
        and isinstance(extension, dict)
        and set(extension) == {"id", "version"}
        and bool(EXTENSION_PATTERN.fullmatch(str(extension.get("id", ""))))
        and bool(VERSION_PATTERN.fullmatch(str(extension.get("version", ""))))
        and bool(TYPE_PATTERN.fullmatch(str(envelope.get("type", ""))))
        and _valid_scalar_string(envelope.get("id"))
        and isinstance(issuer, dict)
        and set(issuer) == {"canonical", "name"}
        and _valid_https_url(issuer.get("canonical"), canonical_identity=True)
        and _valid_scalar_string(issuer.get("name"))
        and isinstance(subject, dict)
        and set(subject) == {"type", "id"}
        and _valid_scalar_string(subject.get("type"))
        and _valid_scalar_string(subject.get("id"))
        and bool(TIMESTAMP_PATTERN.fullmatch(str(envelope.get("created_at", ""))))
        and isinstance(digest, dict)
        and set(digest) == {"alg", "value"}
        and digest.get("alg") == "sha256"
        and bool(SHA256_PATTERN.fullmatch(str(digest.get("value", ""))))
        and isinstance(envelope.get("payload"), dict)
        and isinstance(envelope.get("references"), list)
        and len(envelope["references"]) <= 256
        and all(_valid_reference(item) for item in envelope["references"])
        and isinstance(envelope.get("evidence"), list)
        and len(envelope["evidence"]) <= 256
        and all(_valid_evidence(item) for item in envelope["evidence"])
        and _valid_origin(envelope.get("origin"))
        and _valid_signature_shape(envelope.get("signature"))
    ):
        return False, ()
    if not envelope["references"]:
        warnings.append("no-references")
    return True, tuple(warnings)


def verify_envelope(
    envelope: Any, *, subject_bytes: bytes | None = None
) -> EnvelopeVerification:
    shape_ok, warnings = _validate_shape(envelope)
    checks: dict[str, bool | None] = {
        "format": shape_ok,
        "references": shape_ok,
        "origin": shape_ok,
        "key-id": False if shape_ok else None,
        "signing-input": False if shape_ok else None,
        "signature": False if shape_ok else None,
        "subject": None,
    }
    if not shape_ok:
        return EnvelopeVerification(False, checks, None, warnings)
    signing_input = envelope_signing_input(envelope)
    signing_input_sha256 = _sha256(signing_input)
    signature = envelope["signature"]
    public_key = base64.b64decode(signature["public_key"], validate=True)
    signature_bytes = base64.b64decode(signature["value"], validate=True)
    checks["key-id"] = signature["key_id"] == _key_id(public_key)
    checks["signing-input"] = signature["signing_input_sha256"] == signing_input_sha256
    try:
        if (
            not _valid_ed25519_subgroup_encoding(public_key)
            or not _valid_ed25519_subgroup_encoding(signature_bytes[:32])
            or int.from_bytes(signature_bytes[32:], "little") >= _ED25519_L
        ):
            raise ValueError("non-canonical Ed25519 encoding")
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature_bytes, signing_input
        )
        checks["signature"] = True
    except (InvalidSignature, ValueError):
        checks["signature"] = False
    if subject_bytes is not None:
        checks["subject"] = _sha256(subject_bytes) == envelope["hash"]["value"]
    ok = all(
        checks[name] is True
        for name in ("format", "references", "origin", "key-id", "signing-input", "signature")
    ) and checks["subject"] is not False
    return EnvelopeVerification(ok, checks, signing_input_sha256, warnings)
