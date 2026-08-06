"""Byte-compatible GOVP-1 parsing and verification primitives."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from os import PathLike
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

RECORD_DOMAIN = b"GOVP::record.v1\x00"
TYPECODE = {
    "dataset": "DATA",
    "model": "MODEL",
    "agent": "AGENT",
    "document": "DOC",
    "pipeline": "PIPE",
    "benchmark": "BENCH",
}
REQUIRED = (
    "version",
    "canonical",
    "publisher",
    "asset-type",
    "asset-id",
    "asset-sha256",
    "govp-id",
    "evidence",
    "public-key",
    "signature",
)
LEGACY = {
    "type": "asset-type",
    "sha256": "asset-sha256",
    "pubkey": "public-key",
    "timestamp": "generated-at",
}
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
GOVP_ID_PATTERN = re.compile(
    r"^GOVP-(DOC|DATA|MODEL|AGENT|PIPE|BENCH)-[0-9a-f]{12}$"
)
RFC3339_UTC_PATTERN = re.compile(
    r"^(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})T"
    r"(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
    r"(?P<fraction>\.[0-9]+)?Z$"
)
FORBIDDEN_VALUE_CHARS = frozenset("\x00\r\n")
FORBIDDEN_KEY_CHARS = FORBIDDEN_VALUE_CHARS | {":"}
# Exact GOVP-1 trim set. This freezes the whitespace behavior of the public
# v0.1.x Python verifier without depending on future Unicode database changes.
# CR and LF are intentionally absent because GOVP-1 forbids them in fields.
GOVP1_TRIM_CHARS = (
    "\u0009\u000b\u000c\u001c\u001d\u001e\u001f\u0020\u0085\u00a0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000"
)
ASCII_LOWER_TRANSLATION = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "abcdefghijklmnopqrstuvwxyz",
)
URI_ALLOWED_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    "-._~:/?#[]@!$&'()*+,;="
)
URI_HEX_DIGITS = frozenset("0123456789ABCDEFabcdef")

# GOVP accepts only canonical, prime-subgroup Ed25519 encodings. Standard
# RFC 8032 signers already emit these encodings; making the checks explicit
# prevents runtime crypto backends from disagreeing on exceptional points.
_ED25519_P = 2**255 - 19
_ED25519_D = (-121665 * pow(121666, _ED25519_P - 2, _ED25519_P)) % _ED25519_P
_ED25519_SQRT_M1 = pow(2, (_ED25519_P - 1) // 4, _ED25519_P)
_ED25519_L = 2**252 + 27742317777372353535851937790883648493


@dataclass(frozen=True)
class Verification:
    ok: bool
    fields: dict[str, str]
    checks: dict[str, bool | None]
    derived_govp_id: str | None
    asset_sha256: str | None = None
    warnings: tuple[str, ...] = ()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_field_name(value: str) -> str:
    """Apply GOVP-1 trimming and lowercase ASCII A-Z only.

    Registered GOVP-1 names are ASCII. Leaving every other Unicode code point
    unchanged avoids depending on language- or Unicode-version-specific case
    conversion for extension fields.
    """
    return value.strip(GOVP1_TRIM_CHARS).translate(ASCII_LOWER_TRANSLATION)


def trim_field_value(value: str) -> str:
    """Apply GOVP-1's exact, language-independent value trimming rule."""
    return value.strip(GOVP1_TRIM_CHARS)


def _valid_field_name(value: str) -> bool:
    return bool(value) and not any(char in FORBIDDEN_KEY_CHARS for char in value)


def _valid_field_value(value: str) -> bool:
    return not any(char in FORBIDDEN_VALUE_CHARS for char in value)


def _contains_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(char) <= 0xDFFF for char in value)


def _validate_signable_fields(fields: dict[str, str]) -> None:
    for key, value in fields.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise TypeError("record field names and values must be strings")
        normalized = normalize_field_name(key)
        if _contains_surrogate(normalized) or _contains_surrogate(value):
            raise ValueError(
                "record field names and values must contain Unicode scalar values"
            )
        if not _valid_field_name(normalized):
            raise ValueError(
                "record field names cannot be empty or contain ':', NUL, CR or LF"
            )
        if not _valid_field_value(value):
            raise ValueError("record field values cannot contain NUL, CR or LF")


def parse_record(text: str) -> dict[str, str]:
    """Parse the line-oriented GOVP-1 record format."""
    fields: dict[str, str] = {}
    for raw in text.replace("\r\n", "\n").split("\n"):
        line = raw.strip(GOVP1_TRIM_CHARS)
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        normalized_key = normalize_field_name(key)
        normalized = LEGACY.get(normalized_key, normalized_key)
        fields[normalized] = trim_field_value(value)
    return fields


def load_record(path: str | PathLike[str]) -> dict[str, str]:
    """Load a text record or JSON record/bundle from any path-like value."""
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        payload: Any = json.loads(text)
        bundle_asset: Any = None
        if isinstance(payload, dict) and payload.get("format") == "GOVP-1":
            if not isinstance(payload.get("record"), dict):
                raise ValueError("JSON bundle record must be an object")
            if not isinstance(payload.get("asset"), dict):
                raise ValueError("JSON bundle asset must be an object")
            bundle_asset = payload["asset"]
            payload = payload["record"]
        if not isinstance(payload, dict):
            raise ValueError("JSON record must be an object")
        if not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in payload.items()
        ):
            raise ValueError("JSON record field names and values must be strings")
        _validate_signable_fields(payload)
        fields = {}
        normalized_sources: dict[str, str] = {}
        for key, value in payload.items():
            normalized_key = normalize_field_name(key)
            normalized = LEGACY.get(normalized_key, normalized_key)
            if normalized in normalized_sources:
                previous = normalized_sources[normalized]
                raise ValueError(
                    "JSON record contains colliding normalized field names: "
                    f"{previous!r} and {key!r}"
                )
            normalized_sources[normalized] = key
            fields[normalized] = trim_field_value(value)
        _validate_signable_fields(fields)
        if bundle_asset is not None:
            bundle_hash = bundle_asset.get("hash")
            if (
                not isinstance(bundle_hash, dict)
                or bundle_hash.get("alg") != "sha256"
                or not isinstance(bundle_hash.get("value"), str)
            ):
                raise ValueError("JSON bundle asset hash must declare a textual sha256 value")
            if (
                bundle_asset.get("type") != fields.get("asset-type")
                or bundle_asset.get("id") != fields.get("asset-id")
                or bundle_hash["value"] != fields.get("asset-sha256")
            ):
                raise ValueError("JSON bundle asset must match the signed record")
        return fields
    return parse_record(text)


def signing_input(fields: dict[str, str]) -> bytes:
    _validate_signable_fields(fields)
    normalized_fields: dict[str, str] = {}
    for key, value in fields.items():
        normalized_key = normalize_field_name(key)
        canonical_key = LEGACY.get(normalized_key, normalized_key)
        normalized_fields[canonical_key] = trim_field_value(value)
    items = [
        (key, value)
        for key, value in normalized_fields.items()
        if key != "signature" and value
    ]
    # ASCII field names retain their GOVP-1 ordering. UTF-8 makes the
    # specification's byte-wise ordering well-defined for preserved,
    # unrecognized non-ASCII fields instead of raising UnicodeEncodeError.
    items.sort(key=lambda item: item[0].encode("utf-8"))
    return "".join(f"{key}: {value}\n" for key, value in items).encode("utf-8")


def signing_message(fields: dict[str, str]) -> bytes:
    return RECORD_DOMAIN + signing_input(fields)


def sign_record(
    fields: Mapping[str, str],
    private_key: Ed25519PrivateKey,
) -> dict[str, str]:
    """Create a complete GOVP-1 record with computed identity and signature.

    The caller remains responsible for private-key custody and for the truth of
    every declared field. Computed fields are rejected as input so stale IDs,
    public keys or signatures cannot be silently reused.
    """
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("private_key must be an Ed25519PrivateKey")
    computed = {"govp-id", "public-key", "signature"}
    record: dict[str, str] = {}
    for key, value in fields.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise TypeError("record field names and values must be strings")
        normalized_key = normalize_field_name(key)
        canonical_key = LEGACY.get(normalized_key, normalized_key)
        if canonical_key in computed:
            raise ValueError(f"{canonical_key} is computed and must not be supplied")
        record[canonical_key] = trim_field_value(value)
    if record.get("version", "GOVP-1") != "GOVP-1":
        raise ValueError("sign_record only emits GOVP-1 records")
    record["version"] = "GOVP-1"
    govp_id = derive_govp_id(
        record.get("asset-type", ""),
        record.get("asset-id", ""),
        record.get("asset-sha256", ""),
    )
    if govp_id is None:
        raise ValueError("asset-type must be a registered GOVP-1 type")
    record["govp-id"] = govp_id
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    record["public-key"] = base64.b64encode(public_key).decode("ascii")
    record["signature"] = base64.b64encode(
        private_key.sign(signing_message(record))
    ).decode("ascii")
    result = verify(record)
    if not result.ok:
        raise ValueError("record fields do not form a valid GOVP-1 record")
    return record


DISPLAY_FIELD_ORDER = (
    "version",
    "canonical",
    "publisher",
    "asset-type",
    "asset-id",
    "asset-sha256",
    "license",
    "profile",
    "generated-at",
    "govp-id",
    "evidence",
    "public-key",
    "signature",
)
DISPLAY_FIELD_LABELS = {
    "version": "Version",
    "canonical": "Canonical",
    "publisher": "Publisher",
    "asset-type": "Asset-Type",
    "asset-id": "Asset-ID",
    "asset-sha256": "Asset-SHA256",
    "license": "License",
    "profile": "Profile",
    "generated-at": "Generated-At",
    "govp-id": "GOVP-ID",
    "evidence": "Evidence",
    "public-key": "Public-Key",
    "signature": "Signature",
}


def serialize_record(fields: Mapping[str, str]) -> str:
    """Serialize a GOVP-1 mapping into its readable line-oriented form."""
    normalized: dict[str, str] = {}
    for key, value in fields.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise TypeError("record field names and values must be strings")
        normalized_key = normalize_field_name(key)
        canonical_key = LEGACY.get(normalized_key, normalized_key)
        normalized[canonical_key] = trim_field_value(value)
    _validate_signable_fields(normalized)
    ordered = [key for key in DISPLAY_FIELD_ORDER if key in normalized]
    ordered.extend(
        sorted(
            (key for key in normalized if key not in DISPLAY_FIELD_ORDER),
            key=lambda key: key.encode("utf-8"),
        )
    )
    return "".join(
        f"{DISPLAY_FIELD_LABELS.get(key, key)}: {normalized[key]}\n"
        for key in ordered
        if normalized[key]
    )


def derive_govp_id(asset_type: str, asset_id: str, asset_sha256: str) -> str | None:
    normalized_type = (asset_type or "").lower()
    code = TYPECODE.get(normalized_type)
    if not code:
        return None
    try:
        identity = f"{normalized_type}\n{asset_id}\n{asset_sha256.lower()}".encode()
    except UnicodeEncodeError:
        return None
    digest = sha256(identity)
    return f"GOVP-{code}-{digest[:12]}"


def _decode_ed25519_point(encoded: bytes) -> tuple[int, int, int, int] | None:
    """Decode one canonical Edwards25519 point into extended coordinates."""
    if len(encoded) != 32:
        return None
    sign = encoded[31] >> 7
    y = int.from_bytes(encoded, "little") & ((1 << 255) - 1)
    if y >= _ED25519_P:
        return None
    y_squared = y * y % _ED25519_P
    denominator = (_ED25519_D * y_squared + 1) % _ED25519_P
    if denominator == 0:
        return None
    x_squared = (y_squared - 1) * pow(
        denominator, _ED25519_P - 2, _ED25519_P
    ) % _ED25519_P
    x = pow(x_squared, (_ED25519_P + 3) // 8, _ED25519_P)
    if x * x % _ED25519_P != x_squared:
        x = x * _ED25519_SQRT_M1 % _ED25519_P
    if x * x % _ED25519_P != x_squared or (x == 0 and sign == 1):
        return None
    if x & 1 != sign:
        x = _ED25519_P - x
    return x, y, 1, x * y % _ED25519_P


def _ed25519_add(
    first: tuple[int, int, int, int],
    second: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    """Complete extended-coordinate addition for Edwards25519."""
    x1, y1, z1, t1 = first
    x2, y2, z2, t2 = second
    a = (y1 - x1) * (y2 - x2) % _ED25519_P
    b = (y1 + x1) * (y2 + x2) % _ED25519_P
    c = 2 * _ED25519_D * t1 * t2 % _ED25519_P
    d = 2 * z1 * z2 % _ED25519_P
    e = (b - a) % _ED25519_P
    f = (d - c) % _ED25519_P
    g = (d + c) % _ED25519_P
    h = (b + a) % _ED25519_P
    return e * f % _ED25519_P, g * h % _ED25519_P, f * g % _ED25519_P, e * h % _ED25519_P


def _ed25519_multiply(
    point: tuple[int, int, int, int], scalar: int
) -> tuple[int, int, int, int]:
    result = (0, 1, 1, 0)
    addend = point
    while scalar:
        if scalar & 1:
            result = _ed25519_add(result, addend)
        addend = _ed25519_add(addend, addend)
        scalar >>= 1
    return result


def _valid_ed25519_subgroup_encoding(encoded: bytes) -> bool:
    point = _decode_ed25519_point(encoded)
    if point is None:
        return False
    x, y, z, _ = point
    if x % _ED25519_P == 0 and (y - z) % _ED25519_P == 0:
        return False
    lx, ly, lz, _ = _ed25519_multiply(point, _ED25519_L)
    return lx % _ED25519_P == 0 and (ly - lz) % _ED25519_P == 0


def verify_signature(fields: dict[str, str]) -> bool | None:
    if fields.get("version") != "GOVP-1":
        return None
    try:
        public_key = base64.b64decode(fields["public-key"], validate=True)
        signature = base64.b64decode(fields["signature"], validate=True)
        if (
            len(public_key) != 32
            or len(signature) != 64
            or not _valid_ed25519_subgroup_encoding(public_key)
            or not _valid_ed25519_subgroup_encoding(signature[:32])
            or int.from_bytes(signature[32:], "little") >= _ED25519_L
        ):
            return False
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, signing_message(fields))
        return True
    except (KeyError, TypeError, ValueError, InvalidSignature):
        return False


def normalize_canonical(value: str) -> str:
    if not isinstance(value, str):
        return ""
    raw = trim_field_value(value)
    if not raw or not _valid_uri_characters(raw):
        return ""
    try:
        parsed = urlsplit(raw)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower()
        parsed_port = parsed.port
    except ValueError:
        return ""
    if not scheme or not host:
        return ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = f":{parsed_port}" if parsed_port is not None else ""
    userinfo = ""
    if parsed.username is not None:
        userinfo = parsed.username
        if parsed.password is not None:
            userinfo += f":{parsed.password}"
        userinfo += "@"
    return urlunsplit(
        (scheme, f"{userinfo}{host}{port}", parsed.path, parsed.query, parsed.fragment)
    )


def _valid_base64_length(value: str, expected_length: int) -> bool:
    try:
        return len(base64.b64decode(value, validate=True)) == expected_length
    except (ValueError, TypeError):
        return False


def _valid_absolute_url(value: str, *, https_only: bool = False) -> bool:
    if not isinstance(value, str) or not value or not _valid_uri_characters(value):
        return False
    try:
        parsed = urlsplit(value)
        if not parsed.scheme:
            return False
        if https_only and parsed.scheme.lower() != "https":
            return False
        if parsed.scheme.lower() in {"http", "https"} and not parsed.hostname:
            return False
        if parsed.username is not None or parsed.password is not None:
            return False
        _ = parsed.port
        return True
    except (TypeError, ValueError):
        return False


def _valid_uri_characters(value: str) -> bool:
    """Accept only RFC 3986 ASCII URI characters and complete escapes.

    GOVP URL fields are RFC 3986 URI strings, not unencoded IRIs. Keeping this
    check explicit avoids runtime-dependent URL parsing of controls, invisible
    Unicode and raw internationalized components. Such components remain
    representable through IDNA host names and UTF-8 percent-encoding.
    """
    index = 0
    while index < len(value):
        char = value[index]
        if char == "%":
            if (
                index + 2 >= len(value)
                or value[index + 1] not in URI_HEX_DIGITS
                or value[index + 2] not in URI_HEX_DIGITS
            ):
                return False
            index += 3
            continue
        if char not in URI_ALLOWED_CHARS:
            return False
        index += 1
    return True


def _rfc3339_utc_datetime(value: str) -> datetime | None:
    match = RFC3339_UTC_PATTERN.fullmatch(value)
    if match is None:
        return None
    second = match.group("second")
    leap_second = second == "60"
    if second == "60":
        if match.group("hour") != "23" or match.group("minute") != "59":
            return None
        parseable = value.replace(":60", ":59", 1)
    else:
        parseable = value
    # Python 3.10's datetime.fromisoformat accepts only selected fractional
    # widths, whereas newer versions accept any width. Normalize only the
    # parser input so the GOVP format verdict is identical on every supported
    # runtime; the original signed value is never changed.
    fraction = match.group("fraction")
    if fraction:
        digits = (fraction[1:] + "000000")[:6]
        parseable = parseable.replace(fraction, "." + digits, 1)
    try:
        parsed = datetime.fromisoformat(parseable.removesuffix("Z") + "+00:00")
    except ValueError:
        return None
    if parsed.utcoffset() is None:
        return None
    return parsed + timedelta(seconds=1) if leap_second else parsed


def _valid_rfc3339_utc(value: str) -> bool:
    return _rfc3339_utc_datetime(value) is not None


def _presentation_warnings(fields: dict[str, str]) -> tuple[str, ...]:
    """Return stable advisory identifiers without affecting core validity."""
    warnings: set[str] = set()
    for key, value in fields.items():
        if not isinstance(key, str) or not isinstance(value, str):
            continue
        if any(not char.isprintable() for char in key + value):
            warnings.add("signed-non-printable-text")
    evidence = fields.get("evidence")
    if (
        isinstance(evidence, str)
        and _valid_absolute_url(evidence)
        and urlsplit(evidence).scheme.lower() not in {"http", "https"}
    ):
        warnings.add("non-http-evidence-scheme")
    return tuple(sorted(warnings))


def _valid_format(fields: dict[str, str]) -> bool:
    try:
        _validate_signable_fields(fields)
    except (TypeError, ValueError):
        return False
    if fields.get("version") != "GOVP-1":
        return False
    if not all(
        isinstance(fields.get(key), str) and trim_field_value(fields[key])
        for key in REQUIRED
    ):
        return False
    generated_at = fields.get("generated-at")
    if generated_at and not _valid_rfc3339_utc(generated_at):
        return False
    return (
        _valid_absolute_url(fields["canonical"], https_only=True)
        and fields["asset-type"] in TYPECODE
        and SHA256_PATTERN.fullmatch(fields["asset-sha256"]) is not None
        and GOVP_ID_PATTERN.fullmatch(fields["govp-id"]) is not None
        and _valid_absolute_url(fields["evidence"])
        and _valid_base64_length(fields["public-key"], 32)
        and _valid_base64_length(fields["signature"], 64)
    )


def verify(
    fields: dict[str, str],
    *,
    fetched_url: str | None = None,
    asset_bytes: bytes | None = None,
) -> Verification:
    format_ok = _valid_format(fields)
    derived = None
    if all(
        isinstance(fields.get(key), str) and fields[key]
        for key in ("asset-type", "asset-id", "asset-sha256")
    ):
        derived = derive_govp_id(
            fields["asset-type"],
            fields["asset-id"],
            fields["asset-sha256"],
        )
    govpid_ok = bool(derived and fields.get("govp-id") == derived)
    signature_ok = verify_signature(fields)
    canonical_ok = (
        normalize_canonical(fields.get("canonical", "")) == normalize_canonical(fetched_url)
        if fetched_url
        else None
    )
    asset_digest = sha256(asset_bytes) if asset_bytes is not None else None
    declared_asset_hash = fields.get("asset-sha256", "")
    if asset_digest is None:
        asset_ok = None
    elif isinstance(declared_asset_hash, str):
        asset_ok = asset_digest == declared_asset_hash.lower()
    else:
        asset_ok = False
    checks: dict[str, bool | None] = {
        "format": format_ok,
        "signature": signature_ok,
        "govp-id": govpid_ok,
        "canonical": canonical_ok,
        "asset": asset_ok,
    }
    ok = (
        format_ok
        and signature_ok is True
        and govpid_ok
        and canonical_ok is not False
        and asset_ok is not False
    )
    return Verification(
        ok,
        fields,
        checks,
        derived,
        asset_digest,
        _presentation_warnings(fields),
    )
