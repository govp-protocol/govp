"""GOVP AI-1 public receiving gate and semantic validation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .envelope import canonical_json, parse_envelope, verify_envelope

AI_EXTENSION = {"id": "org.govp.ai", "version": "1.0.0"}
AI_TYPES = frozenset(
    {
        "org.govp.ai-request/1",
        "org.govp.ai-result/1",
        "org.govp.ai-verification/1",
    }
)
AI1_MAX_TRANSPORT_BYTES = 4 * 1024 * 1024
AI1_CODES = frozenset(
    {
        "AI1_INVALID_ENVELOPE",
        "AI1_EXTENSION_UNSUPPORTED",
        "AI1_TYPE_UNSUPPORTED",
        "AI1_PAYLOAD_INVALID",
        "AI1_REFERENCE_INVALID",
        "AI1_STATE_CONFLICT",
        "AI1_COMPARISON_UNSUPPORTED",
        "AI1_SUBJECT_REQUIRED",
        "AI1_SUBJECT_DIGEST_MISMATCH",
    }
)

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REASON = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{22,200}$")
_DISCLOSURES = frozenset({"digest_only", "sealed", "private", "public"})
_STATES = frozenset(
    {"SUCCEEDED", "FAILED", "DENIED", "CANCELLED", "TIMED_OUT", "INDETERMINATE"}
)


@dataclass(frozen=True)
class AiReception:
    """Fail-closed result from the public AI-1 receiving gate."""

    admitted: bool
    code: str | None
    envelope: dict[str, Any] | None
    checks: dict[str, bool | None]
    warnings: tuple[str, ...] = ()


def _exact(value: Any, fields: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == fields


def _digest(value: Any) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def _identifier(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= 200
        and not any(character in value for character in "\x00\r\n")
    )


def _link(value: Any) -> bool:
    return _exact(value, {"id", "digest"}) and _identifier(value["id"]) and _digest(
        value["digest"]
    )


def _committed_input(value: Any) -> bool:
    return (
        _exact(value, {"digest", "disclosure"})
        and _digest(value["digest"])
        and value["disclosure"] in _DISCLOSURES
    )


def _artifact(value: Any) -> bool:
    if not _exact(
        value,
        {"artifact_digest", "identity_basis", "publisher", "publisher_manifest_digest"},
    ):
        return False
    publisher = value["publisher"]
    publisher_manifest = value["publisher_manifest_digest"]
    return (
        _digest(value["artifact_digest"])
        and value["identity_basis"]
        in {"artifact_observed", "publisher_attested", "provider_declared"}
        and (publisher is None or _identifier(publisher))
        and (publisher_manifest is None or _digest(publisher_manifest))
        and (
            value["identity_basis"] != "publisher_attested"
            or (publisher is not None and publisher_manifest is not None)
        )
    )


def _runtime(value: Any) -> bool:
    if not _exact(
        value, {"artifact_digest", "backend", "hardware_class", "deterministic_profile"}
    ):
        return False
    return (
        _digest(value["artifact_digest"])
        and _identifier(value["backend"])
        and (value["hardware_class"] is None or _identifier(value["hardware_class"]))
        and (
            value["deterministic_profile"] is None
            or _identifier(value["deterministic_profile"])
        )
    )


def _request_payload(payload: Any) -> tuple[bool, str | None]:
    fields = {
        "kind",
        "model",
        "runtime",
        "input",
        "inference_parameters",
        "seed",
        "nonce",
        "reproducibility",
        "commitment",
    }
    if not _exact(payload, fields) or payload.get("kind") != "request":
        return False, "AI1_PAYLOAD_INVALID"
    seed = payload["seed"]
    reproducibility = payload["reproducibility"]
    commitment = payload["commitment"]
    valid = (
        _artifact(payload["model"])
        and _runtime(payload["runtime"])
        and _committed_input(payload["input"])
        and _committed_input(payload["inference_parameters"])
        and (
            seed is None
            or (
                isinstance(seed, int)
                and not isinstance(seed, bool)
                and abs(seed) <= 2**53 - 1
            )
        )
        and isinstance(payload["nonce"], str)
        and _NONCE.fullmatch(payload["nonce"]) is not None
        and _exact(reproducibility, {"claimed", "scope_digest"})
        and isinstance(reproducibility.get("claimed"), bool)
        and _digest(reproducibility.get("scope_digest"))
        and _exact(commitment, {"timing", "externalized"})
        and commitment.get("timing") == "pre_inference"
        and isinstance(commitment.get("externalized"), bool)
    )
    return valid, None if valid else "AI1_PAYLOAD_INVALID"


def _result_payload(payload: Any) -> tuple[bool, str | None]:
    fields = {
        "kind",
        "request",
        "attempt_id",
        "status",
        "output_digest",
        "reason_code",
        "effective_model_digest",
        "effective_runtime_digest",
        "execution_metadata_digest",
    }
    if not _exact(payload, fields) or payload.get("kind") != "result":
        return False, "AI1_PAYLOAD_INVALID"
    if not (
        _link(payload["request"])
        and _identifier(payload["attempt_id"])
        and payload["status"] in _STATES
        and _digest(payload["effective_model_digest"])
        and _digest(payload["effective_runtime_digest"])
        and _digest(payload["execution_metadata_digest"])
    ):
        return False, "AI1_PAYLOAD_INVALID"
    if payload["status"] == "SUCCEEDED":
        state_ok = _digest(payload["output_digest"]) and payload["reason_code"] is None
    else:
        state_ok = payload["output_digest"] is None and (
            isinstance(payload["reason_code"], str)
            and _REASON.fullmatch(payload["reason_code"]) is not None
        )
    return state_ok, None if state_ok else "AI1_STATE_CONFLICT"


def _verification_payload(payload: Any) -> tuple[bool, str | None]:
    fields = {
        "kind",
        "request",
        "result",
        "method",
        "verifier_relationship",
        "environment_digest",
        "observed_output_digest",
        "comparison_profile",
        "canonicalization_profile",
        "match",
    }
    if not _exact(payload, fields) or payload.get("kind") != "verification":
        return False, "AI1_PAYLOAD_INVALID"
    comparison = payload["comparison_profile"]
    if comparison not in {"exact", "canonicalized"}:
        return False, "AI1_COMPARISON_UNSUPPORTED"
    canonicalizer = payload["canonicalization_profile"]
    comparison_ok = canonicalizer is None if comparison == "exact" else _identifier(canonicalizer)
    valid = (
        _link(payload["request"])
        and _link(payload["result"])
        and payload["request"] != payload["result"]
        and payload["method"] == "recomputation"
        and payload["verifier_relationship"]
        in {"self", "organizationally_separate", "third_party"}
        and _digest(payload["environment_digest"])
        and _digest(payload["observed_output_digest"])
        and comparison_ok
        and isinstance(payload["match"], bool)
    )
    return valid, None if valid else "AI1_PAYLOAD_INVALID"


def validate_ai_payload(envelope: dict[str, Any]) -> tuple[bool, str | None]:
    """Validate AI-1 payload semantics and exact causal reference bindings."""
    envelope_type = envelope.get("type")
    payload = envelope.get("payload")
    references = envelope.get("references")
    if not isinstance(references, list):
        return False, "AI1_REFERENCE_INVALID"
    if envelope_type == "org.govp.ai-request/1":
        valid, code = _request_payload(payload)
        if not valid:
            return valid, code
        if payload["commitment"]["externalized"] and not any(
            item.get("type") == "external_attestation"
            for item in references
            if isinstance(item, dict)
        ):
            return False, "AI1_REFERENCE_INVALID"
        return True, None
    if envelope_type == "org.govp.ai-result/1":
        valid, code = _result_payload(payload)
        if not valid:
            return valid, code
        links = [item for item in references if item.get("type") == "govp"]
        expected = payload["request"]
        if len(links) != 1 or (links[0].get("id"), links[0].get("digest")) != (
            expected["id"],
            expected["digest"],
        ):
            return False, "AI1_REFERENCE_INVALID"
        return True, None
    if envelope_type == "org.govp.ai-verification/1":
        valid, code = _verification_payload(payload)
        if not valid:
            return valid, code
        links = [item for item in references if item.get("type") == "govp"]
        expected = {
            (payload["request"]["id"], payload["request"]["digest"]),
            (payload["result"]["id"], payload["result"]["digest"]),
        }
        actual = {(item.get("id"), item.get("digest")) for item in links}
        if len(links) != 2 or actual != expected:
            return False, "AI1_REFERENCE_INVALID"
        return True, None
    return False, "AI1_TYPE_UNSUPPORTED"


def receive_ai(data: bytes, *, subject_bytes: bytes | None) -> AiReception:
    """Receive raw canonical AI-1 bytes and fail closed at every boundary."""
    checks: dict[str, bool | None] = {
        "transport": False,
        "l0": None,
        "subject": None,
        "ai-payload": None,
        "references": None,
    }
    if not isinstance(data, bytes) or len(data) > AI1_MAX_TRANSPORT_BYTES:
        return AiReception(False, "AI1_INVALID_ENVELOPE", None, checks)
    try:
        text = data.decode("utf-8", errors="strict")
        envelope = parse_envelope(text)
        if canonical_json(envelope).encode("utf-8") != data:
            return AiReception(False, "AI1_INVALID_ENVELOPE", None, checks)
    except Exception:
        return AiReception(False, "AI1_INVALID_ENVELOPE", None, checks)
    checks["transport"] = True
    if envelope.get("extension") != AI_EXTENSION:
        return AiReception(False, "AI1_EXTENSION_UNSUPPORTED", envelope, checks)
    if envelope.get("type") not in AI_TYPES:
        return AiReception(False, "AI1_TYPE_UNSUPPORTED", envelope, checks)
    if subject_bytes is None:
        return AiReception(False, "AI1_SUBJECT_REQUIRED", envelope, checks)
    try:
        l0 = verify_envelope(envelope, subject_bytes=subject_bytes)
    except Exception:
        return AiReception(False, "AI1_INVALID_ENVELOPE", envelope, checks)
    checks["l0"] = l0.ok
    checks["subject"] = l0.checks["subject"]
    if l0.checks["subject"] is False:
        return AiReception(
            False, "AI1_SUBJECT_DIGEST_MISMATCH", envelope, checks, l0.warnings
        )
    if not l0.ok:
        return AiReception(False, "AI1_INVALID_ENVELOPE", envelope, checks, l0.warnings)
    payload_ok, code = validate_ai_payload(envelope)
    checks["ai-payload"] = payload_ok
    checks["references"] = payload_ok or code not in {"AI1_REFERENCE_INVALID"}
    return AiReception(payload_ok, code, envelope, checks, l0.warnings)

