"""Generate deterministic cross-runtime GOVP AI-1 conformance vectors."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from govp.ai import receive_ai
from govp.envelope import canonical_json, sign_envelope

ROOT = Path(__file__).resolve().parents[1]
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def signed(payload: dict, record_type: str, record_id: str, subject: bytes, references: list):
    return sign_envelope(
        {
            "govp": "GOVP-EXT-1",
            "extension": {"id": "org.govp.ai", "version": "1.0.0"},
            "type": record_type,
            "id": record_id,
            "issuer": {
                "canonical": "https://ai.example/.well-known/govp.txt",
                "name": "AI Example",
            },
            "subject": {"type": "ai-execution-artifact", "id": record_id},
            "created_at": "2026-08-17T12:00:00Z",
            "hash": {"alg": "sha256", "value": hashlib.sha256(subject).hexdigest()},
            "payload": payload,
            "references": references,
            "evidence": [],
            "origin": {
                "origin": "system_observed",
                "observed_by": "govp-ai-conformance/1",
                "observation": {"event": payload["kind"]},
            },
        },
        KEY,
    )


def request_payload(*, externalized: bool = False) -> dict:
    return {
        "kind": "request",
        "model": {
            "artifact_digest": digest(b"model-artifact"),
            "identity_basis": "artifact_observed",
            "publisher": None,
            "publisher_manifest_digest": None,
        },
        "runtime": {
            "artifact_digest": digest(b"runtime-artifact"),
            "backend": "cpu",
            "hardware_class": "x86_64",
            "deterministic_profile": "cpu-reference-v1",
        },
        "input": {"digest": digest(b"prompt"), "disclosure": "private"},
        "inference_parameters": {
            "digest": digest(b'{"temperature":0}'),
            "disclosure": "digest_only",
        },
        "seed": 42,
        "nonce": "AAAAAAAAAAAAAAAAAAAAAA",
        "reproducibility": {"claimed": True, "scope_digest": digest(b"scope")},
        "commitment": {"timing": "pre_inference", "externalized": externalized},
    }


def vector(name: str, envelope: dict, subject: bytes) -> dict:
    data = canonical_json(envelope).encode()
    result = receive_ai(data, subject_bytes=subject)
    return {
        "name": name,
        "transport_base64": base64.b64encode(data).decode(),
        "subject_base64": base64.b64encode(subject).decode(),
        "expected": {"admitted": result.admitted, "code": result.code},
    }


def main() -> None:
    request_subject = b'{"parameters":"committed","prompt":"redacted"}'
    request = signed(
        request_payload(), "org.govp.ai-request/1", "AI-REQUEST-0001", request_subject, []
    )
    request_digest = digest(canonical_json(request).encode())
    request_link = {"id": request["id"], "digest": request_digest}
    request_reference = {"type": "govp", **request_link}

    output = b"deterministic output\n"
    result_payload = {
        "kind": "result",
        "request": request_link,
        "attempt_id": "ATTEMPT-0001",
        "status": "SUCCEEDED",
        "output_digest": digest(output),
        "reason_code": None,
        "effective_model_digest": digest(b"model-artifact"),
        "effective_runtime_digest": digest(b"runtime-artifact"),
        "execution_metadata_digest": digest(b"execution-metadata"),
    }
    result = signed(
        result_payload,
        "org.govp.ai-result/1",
        "AI-RESULT-0001",
        output,
        [request_reference],
    )
    result_link = {"id": result["id"], "digest": digest(canonical_json(result).encode())}
    verification_subject = b'{"recomputation":"exact"}'
    verification_payload = {
        "kind": "verification",
        "request": request_link,
        "result": result_link,
        "method": "recomputation",
        "verifier_relationship": "third_party",
        "environment_digest": digest(b"verification-environment"),
        "observed_output_digest": digest(output),
        "comparison_profile": "exact",
        "canonicalization_profile": None,
        "match": True,
    }
    verification = signed(
        verification_payload,
        "org.govp.ai-verification/1",
        "AI-VERIFICATION-0001",
        verification_subject,
        [{"type": "govp", **request_link}, {"type": "govp", **result_link}],
    )

    externalized_without_witness = signed(
        request_payload(externalized=True),
        "org.govp.ai-request/1",
        "AI-REQUEST-0002",
        request_subject,
        [],
    )
    failed_with_output = signed(
        {**result_payload, "status": "FAILED", "reason_code": "RUNTIME_ERROR"},
        "org.govp.ai-result/1",
        "AI-RESULT-0002",
        output,
        [request_reference],
    )
    wrong_reference = signed(
        result_payload,
        "org.govp.ai-result/1",
        "AI-RESULT-0003",
        output,
        [{"type": "govp", "id": request["id"], "digest": digest(b"wrong")}],
    )
    semantic_comparison = signed(
        {**verification_payload, "comparison_profile": "semantic"},
        "org.govp.ai-verification/1",
        "AI-VERIFICATION-0002",
        verification_subject,
        [{"type": "govp", **request_link}, {"type": "govp", **result_link}],
    )

    vectors = [
        vector("01-valid-request", request, request_subject),
        vector("02-valid-result", result, output),
        vector("03-valid-exact-verification", verification, verification_subject),
        vector(
            "04-externalized-without-witness",
            externalized_without_witness,
            request_subject,
        ),
        vector("05-failed-with-output", failed_with_output, output),
        vector("06-result-reference-mismatch", wrong_reference, output),
        vector("07-semantic-comparison-rejected", semantic_comparison, verification_subject),
    ]
    output_path = ROOT / "conformance/ai-vectors.json"
    output_path.write_text(
        json.dumps({"format": "GOVP-AI-1-CONFORMANCE", "vectors": vectors}, indent=2)
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()

