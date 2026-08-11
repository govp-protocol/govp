import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

from govp.envelope import (
    canonical_json,
    parse_envelope,
    sign_envelope,
    verify_envelope,
)

ROOT = Path(__file__).resolve().parents[1]


def _corpus():
    return json.loads((ROOT / "conformance/extension-vectors.json").read_text())


def test_every_conformance_vector_matches_schema_and_expected_verdict():
    validator = Draft202012Validator(
        json.loads((ROOT / "schema/govp-evidence-envelope-1.schema.json").read_text())
    )
    for vector in _corpus()["vectors"]:
        envelope = vector["envelope"]
        expected = vector["expected"]
        schema_ok = not list(validator.iter_errors(envelope))
        assert schema_ok is expected["format"], vector["name"]
        subject = vector["subject_base64"]
        result = verify_envelope(
            envelope,
            subject_bytes=None if subject is None else base64.b64decode(subject),
        )
        assert result.checks == {key: expected[key] for key in result.checks}, vector["name"]
        assert result.ok is expected["valid"], vector["name"]
        assert result.signing_input_sha256 == expected["signing_input_sha256"], vector["name"]


def test_canonical_json_uses_utf16_key_order_and_rejects_floats():
    assert canonical_json({"\U00010000": 1, "\ue000": 2}) == '{"𐀀":1,"":2}'
    with pytest.raises(TypeError, match="floating-point"):
        canonical_json({"amount": 1.5})


def test_parser_rejects_duplicate_names_and_oversized_safe_integer():
    with pytest.raises(ValueError, match="duplicate"):
        parse_envelope('{"govp":"GOVP-EXT-1","govp":"other"}')
    with pytest.raises(ValueError, match="safe integers"):
        canonical_json({"number": 2**53})


def test_reference_signer_round_trip_and_payload_tampering():
    vector = _corpus()["vectors"][0]
    unsigned = {key: value for key, value in vector["envelope"].items() if key != "signature"}
    signed = sign_envelope(unsigned, Ed25519PrivateKey.from_private_bytes(bytes(range(32))))
    subject = base64.b64decode(vector["subject_base64"])
    assert verify_envelope(signed, subject_bytes=subject).ok
    signed["payload"]["passed"] = False
    assert verify_envelope(signed, subject_bytes=subject).checks["signature"] is False
