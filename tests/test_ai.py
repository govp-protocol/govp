import base64
import json
from pathlib import Path

from govp.ai import AI1_CODES, receive_ai, receive_ai_chain

ROOT = Path(__file__).resolve().parents[1]


def _vectors():
    return json.loads((ROOT / "conformance/ai-vectors.json").read_text())["vectors"]


def test_ai_vectors_reproduce_gate_results():
    assert len(AI1_CODES) == 11
    for vector in _vectors():
        result = receive_ai(
            base64.b64decode(vector["transport_base64"]),
            subject_bytes=base64.b64decode(vector["subject_base64"]),
        )
        assert result.admitted is vector["expected"]["admitted"], vector["name"]
        assert result.code == vector["expected"]["code"], vector["name"]


def test_ai_gate_requires_subject_and_canonical_transport():
    vector = _vectors()[0]
    data = base64.b64decode(vector["transport_base64"])
    assert receive_ai(data, subject_bytes=None).code == "AI1_SUBJECT_REQUIRED"
    assert receive_ai(data + b"\n", subject_bytes=b"irrelevant").code == "AI1_INVALID_ENVELOPE"


def test_ai_gate_rejects_subject_substitution_and_deep_pre_auth_input():
    vector = _vectors()[0]
    data = base64.b64decode(vector["transport_base64"])
    assert receive_ai(data, subject_bytes=b"other").code == "AI1_SUBJECT_DIGEST_MISMATCH"
    deep = (b'{"x":' * 10_000) + b"0" + (b"}" * 10_000)
    result = receive_ai(deep, subject_bytes=b"x")
    assert result.admitted is False
    assert result.code == "AI1_INVALID_ENVELOPE"


def test_ai_schema_accepts_positive_and_rejects_negative_payloads():
    from jsonschema import Draft202012Validator

    schema = json.loads((ROOT / "schema/govp-ai-1.schema.json").read_text())
    validator = Draft202012Validator(schema)
    for vector in _vectors():
        envelope = json.loads(base64.b64decode(vector["transport_base64"]))
        schema_ok = not list(validator.iter_errors(envelope["payload"]))
        expected = vector["name"] not in {
            "05-failed-with-output",
            "07-semantic-comparison-rejected",
        }
        assert schema_ok is expected, vector["name"]


def test_ai_chain_resolves_exact_predecessors_and_rejects_missing_request():
    vectors = _vectors()
    valid = vectors[:3]
    items = [
        (
            base64.b64decode(vector["transport_base64"]),
            base64.b64decode(vector["subject_base64"]),
        )
        for vector in valid
    ]
    assert receive_ai_chain(items).admitted is True
    missing = receive_ai_chain(items[1:])
    assert missing.admitted is False
    assert missing.code == "AI1_CHAIN_INCOMPLETE"


def test_ai_chain_rejects_duplicate_record_and_attempt():
    vectors = _vectors()
    request = (
        base64.b64decode(vectors[0]["transport_base64"]),
        base64.b64decode(vectors[0]["subject_base64"]),
    )
    result = (
        base64.b64decode(vectors[1]["transport_base64"]),
        base64.b64decode(vectors[1]["subject_base64"]),
    )
    assert receive_ai_chain([request, request]).code == "AI1_CHAIN_CONFLICT"
    assert receive_ai_chain([request, result, result]).code == "AI1_CHAIN_CONFLICT"
