import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

import govp
from govp.core import (
    RECORD_DOMAIN,
    load_record,
    normalize_canonical,
    normalize_field_name,
    parse_record,
    serialize_record,
    sha256,
    sign_record,
    signing_input,
    verify,
)

ROOT = Path(__file__).resolve().parents[1]


def test_top_level_api_exports_stable_verifier_contract():
    fields = govp.parse_record(
        (ROOT / "examples/manufacturing-record.govp.txt").read_text(encoding="utf-8")
    )
    result = govp.verify(fields)

    assert isinstance(result, govp.Verification)
    assert isinstance(result, govp.VerifyResult)
    assert govp.derive_govp_id(
        fields["asset-type"], fields["asset-id"], fields["asset-sha256"]
    ) == fields["govp-id"]
    assert govp.signing_input(fields) == signing_input(fields)


def test_load_record_accepts_string_and_pathlike_values():
    record = ROOT / "examples/manufacturing-record.govp.txt"

    assert load_record(str(record)) == load_record(record)


def test_sign_and_serialize_public_api_round_trip():
    asset = b"synthetic release evidence\n"
    fields = {
        "canonical": "https://example.test/.well-known/govp.txt",
        "publisher": "Example issuer",
        "asset-type": "document",
        "asset-id": "example/release-1",
        "asset-sha256": sha256(asset),
        "profile": "GOVP-BASIC",
        "generated-at": "2026-08-05T00:00:00Z",
        "evidence": "https://example.test/release-1.txt",
    }

    record = sign_record(fields, Ed25519PrivateKey.generate())
    rendered = serialize_record(record)
    loaded = parse_record(rendered)

    assert loaded == record
    assert verify(loaded, asset_bytes=asset).ok is True
    assert rendered.startswith("Version: GOVP-1\nCanonical: https://")


def test_sign_record_rejects_computed_fields_and_wrong_key_type():
    fields = {
        "asset-type": "document",
        "asset-id": "example",
        "asset-sha256": "0" * 64,
        "govp-id": "GOVP-DOC-000000000000",
    }

    with pytest.raises(ValueError, match="computed"):
        sign_record(fields, Ed25519PrivateKey.generate())
    with pytest.raises(TypeError, match="Ed25519PrivateKey"):
        sign_record({}, object())  # type: ignore[arg-type]


def test_all_conformance_vectors():
    corpus = json.loads(
        (ROOT / "conformance/vectors.json").read_text(encoding="utf-8")
    )
    assert RECORD_DOMAIN == corpus["domain"].replace("\\0", "\0").encode()
    for vector in corpus["vectors"]:
        fields = parse_record(vector["record"])
        result = verify(fields)
        expected = vector["expected"]
        assert fields.get("govp-id") == expected["govp_id"], vector["name"]
        assert result.checks["format"] == expected["format_ok"], vector["name"]
        assert result.checks["govp-id"] == expected["govpid_ok"], vector["name"]
        assert result.checks["signature"] == expected["signature_ok"], vector["name"]
        assert result.ok == expected["core_valid"], vector["name"]
        assert sha256(signing_input(fields)) == expected["signing_input_sha256"], vector["name"]


def test_all_json_conformance_vectors(tmp_path):
    corpus = json.loads(
        (ROOT / "conformance/json-vectors.json").read_text(encoding="utf-8")
    )
    for vector in corpus["vectors"]:
        path = tmp_path / f"{vector['name']}.json"
        path.write_text(
            json.dumps(vector["payload"], ensure_ascii=False),
            encoding="utf-8",
        )
        expected = vector["expected"]
        if expected["load_ok"]:
            fields = load_record(path)
            assert verify(fields).ok == expected["core_valid"], vector["name"]
        else:
            with pytest.raises(ValueError, match=expected["error"]):
                load_record(path)


def test_json_schema_validates_canonical_record_and_bundle():
    schema = json.loads(
        (ROOT / "schema/govp-1.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    corpus = json.loads(
        (ROOT / "conformance/json-vectors.json").read_text(encoding="utf-8")
    )

    validator.validate(corpus["vectors"][0]["payload"])
    validator.validate(corpus["vectors"][1]["payload"])


def test_asset_binding():
    record = ROOT / "examples/manufacturing-record.govp.txt"
    asset = (ROOT / "examples/manufacturing-record.statement.txt").read_bytes()
    tampered_asset = (
        ROOT / "examples/manufacturing-record.tampered.statement.txt"
    ).read_bytes()
    fields = parse_record(record.read_text(encoding="utf-8"))
    valid = verify(fields, asset_bytes=asset)
    invalid = verify(fields, asset_bytes=tampered_asset)

    assert valid.ok
    assert invalid.ok is False
    assert invalid.checks["format"] is True
    assert invalid.checks["signature"] is True
    assert invalid.checks["govp-id"] is True
    assert invalid.checks["asset"] is False


def test_public_key_is_required_for_format():
    record = ROOT / "examples/manufacturing-record.govp.txt"
    fields = parse_record(record.read_text(encoding="utf-8"))
    fields.pop("public-key")

    result = verify(fields)

    assert result.checks["format"] is False
    assert result.checks["signature"] is False
    assert result.ok is False


def test_ed25519_exceptional_encodings_fail_closed():
    record = ROOT / "examples/manufacturing-record.govp.txt"
    fields = parse_record(record.read_text(encoding="utf-8"))
    identity = bytes([1]) + bytes(31)
    negative_zero = bytes([1]) + bytes(30) + bytes([0x80])
    noncanonical_y = (2**255 - 19).to_bytes(32, "little")
    order = 2**252 + 27742317777372353535851937790883648493

    for public_key in (identity, negative_zero, noncanonical_y):
        candidate = {**fields, "public-key": base64.b64encode(public_key).decode()}
        assert verify(candidate).checks["signature"] is False

    signature = base64.b64decode(fields["signature"])
    identity_r = identity + signature[32:]
    high_s = signature[:32] + order.to_bytes(32, "little")
    for raw_signature in (identity_r, high_s):
        candidate = {
            **fields,
            "signature": base64.b64encode(raw_signature).decode(),
        }
        assert verify(candidate).checks["signature"] is False


def test_canonical_normalization_preserves_security_boundaries():
    https = "https://www.example.test/path/"

    assert normalize_canonical(https) == https
    assert normalize_canonical("http://www.example.test/path/") != normalize_canonical(
        https
    )
    assert normalize_canonical("https://example.test/path") != normalize_canonical(
        https
    )
    assert normalize_canonical("https://www.example.test/path") != normalize_canonical(
        https
    )
    assert normalize_canonical("https://example.test:invalid/path") == ""
    assert normalize_canonical("https://example.test:0/path") == (
        "https://example.test:0/path"
    )


def test_unknown_non_ascii_field_is_preserved_and_sortable():
    fields = {"version": "GOVP-1", "x-évidence": "sí"}

    canonical = signing_input(fields)

    assert "x-évidence: sí\n".encode() in canonical


def test_field_name_normalization_only_lowercases_ascii():
    assert normalize_field_name("X-Évidence") == "x-Évidence"
    assert normalize_field_name("X-İ") == "x-İ"
    assert normalize_field_name("x-i̇") == "x-i̇"


def test_frozen_govp1_trim_set_preserves_published_behavior():
    assert parse_record("Publisher: example\u00a0\n")["publisher"] == "example"
    assert parse_record("Publisher: example\u3000\n")["publisher"] == "example"


def test_internal_looking_unknown_field_is_still_signed():
    fields = {"version": "GOVP-1", "__extension": "signed"}

    assert b"__extension: signed\n" in signing_input(fields)


def test_duplicate_normalized_field_names_keep_the_last_value():
    canonical = signing_input({"Version": "GOVP-0", "version": "GOVP-1"})

    assert canonical == b"version: GOVP-1\n"


def test_bare_carriage_return_is_not_trimmed_into_a_valid_record():
    record = (ROOT / "examples/manufacturing-record.govp.txt").read_text(
        encoding="utf-8"
    )
    crlf_fields = parse_record(
        record.replace(
            "Publisher: Example Manufacturing Organization\n",
            "Publisher: Example Manufacturing Organization\r\n",
        )
    )
    # CRLF is valid and normalized.
    assert crlf_fields["publisher"] == "Example Manufacturing Organization"

    fields = parse_record(
        record.replace(
            "Publisher: Example Manufacturing Organization\n",
            "Publisher: Example Manufacturing Organization\r \n",
        )
    )
    assert fields["publisher"].endswith("\r")
    assert verify(fields).checks["format"] is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("publisher", "winery.example\nq: injected"),
        ("asset-id", "asset\rreplacement"),
        ("x-extension", "value\x00suffix"),
    ],
)
def test_format_and_signing_reject_control_character_injection(field, value):
    record = ROOT / "examples/manufacturing-record.govp.txt"
    fields = parse_record(record.read_text(encoding="utf-8"))
    fields[field] = value

    result = verify(fields)

    assert result.checks["format"] is False
    assert result.checks["signature"] is False
    with pytest.raises(ValueError, match="cannot contain"):
        signing_input(fields)


@pytest.mark.parametrize("field_name", ["", "x:injected", "x\ninjected", "x\x00"])
def test_signing_rejects_invalid_field_names(field_name):
    with pytest.raises(ValueError, match="field names"):
        signing_input({"version": "GOVP-1", field_name: "value"})


def test_json_record_rejects_non_string_values(tmp_path):
    path = tmp_path / "record.json"
    path.write_text('{"version": "GOVP-1", "asset-id": 7}', encoding="utf-8")

    with pytest.raises(ValueError, match="must be strings"):
        load_record(path)


def test_direct_verification_rejects_non_string_values():
    fields = {"version": "GOVP-1", "public-key": 7, "signature": 9}

    result = verify(fields, asset_bytes=b"test")  # type: ignore[arg-type]

    assert result.checks["format"] is False
    assert result.checks["signature"] is False
    assert result.checks["asset"] is False
    assert result.ok is False


def test_json_and_direct_verification_reject_lone_surrogates(tmp_path):
    path = tmp_path / "record.json"
    path.write_text('{"version":"GOVP-1","asset-id":"\\ud800"}', encoding="utf-8")

    with pytest.raises(ValueError, match="Unicode scalar values"):
        load_record(path)

    fields = {"version": "GOVP-1", "asset-id": "\ud800"}
    result = verify(fields)
    assert result.checks["format"] is False
    assert result.checks["signature"] is False
    assert result.derived_govp_id is None


def test_json_bundle_requires_textual_unambiguous_fields(tmp_path):
    path = tmp_path / "bundle.json"
    path.write_text(
        '{"format":"GOVP-1","record":{"version":"GOVP-1",'
        '"publisher":"winery.example\\nq: injected"},"asset":{}}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="cannot contain"):
        load_record(path)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("canonical", "http://winery.example/.well-known/govp.txt"),
        ("canonical", "https://user@winery.example/.well-known/govp.txt"),
        ("asset-type", "DOCUMENT"),
        ("asset-sha256", "A" * 64),
        ("asset-sha256", "0" * 63),
        ("govp-id", "GOVP-DOC-not-hex"),
        ("evidence", "not-a-url"),
        ("generated-at", "2026-02-30T10:00:00Z"),
        ("generated-at", "2026-05-31T10:00:00+00:00"),
        ("public-key", "invalid"),
        ("signature", "invalid"),
    ],
)
def test_format_rejects_values_outside_the_normative_shape(field, value):
    record = ROOT / "examples/manufacturing-record.govp.txt"
    fields = parse_record(record.read_text(encoding="utf-8"))
    fields[field] = value

    assert verify(fields).checks["format"] is False


def test_format_accepts_rfc3339_utc_leap_second_shape():
    record = ROOT / "examples/manufacturing-record.govp.txt"
    fields = parse_record(record.read_text(encoding="utf-8"))
    fields["generated-at"] = "2016-12-31T23:59:60Z"

    result = verify(fields)

    assert result.checks["format"] is True
    assert result.checks["signature"] is False


@pytest.mark.parametrize(
    "fraction",
    ["1", "12", "123", "1234", "12345", "123456", "1234567", "123456789"],
)
def test_generated_at_fraction_length_is_version_independent(fraction):
    record = ROOT / "examples/manufacturing-record.govp.txt"
    fields = parse_record(record.read_text(encoding="utf-8"))
    fields["generated-at"] = f"2026-01-01T00:00:00.{fraction}Z"

    assert verify(fields).checks["format"] is True


def test_generated_at_empty_fraction_is_rejected():
    record = ROOT / "examples/manufacturing-record.govp.txt"
    fields = parse_record(record.read_text(encoding="utf-8"))
    fields["generated-at"] = "2026-01-01T00:00:00.Z"

    assert verify(fields).checks["format"] is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("canonical", "https://control\x01.example/record"),
        ("canonical", "https://zero-width.example/\u200b"),
        ("evidence", "https://control.example/\x1basset"),
        ("evidence", "https://unicode.example/évidence"),
        ("evidence", "https://example.test/%zz"),
        ("evidence", 'https://example.test/"quoted"'),
        ("evidence", "https://example.test/back\\slash"),
    ],
)
def test_url_fields_require_visible_ascii_uri_text(field, value):
    record = ROOT / "examples/manufacturing-record.govp.txt"
    fields = parse_record(record.read_text(encoding="utf-8"))
    fields[field] = value

    assert verify(fields).checks["format"] is False


def test_free_text_controls_are_signed_but_reported_as_advisory():
    record = ROOT / "examples/manufacturing-record.govp.txt"
    fields = parse_record(record.read_text(encoding="utf-8"))
    fields["publisher"] = "Example\x01 Organization"

    result = verify(fields)

    assert result.checks["format"] is True
    assert result.checks["signature"] is False
    assert result.warnings == ("signed-non-printable-text",)


def test_url_fields_accept_complete_percent_encoding():
    record = ROOT / "examples/manufacturing-record.govp.txt"
    fields = parse_record(record.read_text(encoding="utf-8"))
    fields["evidence"] = "https://example.test/%C3%A9vidence"

    assert verify(fields).checks["format"] is True


def test_non_http_evidence_scheme_is_valid_but_warned():
    record = ROOT / "examples/manufacturing-record.govp.txt"
    fields = parse_record(record.read_text(encoding="utf-8"))
    fields["evidence"] = "data:text/plain,example"

    result = verify(fields)

    assert result.checks["format"] is True
    assert result.warnings == ("non-http-evidence-scheme",)


def test_schema_requires_public_key():
    schema = json.loads(
        (ROOT / "schema/govp-1.schema.json").read_text(encoding="utf-8")
    )

    assert "public-key" in schema["$defs"]["canonicalRecord"]["required"]
    assert "Public-Key" in schema["$defs"]["displayRecord"]["required"]
    assert "govp-id" in schema["$defs"]["verificationResult"]["properties"]["checks"]["required"]
    assert "govpid" not in schema["$defs"]["verificationResult"]["properties"]["checks"]["properties"]
    assert set(
        schema["$defs"]["verificationResult"]["properties"]["warnings"]["items"][
            "enum"
        ]
    ) == {"non-http-evidence-scheme", "signed-non-printable-text"}


def test_json_schema_rejects_non_ascii_url_text():
    schema = json.loads(
        (ROOT / "schema/govp-1.schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    fields = load_record(ROOT / "examples/manufacturing-record.govp.txt")
    fields["evidence"] = "https://example.test/évidence"

    with pytest.raises(ValidationError):
        validator.validate(fields)
