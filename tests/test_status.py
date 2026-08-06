import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator, FormatChecker

from govp import (
    derive_key_id,
    load_status,
    sign_record,
)
from govp import (
    evaluate_status as _evaluate_status,
)

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 8, 5, 0, 2, tzinfo=timezone.utc)


def evaluate_status(*args, **kwargs):
    kwargs.setdefault("now", NOW)
    return _evaluate_status(*args, **kwargs)


def make_record_and_status():
    key = Ed25519PrivateKey.generate()
    record = sign_record(
        {
            "canonical": "https://example.test/.well-known/govp.txt",
            "publisher": "Example issuer",
            "asset-type": "document",
            "asset-id": "example/status",
            "asset-sha256": hashlib.sha256(b"example").hexdigest(),
            "profile": "GOVP-BASIC",
            "generated-at": "2026-08-05T00:00:00Z",
            "evidence": "https://example.test/example.txt",
        },
        key,
    )
    public_key = record["public-key"]
    status = {
        "format": "GOVP-STATUS-1",
        "canonical": "https://example.test/.well-known/govp/revoked.json",
        "publisher": "Example issuer",
        "authority": "https-origin",
        "generated_at": "2026-08-05T00:00:00Z",
        "keys": [
            {
                "key_id": derive_key_id(public_key),
                "public_key": public_key,
                "state": "active",
                "changed_at": "2026-08-05T00:00:00Z",
            }
        ],
        "revoked_records": [],
    }
    return record, status


def test_online_status_reaches_currently_trusted():
    record, status = make_record_and_status()

    result = evaluate_status(
        record,
        status,
        record_fetched_url=record["canonical"],
        fetched_url=status["canonical"],
    )

    assert result.currently_trusted is True
    assert result.snapshot_trusted is True
    assert all(value is True for value in result.checks.values())


def test_offline_status_is_a_valid_snapshot_not_live_trust():
    record, status = make_record_and_status()

    result = evaluate_status(record, status)

    assert result.currently_trusted is None
    assert result.snapshot_valid is True
    assert result.snapshot_trusted is True
    assert result.checks["status-canonical"] is None


def test_live_status_rejects_stale_and_future_snapshots():
    record, status = make_record_and_status()
    options = {
        "record_fetched_url": record["canonical"],
        "fetched_url": status["canonical"],
    }

    status["generated_at"] = "2026-08-04T23:56:59Z"
    stale = evaluate_status(record, status, **options)
    assert stale.snapshot_valid is True
    assert stale.currently_trusted is False
    assert stale.checks["status-fresh"] is False

    status["generated_at"] = "2026-08-05T00:03:01Z"
    future = evaluate_status(record, status, **options)
    assert future.snapshot_valid is True
    assert future.currently_trusted is False
    assert future.checks["status-fresh"] is False


def test_status_freshness_window_is_explicitly_configurable():
    record, status = make_record_and_status()
    result = evaluate_status(
        record,
        status,
        record_fetched_url=record["canonical"],
        fetched_url=status["canonical"],
        max_age_seconds=60,
    )
    assert result.currently_trusted is False
    assert result.reasons == ("status-fresh",)


@pytest.mark.parametrize("key_state", ["retired", "revoked"])
def test_non_active_key_is_not_currently_trusted(key_state):
    record, status = make_record_and_status()
    status["keys"][0]["state"] = key_state

    result = evaluate_status(
        record,
        status,
        record_fetched_url=record["canonical"],
        fetched_url=status["canonical"],
    )

    assert result.currently_trusted is False
    assert result.checks["key-active"] is False


def test_explicit_record_revocation_is_not_trusted():
    record, status = make_record_and_status()
    status["revoked_records"].append(
        {
            "govp_id": record["govp-id"],
            "revoked_at": "2026-08-05T01:00:00Z",
            "reason": "withdrawn",
        }
    )

    result = evaluate_status(
        record,
        status,
        record_fetched_url=record["canonical"],
        fetched_url=status["canonical"],
    )

    assert result.currently_trusted is False
    assert result.checks["record-not-revoked"] is False


def test_status_rejects_wrong_origin_and_incorrect_key_identifier():
    record, status = make_record_and_status()
    status["canonical"] = "https://attacker.example/.well-known/govp/revoked.json"
    result = evaluate_status(record, status)
    assert result.snapshot_trusted is False
    assert result.checks["same-origin"] is False

    status["canonical"] = "https://example.test/.well-known/govp/revoked.json"
    status["keys"][0]["key_id"] = "sha256:" + "0" * 64
    result = evaluate_status(record, status)
    assert result.checks["status-format"] is False

    _, status = make_record_and_status()
    status["unexpected"] = "unsigned ambiguity"
    result = evaluate_status(record, status)
    assert result.checks["status-format"] is False


def test_status_schema_and_conformance_vectors(tmp_path):
    schema = json.loads(
        (ROOT / "schema/govp-status-1.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    corpus = json.loads(
        (ROOT / "conformance/status-vectors.json").read_text(encoding="utf-8")
    )
    for vector in corpus["vectors"]:
        status_file = tmp_path / f"{vector['name']}.json"
        status_file.write_text(json.dumps(vector["status"]), encoding="utf-8")
        loaded = load_status(str(status_file))
        if vector["expected"]["schema_valid"]:
            validator.validate(loaded)
        else:
            assert list(validator.iter_errors(loaded))
