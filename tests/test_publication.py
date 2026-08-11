import base64
import functools
import json
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

from govp import (
    authorize_subordinate_key,
    build_publication_tree,
    canonical_json,
    cli,
    publication_entry_id,
    publish_request,
    serialize_record,
    sign_envelope,
    sign_record,
    verify_publication_custody,
    verify_publication_tree,
    verify_publication_url,
)
from govp._bundled import run_bundled_publication_conformance
from govp.publication import (
    _batch_envelope,
    _verify_components,
    event_descriptor,
)

DOMAIN = "https://example.com"
NOW = "2026-08-11T12:00:00Z"


def _private(path: Path, seed: int) -> Ed25519PrivateKey:
    key = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)
    return key


def _public(path: Path, key: Ed25519PrivateKey) -> None:
    path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def _raw(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def _event(
    key: Ed25519PrivateKey,
    identifier: str,
    event_type: str,
    subject: bytes,
) -> dict:
    return sign_envelope(
        {
            "govp": "GOVP-EXT-1",
            "extension": {"id": "org.govp.test", "version": "1.0.0"},
            "type": event_type,
            "id": identifier,
            "issuer": {
                "canonical": f"{DOMAIN}/.well-known/govp.txt",
                "name": "Example",
            },
            "subject": {"type": "build-artifact", "id": identifier},
            "created_at": NOW,
            "hash": {
                "alg": "sha256",
                "value": __import__("hashlib").sha256(subject).hexdigest(),
            },
            "payload": {"result": "pass"},
            "references": [],
            "evidence": [],
            "origin": {
                "origin": "system_observed",
                "observed_by": "pytest/1",
                "observation": {"task": "build"},
            },
        },
        key,
    )


def _setup_request(tmp_path: Path, event_count: int = 2):
    domain_key_path = tmp_path / "domain.pem"
    developer_key_path = tmp_path / "developer.pem"
    developer_public_path = tmp_path / "developer.pub.pem"
    domain_key = _private(domain_key_path, 91)
    developer_key = _private(developer_key_path, 92)
    _public(developer_public_path, developer_key)

    identity_asset = b"example.com GOVP identity\n"
    identity = sign_record(
        {
            "version": "GOVP-1",
            "canonical": f"{DOMAIN}/.well-known/govp.txt",
            "publisher": "Example",
            "asset-type": "document",
            "asset-id": "publication-identity",
            "asset-sha256": __import__("hashlib").sha256(identity_asset).hexdigest(),
            "profile": "GOVP-PUBLICATION",
            "generated-at": "2026-08-01T00:00:00Z",
            "evidence": f"{DOMAIN}/publication",
        },
        domain_key,
    )
    (tmp_path / "govp.txt").write_text(serialize_record(identity), encoding="utf-8")
    domain_raw = _raw(domain_key)
    status = {
        "format": "GOVP-STATUS-1",
        "canonical": f"{DOMAIN}/.well-known/govp/revoked.json",
        "publisher": "Example",
        "authority": "https-origin",
        "generated_at": NOW,
        "keys": [
            {
                "key_id": "sha256:"
                + __import__("hashlib").sha256(domain_raw).hexdigest(),
                "public_key": base64.b64encode(domain_raw).decode(),
                "state": "active",
                "changed_at": "2026-08-01T00:00:00Z",
            }
        ],
        "revoked_records": [],
    }
    (tmp_path / "revoked.json").write_text(
        json.dumps(status, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (tmp_path / "index.json").write_text(
        json.dumps(
            {
                "canonical": f"{DOMAIN}/.well-known/govp/index.json",
                "format": "GOVP-DISCOVERY-1",
                "identity": f"{DOMAIN}/.well-known/govp.txt",
                "records": [f"{DOMAIN}/.well-known/govp.txt"],
                "status": f"{DOMAIN}/.well-known/govp/revoked.json",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    authorization_path = tmp_path / "authorization.json"
    authorization = authorize_subordinate_key(
        domain=DOMAIN,
        domain_private_key=domain_key_path,
        subordinate_public_key=developer_public_path,
        allowed_types=["org.govp.build/1"],
        valid_from="2026-08-01T00:00:00Z",
        valid_until="2026-09-01T00:00:00Z",
        output=authorization_path,
        created_at=NOW,
    )
    events = []
    values = []
    for index in range(event_count):
        subject = f"artifact-{index}\n".encode()
        envelope = _event(
            developer_key, f"BUILD-{index:05d}", "org.govp.build/1", subject
        )
        envelope_path = tmp_path / f"event-{index}.json"
        subject_path = tmp_path / f"subject-{index}.bin"
        envelope_path.write_text(
            json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        subject_path.write_bytes(subject)
        events.append(
            {
                "disposition": "publish" if index == 0 else "sealed_private",
                "envelope": envelope_path.name,
                "subject": subject_path.name,
            }
        )
        values.append((envelope, subject))
    request = {
        "authorization": authorization_path.name,
        "base_index": "index.json",
        "batch_id": "BUILD-20260811",
        "created_at": NOW,
        "domain": DOMAIN,
        "events": events,
        "identity_record": "govp.txt",
        "publish_types": ["org.govp.build/1"],
        "schema": "org.govp.publish-request/1",
        "status": "revoked.json",
        "workload": {
            "refs": ["refs/tags/v0.1.13"],
            "repository": "govp-protocol/govp",
        },
    }
    request_path = tmp_path / "publish-request.json"
    request_path.write_text(
        json.dumps(request, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {
        "authorization": authorization,
        "developer_key": developer_key,
        "domain_key": domain_key,
        "domain_key_path": domain_key_path,
        "request_path": request_path,
        "status": status,
        "values": values,
    }


def _workload(monkeypatch):
    values = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": "govp-protocol/govp",
        "GITHUB_REF": "refs/tags/v0.1.13",
        "GITHUB_SHA": "a" * 40,
        "GITHUB_RUN_ID": "123456",
        "GITHUB_WORKFLOW_REF": "govp-protocol/govp/.github/workflows/publish.yml@refs/tags/v0.1.13",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)


def test_publication_schema_and_10000_vector_are_exact():
    schema = json.loads(Path("schema/govp-publication-1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    result = run_bundled_publication_conformance()
    assert result.ok, result.failures
    assert result.passed == 2
    vectors = json.loads(Path("conformance/publication-vectors.json").read_text())
    large = vectors["vectors"][1]
    assert large["recipe"]["count"] == 10000
    assert len(large["expected"]["proof"]["top_proof"]) == 8


def test_publish_is_static_scoped_private_and_verifies_l1(tmp_path, monkeypatch):
    setup = _setup_request(tmp_path)
    _workload(monkeypatch)
    public = tmp_path / "site"
    custody = tmp_path / "custody"
    result = publish_request(
        request_path=setup["request_path"],
        domain_private_key=setup["domain_key_path"],
        public_dir=public,
        custody_dir=custody,
    )
    assert result.public_count == 1
    assert result.sealed_count == 1
    assert result.public_root != result.sealed_root
    public_files = {
        path.relative_to(public).as_posix()
        for path in public.rglob("*")
        if path.is_file()
    }
    assert public_files == {
        ".well-known/govp.txt",
        ".well-known/govp/index.json",
        ".well-known/govp/publication/batches/BUILD-20260811.json",
        ".well-known/govp/publication/index.json",
        ".well-known/govp/publication/keys/"
        + setup["authorization"]["payload"]["key_id"].removeprefix("sha256:")
        + ".json",
        ".well-known/govp/revoked.json",
    }
    assert not any("sealed" in path for path in public_files)
    proofs = sorted((custody / "proofs").glob("*.json"))
    assert len(proofs) == 2
    public_proof = next(
        path for path in proofs if json.loads(path.read_text())["disposition"] == "publish"
    )
    verification = verify_publication_tree(public_proof, public)
    assert verification.ok
    assert verification.layers == {"L0": True, "L1": True, "L2": None}
    private_proof = next(
        path
        for path in proofs
        if json.loads(path.read_text())["disposition"] == "sealed_private"
    )
    private_verification = verify_publication_custody(private_proof, custody)
    assert private_verification.ok
    discovery = json.loads((public / ".well-known/govp/index.json").read_text())
    assert discovery["records"] == [f"{DOMAIN}/.well-known/govp.txt"]
    assert discovery["publication"].endswith("/publication/index.json")


def test_publish_rejects_editor_and_unopted_type(tmp_path, monkeypatch):
    setup = _setup_request(tmp_path, event_count=1)
    with pytest.raises(ValueError, match="GitHub Actions workload"):
        publish_request(
            request_path=setup["request_path"],
            domain_private_key=setup["domain_key_path"],
            public_dir=tmp_path / "site",
            custody_dir=tmp_path / "custody",
        )
    _workload(monkeypatch)
    request = json.loads(setup["request_path"].read_text())
    request["publish_types"] = ["org.govp.deploy/1"]
    setup["request_path"].write_text(json.dumps(request))
    with pytest.raises(ValueError, match="not opted in"):
        publish_request(
            request_path=setup["request_path"],
            domain_private_key=setup["domain_key_path"],
            public_dir=tmp_path / "site",
            custody_dir=tmp_path / "custody",
        )


def test_out_of_scope_subordinate_event_is_rejected_at_l1(tmp_path):
    setup = _setup_request(tmp_path, event_count=1)
    subject = b"deployment\n"
    event = _event(
        setup["developer_key"], "DEPLOY-1", "org.govp.deploy/1", subject
    )
    descriptor = event_descriptor(event)
    root, proofs = build_publication_tree([descriptor], "OUT-OF-SCOPE")
    workload = {
        "provider": "github-actions",
        "repository": "govp-protocol/govp",
        "ref": "refs/tags/v0.1.13",
        "commit": "a" * 40,
        "run_id": "123456",
        "workflow_ref": "release.yml",
    }
    batch = _batch_envelope(
        batch_id="OUT-OF-SCOPE",
        created_at=NOW,
        disposition="publish",
        descriptors=[descriptor],
        root=root,
        domain=DOMAIN,
        domain_key=setup["domain_key"],
        workload=workload,
    )
    entry = publication_entry_id(descriptor)
    bundle = {
        "authorization_key_id": setup["authorization"]["payload"]["key_id"],
        "batch_id": "OUT-OF-SCOPE",
        "disposition": "publish",
        "envelope": event,
        "proof": proofs[entry],
        "schema": "org.govp.publication-proof/1",
        "subject_base64": base64.b64encode(subject).decode(),
    }
    result = _verify_components(
        bundle=bundle,
        batch=batch,
        authorization=setup["authorization"],
        status=setup["status"],
        domain=DOMAIN,
        live=False,
    )
    assert not result.ok
    assert result.layers == {"L0": True, "L1": False, "L2": None}
    assert result.reasons == ("SCOPE_MISMATCH",)


class _QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass


def test_python_http_server_tree_verifies_without_dynamic_routes(tmp_path, monkeypatch):
    setup = _setup_request(tmp_path, event_count=1)
    _workload(monkeypatch)
    public = tmp_path / "site"
    custody = tmp_path / "custody"
    publish_request(
        request_path=setup["request_path"],
        domain_private_key=setup["domain_key_path"],
        public_dir=public,
        custody_dir=custody,
    )
    proof = next((custody / "proofs").glob("*.json"))
    handler = functools.partial(_QuietHandler, directory=str(public))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = verify_publication_url(
            proof, f"http://127.0.0.1:{server.server_address[1]}"
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
    assert result.ok
    assert result.layers == {"L0": True, "L1": True, "L2": None}


def test_canonical_descriptor_bytes_are_stable():
    descriptor = {
        "id": "BUILD-1",
        "key_id": "sha256:" + "11" * 32,
        "signing_input_sha256": "22" * 32,
        "type": "org.govp.build/1",
    }
    assert canonical_json(descriptor) == (
        '{"id":"BUILD-1","key_id":"sha256:'
        + "11" * 32
        + '","signing_input_sha256":"'
        + "22" * 32
        + '","type":"org.govp.build/1"}'
    )


def test_publish_and_verify_cli_demo(tmp_path, monkeypatch, capsys):
    setup = _setup_request(tmp_path, event_count=1)
    _workload(monkeypatch)
    public = tmp_path / "cli-site"
    custody = tmp_path / "cli-custody"
    monkeypatch.setattr(
        cli.sys,
        "argv",
        [
            "govp",
            "publish",
            "--request",
            str(setup["request_path"]),
            "--domain-private-key",
            str(setup["domain_key_path"]),
            "--public-dir",
            str(public),
            "--custody-dir",
            str(custody),
        ],
    )
    assert cli.main() == 0
    assert "Published 1 event" in capsys.readouterr().out
    proof = next((custody / "proofs").glob("*.json"))
    monkeypatch.setattr(
        cli.sys,
        "argv",
        [
            "govp",
            "publication",
            "verify",
            str(proof),
            "--tree",
            str(public),
        ],
    )
    assert cli.main() == 0
    assert "L1   pass" in capsys.readouterr().out
