import json
from argparse import Namespace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from govp import cli

ROOT = Path(__file__).resolve().parents[1]


class FakeResponse:
    def __init__(
        self,
        body: bytes,
        *,
        final_url: str = "https://example.test/.well-known/govp.txt",
        content_length: str | None = None,
    ):
        self.body = body
        self.final_url = final_url
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = content_length

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def geturl(self):
        return self.final_url

    def read(self, limit):
        return self.body[:limit]


class FakeOpener:
    def __init__(self, response):
        self.response = response

    def open(self, request, timeout):
        assert request.full_url.startswith("https://")
        assert timeout == 15
        return self.response


def install_fake_response(monkeypatch, response):
    monkeypatch.setattr(cli.ssl, "create_default_context", lambda **_: object())
    monkeypatch.setattr(cli, "build_opener", lambda *_: FakeOpener(response))


@pytest.mark.parametrize(
    "url",
    [
        "http://example.test/record",
        "example.test/record",
        "https://user@example.test/record",
        "https:///record",
    ],
)
def test_fetch_rejects_non_https_or_credentialed_urls(url):
    with pytest.raises(ValueError, match="absolute HTTPS"):
        cli._fetch(url)


def test_redirect_handler_rejects_https_downgrade():
    handler = cli._HTTPSOnlyRedirectHandler()

    with pytest.raises(ValueError, match="absolute HTTPS"):
        handler.redirect_request(None, None, 302, "Found", {}, "http://example.test/")


def test_fetch_returns_final_https_url(monkeypatch):
    response = FakeResponse(
        b"Version: GOVP-1\n",
        final_url="https://cdn.example.test/record",
    )
    install_fake_response(monkeypatch, response)

    text, final_url = cli._fetch("https://example.test/record")

    assert text == "Version: GOVP-1\n"
    assert final_url == "https://cdn.example.test/record"


def test_fetch_rejects_declared_or_streamed_oversize(monkeypatch):
    declared = FakeResponse(b"", content_length=str(cli.MAX_RECORD_BYTES + 1))
    install_fake_response(monkeypatch, declared)
    with pytest.raises(ValueError, match="download limit"):
        cli._fetch("https://example.test/record")

    streamed = FakeResponse(b"x" * (cli.MAX_RECORD_BYTES + 1))
    install_fake_response(monkeypatch, streamed)
    with pytest.raises(ValueError, match="download limit"):
        cli._fetch("https://example.test/record")


def test_fetch_rejects_invalid_utf8(monkeypatch):
    install_fake_response(monkeypatch, FakeResponse(b"\xff"))

    with pytest.raises(ValueError, match="valid UTF-8"):
        cli._fetch("https://example.test/record")


def test_fetch_tolerates_invalid_content_length_header(monkeypatch):
    response = FakeResponse(b"Version: GOVP-1\n", content_length="not-a-number")
    install_fake_response(monkeypatch, response)

    text, _ = cli._fetch("https://example.test/.well-known/govp.txt")

    assert text == "Version: GOVP-1\n"


def test_fetch_uses_certifi_by_default_and_explicit_ca_bundle(monkeypatch, tmp_path):
    selected = []
    monkeypatch.setattr(
        cli.ssl,
        "create_default_context",
        lambda **kwargs: selected.append(kwargs["cafile"]) or object(),
    )
    monkeypatch.setattr(
        cli,
        "build_opener",
        lambda *_: FakeOpener(FakeResponse(b"Version: GOVP-1\n")),
    )
    custom = tmp_path / "enterprise-ca.pem"
    custom.write_text("test CA placeholder", encoding="utf-8")

    cli._fetch("https://example.test/.well-known/govp.txt")
    cli._fetch(
        "https://example.test/.well-known/govp.txt", ca_bundle=custom
    )

    assert selected == [cli.certifi.where(), str(custom)]


def test_verify_url_binds_to_final_redirect_url(monkeypatch, capsys):
    record = (ROOT / "examples/manufacturing-record.govp.txt").read_text(
        encoding="utf-8"
    )
    monkeypatch.setattr(
        cli,
        "_fetch",
        lambda _, **__: (record, "https://redirected.example/record"),
    )

    exit_code = cli.command_verify_url(
        Namespace(
            url="https://govp.io/.well-known/govp.txt",
            ca_bundle=None,
            json=True,
        )
    )
    payload = capsys.readouterr().out

    assert exit_code == 1
    assert '"format": true' in payload
    assert '"signature": true' in payload
    assert '"canonical": false' in payload


def test_local_commands_cover_human_and_json_results(tmp_path, capsys):
    record = ROOT / "examples/manufacturing-record.govp.txt"
    asset = ROOT / "examples/manufacturing-record.statement.txt"

    assert cli.command_verify(
        Namespace(record=str(record), asset=str(asset), json=False)
    ) == 0
    assert "GOVP verification: VALID" in capsys.readouterr().out

    bad_asset = tmp_path / "bad.txt"
    bad_asset.write_text("tampered", encoding="utf-8")
    assert cli.command_verify(
        Namespace(record=str(record), asset=str(bad_asset), json=True)
    ) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["checks"]["asset"] is False
    assert payload["warnings"] == []


def test_inspect_id_self_test_and_parser_commands(capsys):
    record = ROOT / "examples/manufacturing-record.govp.txt"

    assert cli.command_inspect(Namespace(record=str(record))) == 0
    inspected = json.loads(capsys.readouterr().out)
    assert inspected["derived_govp_id"] == "GOVP-DOC-cb352d4b8a77"

    assert cli.command_id(
        Namespace(type="document", asset_id="sample", sha256="0" * 64)
    ) == 0
    assert capsys.readouterr().out.startswith("GOVP-DOC-")

    assert cli.command_id(
        Namespace(type="unsupported", asset_id="sample", sha256="0" * 64)
    ) == 2
    assert "unsupported asset type" in capsys.readouterr().err

    assert cli.command_self_test(Namespace()) == 0
    assert "GOVP self-test: PASS" in capsys.readouterr().out

    parser = cli.build_parser()
    args = parser.parse_args(["verify", str(record), "--json"])
    assert args.handler is cli.command_verify


def test_bundled_conformance_and_example_extraction(tmp_path, capsys):
    assert cli.command_conformance(Namespace(run=True)) == 0
    output = capsys.readouterr().out
    assert "GOVP conformance: PASS" in output
    assert "19/19 vectors" in output

    assert cli.command_status_conformance(Namespace(run=True)) == 0
    output = capsys.readouterr().out
    assert "GOVP-STATUS-1 conformance: PASS" in output
    assert "3/3 vectors" in output

    destination = tmp_path / "govp-examples"
    assert cli.command_examples(Namespace(directory=str(destination))) == 0
    output = capsys.readouterr().out
    assert "Extracted 3 synthetic GOVP examples" in output

    record = destination / "manufacturing-record.govp.txt"
    asset = destination / "manufacturing-record.statement.txt"
    tampered = destination / "manufacturing-record.tampered.statement.txt"
    assert record.is_file()
    assert asset.is_file()
    assert tampered.is_file()
    assert cli.command_verify(
        Namespace(record=str(record), asset=str(asset), json=False)
    ) == 0
    capsys.readouterr()
    assert cli.command_verify(
        Namespace(record=str(record), asset=str(tampered), json=False)
    ) == 1


def test_example_extraction_refuses_to_overwrite_different_file(tmp_path):
    destination = tmp_path / "govp-examples"
    destination.mkdir()
    (destination / "manufacturing-record.govp.txt").write_text(
        "different", encoding="utf-8"
    )

    with pytest.raises(ValueError, match="refusing to overwrite"):
        cli.command_examples(Namespace(directory=str(destination)))


def test_issue_command_creates_new_verified_record_without_overwrite(tmp_path, capsys):
    asset = tmp_path / "release.txt"
    asset.write_text("synthetic release\n", encoding="utf-8")
    private_key = tmp_path / "issuer-private.pem"
    private_key.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    private_key.chmod(0o600)
    output = tmp_path / "release.govp"
    args = Namespace(
        asset=str(asset),
        canonical="https://example.test/.well-known/govp/{govp-id}.govp",
        publisher="Example issuer",
        asset_type="document",
        asset_id="example/release",
        evidence="https://example.test/release.txt",
        private_key=str(private_key),
        profile="GOVP-BASIC",
        license="Apache-2.0",
        generated_at="2026-08-05T00:00:00Z",
        output=str(output),
    )

    assert cli.command_issue(args) == 0
    record = cli.load_record(output)
    assert cli.verify(record, asset_bytes=asset.read_bytes()).ok is True
    assert record["canonical"].endswith(f"/{record['govp-id']}.govp")
    assert "Wrote GOVP-DOC-" in capsys.readouterr().out
    with pytest.raises(FileExistsError):
        cli.command_issue(args)


def test_issue_command_rejects_private_key_with_broad_permissions(tmp_path):
    if cli.os.name == "nt":
        pytest.skip("POSIX file mode check")
    private_key = tmp_path / "issuer-private.pem"
    private_key.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    private_key.chmod(0o644)

    with pytest.raises(ValueError, match="chmod 600"):
        cli._load_private_key(private_key)


def test_main_reports_expected_user_errors(monkeypatch, capsys):
    monkeypatch.setattr(cli.sys, "argv", ["govp", "verify", "missing.govp"])

    assert cli.main() == 2
    assert "govp:" in capsys.readouterr().err
