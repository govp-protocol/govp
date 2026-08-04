import json
from argparse import Namespace
from pathlib import Path

import pytest

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


def test_verify_url_binds_to_final_redirect_url(monkeypatch, capsys):
    record = (ROOT / "examples/manufacturing-record.govp.txt").read_text(
        encoding="utf-8"
    )
    monkeypatch.setattr(
        cli,
        "_fetch",
        lambda _: (record, "https://redirected.example/record"),
    )

    exit_code = cli.command_verify_url(
        Namespace(url="https://govp.io/.well-known/govp.txt", json=True)
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


def test_main_reports_expected_user_errors(monkeypatch, capsys):
    monkeypatch.setattr(cli.sys, "argv", ["govp", "verify", "missing.govp"])

    assert cli.main() == 2
    assert "govp:" in capsys.readouterr().err
