"""Command-line interface for the GOVP reference verifier."""

from __future__ import annotations

import argparse
import json
import ssl
import sys
from pathlib import Path
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    Request,
    build_opener,
)

import certifi

from . import __version__
from ._bundled import extract_bundled_examples, run_bundled_conformance
from .core import (
    _valid_absolute_url,
    derive_govp_id,
    load_record,
    parse_record,
    sha256,
    signing_input,
    verify,
)

MAX_RECORD_BYTES = 1024 * 1024


def _require_https_url(url: str) -> None:
    if not _valid_absolute_url(url, https_only=True):
        raise ValueError("verify-url requires an absolute HTTPS URL without credentials")


class _HTTPSOnlyRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _require_https_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _fetch(url: str) -> tuple[str, str]:
    _require_https_url(url)
    request = Request(url, headers={"User-Agent": f"govp/{__version__}"})
    # Standalone PyInstaller binaries cannot rely on the host Python's CA
    # location. certifi supplies the same explicit trust store on every
    # supported platform and is bundled into the executable.
    context = ssl.create_default_context(cafile=certifi.where())
    opener = build_opener(_HTTPSOnlyRedirectHandler(), HTTPSHandler(context=context))
    with opener.open(request, timeout=15) as response:
        final_url = response.geturl()
        _require_https_url(final_url)
        declared_length = response.headers.get("Content-Length")
        if declared_length is not None:
            try:
                declared_size = int(declared_length)
            except (TypeError, ValueError):
                declared_size = None
            if declared_size is not None and declared_size > MAX_RECORD_BYTES:
                raise ValueError(
                    f"record exceeds the {MAX_RECORD_BYTES}-byte download limit"
                )
        raw = response.read(MAX_RECORD_BYTES + 1)
        if len(raw) > MAX_RECORD_BYTES:
            raise ValueError(
                f"record exceeds the {MAX_RECORD_BYTES}-byte download limit"
            )
        try:
            return raw.decode("utf-8", errors="strict"), final_url
        except UnicodeDecodeError as error:
            raise ValueError("record is not valid UTF-8") from error


def _print_result(result, as_json: bool) -> None:
    payload = {
        "ok": result.ok,
        "govp_id": result.fields.get("govp-id"),
        "derived_govp_id": result.derived_govp_id,
        "checks": result.checks,
        "warnings": list(result.warnings),
    }
    if result.asset_sha256:
        payload["asset_sha256"] = result.asset_sha256
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    print("GOVP verification:", "VALID" if result.ok else "INVALID")
    for name, value in result.checks.items():
        label = "not checked" if value is None else ("pass" if value else "FAIL")
        print(f"  {name:<12} {label}")
    if result.fields.get("govp-id"):
        print(f"  record       {result.fields['govp-id']}")
    for warning in result.warnings:
        print(f"  warning      {warning}")


def command_verify(args: argparse.Namespace) -> int:
    path = Path(args.record)
    fields = load_record(path)
    asset = Path(args.asset).read_bytes() if args.asset else None
    result = verify(fields, asset_bytes=asset)
    _print_result(result, args.json)
    return 0 if result.ok else 1


def command_verify_url(args: argparse.Namespace) -> int:
    text, final_url = _fetch(args.url)
    fields = parse_record(text)
    result = verify(fields, fetched_url=final_url)
    _print_result(result, args.json)
    return 0 if result.ok else 1


def command_inspect(args: argparse.Namespace) -> int:
    fields = load_record(Path(args.record))
    payload = {
        "fields": fields,
        "signing_input_sha256": sha256(signing_input(fields)),
        "derived_govp_id": derive_govp_id(
            fields.get("asset-type", ""),
            fields.get("asset-id", ""),
            fields.get("asset-sha256", ""),
        ),
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def command_id(args: argparse.Namespace) -> int:
    value = derive_govp_id(args.type, args.asset_id, args.sha256)
    if value is None:
        print(f"unsupported asset type: {args.type}", file=sys.stderr)
        return 2
    print(value)
    return 0


def command_self_test(_: argparse.Namespace) -> int:
    fields = parse_record(
        "Version: GOVP-1\n"
        "Canonical: https://winery.example/.well-known/govp.txt\n"
        "Publisher: winery.example\n"
        "Asset-Type: document\n"
        "Asset-ID: aviso-legal\n"
        "Asset-SHA256: "
        "71e5bb01f249ad18a551a218b0b5b9eb40263c64ae1c8f37dc48951622a54734\n"
        "License: CC-BY-4.0\n"
        "Profile: GOVP-BASIC\n"
        "Generated-At: 2026-05-31T10:00:00Z\n"
        "GOVP-ID: GOVP-DOC-39969a54190e\n"
        "Evidence: https://winery.example/ev/1\n"
        "Public-Key: A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=\n"
        "Signature: "
        "uq+dPdfTRlEPPVOosgWAjpjAU+FO0E5SDl5Wo5m9RVK8Ysk/"
        "mAN907neMZMD7ISly/VF5Rxcq0JyKwHmjg9YAg==\n"
    )
    parser_ok = fields.get("version") == "GOVP-1"
    id_ok = fields.get("govp-id") == derive_govp_id(
        "document",
        "aviso-legal",
        "71e5bb01f249ad18a551a218b0b5b9eb40263c64ae1c8f37dc48951622a54734",
    )
    valid_accepted = verify(fields).ok
    tampered = dict(fields)
    tampered["publisher"] = "attacker.example"
    tampered_rejected = not verify(tampered).ok
    ok = parser_ok and id_ok and valid_accepted and tampered_rejected
    print("GOVP self-test:", "PASS" if ok else "FAIL")
    print(f"  parser       {'pass' if parser_ok else 'FAIL'}")
    print(f"  GOVP-ID      {'pass' if id_ok else 'FAIL'}")
    print(f"  valid signature {'accepted' if valid_accepted else 'REJECTED'}")
    print(f"  tampering    {'rejected' if tampered_rejected else 'ACCEPTED'}")
    return 0 if ok else 1


def command_conformance(_: argparse.Namespace) -> int:
    result = run_bundled_conformance()
    print(
        "GOVP conformance:",
        "PASS" if result.ok else "FAIL",
        f"({result.passed}/{result.total} vectors)",
    )
    for failure in result.failures:
        print(f"  FAIL {failure}")
    return 0 if result.ok else 1


def command_examples(args: argparse.Namespace) -> int:
    extracted = extract_bundled_examples(Path(args.directory))
    print(f"Extracted {len(extracted)} synthetic GOVP examples to {args.directory}")
    for path in extracted:
        print(f"  {path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="govp", description="Verify GOVP evidence without a central service.")
    parser.add_argument("--version", action="version", version=f"govp {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    verify_parser = sub.add_parser("verify", help="verify a local GOVP-1 record")
    verify_parser.add_argument("record")
    verify_parser.add_argument("--asset", help="also compare the declared SHA-256 with this file")
    verify_parser.add_argument("--json", action="store_true")
    verify_parser.set_defaults(handler=command_verify)

    url_parser = sub.add_parser("verify-url", help="fetch and verify a GOVP-1 record")
    url_parser.add_argument("url")
    url_parser.add_argument("--json", action="store_true")
    url_parser.set_defaults(handler=command_verify_url)

    inspect_parser = sub.add_parser("inspect", help="show parsed fields and deterministic inputs")
    inspect_parser.add_argument("record")
    inspect_parser.set_defaults(handler=command_inspect)

    id_parser = sub.add_parser("id", help="derive a GOVP-ID")
    id_parser.add_argument("--type", required=True)
    id_parser.add_argument("--asset-id", required=True)
    id_parser.add_argument("--sha256", required=True)
    id_parser.set_defaults(handler=command_id)

    self_test = sub.add_parser("self-test", help="run local invariants and rejection checks")
    self_test.set_defaults(handler=command_self_test)

    conformance = sub.add_parser(
        "conformance",
        help="run the byte-exact conformance vectors bundled with GOVP",
    )
    conformance.add_argument(
        "--run",
        action="store_true",
        required=True,
        help="execute all bundled text and JSON vectors",
    )
    conformance.set_defaults(handler=command_conformance)

    examples = sub.add_parser("examples", help="extract bundled synthetic examples")
    examples.add_argument(
        "--extract",
        dest="directory",
        required=True,
        metavar="DIR",
        help="destination directory",
    )
    examples.set_defaults(handler=command_examples)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.handler(args)
    except (OSError, ValueError, KeyError) as error:
        print(f"govp: {error}", file=sys.stderr)
        return 2
