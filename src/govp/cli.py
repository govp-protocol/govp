"""Command-line interface for the GOVP reference verifier."""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    Request,
    build_opener,
)

import certifi
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import __version__
from ._bundled import (
    extract_bundled_examples,
    run_bundled_conformance,
    run_bundled_status_conformance,
)
from .core import (
    _valid_absolute_url,
    derive_govp_id,
    load_record,
    parse_record,
    serialize_record,
    sha256,
    sign_record,
    signing_input,
    verify,
)
from .envelope import load_envelope, verify_envelope
from .status import StatusResult, evaluate_status, load_status, parse_status

MAX_RECORD_BYTES = 1024 * 1024


def _require_https_url(url: str) -> None:
    if not _valid_absolute_url(url, https_only=True):
        raise ValueError("verify-url requires an absolute HTTPS URL without credentials")


class _HTTPSOnlyRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _require_https_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _fetch(url: str, *, ca_bundle: str | Path | None = None) -> tuple[str, str]:
    _require_https_url(url)
    request = Request(url, headers={"User-Agent": f"govp/{__version__}"})
    # Standalone PyInstaller binaries cannot rely on the host Python's CA
    # location. certifi supplies the same explicit trust store on every
    # supported platform and is bundled into the executable.
    # Environment-controlled CA variables are intentionally not read. The
    # caller must opt in to an enterprise/private trust store explicitly.
    cafile = str(ca_bundle) if ca_bundle is not None else certifi.where()
    context = ssl.create_default_context(cafile=cafile)
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
    text, final_url = _fetch(args.url, ca_bundle=args.ca_bundle)
    fields = parse_record(text)
    result = verify(fields, fetched_url=final_url)
    _print_result(result, args.json)
    return 0 if result.ok else 1


def command_envelope_verify(args: argparse.Namespace) -> int:
    envelope = load_envelope(args.envelope)
    subject = Path(args.subject).read_bytes() if args.subject else None
    result = verify_envelope(envelope, subject_bytes=subject)
    payload = {
        "ok": result.ok,
        "id": envelope.get("id"),
        "type": envelope.get("type"),
        "checks": result.checks,
        "signing_input_sha256": result.signing_input_sha256,
        "warnings": list(result.warnings),
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print("GOVP evidence envelope:", "VALID" if result.ok else "INVALID")
        for name, value in result.checks.items():
            label = "not checked" if value is None else ("pass" if value else "FAIL")
            print(f"  {name:<16} {label}")
        print(f"  envelope       {envelope.get('id', '-')}")
    return 0 if result.ok else 1


STATUS_CHECK_NAMES = (
    "core",
    "status-format",
    "status-fresh",
    "status-canonical",
    "same-origin",
    "key-active",
    "record-not-revoked",
)


def _tri_state(value: bool | None) -> bool | None:
    if value is True:
        return True
    if value is False:
        return False
    return None


def _print_status(result: StatusResult, as_json: bool) -> None:
    checks = {
        name: _tri_state(result.checks.get(name)) for name in STATUS_CHECK_NAMES
    }
    payload = {
        "currently_trusted": _tri_state(result.currently_trusted),
        "snapshot_valid": result.snapshot_valid is True,
        # Retained as a compatibility alias through the 0.1.x line.
        "snapshot_trusted": result.snapshot_trusted is True,
        "checks": checks,
        "reasons": [name for name, value in checks.items() if value is False],
    }
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    if result.currently_trusted is None:
        label = "SNAPSHOT VALID" if result.snapshot_valid else "SNAPSHOT INVALID"
    else:
        label = "CURRENTLY TRUSTED" if result.currently_trusted else "NOT TRUSTED"
    print("GOVP status:", label)
    for name, value in checks.items():
        check = "not checked" if value is None else ("pass" if value else "FAIL")
        print(f"  {name:<20} {check}")


def command_status(args: argparse.Namespace) -> int:
    fields = load_record(args.record)
    status = load_status(args.status)
    result = evaluate_status(fields, status)
    _print_status(result, args.json)
    return 0 if result.snapshot_valid else 1


def command_status_url(args: argparse.Namespace) -> int:
    record_text, record_final_url = _fetch(
        args.record_url, ca_bundle=args.ca_bundle
    )
    status_text, status_final_url = _fetch(
        args.status_url, ca_bundle=args.ca_bundle
    )
    result = evaluate_status(
        parse_record(record_text),
        parse_status(status_text),
        fetched_url=status_final_url,
        record_fetched_url=record_final_url,
    )
    _print_status(result, args.json)
    return 0 if result.currently_trusted is True else 1


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    if os.name != "nt" and path.stat().st_mode & 0o077:
        raise ValueError(
            f"private key permissions are too broad: {path} (use chmod 600)"
        )
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("private key must be an Ed25519 PKCS8 PEM key")
    return key


def command_issue(args: argparse.Namespace) -> int:
    asset_path = Path(args.asset)
    asset = asset_path.read_bytes()
    asset_sha256 = sha256(asset)
    govp_id = derive_govp_id(args.asset_type, args.asset_id, asset_sha256)
    if govp_id is None:
        raise ValueError("asset-type must be a registered GOVP-1 type")
    canonical = args.canonical.replace("{govp-id}", govp_id)
    generated_at = args.generated_at or datetime.now(timezone.utc).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")
    fields = {
        "version": "GOVP-1",
        "canonical": canonical,
        "publisher": args.publisher,
        "asset-type": args.asset_type,
        "asset-id": args.asset_id,
        "asset-sha256": asset_sha256,
        "profile": args.profile,
        "generated-at": generated_at,
        "evidence": args.evidence,
    }
    if args.license:
        fields["license"] = args.license
    record = sign_record(fields, _load_private_key(Path(args.private_key)))
    if not verify(record, asset_bytes=asset).ok:
        raise ValueError("issued record did not verify against the supplied asset")
    output = serialize_record(record)
    if args.output == "-":
        sys.stdout.write(output)
    else:
        destination = Path(args.output)
        with destination.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(output)
        print(f"Wrote {record['govp-id']} to {destination}")
    return 0


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


def command_status_conformance(_: argparse.Namespace) -> int:
    result = run_bundled_status_conformance()
    print(
        "GOVP-STATUS-1 conformance:",
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
    url_parser.add_argument(
        "--ca-bundle",
        metavar="PEM",
        help="explicit CA bundle for enterprise/private HTTPS (Certifi by default)",
    )
    url_parser.add_argument("--json", action="store_true")
    url_parser.set_defaults(handler=command_verify_url)

    envelope_parser = sub.add_parser(
        "envelope", help="work with signed GOVP-EXT-1 evidence envelopes"
    )
    envelope_sub = envelope_parser.add_subparsers(dest="envelope_command", required=True)
    envelope_verify = envelope_sub.add_parser("verify", help="verify a local evidence envelope")
    envelope_verify.add_argument("envelope")
    envelope_verify.add_argument(
        "--subject", help="also bind the declared SHA-256 to these exact bytes"
    )
    envelope_verify.add_argument("--json", action="store_true")
    envelope_verify.set_defaults(handler=command_envelope_verify)

    status_parser = sub.add_parser(
        "status", help="evaluate a local GOVP-STATUS-1 snapshot"
    )
    status_parser.add_argument("record")
    status_parser.add_argument("status")
    status_parser.add_argument("--json", action="store_true")
    status_parser.set_defaults(handler=command_status)

    status_url_parser = sub.add_parser(
        "status-url", help="fetch a GOVP-1 record and its live status over HTTPS"
    )
    status_url_parser.add_argument("record_url")
    status_url_parser.add_argument("--status-url", required=True)
    status_url_parser.add_argument(
        "--ca-bundle",
        metavar="PEM",
        help="explicit CA bundle for enterprise/private HTTPS (Certifi by default)",
    )
    status_url_parser.add_argument("--json", action="store_true")
    status_url_parser.set_defaults(handler=command_status_url)

    issue_parser = sub.add_parser(
        "issue", help="issue a GOVP-1 record for an exact local asset"
    )
    issue_parser.add_argument("--asset", required=True)
    issue_parser.add_argument("--canonical", required=True)
    issue_parser.add_argument("--publisher", required=True)
    issue_parser.add_argument("--asset-type", required=True, choices=sorted({
        "agent", "benchmark", "dataset", "document", "model", "pipeline"
    }))
    issue_parser.add_argument("--asset-id", required=True)
    issue_parser.add_argument("--evidence", required=True)
    issue_parser.add_argument("--private-key", required=True, metavar="PEM")
    issue_parser.add_argument("--profile", default="GOVP-BASIC")
    issue_parser.add_argument("--license")
    issue_parser.add_argument("--generated-at")
    issue_parser.add_argument(
        "--output",
        default="-",
        metavar="RECORD",
        help="new output path, or - for stdout (existing files are never overwritten)",
    )
    issue_parser.set_defaults(handler=command_issue)

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

    status_conformance = sub.add_parser(
        "status-conformance",
        help="run the GOVP-STATUS-1 vectors bundled with GOVP",
    )
    status_conformance.add_argument(
        "--run",
        action="store_true",
        required=True,
        help="execute all bundled status vectors",
    )
    status_conformance.set_defaults(handler=command_status_conformance)

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
    except (OSError, TypeError, ValueError, KeyError) as error:
        print(f"govp: {error}", file=sys.stderr)
        return 2
