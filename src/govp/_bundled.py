"""Access and validate the public resources bundled with the GOVP package."""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from tempfile import TemporaryDirectory

from .core import (
    RECORD_DOMAIN,
    load_record,
    parse_record,
    sha256,
    signing_input,
    verify,
)
from .status import _status_format_ok


@dataclass(frozen=True)
class ConformanceResult:
    """Result of running the bundled GOVP-1 conformance suites."""

    ok: bool
    passed: int
    total: int
    failures: tuple[str, ...] = ()


def _resource(*parts: str):
    resource = files("govp").joinpath("_resources")
    for part in parts:
        resource = resource.joinpath(part)
    if not resource.is_file() and not resource.is_dir():
        # Source checkouts keep the canonical resources at repository root;
        # wheels remap the same bytes into govp/_resources.
        resource = Path(__file__).resolve().parents[2].joinpath(*parts)
    return resource


def _read_json(*parts: str) -> dict:
    payload = json.loads(_resource(*parts).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError(f"bundled resource {'/'.join(parts)} must be a JSON object")
    return payload


def run_bundled_conformance() -> ConformanceResult:
    """Run the byte-exact text and JSON suites shipped in the wheel."""
    failures: list[str] = []
    passed = 0
    total = 0

    text_corpus = _read_json("conformance", "vectors.json")
    expected_domain = text_corpus.get("domain")
    if not isinstance(expected_domain, str):
        failures.append("text-suite: missing domain")
    elif RECORD_DOMAIN != expected_domain.replace("\\0", "\0").encode():
        failures.append("text-suite: domain separator mismatch")

    text_vectors = text_corpus.get("vectors")
    if not isinstance(text_vectors, list):
        raise TypeError("bundled text conformance vectors must be a list")
    for vector in text_vectors:
        total += 1
        name = str(vector.get("name", f"text-{total}"))
        try:
            fields = parse_record(vector["record"])
            expected = vector["expected"]
            result = verify(fields)
            checks = (
                fields.get("govp-id") == expected["govp_id"],
                result.checks["format"] == expected["format_ok"],
                result.checks["govp-id"] == expected["govpid_ok"],
                result.checks["signature"] == expected["signature_ok"],
                result.ok == expected["core_valid"],
                sha256(signing_input(fields)) == expected["signing_input_sha256"],
            )
            if all(checks):
                passed += 1
            else:
                failures.append(f"{name}: verdict mismatch")
        except (KeyError, TypeError, ValueError) as error:
            failures.append(f"{name}: {error}")

    json_corpus = _read_json("conformance", "json-vectors.json")
    json_vectors = json_corpus.get("vectors")
    if not isinstance(json_vectors, list):
        raise TypeError("bundled JSON conformance vectors must be a list")
    with TemporaryDirectory(prefix="govp-conformance-") as directory:
        root = Path(directory)
        for index, vector in enumerate(json_vectors, start=1):
            total += 1
            name = str(vector.get("name", f"json-{index}"))
            expected = vector.get("expected", {})
            path = root / f"vector-{index}.json"
            try:
                path.write_text(
                    json.dumps(vector["payload"], ensure_ascii=False),
                    encoding="utf-8",
                )
                if expected.get("load_ok"):
                    result = verify(load_record(path))
                    if result.ok == expected.get("core_valid"):
                        passed += 1
                    else:
                        failures.append(f"{name}: validity mismatch")
                else:
                    try:
                        load_record(path)
                    except ValueError as error:
                        if str(expected.get("error", "")) in str(error):
                            passed += 1
                        else:
                            failures.append(f"{name}: unexpected error: {error}")
                    else:
                        failures.append(f"{name}: invalid input was accepted")
            except (KeyError, TypeError, ValueError) as error:
                failures.append(f"{name}: {error}")

    return ConformanceResult(not failures, passed, total, tuple(failures))


def run_bundled_status_conformance() -> ConformanceResult:
    """Run the independently versioned GOVP-STATUS-1 vectors."""
    failures: list[str] = []
    passed = 0
    corpus = _read_json("conformance", "status-vectors.json")
    vectors = corpus.get("vectors")
    if not isinstance(vectors, list):
        raise TypeError("bundled status conformance vectors must be a list")
    for index, vector in enumerate(vectors, start=1):
        name = str(vector.get("name", f"status-{index}"))
        try:
            observed = _status_format_ok(vector["status"])
            expected = bool(vector["expected"]["schema_valid"])
            if observed == expected:
                passed += 1
            else:
                failures.append(f"{name}: validity mismatch")
        except (KeyError, TypeError, ValueError) as error:
            failures.append(f"{name}: {error}")
    return ConformanceResult(
        not failures, passed, len(vectors), tuple(failures)
    )


def extract_bundled_examples(destination: Path) -> tuple[Path, ...]:
    """Extract synthetic examples without overwriting different local files."""
    if destination.exists() and not destination.is_dir():
        raise ValueError(f"destination is not a directory: {destination}")
    destination.mkdir(parents=True, exist_ok=True)

    extracted: list[Path] = []
    for source in sorted(_resource("examples").iterdir(), key=lambda item: item.name):
        if not source.is_file():
            continue
        target = destination / source.name
        content = source.read_bytes()
        if target.exists() and target.read_bytes() != content:
            raise ValueError(f"refusing to overwrite different file: {target}")
        if not target.exists():
            target.write_bytes(content)
        extracted.append(target)
    return tuple(extracted)
