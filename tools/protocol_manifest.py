#!/usr/bin/env python3
"""Create a deterministic manifest of GOVP normative public contracts."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOTS = ("spec", "schema", "conformance", "extensions")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    files = []
    for directory in ROOTS:
        files.extend(path for path in (root / directory).rglob("*") if path.is_file())
    records = {
        path.relative_to(root).as_posix(): f"sha256:{sha256(path)}"
        for path in sorted(files)
    }
    aggregate = hashlib.sha256(
        "".join(f"{name}\0{value}\n" for name, value in records.items()).encode()
    ).hexdigest()
    manifest = {
        "schema": "org.govp.protocol-manifest/1",
        "source_commit": args.source_commit,
        "aggregate": f"sha256:{aggregate}",
        "files": records,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
