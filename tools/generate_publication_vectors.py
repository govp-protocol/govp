"""Regenerate deterministic GOVP-PUBLICATION-1 Merkle vectors."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from govp.publication import (
    EMPTY_ROOT,
    build_publication_tree,
    publication_entry_id,
)

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "conformance/publication-vectors.json"
KEY_ID = "sha256:" + hashlib.sha256(b"subordinate-vector-key").hexdigest()


def descriptor(index: int, *, prefix: str = "EVENT") -> dict[str, str]:
    return {
        "id": f"{prefix}-{index:05d}",
        "key_id": KEY_ID,
        "signing_input_sha256": hashlib.sha256(
            f"signing-input-{index}".encode()
        ).hexdigest(),
        "type": "org.govp.build/1",
    }


def main() -> None:
    small = [descriptor(index) for index in range(7)]
    small_root, small_proofs = build_publication_tree(small, "VECTOR-SMALL")
    selected_small = small[3]
    small_entry = publication_entry_id(selected_small)

    large = [descriptor(index, prefix="LARGE") for index in range(10000)]
    large_root, large_proofs = build_publication_tree(large, "VECTOR-10000")
    selected_large = large[6789]
    large_entry = publication_entry_id(selected_large)
    value = {
        "algorithm": "sha256-rfc6962-sharded-256",
        "empty_root": EMPTY_ROOT.hex(),
        "format": "GOVP-PUBLICATION-CONFORMANCE-1",
        "key_id": KEY_ID,
        "vectors": [
            {
                "batch_id": "VECTOR-SMALL",
                "descriptors": small,
                "expected": {
                    "entry_id": small_entry,
                    "proof": small_proofs[small_entry],
                    "root": small_root,
                },
                "name": "seven-events",
                "selected": 3,
            },
            {
                "batch_id": "VECTOR-10000",
                "expected": {
                    "entry_id": large_entry,
                    "proof": large_proofs[large_entry],
                    "root": large_root,
                },
                "name": "ten-thousand-events",
                "recipe": {
                    "count": 10000,
                    "id_prefix": "LARGE",
                    "signing_input_prefix": "signing-input-",
                    "type": "org.govp.build/1"
                },
                "selected": 6789,
            },
        ],
    }
    OUTPUT.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
