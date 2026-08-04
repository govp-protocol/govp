"""Validate the canonical GOVP visual identity manifest."""

from __future__ import annotations

import hashlib
import json
import struct
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BRAND = ROOT / "brand"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def png_dimensions(data: bytes) -> tuple[int, int]:
    if data[:8] != PNG_SIGNATURE or data[12:16] != b"IHDR":
        raise ValueError("invalid PNG header")
    return struct.unpack(">II", data[16:24])


def svg_dimensions(path: Path) -> tuple[int, int]:
    root = ET.parse(path).getroot()
    values = root.attrib.get("viewBox", "").split()
    if len(values) != 4:
        raise ValueError("SVG has no four-value viewBox")
    return int(float(values[2])), int(float(values[3]))


def main() -> None:
    manifest: dict[str, Any] = json.loads(
        (BRAND / "ASSET-MANIFEST.json").read_text(encoding="utf-8")
    )
    assets = manifest["assets"]

    for name, expected in assets.items():
        path = BRAND / name
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest != expected["sha256"]:
            raise ValueError(f"{name}: SHA-256 mismatch")

        dimensions = (
            png_dimensions(data) if path.suffix == ".png" else svg_dimensions(path)
        )
        expected_dimensions = expected["width"], expected["height"]
        if dimensions != expected_dimensions:
            raise ValueError(
                f"{name}: dimensions {dimensions} != {expected_dimensions}"
            )

    print(f"Verified {len(assets)} canonical GOVP brand assets.")


if __name__ == "__main__":
    main()
