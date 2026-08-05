"""Stable public API for the GOVP reference implementation."""

from .core import (
    Verification,
    derive_govp_id,
    load_record,
    parse_record,
    signing_input,
    verify,
)

__version__ = "0.1.9"

# Descriptive alias for integrations that prefer result-oriented naming.
# Verification remains supported for compatibility with the 0.1.x API.
VerifyResult = Verification

__all__ = [
    "Verification",
    "VerifyResult",
    "__version__",
    "derive_govp_id",
    "load_record",
    "parse_record",
    "signing_input",
    "verify",
]
