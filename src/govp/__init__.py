"""Stable public API for the GOVP reference implementation."""

from .core import (
    Verification,
    derive_govp_id,
    load_record,
    parse_record,
    serialize_record,
    sign_record,
    signing_input,
    verify,
)
from .status import (
    StatusResult,
    derive_key_id,
    evaluate_status,
    load_status,
    parse_status,
)

__version__ = "0.1.11"

# Descriptive alias for integrations that prefer result-oriented naming.
# Verification remains supported for compatibility with the 0.1.x API.
VerifyResult = Verification

__all__ = [
    "StatusResult",
    "Verification",
    "VerifyResult",
    "__version__",
    "derive_govp_id",
    "derive_key_id",
    "evaluate_status",
    "load_record",
    "load_status",
    "parse_record",
    "parse_status",
    "serialize_record",
    "sign_record",
    "signing_input",
    "verify",
]
