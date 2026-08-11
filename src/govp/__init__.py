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
from .envelope import (
    EnvelopeVerification,
    canonical_json,
    envelope_signing_input,
    load_envelope,
    parse_envelope,
    sign_envelope,
    verify_envelope,
)
from .status import (
    StatusResult,
    derive_key_id,
    evaluate_status,
    load_status,
    parse_status,
    status_format_ok,
)

__version__ = "0.1.12"

# Descriptive alias for integrations that prefer result-oriented naming.
# Verification remains supported for compatibility with the 0.1.x API.
VerifyResult = Verification

__all__ = [
    "EnvelopeVerification",
    "StatusResult",
    "Verification",
    "VerifyResult",
    "__version__",
    "canonical_json",
    "derive_govp_id",
    "derive_key_id",
    "envelope_signing_input",
    "evaluate_status",
    "load_envelope",
    "load_record",
    "load_status",
    "parse_envelope",
    "parse_record",
    "parse_status",
    "serialize_record",
    "sign_envelope",
    "sign_record",
    "signing_input",
    "status_format_ok",
    "verify",
    "verify_envelope",
]
