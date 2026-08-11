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
from .publication import (
    PublicationOutput,
    PublicationVerification,
    authorize_subordinate_key,
    build_publication_tree,
    event_descriptor,
    merkle_root,
    publication_entry_id,
    publication_leaf,
    publish_request,
    verify_publication_custody,
    verify_publication_proof,
    verify_publication_tree,
    verify_publication_url,
)
from .status import (
    StatusResult,
    derive_key_id,
    evaluate_status,
    load_status,
    parse_status,
    status_format_ok,
)

__version__ = "0.1.13"

# Descriptive alias for integrations that prefer result-oriented naming.
# Verification remains supported for compatibility with the 0.1.x API.
VerifyResult = Verification

__all__ = [
    "EnvelopeVerification",
    "PublicationOutput",
    "PublicationVerification",
    "StatusResult",
    "Verification",
    "VerifyResult",
    "__version__",
    "authorize_subordinate_key",
    "build_publication_tree",
    "canonical_json",
    "derive_govp_id",
    "derive_key_id",
    "envelope_signing_input",
    "evaluate_status",
    "event_descriptor",
    "load_envelope",
    "load_record",
    "load_status",
    "merkle_root",
    "parse_envelope",
    "parse_record",
    "parse_status",
    "publication_entry_id",
    "publication_leaf",
    "publish_request",
    "serialize_record",
    "sign_envelope",
    "sign_record",
    "signing_input",
    "status_format_ok",
    "verify",
    "verify_envelope",
    "verify_publication_custody",
    "verify_publication_proof",
    "verify_publication_tree",
    "verify_publication_url",
]
