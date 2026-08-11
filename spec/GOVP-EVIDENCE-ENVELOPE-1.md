# GOVP-EVIDENCE-ENVELOPE-1

Status: draft for conformance implementation.

The normative machine contract is
`schema/govp-evidence-envelope-1.schema.json`. This document defines the
meaning that JSON Schema alone cannot express.

## Core members

- `govp`: literal `GOVP-EXT-1`.
- `extension`: registered extension identifier and semantic version.
- `type`: registered payload type.
- `id`: stable identifier assigned by the issuer.
- `issuer`: GOVP canonical identity and human-readable name.
- `subject`: class and stable identifier of the evaluated object.
- `created_at`: issuer-asserted RFC 3339 UTC time.
- `hash`: SHA-256 of the exact subject bytes.
- `payload`: the only extension-defined semantic object.
- `references`: GOVP records or external attestations cited by digest.
- `evidence`: typed evidence objects used by the assertion.
- `origin`: how the component obtained the asserted facts.
- `signature`: Ed25519 binding over the canonical unsigned envelope.

## Evidence origin

Allowed origins are:

- `system_observed`: the component saw the event first-hand;
- `artifact_derived`: the component calculated a digest from present bytes;
- `human_asserted`: a person supplied the assertion;
- `upstream_attested`: another system asserted it and its evidence is cited.

`system_observed`, `artifact_derived` and `upstream_attested` require a non-null
`observation`. `human_asserted` requires `observation: null`. Implementations
MUST NOT promote one class to another. Acceptance policies compare allowed
classes explicitly; the enumeration order is not a trust hierarchy.

## External attestations

`references.type = external_attestation` requires exactly
`{type, format, digest, locator}`. The initial format registry contains
in-toto/SLSA JSON, Sigstore bundle 0.3, Rekor entry JSON and RFC 3161 timestamp
reply. Implementations validate the declared format and `sha256:` digest but
do not embed, reissue or resign the referenced evidence.

The native verifier for the declared format remains mandatory when a policy
requires L1. Failure to obtain or run it is `not_evaluable`, not pass or fail.

## Subject bytes

When exact subject bytes are supplied, their SHA-256 MUST equal `hash.value`.
Changing one byte therefore invalidates the subject binding without changing
the independent signature verdict. When bytes are absent, the subject check is
null and the caller decides whether that is acceptable.

## Receipt requirement

An extension is incomplete until a receiving gate can reject with it. The
registry names that gate and its rejection codes. Producer-only schemas are not
registered as stable.
