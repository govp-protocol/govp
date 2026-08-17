# GOVP AI-1 — Verifiable AI execution evidence

Status: draft for conformance implementation.

GOVP AI-1 represents evidence about an AI execution. Its unit is the execution,
not the truth, quality, safety or legality of the generated content. It uses
GOVP-EXT-1 envelopes and does not change the frozen GOVP-1 format.

## Registered identifiers

- extension: `org.govp.ai`, version `1.0.0`;
- `org.govp.ai-request/1`;
- `org.govp.ai-result/1`;
- `org.govp.ai-verification/1`.

An AI execution is a causal chain:

```text
request commitment -> result -> optional independent verification
```

The request is signed before inference. A signature alone proves neither when
it was made nor that all attempts were disclosed. External timestamp or witness
evidence is therefore represented separately and never inferred.

## Common rules

All digests use lowercase `sha256:<64 hex>`. A digest identifies exact bytes;
associating those bytes with a publisher or commercial model name requires a
separate publisher manifest or attestation.

Sensitive prompts, inputs, outputs and parameters SHOULD remain outside the
envelope. AI-1 records their digests and disclosure mode. A locator is an
untrusted retrieval hint and MUST NOT contain credentials.

`claimed: true` under `reproducibility` is an issuer assertion, not a verified
property. `temperature=0`, a seed or a deterministic profile is never by itself
proof of reproducibility.

## REQUEST

The subject bytes are the exact execution-request artifact committed by the
issuer. The payload fixes:

- `model.artifact_digest`, the exact model artifact available to the executor;
- an optional publisher claim and publisher-manifest digest;
- `runtime.artifact_digest`, backend, hardware class and deterministic profile;
- input and inference-parameter digests and their disclosure modes;
- seed, nonce and reproducibility scope;
- whether an external commitment witness is cited.

`commitment.externalized: true` requires at least one external attestation in
`references`. AI-1 verifies the citation digest but native verification of the
attestation remains L1. `externalized: false` is valid lower-strength evidence.

## RESULT

A result MUST cite exactly one GOVP request reference whose `id` and `digest`
equal `payload.request`. `attempt_id` identifies one attempt. Terminal states
are `SUCCEEDED`, `FAILED`, `DENIED`, `CANCELLED`, `TIMED_OUT` and
`INDETERMINATE`.

`SUCCEEDED` requires `output_digest` and prohibits `reason_code`. Every other
state requires `reason_code` and requires `output_digest` to be null. The
effective model and runtime digests are recorded again so a receiver can detect
execution drift from the request when both records are available.

AI-1 alone cannot prove that no sibling attempt was hidden. Attempt
completeness requires an externally witnessed append-only sequence or a
regulated enforcement runtime.

## VERIFICATION

A verification MUST cite exactly one request and one result, matching the IDs
and digests in its payload. Version 1 supports only `recomputation` with
comparison profiles `exact` and `canonicalized`.

`exact` compares exact output bytes. `canonicalized` compares bytes produced by
the explicitly named canonicalization profile. Semantic equivalence is not an
AI-1 comparison profile.

The verifier declares its relationship as `self`,
`organizationally_separate` or `third_party`. This declaration is evidence to
evaluate, not automatic proof of independence.

## Receiving gate

The public receiving gate performs GOVP L0 followed by AI-1 semantic checks and
returns one of:

- `AI1_INVALID_ENVELOPE`;
- `AI1_EXTENSION_UNSUPPORTED`;
- `AI1_TYPE_UNSUPPORTED`;
- `AI1_PAYLOAD_INVALID`;
- `AI1_REFERENCE_INVALID`;
- `AI1_STATE_CONFLICT`;
- `AI1_COMPARISON_UNSUPPORTED`;
- `AI1_SUBJECT_REQUIRED`;
- `AI1_SUBJECT_DIGEST_MISMATCH`.
- `AI1_CHAIN_INCOMPLETE`;
- `AI1_CHAIN_CONFLICT`.

Acceptance means only that the supplied bytes form a valid AI-1 record. Trust,
authorization, evidence sufficiency, regulatory policy and permission to run
remain outside GOVP and belong to the receiving system.

The bundle gate additionally resolves every causal digest against earlier
records in the supplied ordered chain and rejects duplicate IDs, duplicate
request nonces and repeated `(request, attempt_id)` pairs. This proves internal
completeness only for that supplied bundle; it cannot rule out records withheld
from the receiver.

## Offline verification

L0 and AI-1 semantic validation are offline. Native witness verification,
publisher identity, current key status and recomputation may be unavailable;
unavailable checks MUST NOT be promoted to successful claims.
