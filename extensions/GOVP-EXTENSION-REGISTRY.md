# GOVP extension registry

This registry is normative for governed GOVP-EXT-1 identifiers. Registration
does not change GOVP-1 and does not certify the truth of an envelope.

| Extension | Version | Payload type | Schema | Receiving gate | Status |
|---|---:|---|---|---|---|
| `org.govp.conformance` | `1.0.0` | `org.govp.conformance-envelope/1` | `govp-evidence-envelope-1.schema.json` | GOVP extension conformance gate (`INVALID_ENVELOPE`, `SIGNATURE_INVALID`, `SUBJECT_DIGEST_MISMATCH`, `ORIGIN_INVALID`, `REFERENCE_INVALID`) | conformance-only |
| `org.govp.gate` | `1.0.0` | `org.govp.acceptance-decision/1` | `govp-gate/schema/acceptance-decision-1.schema.json` | `govp-gate` (`EVIDENCE_ABSENT`, `SIGNATURE_INVALID`, `ISSUER_NOT_ALLOWED`, `LAYER_NOT_REACHED`, `TOO_OLD`, `ORIGIN_INSUFFICIENT`, `REFERENCE_MISSING`, `REVOKED`, `POLICY_EXPIRED`, `SUBJECT_DIGEST_MISMATCH`, `EXCEPTION_NOT_AUTHORIZED`) | draft-conformance |

## Registration rules

Every stable entry requires:

1. a JSON Schema whose extension semantics live only in `payload`;
2. positive, tampered and not-evaluable vectors;
3. Python and TypeScript byte-parity results;
4. a named receiver capable of rejection;
5. enumerated rejection codes;
6. a threat model and offline verification instructions.

DATA, CONTROL, DEVICE, RIGHTS, WORKFLOW, AI and CLAIM remain unregistered until
an identified receiving gate exists for each one.
