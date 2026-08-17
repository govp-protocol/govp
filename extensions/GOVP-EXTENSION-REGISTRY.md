# GOVP extension registry

This registry is normative for governed GOVP-EXT-1 identifiers. Registration
does not change GOVP-1 and does not certify the truth of an envelope.

| Extension | Version | Payload type | Schema | Receiving gate | Status |
|---|---:|---|---|---|---|
| `org.govp.conformance` | `1.0.0` | `org.govp.conformance-envelope/1` | `govp-evidence-envelope-1.schema.json` | GOVP extension conformance gate (`INVALID_ENVELOPE`, `SIGNATURE_INVALID`, `SUBJECT_DIGEST_MISMATCH`, `ORIGIN_INVALID`, `REFERENCE_INVALID`) | conformance-only |
| `org.govp.gate` | `1.0.0` | `org.govp.acceptance-decision/1` | [`acceptance-decision-1.schema.json`](https://github.com/govp-protocol/govp-gate/blob/v0.1.0/schema/acceptance-decision-1.schema.json) | [`govp-gate`](https://github.com/govp-protocol/govp-gate) (`EVIDENCE_ABSENT`, `SIGNATURE_INVALID`, `ISSUER_NOT_ALLOWED`, `LAYER_NOT_REACHED`, `TOO_OLD`, `ORIGIN_INSUFFICIENT`, `REFERENCE_MISSING`, `REVOKED`, `POLICY_EXPIRED`, `SUBJECT_DIGEST_MISMATCH`, `EXCEPTION_NOT_AUTHORIZED`) | active |
| `org.govp.publication` | `1.0.0` | `org.govp.subordinate-key/1`, `org.govp.publication-batch/1` | `govp-publication-1.schema.json` | `govp publication verify` (`INVALID_L0`, `INVALID_BATCH`, `INVALID_EVENT`, `KEY_NOT_AUTHORIZED`, `SCOPE_MISMATCH`, `AUTHORIZATION_WINDOW_MISMATCH`, `DOMAIN_MISMATCH`, `BATCH_MISMATCH`, `DISPOSITION_MISMATCH`, `INCLUSION_INVALID`, `CURRENT_STATUS_INVALID`) | active — [static index](https://govp.io/.well-known/govp/publication/index.json), [public proof](https://govp.io/govp/examples/publication-proof.json), [protected CI run](https://github.com/govp-protocol/govp.io/actions/runs/31508344449) |
| `org.govp.ai` | `1.0.0` | `org.govp.ai-request/1`, `org.govp.ai-result/1`, `org.govp.ai-verification/1` | `govp-ai-1.schema.json` | GOVP AI-1 receiver (`AI1_INVALID_ENVELOPE`, `AI1_EXTENSION_UNSUPPORTED`, `AI1_TYPE_UNSUPPORTED`, `AI1_PAYLOAD_INVALID`, `AI1_REFERENCE_INVALID`, `AI1_STATE_CONFLICT`, `AI1_COMPARISON_UNSUPPORTED`, `AI1_SUBJECT_REQUIRED`, `AI1_SUBJECT_DIGEST_MISMATCH`) | draft — conformance implementation |

## Registration rules

Every stable entry requires:

1. a JSON Schema whose extension semantics live only in `payload`;
2. positive, tampered and not-evaluable vectors;
3. Python and TypeScript byte-parity results;
4. a named receiver capable of rejection;
5. enumerated rejection codes;
6. a threat model and offline verification instructions.

DATA, CONTROL, DEVICE, RIGHTS, WORKFLOW and CLAIM remain unregistered until
an identified receiving gate exists for each one.

The `org.govp.gate` receiver is live at `https://accept.govp.io`. Its first
production submission bound the published `govp-gate` 0.1.0 source archive,
passed L0 and was rejected fail-closed because native in-toto verification was
not configured. The signed decision and exact hashes are retained in the
[`v0.1.0` production evidence](https://github.com/govp-protocol/govp-gate/tree/main/production-evidence/v0.1.0).
