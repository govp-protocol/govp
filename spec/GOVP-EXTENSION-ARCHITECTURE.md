# GOVP-EXT-1 — Extension architecture

Status: draft for conformance implementation.

GOVP-EXT-1 adds typed evidence envelopes without changing the frozen GOVP-1
wire format, identifiers or L0 verification rules. GOVP-1 remains the portable
byte-binding layer. An extension adds domain semantics only inside `payload`.

## Invariants

Every envelope has exactly one core with these members:

`govp`, `extension`, `type`, `id`, `issuer`, `subject`, `created_at`, `hash`,
`payload`, `references`, `evidence`, `origin` and `signature`.

Extensions MUST NOT redefine, shadow or move those members. Their only semantic
namespace is `payload`. Unknown top-level members are rejected.

The `hash` member is the SHA-256 of the exact subject bytes evaluated by the
issuer. It is not a semantic JSON hash. If subject bytes are unavailable, the
check is `not_evaluable`; it is never promoted to pass.

## Signing input

The signing input is:

```text
UTF8("GOVP::extension-envelope.v1\0") || UTF8(CANONICAL_JSON(unsigned_envelope))
```

`unsigned_envelope` is the complete envelope with the `signature` member
removed. Canonical JSON accepts only null, booleans, strings, arrays, objects
and integers in the interoperable range `[-(2^53-1), 2^53-1]`. Floating-point
numbers, lone UTF-16 surrogates and duplicate object names are rejected. Object
names are ordered by UTF-16 code units and JSON strings use their shortest
standard JSON escaping.

The signature object records Ed25519, the raw public key, its SHA-256 key ID,
the signing-input SHA-256 and the signature. A consumer MUST recompute all of
them. A matching key is not by itself proof that the key is currently
authorized; L2 remains a separate status decision.

## Verification layers

- L0: envelope shape, signing input, Ed25519 signature, key ID and optional
  subject-byte digest.
- L1: native verification of required evidence and external attestations.
- L2: current issuer authorization, key status, revocation and policy.

Results expose every layer separately. Offline verification can reach L0 and
can evaluate bundled native evidence, but unavailable checks remain
`not_evaluable`.

## Extension registration

An extension is usable only after its identifier, current version, schema,
payload types and receiving gate are present in `GOVP-EXTENSION-REGISTRY.md`.
Registration does not imply that its assertions are true or acceptable.

## Security boundary

- `issuer.canonical` uses the single GOVP identity at
  `https://<domain>/.well-known/govp.txt`.
- DNS, DID, JWKS and alternate discovery documents are not identities.
- Locators are untrusted hints. Digests bind exact bytes.
- External attestations are cited and natively verified; GOVP does not reissue
  or resign them.
- The extension payload cannot grant a key more authority than the domain
  publishes for it.
