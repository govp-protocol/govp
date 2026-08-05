# Composing GOVP with signing, attestation and transparency ecosystems

GOVP is a portable byte-binding layer. It is not an alternative trust
infrastructure to SCITT, COSE, DSSE, in-toto, Sigstore or other evidence
systems. Those technologies occupy different, complementary layers and their
outputs can be used as GOVP-bound artifacts.

In GOVP-1, the asset identified by `asset-sha256` is an opaque octet sequence.
It can be a document or software release, but it can also be a signed message,
receipt, envelope, attestation, bundle, manifest or credential produced by
another system. GOVP preserves the exact serialization: semantically equivalent
JSON or CBOR encoded into different bytes is a different GOVP asset.

## The layered verification model

| Layer | Establishes | Does not establish |
|---|---|---|
| GOVP core | GOVP record format, Ed25519 signature, GOVP-ID and exact asset-byte binding; optional canonical URL binding | The internal validity or meaning of an upstream evidence object |
| Native upstream verifier | The system-specific signature, receipt, certificate chain, transparency proof, envelope or attestation structure | Whether the application accepts the asserted identity, predicate or policy outcome |
| Application policy | Required identities, trust roots, predicates, freshness, thresholds and other acceptance rules | New cryptographic facts beyond the verified inputs |

A composed result is acceptable only when every required layer succeeds:

```text
accepted = govp_valid AND upstream_valid AND policy_allows(result)
```

Applications must expose these verdicts separately. A successful GOVP check
must not be presented as successful verification by an upstream system.

## Common evidence inputs

| Ecosystem | What it contributes | How GOVP composes with it | Native verification that remains required |
|---|---|---|---|
| [SCITT](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/) | Signed statements, registration receipts and transparency-service evidence | Bind the exact signed statement, receipt or retained bundle as the GOVP asset | Validate the receipt, transparency service and applicable SCITT policy |
| [COSE](https://www.rfc-editor.org/rfc/rfc9052.html) | Signatures, MACs and encryption for CBOR structures | Bind the exact serialized COSE message | Validate protected headers, algorithm, key, signature or MAC and application policy |
| [DSSE](https://github.com/secure-systems-lab/dsse) | A signing envelope for arbitrary payloads and payload types | Bind the exact serialized DSSE envelope | Validate the pre-authentication encoding, signatures, signer identity and payload type |
| [in-toto Attestation](https://github.com/in-toto/attestation/blob/main/spec/README.md) | Statements, subjects, predicates, envelopes and bundles for attestations | Bind the exact attestation, envelope or bundle | Validate its envelope, subject relationship, predicate semantics and supply-chain policy |
| [Sigstore](https://docs.sigstore.dev/about/bundle/) | Artifact signatures or DSSE attestations with verification material and transparency evidence | Bind the exact Sigstore bundle or the release evidence distributed with an artifact | Validate signature, certificate identity, Rekor evidence, trusted root and policy with Sigstore tooling |
| [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model-2.0/) | Claims about subjects in an issuer-holder-verifier model | Bind the exact credential or presentation representation when portability requires it | Validate the credential securing mechanism, issuer, status, schema and relying-party policy |
| [C2PA Content Credentials](https://spec.c2pa.org/specifications/) | Content provenance through manifests, assertions, ingredients and content bindings | Bind an exact C2PA object or media asset as an additional portable record | Perform native C2PA validation and evaluate its trust model and assertions |

The labels above are intentionally precise: COSE and DSSE are formats or
envelopes; in-toto is an attestation framework; SCITT defines an architecture
for transparency services; and Sigstore is a signing and transparency
ecosystem.

## Recommended integration pattern

1. Produce or obtain the upstream evidence using its normal workflow.
2. Verify it with the upstream system's native verifier.
3. Preserve the exact byte sequence that was verified.
4. Issue a GOVP record whose `asset-sha256` binds those exact bytes.
5. Distribute the GOVP record with the upstream evidence object.
6. On receipt, run both GOVP verification and native upstream verification,
   then apply local acceptance policy.

The `evidence` field may identify a location for an upstream object, but the URI
is untrusted input and GOVP core does not automatically dereference or validate
the object found there. Consumers bind content by supplying the retrieved bytes
for the GOVP asset check.

## Bidirectional composition

Composition is not limited to placing an upstream object inside the GOVP asset
boundary. A GOVP record can itself be submitted to a transparency, attestation
or signing system that accepts arbitrary payloads, subject to that system's
rules. For example, a deployment can register a GOVP record with a SCITT
transparency service while retaining GOVP's offline verification properties.

No external service is required for GOVP core verification. Adding one extends
the evidence available to an application; it does not change the frozen GOVP-1
wire format or cause GOVP to inherit the other system's guarantees
automatically.

## Implementation status

The GOVP 0.1.8 reference verifier validates GOVP-1 records and their binding to
supplied asset bytes. It does not include native SCITT, COSE, DSSE, in-toto,
Sigstore, Verifiable Credentials or C2PA verifiers. Applications must invoke
the relevant implementation and policy engine explicitly. Future integration
profiles may standardize these orchestration rules without changing GOVP-1.
