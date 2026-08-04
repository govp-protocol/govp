# How GOVP fits

GOVP is a narrow protocol for binding a readable signed record to exact
artifact bytes. It is not intended to replace broader credential, media
provenance or software-supply-chain ecosystems.

The right choice depends on the trust question an integration needs to answer.
The technologies below can also be combined.

## At a glance

| Technology | Primary problem | Core model | External trust infrastructure |
|---|---|---|---|
| GOVP | Portable verification of a record and exact artifact bytes | Signed record, artifact digest, content-derived identifier and optional canonical URL | None required for core verification; identity, time and revocation can be added separately |
| W3C Verifiable Credentials | Expressing and presenting claims made by issuers about subjects | Issuer, holder, subject, verifier, credential and presentation | Depends on the chosen identifier, securing, status and trust mechanisms |
| C2PA Content Credentials | Rich provenance and history of digital content | Manifests, assertions, claims, signatures, ingredients and content bindings | Uses its trust and validation model; deployment choices depend on the content workflow |
| Sigstore | Signing and auditing software-supply-chain artifacts | OIDC identity, short-lived certificate, artifact signature and transparency-log evidence | Fulcio, Rekor and the Sigstore trust root in the standard keyless flow; private deployments are possible |

This table describes typical use, not every capability or deployment option.
Always evaluate the normative specification and threat model of the technology
you select.

## GOVP

Choose GOVP when the central object is an arbitrary file or byte sequence and
recipients need a small record that remains independently verifiable after the
artifact leaves its originating system.

GOVP provides:

- a compact human-readable record and a JSON representation;
- deterministic signing and verification behavior;
- binding to exact artifact bytes through SHA-256;
- a content-derived GOVP-ID and optional canonical HTTPS binding;
- JSON Schema and byte-exact conformance vectors;
- offline core verification with an included Ed25519 public key.

GOVP does not certify the identity or authority behind that key, determine
whether signed statements are true, provide revocation or create independent
time evidence. Applications add those layers according to their policy.

## W3C Verifiable Credentials

The
[Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
defines an extensible model for claims made by issuers and exchanged through an
issuer-holder-verifier ecosystem. Credentials and presentations can model
subjects, credential status, validity, selective disclosure and other concepts
that GOVP intentionally does not define.

Use Verifiable Credentials when the primary object is a credential or set of
claims about a subject and the holder/presentation lifecycle matters. Use GOVP
when the primary object is an artifact whose exact bytes and adjacent signed
record must remain portable. A credential can reference a GOVP-identified
artifact, so the two models are not mutually exclusive.

## C2PA Content Credentials

The [C2PA specification](https://spec.c2pa.org/specifications/) defines Content
Credentials for content provenance and authenticity. Its manifests and
assertions can describe actors, ingredients, actions and the history of digital
content while cryptographic content bindings associate that provenance with an
asset.

Use C2PA when rich media or content provenance, edit history and ecosystem
interoperability around Content Credentials are required. Use GOVP when a small
external record bound to exact bytes is sufficient, including for non-media
artifacts. A C2PA manifest or a media asset can itself be identified by a GOVP
record when both layers are useful.

## Sigstore

[Sigstore](https://docs.sigstore.dev/) focuses on software supply-chain
security. Its standard keyless flow binds an OIDC identity to a short-lived
certificate, records signing evidence in transparency infrastructure and gives
software consumers tools such as Cosign for signing and verification.

Use Sigstore when software-artifact identity, short-lived certificates and
public auditability through transparency logs are desired. Use GOVP when the
artifact domain is broader, publisher-controlled keys are appropriate and core
verification must not require a particular identity provider, certificate
authority or log. A software release can carry both Sigstore evidence and a
GOVP record; each then demonstrates different properties.

## Primitive alternatives

### SHA-256 alone

A digest answers whether supplied bytes match an expected digest. It does not
show that a signing key approved the digest or standardize the surrounding
artifact identity and metadata.

### A custom detached signature

A direct Ed25519 signature can be entirely appropriate inside one controlled
system. Interoperability becomes harder when separate implementations must
agree on field encoding, ordering, whitespace, identifier derivation, URL
binding, unknown fields, resource limits and machine-readable results. GOVP
standardizes and tests those decisions.

### A hosted attestation API

A hosted API can add identity, policy, indexing and operational convenience.
It also creates a service dependency. GOVP can be the portable verification
layer beneath such a service so records remain usable outside it.

## Selection questions

1. Is the primary object a claim about a subject, rich content provenance,
   software-supply-chain identity or an arbitrary artifact?
2. Must verification work without contacting the issuer or a shared service?
3. Is an included publisher-controlled public key sufficient, or is certified
   identity required?
4. Do you need independent timestamps, transparency, revocation or status?
5. Do recipients need rich history, or only a deterministic binding to exact
   bytes?

If the answer is “an arbitrary artifact, portable verification and exact byte
binding,” GOVP is a focused option. If other assurances are required, select
the ecosystem that supplies them or compose it with GOVP.

## Accuracy and corrections

This comparison is explanatory, not normative. The linked projects evolve and
their specifications control. If a description is incomplete or inaccurate,
please [open an issue](https://github.com/govp-protocol/govp/issues/new) with a
link to the relevant primary source.
