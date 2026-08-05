# Security model

GOVP separates cryptographic evidence from claims about the real world.

## Guarantees

For a CORE-VALID record, the verifier establishes that:

- the holder of the corresponding Ed25519 private key signed the exact fields;
- the GOVP-ID matches the declared asset type, identifier and SHA-256 digest;
- supplied asset bytes match the signed digest;
- a remotely fetched record came from its signed final canonical HTTPS URL.

## Non-guarantees

Core validity does not establish that:

- the publisher's statement is true;
- a physical or organizational event occurred;
- `generated-at` is independently anchored;
- the signer was authorized under an external legal or business process;
- a linked resource is safe to open or execute.

GOVP-STATUS-1 can add a current same-origin HTTPS statement about active keys
and revoked records. A saved status document is only a snapshot; it cannot
establish current trust.

## Trust boundaries

Private keys never belong in this repository, a web root or a GOVP record.
Production issuers should use protected external signing systems. Consumers
must establish their own trust in publisher keys and domains.

Comments are unsigned. Evidence URIs, free text and extension fields are
untrusted presentation data even when signed. Escape them for their output
context and apply a local allowlist before following evidence schemes.

## Network verifier

The reference network command requires HTTPS for records and redirects,
rejects credentials, validates UTF-8, uses Certifi by default, applies a timeout
and limits downloads to 1 MiB. Enterprise users must select a different trust
store explicitly with `--ca-bundle`; ambient CA environment variables are not
used. The verifier never fetches the declared asset or evidence URI
automatically.

## Cryptographic scope

GOVP-1 fixes Ed25519 and SHA-256. Algorithm migration is a new protocol format,
not a silent implementation update. Domain separation is the 16-byte prefix
`GOVP::record.v1\0`.

## Distribution integrity

Release checksums detect corruption and accidental substitution, but a digest
served from the same compromised origin is not an independent signature.
Standalone binaries are not currently signed with Apple Developer ID or
Windows Authenticode. High-assurance distributors should pin the immutable Git
tag and retained digest, rebuild from source, and compare the release manifest
before redistribution.

Report exploitable vulnerabilities privately as described in
[`SECURITY.md`](../SECURITY.md).
