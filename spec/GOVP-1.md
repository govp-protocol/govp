# GOVP-1 core record

Status: stable and frozen; public repository edition.

GOVP-1 is a line-oriented UTF-8 signed evidence record containing Unicode
scalar values. It binds an issuer, an
artifact identifier and a SHA-256 digest. Verification is deterministic and
does not require a GOVP service.

## Required fields

`Version`, `Canonical`, `Publisher`, `Asset-Type`, `Asset-ID`,
`Asset-SHA256`, `GOVP-ID`, `Evidence`, `Public-Key` and `Signature`.

The complete normative, citable edition is published in `GOVP-1.txt` and at
https://govp.io/govp/spec/govp-1.html. The JSON schema in
`schema/govp-1.schema.json` describes the bundle form. The normative
conformance examples are in `conformance/vectors.json`.

## Signing input

1. Parse one `key: value` pair per line.
2. Ignore blank lines and lines beginning with `#`.
3. Apply the exact frozen GOVP-1 whitespace trim set defined in the normative
   text, lowercase ASCII `A`–`Z` in names, and apply the published legacy
   aliases. Other code points are preserved as signed data.
4. Reject empty field names, `:` in a field name, and NUL, CR or LF in any
   field name or value.
5. Exclude `signature` and empty values. Every other field, including unknown
   and `__`-prefixed fields, remains signed.
6. Sort field names by their UTF-8 bytes. Registered GOVP-1 field names are
   ASCII, so this is byte-identical for every registered field while remaining
   defined for preserved extension fields.
7. Render every field as `key: value\n`, encoded as UTF-8.
8. Prefix the bytes `GOVP::record.v1\0`.
9. Sign or verify the result with Ed25519.

Ed25519 point encodings for the public key and signature `R` component MUST be
canonical and belong to the prime-order subgroup; the identity is rejected.
The signature scalar `S` MUST be less than the Ed25519 subgroup order. These
rules make exceptional-point verdicts identical across cryptographic runtimes.

`canonical` is absolute HTTPS and `evidence` is an absolute URL. URL fields
use visible ASCII RFC 3986 URI text; internationalized host names use IDNA and
internationalized path data uses UTF-8 percent-encoding. If `generated-at` is
present, it is an RFC 3339 UTC timestamp ending in `Z`. A fractional second,
when present, contains one or more digits and has the same format verdict on
every supported runtime.

The optional JSON representation MUST reject two source names that normalize
or alias to the same canonical field. This JSON rule prevents property-order
ambiguity; the line-oriented text format retains its frozen last-occurrence
wins rule.

For online verification, `canonical` is the exact final HTTPS URL that serves
that record. `/.well-known/govp.txt` is the domain identity record; a record
published at `/.well-known/govp/<id>.govp` names that individual URL instead.

## GOVP-ID

For supported artifact types, calculate SHA-256 over:

```text
<lowercase asset type>\n<asset id>\n<lowercase asset sha256>
```

The identifier is `GOVP-<TYPECODE>-<first 12 hex characters>`.

## Scope

A valid core record proves that the holder of the private key signed the exact
record and that the supplied artifact, when present, matches the declared
digest. It does not prove the truth of the publisher's statement or establish
independent time by itself.

Non-URL free-text and extension values are signed byte-for-byte. Consumers
must escape them before display. The reference verifier reports advisory
warnings for signed non-printable text and for non-HTTP evidence schemes;
warnings do not change GOVP-1 core validity.
