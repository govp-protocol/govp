# Verify a GOVP evidence envelope

GOVP evidence envelopes are local JSON files. Verification never requires a
GOVP account or central verification endpoint.

```sh
govp envelope verify envelope.json --subject subject.bin --json
govp conformance --run
```

The first command checks the GOVP-EXT-1 shape, signing bytes, Ed25519 signature,
key identifier, external-reference syntax and exact subject digest. Omitting
`--subject` leaves the subject check as `not_evaluable`.

Application code must additionally verify any required in-toto, Sigstore,
Rekor or RFC3161 reference with that ecosystem's native verifier before
claiming L1. Current key authorization and revocation remain L2.
