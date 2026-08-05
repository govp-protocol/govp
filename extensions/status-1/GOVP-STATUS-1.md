# GOVP-STATUS-1 online status extension

Status: stable extension to the frozen GOVP-1 core. It does not change GOVP-1
signing inputs, identifiers or core-validity verdicts.

## Purpose

GOVP-1 proves record integrity and authorship. GOVP-STATUS-1 lets the HTTPS
origin named by a record make a current, fail-closed statement about authorized
keys and explicitly revoked records.

The default endpoint is:

```text
https://<origin>/.well-known/govp/revoked.json
```

The discovery index SHOULD expose its absolute URL in a top-level `status`
member.

## Transport authority

The document MUST be fetched over HTTPS from the same origin as the GOVP-1
record's `canonical` URI. Its `canonical` member MUST equal the final response
URL after redirects. Credentialed URLs and HTTPS downgrades MUST be rejected.

`authority` is `https-origin`: freshness and authority come from a successful,
current TLS fetch from that origin. A saved status file is only a snapshot and
MUST NOT be presented as proof of current trust. The endpoint SHOULD send
`Cache-Control: no-store` and `Access-Control-Allow-Origin: *`.

Status is not signed by the record key. That is deliberate: a compromised key
cannot be trusted to revoke itself. Deployments requiring a trust anchor beyond
the HTTPS origin can compose GOVP with DNSSEC, a transparency log, PKI or an
external status signer.

## JSON document

The normative schema is `schema/govp-status-1.schema.json`. Required members:

- `format`: literal `GOVP-STATUS-1`;
- `canonical`: final absolute HTTPS URL of this document;
- `publisher`: human-readable operator name;
- `authority`: literal `https-origin`;
- `generated_at`: issuer-asserted RFC 3339 UTC generation time;
- `keys`: one or more key-state objects;
- `revoked_records`: zero or more record-revocation objects.

Each key object contains:

- `public_key`: Base64 raw Ed25519 public key (32 bytes);
- `key_id`: `sha256:` followed by SHA-256 of those 32 raw bytes;
- `state`: `active`, `retired` or `revoked`;
- `changed_at`: issuer-asserted RFC 3339 UTC state-change time.

Each revoked-record object contains `govp_id`, `revoked_at` and a `reason` from
`compromised`, `superseded`, `withdrawn`, `cessation` or `other`.

Key IDs and GOVP IDs MUST be unique within their respective arrays.

## Trust evaluation

For an online result of `currently_trusted=true`, a verifier MUST establish all
of the following:

1. the GOVP-1 record is core-valid, including canonical binding to the final
   URL from which that record was fetched;
2. the status document satisfies the normative schema and semantic key-ID
   checks;
3. the record and status canonical URLs have the same HTTPS origin;
4. the status document is canonically bound to its final fetched URL;
5. the record public key appears exactly once with state `active`;
6. the record GOVP-ID does not occur in `revoked_records`.

Any failed check yields `currently_trusted=false`. Network failure or offline
evaluation yields an indeterminate current state, never `true`. Core validity
remains separately reportable and is not changed by status.

`retired` means the key is no longer authorized for a current-trust result.
`revoked` means the origin explicitly distrusts it. Historical acceptance and
the meaning of issuer-asserted timestamps remain application policy.

## Rotation and compromise

Planned rotation SHOULD temporarily publish old and new keys as `active`, then
switch the canonical identity record, then mark the old key `retired`.
Compromise response MUST publish the replacement key as `active`, mark the old
key `revoked`, replace affected canonical records and add any specifically
withdrawn GOVP IDs to `revoked_records`.

See `docs/key-lifecycle.md` for the operational procedure.

## Security considerations

- `generated_at`, `changed_at` and `revoked_at` are origin assertions, not
  independent timestamps.
- A TLS or origin compromise can falsify online status. Independent deployments
  should add DNSSEC, transparency or an external trust anchor.
- Cached or mirrored copies are snapshots. They cannot produce current trust.
- Clients must apply normal JSON size, depth and duplicate-handling limits.
- Status failure must never be converted into `currently_trusted=true`.
