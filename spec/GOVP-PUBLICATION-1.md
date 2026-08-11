# GOVP-PUBLICATION-1

Status: governed extension to GOVP-EXT-1. It does not modify GOVP-1.

## Purpose and boundary

GOVP-PUBLICATION-1 turns locally signed evidence into a domain-attributable,
static publication. The publisher emits files only. Verification is always a
client operation; a conforming tree MUST NOT expose a dynamic `/verify` route.

Publication has two dispositions. `publish` is an explicit opt-in and commits
an event to a publicly served batch root. `sealed_private` commits an event to
a domain-signed batch retained in local custody; its event, proof, count and
root MUST NOT occur in the public tree.

## Subordinate keys

The organization signs an `org.govp.subordinate-key/1` GOVP-EXT-1 envelope.
Its subject is the exact 32-byte raw Ed25519 subordinate public key and its
payload conforms to `$defs.authorizationPayload` in the normative schema.
The payload declares an exact domain, an inclusive `valid_from`, an exclusive
`valid_until` and an explicit set of GOVP-EXT-1 event types.

The authorization signer is an organizational key listed by the domain's
GOVP-STATUS-1 document. A subordinate event reaches L1 only when all are true:

1. event and subject pass GOVP-EXT-1 L0;
2. the event key equals the authorized subordinate key;
3. the event type is in `allowed_types` and its `created_at` is in the window;
4. authorization and batch root are valid and signed by the same organizational key;
5. that organizational key is listed by the domain status snapshot and is not revoked;
6. the event has a valid inclusion proof in the signed batch root.

No scope hierarchy, wildcard, normalization or promotion exists.

## Merkle construction

This extension reuses the GOVP Mesh 2.6 registry construction exactly: 256
shards, RFC 6962 hashing and an eight-step top proof.

For each event, define the descriptor with exactly `id`, `key_id`,
`signing_input_sha256` and `type`. Encode it with GOVP canonical JSON.

```text
entry_id = SHA256(UTF8(id) || 0x00 || ASCII(signing_input_sha256))
shard    = last byte of entry_id
leaf     = SHA256(0x00 || canonical_json(descriptor))
node     = SHA256(0x01 || left || right)
empty    = SHA256(empty byte string)
```

Within each shard descriptors are sorted by lowercase hexadecimal `entry_id`
using code-point order. The RFC 6962 root recursively splits a list before the
largest power of two smaller than its length. Empty shards use `empty`. A
second RFC 6962 tree over the 256 shard roots produces the batch root. A proof
contains the intra-shard path and the eight-step top path. Each step is
`[sibling_sha256, is_right_sibling]`.

Duplicate event IDs or duplicate `entry_id` values are invalid. Verification
recomputes the descriptor, entry ID, shard and both paths.

## Batch and static tree

The organization signs one `org.govp.publication-batch/1` GOVP-EXT-1 envelope
per non-empty disposition. Its exact subject bytes are the 32 raw bytes of the
Merkle root. The payload conforms to `$defs.batchPayload`.

The public output contains only:

```text
.well-known/govp.txt
.well-known/govp/revoked.json
.well-known/govp/index.json
.well-known/govp/publication/index.json
.well-known/govp/publication/batches/<batch-id>.json
.well-known/govp/publication/keys/<key-id-without-prefix>.json
```

Event envelopes, subjects and inclusion bundles stay in the separate custody
directory. The publication index lists batch roots, never event identifiers.

## Workload boundary

`govp publish` is a CI operation. The reference implementation accepts only a
GitHub Actions workload whose repository and ref match the request allowlist.
The workload identity is recorded in the signed batch `origin.observation`.
The organizational private key is supplied by CI secret/KMS policy and MUST
NOT be stored by an editor or extension.

## Verification layers

- L0: event, authorization and batch signatures plus exact subject bindings.
- L1: exact domain-key snapshot binding, subordinate scope/window and Merkle inclusion.
- L2: optional fresh same-origin GOVP-STATUS-1 retrieval and active keys.

A saved status snapshot can establish the declared L1 chain but never current
trust. Missing live status is `not_evaluable`, not pass or fail.
