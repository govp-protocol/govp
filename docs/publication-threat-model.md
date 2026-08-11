# GOVP publication threat model

Inputs, paths, envelopes, subjects, status snapshots, authorizations and
workload environment variables are untrusted. The reference implementation
fails closed on path traversal, symlinks escaping the request directory,
duplicate IDs, malformed Base64, unknown event types, scope mismatches,
expired authorizations, mismatched domain keys and invalid Merkle paths.

The organizational private key is the publication authority. It belongs in a
CI secret store or KMS whose access policy validates workload identity. The
CLI's GitHub workload checks prevent accidental editor use but do not turn
environment variables into cryptographic identity; key-store policy remains
mandatory.

The public index intentionally omits event IDs, repositories, authors and
failures. Even roots and counts reveal cadence, so every public event class is
opt-in. `sealed_private` uses a separate batch and custody tree; mixing private
and public events in one root would leak private batch size and is forbidden.

An inclusion proof establishes membership, not truth. A compromised
subordinate key is limited by exact type and time scope, but events already
published remain attributable until application policy revokes or disputes
them. Status snapshots are not live authority and cannot produce L2.

Static hosting may cache old roots or present a split view. Independent
mirrors, transparency logging and gossip can detect that condition; this
extension does not claim to prevent it. Existing published batches are
immutable and must not be overwritten.
