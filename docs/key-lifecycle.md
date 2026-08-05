# Key lifecycle and revocation

This procedure applies to GOVP-STATUS-1. GOVP-1 core validity remains an
offline cryptographic fact; current trust is a separate online decision.

## Normal operation

1. Keep private keys outside repositories, web roots, build artifacts and
   deployment bundles.
2. Restrict local key files to the account that signs (`chmod 600`). Prefer an
   HSM or KMS for high-value production issuance.
3. Publish every currently authorized public key as `active` in
   `/.well-known/govp/revoked.json`.
4. Monitor the identity record, discovery index, status endpoint and a complete
   `govp status-url` evaluation.

## Planned rotation

1. Generate the replacement key in the intended secure signer.
2. Add its public key to status as `active`; leave the old key active during a
   short overlap and deploy.
3. Confirm status from an independent network and verifier.
4. reissue the canonical identity record and new records with the replacement
   key; deploy and verify canonical binding.
5. Change the previous key to `retired`; deploy and verify again.
6. Archive public evidence and destroy or seal the previous private key under
   the organization's retention policy.

The overlap avoids a state where neither the old nor new canonical record can
reach current trust.

## Suspected or confirmed compromise

1. Stop issuance with the affected key.
2. Generate a replacement in a clean signer.
3. Publish the replacement as `active` and the affected key as `revoked`.
4. Add withdrawn record IDs to `revoked_records` with the most accurate reason.
5. Replace canonical records, invalidate caches and verify from an independent
   network.
6. Preserve incident evidence and communicate the affected scope.

A compromised key can backdate `generated-at`; do not use issuer-asserted time
to grandfather records signed by that key.

## Loss without evidence of compromise

Rotate as above and mark the unavailable key `retired`. Use `revoked` whenever
the operator cannot reasonably exclude unauthorized use.
