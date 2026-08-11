# GOVP-EXT-1 security and threat model

## Protected properties

The envelope protects exact signed bytes, the exact subject digest, declared
evidence origin and cited reference digests. It does not prove that an issuer
was honest, that an external attestation is natively valid or that a policy
should accept the assertion.

## Threats and controls

| Threat | Control |
|---|---|
| Payload changed after signing | Ed25519 verification fails |
| Subject bytes replaced | `hash.value` comparison fails |
| Human claim presented as observation | origin constructor and validator reject incompatible observation |
| SLSA/Rekor/RFC3161 object substituted | exact `sha256:` reference digest fails |
| Foreign evidence reissued as GOVP evidence | only a citation is allowed; native verification stays separate |
| Alternate identity injected | issuer must use the GOVP canonical identity path |
| Stale or revoked key accepted | L2 status is separate and fail-closed |
| Network unavailable | L0 remains available; unavailable layers are `not_evaluable` |
| JSON implementation disagreement | constrained canonical JSON and shared byte vectors |
| Oversized/deep input | callers enforce bounded input before parsing |

## Residual risks

Issuer compromise, malicious first-hand observers and compromised native
attestation systems remain outside L0. Receiving policies must select trusted
issuers, origins, native verifiers, freshness and revocation requirements.
