# GOVP AI-1 privacy and threat model

## Protected properties

AI-1 binds a request, its declared execution scope, a terminal result and an
optional recomputation through signed byte digests and causal references. It
can make post-commitment alteration, reference substitution and contradictory
terminal fields detectable.

## Threats and controls

| Threat | Public control | Residual dependency |
|---|---|---|
| Result selected after many hidden attempts | pre-inference request plus external witness citation | witness completeness or QEL enforcement |
| Model name substituted | exact artifact and publisher-manifest digests | publisher attestation |
| Runtime/backend drift | request and effective execution digests | trustworthy observer |
| Prompt or output changed | exact digest binding | custody of original bytes |
| Result detached from request | mandatory exact GOVP reference | availability of both envelopes |
| False reproducibility claim | separate verification record | verifier independence and environment |
| Semantic match presented as exact | only `exact` and named `canonicalized` profiles | canonicalizer correctness |
| Cloud opacity hidden | fields remain declared and cannot be promoted by GOVP | provider attestation or hardware evidence |
| Secret prompt disclosed in metadata | digest-first payload and disclosure label | issuer redaction discipline |
| Replay of an attempt | stable nonce and attempt ID | cross-transaction stateful receiver |

## Privacy model

Envelopes are expected to be durable and widely replicated. They MUST NOT
contain prompts, personal data, raw outputs, credentials or provider tokens.
Identifiers SHOULD be pseudonymous and non-correlating where regulation and
audit requirements permit. The four disclosure labels are `digest_only`,
`sealed`, `private` and `public`; they describe custody but do not encrypt data.

Deletion of off-envelope content does not delete its digest. A digest may still
enable guessing attacks against low-entropy prompts or outputs. Deployments
SHOULD use access-controlled salted commitment artifacts when equality testing
is not required, and record only the digest of that artifact.

## Explicit non-claims

AI-1 does not establish content truth, safety, fairness, legal compliance,
commercial model identity, complete attempt accounting, current key authority,
trusted time, verifier independence or permission to execute.

