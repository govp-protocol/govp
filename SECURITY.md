# Security policy

## Supported versions

| Version | Security support |
| --- | --- |
| 0.1.9 | Supported |
| 0.1.8 | Security fixes only |
| 0.1.7 and earlier | Upgrade to 0.1.9 |

Do not open a public issue for an exploitable vulnerability.

Send a private report to `research@gemacode.org` with:

- the affected version or component;
- reproduction steps or a minimal record;
- the expected and observed verification result;
- the practical impact.

The project will acknowledge a complete report within 72 hours, coordinate a
fix and credit the reporter unless anonymity is requested.

Protocol limitations already documented in GOVP-1—such as issuer-asserted time,
unsigned comments and the distinction between integrity and truth—are not
vulnerabilities by themselves.

## Runtime dependency policy

The minimum direct dependency versions are recorded in
`requirements-minimum.txt` and exercised on the oldest and newest supported
Python versions in CI. The Ed25519 API existing in an older release is not by
itself sufficient support evidence: GOVP also requires a maintained security
baseline, compatible wheels and consistent behavior across Python 3.10–3.14.

The `cryptography>=50` floor is the reviewed baseline for GOVP 0.1.9. It may be
lowered in a future release only after the proposed floor passes the complete
test and vulnerability-review matrix. `certifi` supplies the explicit CA
store used by bounded HTTPS verification and standalone binaries.
