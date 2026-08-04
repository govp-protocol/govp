# Changelog

All notable verifier changes are documented here. GOVP format compatibility is
governed by the frozen specification and the published conformance vectors.

## 0.1.8 — pending public release

- make RFC 3339 fractional-second validation identical on Python 3.10 through
  3.14 without altering the signed timestamp;
- add a signed conformance vector for a one-digit fractional second;
- require URL fields to use visible ASCII RFC 3986 URI text, with IDNA and
  percent-encoding available for internationalized components;
- reject lone surrogate code points supplied through JSON or direct API use,
  because they cannot be encoded as the normative UTF-8 signing input;
- report stable advisory identifiers for signed non-printable text and
  non-HTTP evidence schemes without changing GOVP-1 core validity;
- add public integration, conformance, security, governance, support and
  release documentation;
- add Dependabot and CodeQL configuration for the clean publication
  repository.

## 0.1.7 — private publication candidate

- freeze the exact trim set already used by the v0.1.x verifier and add a
  signed interoperability vector for non-ASCII whitespace;
- reject bare carriage returns and malformed `generated-at` values
  consistently;
- align the JSON schema with both normalized records and bundles and remove a
  non-core state definition;
- replace the illustrative manufacturing fixture with fully synthetic data on
  a reserved `.example` domain;
- update the vulnerable `cryptography` release pin to 50.0.0;
- establish Brilyetz Holding S.L. attribution, Apache-2.0 licensing, trademark
  boundaries and an explicit public protocol scope.

## 0.1.6 — 2026-07-27

Security, interoperability and distribution release:

- reject NUL, CR and LF in field values and delimiters in field names so two
  distinct JSON field sets cannot share one signing input;
- require JSON record field names and values to be strings;
- define field-name normalization as ASCII `A`–`Z` lowercasing while preserving
  every other Unicode code point;
- add a signed non-ASCII extension vector and a JSON conformance suite;
- align the repository schema identity with `govp.io` and correct the
  machine-readable `govp-id` verification check name;
- pin the installer to this release and source-install examples to this tag;
- scope release permissions per job, stop persisting checkout credentials and
  pin every GitHub Action to a reviewed commit;
- verify release tags against package and runtime versions before publishing;
- publish dependency notices with Python and standalone release artifacts.

Previously valid GOVP-1 text records keep the same signing input, signature and
GOVP-ID. Inputs containing ambiguous control characters were never valid
line-oriented records and are now rejected consistently in JSON and direct API
use.

## 0.1.5 — 2026-07-27

Security and conformance release:

- require `public-key` in format validation and the JSON schema;
- preserve URL schemes, `www` hosts and trailing slashes in canonical binding;
- bind remote verification to the final HTTPS response URL;
- reject non-HTTPS and credentialed URLs, including redirect downgrades;
- cap downloaded records at 1 MiB and reject malformed UTF-8;
- define byte-wise sorting for non-ASCII extension fields using UTF-8;
- include every unknown field in the signature, including `__` prefixes;
- enforce the required GOVP-1 field shapes during format validation;
- make `self-test` prove acceptance of a valid Ed25519 signature and rejection
  of a tampered record;
- add the missing-public-key conformance vector and hostile transport tests;
- make the documented source-checkout test command work without `PYTHONPATH`;
- build, inspect and smoke-test distributions on every pull request.

No valid published GOVP-1 signing input, signature or GOVP-ID changes.

## 0.1.4 — 2026-07-25

- bundle an explicit CA certificate store in standalone verifier binaries.
