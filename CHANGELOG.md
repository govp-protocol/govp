# Changelog

All notable verifier changes are documented here. GOVP format compatibility is
governed by the frozen specification and the published conformance vectors.

## Unreleased

- define GOVP AI-1 request, result and verification evidence without changing
  GOVP-1 or presenting evidence admission as regulated authorization;
- add a fail-closed Python receiving gate, privacy/threat model, JSON Schema and
  byte-exact Python/JavaScript conformance vectors;
- restrict initial recomputation comparisons to `exact` and explicitly named
  `canonicalized` profiles.

## 0.1.13 — 2026-08-11

- add `govp publish`, a static-only organizational publication workflow with
  exact CI workload identity and time-bounded subordinate signing keys;
- add mesh-compatible 256-shard RFC 6962 batches and O(log N) inclusion proofs,
  including byte-exact Python/JavaScript vectors for 10,000 events;
- separate public publication from `sealed_private` custody and reject
  unapproved event classes, editor publication and out-of-scope keys;
- add local-tree, custody-tree and static-URL verification, threat model,
  schema, reproducible CLI tests and the `org.govp.publication` registry entry.

## 0.1.12 — 2026-08-11

- define GOVP-EXT-1 evidence envelopes, their origin contract, security model
  and extension registry without changing GOVP-1;
- add strict Python signing and verification, a local `govp envelope verify`
  command, JSON Schema and six byte-exact cross-language vectors;
- register digest-bound SLSA/in-toto, Sigstore, Rekor and RFC 3161 external
  attestations without implying that a locator alone proves validity.

## 0.1.11 — 2026-08-06

- require a recent GOVP-STATUS-1 `generated_at` value before returning
  `currently_trusted=true`, with explicit maximum-age and future-skew policy;
- add the unambiguous `snapshot_valid` status result while retaining
  `snapshot_trusted` as a compatibility alias;
- reject normalized or legacy-alias field-name collisions in JSON records and
  bundles without changing the frozen text parser's last-value rule;
- require canonical prime-subgroup Ed25519 public-key and signature point
  encodings and a reduced signature scalar across supported runtimes;
- add replay, clock-skew, collision and exceptional-point regressions while
  keeping every published GOVP-1 signing input and identifier unchanged.

## 0.1.10 — 2026-08-05

- accept `str` and all standard path-like values in the public `load_record`
  API;
- add explicit `--ca-bundle` support while retaining Certifi as the secure,
  reproducible default for network and standalone verification;
- add `sign_record`, `serialize_record` and `govp issue` so adopters can emit
  conforming records without reconstructing the signing algorithm;
- publish the separate GOVP-STATUS-1 extension, schema, conformance vectors,
  status API and CLI for fail-closed online key and record status;
- document planned rotation, compromise response, local issuance and the IANA
  Well-Known URI registration request;
- clarify that a discovered record's canonical field names its own exact final
  URL, while `/.well-known/govp.txt` remains the domain identity record;
- add public-domain monitoring and first-party production evidence without
  changing GOVP-1 signing bytes or core-verification semantics.

## 0.1.9 — 2026-08-05

- make `pip install govp` the primary installation path and ensure every
  quick-start command works without a source checkout;
- bundle the frozen specification, schema, conformance vectors and synthetic
  examples in both wheel and source distributions;
- add `govp conformance --run` and `govp examples --extract DIR` for installed
  package validation and reproducible demonstrations;
- publish the supported top-level Python API and typed `VerifyResult` alias
  while preserving `govp.core` compatibility;
- replace PyPI-relative documentation links with canonical absolute URLs;
- add a tested minimum-dependency matrix and document the reviewed security
  floor;
- move historical MIT licensing context to `LICENSE-HISTORY.md` so the current
  Apache-2.0 license is unambiguous;
- prepare live `govp.io` canonical discovery records without changing GOVP-1
  signing inputs, signatures, identifiers or conformance verdicts.

## 0.1.8 — 2026-08-04

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
