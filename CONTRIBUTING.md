# Contributing to GOVP

GOVP changes are judged by interoperability, security and clarity rather than
implementation preference.

## Contributions we especially want

- independent implementations in additional languages and runtimes;
- conformance reports that identify passing and failing vectors;
- minimal synthetic vectors for behavior not already covered;
- specification ambiguities found during independent implementation;
- integration guides for artifact, CI, data and publishing workflows;
- security hardening and precise trust-boundary documentation.

Use the
[independent implementation form](https://github.com/govp-protocol/govp/issues/new?template=implementation.yml)
to introduce an implementation. If two reasonable implementations can produce
different signing bytes, IDs or verdicts, stop and use the
[specification ambiguity form](https://github.com/govp-protocol/govp/issues/new?template=spec-ambiguity.yml)
before choosing private behavior.

## Frozen protocol boundary

GOVP-1 is frozen. Low churn in normative files is intentional and protects
interoperability.

Changes to published signing inputs or wire behavior require a new protocol
version or an explicitly backward-compatible clarification. Any proposal that
changes canonical bytes must include updated vectors, compatibility analysis
and migration consequences.

The public repository does not accept issuing products, control panels,
customer integrations, hosted-service code, operational data or commercial
extensions. See [`SCOPE.md`](SCOPE.md).

## Development setup

Create a virtual environment, then install the reviewed test toolchain:

```bash
python -m pip install \
  -c requirements-release.txt \
  -r requirements-test.txt \
  -e .
```

Run the complete local checks:

```bash
pytest --strict-config --strict-markers
python -m govp self-test
python -m govp verify examples/manufacturing-record.govp.txt \
  --asset examples/manufacturing-record.statement.txt
ruff check .
mypy --check-untyped-defs src
bandit -q -r src packaging
pip-audit -r requirements-release.txt --progress-spinner=off
```

## Pull-request requirements

Every pull request must explain whether it affects:

- GOVP-1 signing bytes or canonicalization;
- GOVP-ID derivation;
- record or JSON Schema behavior;
- conformance vectors and verdicts;
- warning identifiers;
- URL, rendering or resource-limit security boundaries.

Add or update tests for every observable behavior change. Documentation-only
changes must still preserve normative claims and working links.

By submitting a contribution for inclusion, you agree that it is provided
under Apache License 2.0 and that you have the right to provide it. Do not
submit customer data, production credentials, personal data, private keys,
proprietary product code or material outside the public protocol scope.

Security reports must use
[private vulnerability reporting](https://github.com/govp-protocol/govp/security/advisories/new)
or follow [`SECURITY.md`](SECURITY.md), not public issues.
