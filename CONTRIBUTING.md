# Contributing to GOVP

GOVP changes are judged by interoperability, not implementation preference.

Before proposing a change:

1. Create a virtual environment and run
   `python -m pip install -c requirements-release.txt -r requirements-test.txt -e .`.
2. Run `pytest --strict-config --strict-markers`.
3. Run `python -m govp self-test`.
4. Run `python -m govp verify examples/manufacturing-record.govp.txt --asset
   examples/manufacturing-record.statement.txt`.
5. Explain whether the change affects GOVP-1 bytes, identifiers, signatures,
   schemas, warnings or conformance verdicts.

By submitting a contribution for inclusion, you agree that it is provided
under Apache License 2.0 and that you have the right to provide it. Do not
submit customer data, production credentials, private keys, proprietary
product code or material outside the scope defined in `SCOPE.md`.

Changes to frozen GOVP-1 behavior require a new version or an explicitly
backward-compatible clarification. A proposal that changes canonical bytes
must include updated vectors and migration consequences.

Use GitHub issues for specification ambiguities and pull requests for reviewed
changes. Security reports must follow `SECURITY.md`.
