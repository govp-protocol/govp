# Conformance guide

An implementation is GOVP-1 conformant only when it reproduces the normative
text and JSON conformance suites exactly.

## Normative inputs

- `spec/GOVP-1.txt` — normative protocol text
- `conformance/vectors.json` — text parsing, canonical bytes and verdicts
- `conformance/json-vectors.json` — optional JSON record and bundle behavior
- `schema/govp-1.schema.json` — machine-readable JSON contract

The concise Markdown specification is explanatory. If prose and a vector ever
appear to disagree, stop and report the ambiguity rather than silently choosing
new behavior.

## Reference checks

```bash
python -m pip install -c requirements-release.txt -r requirements-test.txt .
pytest --strict-config --strict-markers
govp self-test
ruff check .
mypy --check-untyped-defs src
bandit -q -r src packaging
pip-audit -r requirements-release.txt --progress-spinner=off
```

## Implementation checklist

- Decode input as strict UTF-8.
- Normalize CRLF line endings but reject bare CR in a field.
- Use the frozen GOVP-1 trim set, not a runtime's generic whitespace table.
- Lowercase ASCII `A`–`Z` only in field names.
- Apply legacy aliases and last-value-wins before signing.
- Preserve unknown fields, including non-ASCII extension names.
- Sort normalized names by UTF-8 bytes.
- Exclude only `signature` and empty values.
- Prefix `GOVP::record.v1` followed by a NUL byte.
- Verify Ed25519, GOVP-ID and every applicable conditional check.
- Validate fractional RFC 3339 seconds independently of runtime parser width.
- Treat URL fields as visible ASCII RFC 3986 URI strings.
- Keep offline canonical and absent-asset checks as not evaluated, not passed.

## Compatibility rule

The first ten public text vectors and the complete public JSON suite predate
the clean repository. Their bytes and expected outcomes must not change. New
vectors may add coverage but cannot redefine an earlier vector silently.

Any proposed change to canonical signing bytes, GOVP-ID derivation or required
verification outcomes needs a new protocol version or an explicitly documented
backward-compatible clarification with migration analysis.
