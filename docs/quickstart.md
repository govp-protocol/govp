# Quick start

This guide verifies a signed GOVP-1 record and its declared asset locally.
Local verification is offline: no account, API key or network request is
required.

## Requirements

- Python 3.10 or newer
- a supported operating system with Python wheels for `cryptography`
- the published `govp` package

## Install from PyPI

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install govp
govp self-test
govp conformance --run
```

On Windows PowerShell, activate with `.venv\Scripts\Activate.ps1`.

## Verify the bundled example

```bash
govp examples --extract govp-examples
govp verify govp-examples/manufacturing-record.govp.txt \
  --asset govp-examples/manufacturing-record.statement.txt
```

The result is valid only when the record format, signature, GOVP-ID and
supplied asset digest pass. Because the record is local, canonical URL binding
is reported as `not checked`.

For machine-readable output:

```bash
govp verify govp-examples/manufacturing-record.govp.txt \
  --asset govp-examples/manufacturing-record.statement.txt \
  --json
```

Do not use only the top-level `ok` value when an integration needs a specific
guarantee. Retain the individual checks and any advisory `warnings`.

## Verify a remote identity record

```bash
govp verify-url https://govp.io/.well-known/govp.txt --json
```

Remote verification accepts HTTPS only, follows HTTPS redirects, caps the
record at 1 MiB, requires valid UTF-8 and binds the final response URL to the
signed `canonical` value. It does not download or execute the evidence URL.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | The requested operation succeeded and the record is valid. |
| `1` | Verification completed and the record is not valid. |
| `2` | The command, file, network response or argument could not be processed. |

Continue with the [integration guide](integration.md) for application use and
the [security model](security-model.md) before exposing results to end users.

## Development and independent audit

Clone the repository only when developing GOVP, running the complete source
test suite or auditing the exact release tree:

```bash
git clone --branch v0.1.9 --depth 1 https://github.com/govp-protocol/govp.git
cd govp
python -m pip install -r requirements-test.txt
python -m pip install .
pytest --strict-config --strict-markers
```
