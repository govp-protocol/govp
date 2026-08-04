# Quick start

This guide verifies a signed GOVP-1 record and its declared asset locally.
Local verification is offline: no account, API key or network request is
required.

## Requirements

- Python 3.10 or newer
- a supported operating system with Python wheels for `cryptography`
- the GOVP source checkout or a published package

## Install from the repository

```bash
git clone https://github.com/govp-protocol/govp.git
cd govp
python -m venv .venv
. .venv/bin/activate
python -m pip install .
govp self-test
```

On Windows PowerShell, activate with `.venv\Scripts\Activate.ps1`.

## Verify the bundled example

```bash
govp verify examples/manufacturing-record.govp.txt \
  --asset examples/manufacturing-record.statement.txt
```

The result is valid only when the record format, signature, GOVP-ID and
supplied asset digest pass. Because the record is local, canonical URL binding
is reported as `not checked`.

For machine-readable output:

```bash
govp verify examples/manufacturing-record.govp.txt \
  --asset examples/manufacturing-record.statement.txt \
  --json
```

Do not use only the top-level `ok` value when an integration needs a specific
guarantee. Retain the individual checks and any advisory `warnings`.

## Verify a remote identity record

```bash
govp verify-url https://publisher.example/.well-known/govp.txt --json
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
