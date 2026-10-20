# Verify a synthetic agent activity record

This example follows a proposal, a declared authorization, a declared action,
and a refusal of a second proposal. It contains **five fictional events**:
no language model or Gemacode containment runtime was executed. The event JSON
is a teaching format, not a normative GOVP extension or a security benchmark.

GOVP verifies the signed record and the exact supplied bytes. It does not
independently observe, authorize or enforce the events described in those bytes.

## Obtain the example before going offline

Install the released verifier and download the sample while connected:

```bash
python -m pip install govp==0.1.13
python -m govp self-test
git clone https://github.com/govp-protocol/govp.git govp-agent-example
cd govp-agent-example
```

Record the checkout commit with `git rev-parse HEAD` when reporting a result.
The files live in [`examples/agent-record/`](../examples/agent-record).
This newly added example is obtained from the repository; it is not included
in the existing 0.1.13 package's `govp examples --extract` output.

Copy those files to the recipient's machine with the verifier and its
platform-compatible dependencies already installed. The verification commands
below read local files and do not contact the sender.

## Follow the statement

| Sequence | Declared event | Meaning in this fixture |
| ---: | --- | --- |
| 1 | Proposal A | Write `operation-A.txt` |
| 2 | Authorization A | Fictional permission allows A |
| 3 | Action A | Declares completion and the output file's SHA-256 |
| 4 | Proposal B | Write `operation-B.txt` |
| 5 | Refusal B | Declares denial under the fictional permission |

The absence of an output for B is part of the constructed example. It is not
evidence that a real prohibited action was prevented.

## Verify the original

```bash
python -m govp verify examples/agent-record/agent-record.govp.txt \
  --asset examples/agent-record/agent-record.json
```

Expected: `VALID`, exit `0`; format, signature, GOVP-ID and asset checks pass.
`canonical` is **not checked** because the record is read from disk.

## Change the declaration

The supplied manipulated JSON changes the last event's decision from `deny`
to `allow`, leaving the signed record untouched:

```bash
python -m govp verify examples/agent-record/agent-record.govp.txt \
  --asset examples/agent-record/agent-record.tampered.json
```

Expected: `INVALID`, exit `1`; signature passes and asset is `FAIL`. This
detects a byte mismatch, not a forged signature or a policy violation.

## Change the signed record

The manipulated record changes its publisher field without a new signature:

```bash
python -m govp verify examples/agent-record/agent-record.tampered.govp.txt \
  --asset examples/agent-record/agent-record.json
```

Expected: `INVALID`, exit `1`; signature is `FAIL` and asset passes.
Add `--json` to preserve individual checks. Exit `2` means an input or command
problem and must not be counted as a cryptographic rejection.

## Check the separately referenced output

GOVP verification of the JSON does not automatically inspect files named
inside it. Check `operation-A.txt` separately against the hash in event 3:

```bash
python -c "import hashlib,json,pathlib; p=pathlib.Path('examples/agent-record'); s=json.loads((p/'agent-record.json').read_text()); actual=hashlib.sha256((p/'operation-A.txt').read_bytes()).hexdigest(); expected=s['events'][2]['artifact_sha256']; print('Output A:', 'PASS' if actual==expected else 'FAIL'); raise SystemExit(0 if actual==expected else 1)"
```

Expected: `Output A: PASS`, exit `0`.

## Check installation and verification without external network access

The `agent-record-offline` workflow repeats these checks on a GitHub-hosted
Ubuntu runner. It downloads hash-pinned public wheels while online, then
installs GOVP 0.1.13 in a fresh Python environment inside a pinned Linux
container with `--network none`. Installation uses `--no-index` and
`--require-hashes`. The fixture and wheels are mounted read-only.

The check requires only a loopback interface, no IPv4 route, and an unreachable
external connection before and after verification. It asserts the three
verdicts and the separately referenced output hash. Logs preserve the runner
identity, commit, image digest, input hashes, isolation settings and results
between `BEGIN_AGENT_OFFLINE_REPORT` and `END_AGENT_OFFLINE_REPORT`.

To repeat on Linux x86_64 with Python 3.12 and Docker:

```bash
python -m pip download --only-binary=:all: --require-hashes \
  -r tools/agent-record-offline-requirements.txt --dest /tmp/agent-record-wheels
python tools/check_agent_record_offline.py --wheels /tmp/agent-record-wheels
```

Downloading the image and wheels needs a connection; installation and verification
inside the container do not. Loopback remains available. This demonstrates
reproduction on another execution host, not review by an independent evaluator.
It exercises the released verifier, not an unreleased change to its implementation.

## Trust limits

The signing key was generated for this demonstration; the private key was
discarded and is not included. The record's embedded public key and the
provided PEM are demonstration material, not an institutional trust anchor
or a signature by Gemacode's CEO.

The `agent.example` URLs and the declared timestamp are fictional sample
metadata. No canonical retrieval, live status, independent timestamp,
institutional identity or event completeness has been established.
Verification does not prove that a real agent acted, was authorized, or was
contained. Evaluate source evidence and recipient policy separately.

The supplied bytes can be verified repeatedly. This example does not claim
that the discarded private key or its exact signature can be regenerated.
Neither this fixture nor successful verification qualifies a product for
production or substitutes for an independent evaluator.

See the [quick start](quickstart.md), [security model](security-model.md)
and [web walkthrough](https://govp.io/govp/agent-record.html).
