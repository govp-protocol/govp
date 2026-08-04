# GOVP

GOVP is the open protocol for portable, independently verifiable evidence.
GOVP-1 binds a publisher, an artifact identifier and the artifact's SHA-256
digest in a small Ed25519-signed record. Verification is deterministic and
does not require a GOVP account, central API or hosted service.

This repository is the canonical public-source package for:

- the stable GOVP-1 specification;
- byte-exact conformance vectors and JSON Schema;
- the Python reference verifier and command-line interface;
- synthetic examples, tests and reproducible release automation.

The current verifier release candidate is **0.1.8**. GOVP-1 remains the frozen
wire format; 0.1.8 closes cross-runtime timestamp validation and publication
hardening findings without changing existing signing inputs.

## Verify from a source checkout

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install .
govp self-test
govp verify examples/manufacturing-record.govp.txt \
  --asset examples/manufacturing-record.statement.txt
```

Windows PowerShell activation:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install .
govp self-test
```

After tag `v0.1.8` and its matching packages are published, the pinned source
installation is:

```bash
pipx install git+https://github.com/govp-protocol/govp.git@v0.1.8
govp self-test
```

The future PyPI and standalone installer commands become supported only when
the tag, release assets, checksums and `govp.io` copies are published together.
Until then, use the source-checkout procedure above.

## Commands

```text
govp verify RECORD [--asset FILE] [--json]
govp verify-url URL [--json]
govp inspect RECORD
govp id --type TYPE --asset-id ID --sha256 DIGEST
govp self-test
govp --version
```

Exit code `0` means the requested verification succeeded, `1` means the record
was evaluated and is not valid, and `2` means the command or input could not be
processed. Machine consumers should use `--json`, inspect every individual
check and retain any advisory `warnings`.

## What GOVP proves

A CORE-VALID result proves that the supplied public key signed the exact GOVP
record, the GOVP-ID matches its declared asset identity and—when asset bytes
are supplied—the SHA-256 digest matches. Remote verification additionally
checks the final HTTPS URL against `canonical`.

GOVP does not prove that a statement is true, that an event occurred, or that
an issuer-controlled timestamp is independently anchored. Evidence URLs are
untrusted data and are never executed by the verifier.

## Documentation

- [Quick start](docs/quickstart.md)
- [Integration guide](docs/integration.md)
- [Conformance guide](docs/conformance.md)
- [Security model](docs/security-model.md)
- [Release process](docs/release-process.md)
- [Normative GOVP-1 text](spec/GOVP-1.txt)
- [Public protocol boundary](SCOPE.md)
- [Governance](GOVERNANCE.md)
- [Support](SUPPORT.md)
- [Security reporting](SECURITY.md)

## Repository map

- `spec/` — normative and concise protocol text
- `schema/` — machine-readable record and bundle schema
- `conformance/` — byte-exact text and JSON vectors
- `src/govp/` — reference verifier and CLI
- `examples/` — valid signed records with fully synthetic content
- `tests/` — protocol, transport and CLI regression tests
- `docs/` — adoption, integration, security and release guidance

## License and trademarks

The specification, conformance material, software and repository documentation
are licensed under Apache License 2.0. Copyright is held by Brilyetz Holding
S.L.; Gemacode is its brand. Apache-2.0 does not grant rights to the GOVP or
Gemacode names—see [TRADEMARKS.md](TRADEMARKS.md).

Copies of v0.1.6 material already distributed under MIT remain under that
license. The 0.1.8 public repository edition and new contributions use
Apache-2.0.
