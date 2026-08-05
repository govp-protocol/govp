# Dependency licensing

This file records the direct dependencies needed to build or run GOVP CLI. It
is a review aid, not a replacement for each dependency's own license file.

## Runtime

| Dependency | Requirement | License | Purpose |
| --- | --- | --- | --- |
| `certifi` | `>=2024.7.4` | MPL-2.0 | Portable CA certificate store for HTTPS |
| `cryptography` | `>=50` | Apache-2.0 OR BSD-3-Clause | Ed25519 verification |

Both alternatives are free software licenses. GOVP does not require a hosted
service, proprietary SDK or non-free runtime component.

The supported lower bounds are pinned in `requirements-minimum.txt` and run in
CI on Python 3.10 and 3.14. They are support and security baselines, not claims
about the earliest upstream release containing a particular primitive.

## Build and test

| Dependency | License | Purpose |
| --- | --- | --- |
| Hatchling | MIT | PEP 517 package build backend |
| build | MIT | Build frontend |
| pytest | MIT | Test runner |
| twine | Apache-2.0 | Distribution metadata validation and publication client |
| pyinstaller-hooks-contrib | Apache-2.0 / GPL-2.0 (component-specific) | PyInstaller build hooks |
| Ruff | MIT | Static analysis and formatting checks |
| mypy | MIT | Type checking |
| Bandit | Apache-2.0 | Security-focused static analysis |
| jsonschema | MIT | Machine-readable schema conformance tests |
| pip-audit | Apache-2.0 | Published vulnerability database checks |
| PyInstaller | GPL-2.0-or-later with a special exception | Standalone release binaries |

The PyInstaller exception permits distribution of executables produced with
PyInstaller without imposing the GPL on the bundled application. Build and
test tools are not runtime dependencies of the Python package.

## Documentation

Repository documentation is distributed under the same Apache-2.0 license as the
software. The normative GOVP-1 specification is included in this repository
under that license.

Before every public release, review the resolved dependency tree and the
licenses actually bundled in standalone executables. The reviewed direct
release inputs are pinned in `requirements-release.txt`, and notices intended
to accompany redistributed binaries are in `THIRD_PARTY_NOTICES.md`.
