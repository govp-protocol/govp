# Release process

This process keeps source, packages, binaries, checksums and public protocol
material synchronized.

## Release gates

1. Work only from the clean publication repository and a reviewed pull
   request. Historical development repositories are not publication sources.
2. Require the complete CI matrix, quality job and package job to pass.
3. Review dependency updates, action commit pins and dependency licenses.
4. Scan the reachable Git history and candidate tree for secrets and personal
   or operational data.
5. Build wheel and source distribution twice with the commit timestamp as
   `SOURCE_DATE_EPOCH`; require byte-identical output.
6. Install the wheel in an isolated environment and run self-test plus signed
   example verification.
7. Confirm version equality in `pyproject.toml`, `govp.__version__`, tag,
   installer and documentation.
8. Synchronize the specification, schema, vectors, installer and release
   checksums on `govp.io`.
9. Create the immutable `vX.Y.Z` tag and GitHub release from the reviewed
   commit. Publish PyPI only through the protected OIDC environment.
10. Verify every published asset from a fresh download and retain the release
    manifest.

## Required repository controls

- protected default branch or organization ruleset;
- pull-request review and required CI checks;
- secret scanning and push protection when available;
- Dependabot for Python and GitHub Actions;
- CodeQL scanning;
- least-privilege workflow permissions;
- no long-lived package registry credentials.

If any released checksum, tag or source tree differs from the reviewed commit,
stop publication and issue a new version. Do not replace published artifacts
under an existing version.
