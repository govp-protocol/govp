# Remediate one validated security finding

Read `.codex-security-input/finding.md` and treat it as the only finding in scope. Inspect
repository instructions, the affected implementation, direct callers, existing controls, and the
nearest relevant tests before editing.

Revalidate the concrete vulnerable path and security invariant. If it is not reproducible or not
provable in this checkout, make no speculative change and explain the missing proof. Otherwise:

1. Add a focused regression test or the strongest safe repeatable validation artifact.
2. Implement the smallest repository-native fix that fully closes the boundary.
3. Preserve legitimate behavior, public APIs, error semantics, compatibility, authentication,
   authorization, tenant isolation, validation, logging, and cryptographic invariants.
4. Rerun the original reproducer or strongest exploit check, a legitimate control case, focused
   tests, and the relevant repository checks.
5. Review the final diff for adjacent bypasses and unrelated changes.

Do not modify `.github/workflows/**`, `.github/actions/**`, repository secrets, release settings, or
deployment configuration. Do not push, create a pull request, or merge. Leave only the focused
source and regression-test changes in the working tree.

Finish with `fixed`, `no_change`, or `blocked`; list changed files and exact commands with their
results; state how the original issue stopped reproducing, how legitimate behavior remained, and
any remaining proof gap.
