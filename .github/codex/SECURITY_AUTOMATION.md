# Codex Security automation

This repository has two cost-gated workflows:

- `Codex Security scan` reviews trusted pull-request diffs and can run a manual full scan. High or
  critical findings fail the check. Results are uploaded to GitHub code scanning without exposing
  detailed raw scan artifacts through this public repository.
- `Codex Security remediation` accepts one validated finding and generates the smallest verified
  fix. Because this repository is public, it has a second gate named
  `CODEX_SECURITY_PUBLIC_REMEDIATION_ENABLED`. A draft pull request or Actions patch artifact can
  disclose the issue; keep the second gate disabled for undisclosed vulnerabilities and remediate
  those locally with the Codex Security workbench.

Neither workflow merges to `main`. Remediation runs one finding at a time. The workflows remain
disabled unless the repository variable `CODEX_SECURITY_AUTOMATION_ENABLED` equals `true`, and
they require the repository secret `CODEX_SECURITY_API_KEY`. API-backed scans and remediations can
incur OpenAI API charges.

Recommended activation sequence:

1. Add a scoped `CODEX_SECURITY_API_KEY` repository secret with a project spend limit.
2. Keep `CODEX_SECURITY_AUTOMATION_ENABLED=false` while validating one manual run.
3. Set `CODEX_SECURITY_REMEDIATION_MODEL` only if overriding the reviewed default.
4. Set `CODEX_SECURITY_AUTOMATION_ENABLED=true` after the budget and first result are accepted.
5. Set `CODEX_SECURITY_PUBLIC_REMEDIATION_ENABLED=true` only when publishing the patch through this
   public repository is acceptable.
6. Require the scan and existing CI checks in branch protection only after observing stable runtime
   and coverage.
