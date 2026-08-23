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

## Shared 30 USD budget envelope

This repository shares one dedicated OpenAI API project with the four priority repositories. The
activation target is 30 USD per calendar month across that project, not 30 USD per repository.
Pull-request scans default to an estimated 1 USD limit and manually dispatched full scans default
to 5 USD. Override them only with CODEX_SECURITY_PR_MAX_COST_USD and
CODEX_SECURITY_FULL_MAX_COST_USD. Codex Security's --max-cost is an estimate, not a hard cap, so
the OpenAI project must also be monitored in the Usage Dashboard. Deep scans remain outside the
automatic workflow.

Recommended activation sequence:

1. Create a dedicated OpenAI API project for these four repositories, record a 30 USD monthly
   budget target, and configure billing notifications or controls available to the account.
2. Add that project's scoped CODEX_SECURITY_API_KEY as a repository secret.
3. Keep CODEX_SECURITY_AUTOMATION_ENABLED=false while validating one manual run.
4. Set CODEX_SECURITY_REMEDIATION_MODEL only if overriding the reviewed default.
5. Set CODEX_SECURITY_AUTOMATION_ENABLED=true after the budget and first result are accepted.
6. Set CODEX_SECURITY_PUBLIC_REMEDIATION_ENABLED=true only when publishing the patch through this
   public repository is acceptable.
7. Require the scan and existing CI checks in branch protection only after observing stable runtime
   and coverage.
