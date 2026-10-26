# Bugbot rules

Follow AGENTS.md "Dependency artifact review". The review agent is trusted and
the design is intentionally minimal.

Do not raise anything listed under "Accepted risks, do not flag" in AGENTS.md,
and do not ask for added hardening, scanners, caps, binding or sandboxing.

Raise only:

- PR-head code running in a trusted job.
- Secrets, tokens or write permissions reachable by the agent step.
- A verdict or metadata path that passes when it should fail.
- The review workflow becoming updatable by Dependabot.
- Correctness bugs that break real Dependabot PRs.
