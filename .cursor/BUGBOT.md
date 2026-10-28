# Bugbot rules

Follow AGENTS.md "Dependency artifact review". The review agent is trusted and
the design is intentionally minimal.

Do not raise anything listed under "Accepted risks, do not flag" in AGENTS.md,
and do not ask for added hardening, scanners, caps, binding or sandboxing.

Tag pins (full or bare) for dependencies and actions are accepted. Do not flag
them, ask for commit-SHA pins, or treat tag movement as a finding; the review
records the resolved commit.

Raise only:

- PR-head code running in a trusted job.
- Secrets, tokens or write permissions reachable by the agent step.
- A verdict or metadata path that passes when it should fail.
- The review workflow becoming updatable by Dependabot.
- Correctness bugs that break real Dependabot PRs.
- Before raising a correctness bug, ground it in actual Dependabot or
  fetch-metadata behaviour (dependency-name, version formats), not a
  hypothetical input. A finding whose failure mode is "the check fails closed"
  on an input Dependabot does not produce is not a finding. "Updatable by
  Dependabot" applies only to the target-repo workflow, not to rcu's templates.
