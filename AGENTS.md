# Agent instructions

## Dependency artifact review

A trusted AI agent reviews the published code changes of a Dependabot update
for signs of malware. Keep it small.

Flow: fetch-metadata gives name/old/new version -> the name and new version must
appear literally on an added PR diff line (else `unverified`, fail) -> fetch old
and new artifacts with native tools (`npm pack --ignore-scripts`, PyPI JSON,
`go mod download`, `git fetch` of a SHA-pinned action, or of the commits that
`git ls-remote` resolves vX, vX.Y or vX.Y.Z tag pins to, peeled; an unresolved
or branch-ambiguous tag is `unverified`) -> `diff -ruN` the
extracted trees plus a script-computed facts list -> the agent writes findings
and a Compatibility section, ending with a strict block of `MALWARE:
clean|suspicious|malicious`, `MERGE: yes|no` and `REASON:` lines (exactly once,
within the last 10 non-empty lines, ordinary text may follow) -> one comment whose last
line is `**Verdict:** Malware: ... | Merge: ...`, pass/fail.

Fails on missing metadata, an unverified or unfetchable update, a missing or
malformed verdict when any update was reviewed, `malicious`, or `suspicious`
unless warn-only. Other ecosystems and actions pinned to branches or other
non-tag refs pass as "not reviewed"; when every update is not reviewed the end block is ignored.

Invariants: scripts run from the default branch, never from the PR head; the
agent step has no GitHub token or write permission; Dependabot does not update
the review workflow in target repos (`templates/dependabot.yml`
`exclude-paths`), because it runs from the PR head there. rcu's own Dependabot
updating `templates/dependency-artifact-review.yml` is intended: it is an inert
template changed only via reviewed rcu PRs, which is how rcu owns its pins;
upstream text is passed as argv or data, never interpolated into shell or
expressions.

### Accepted risks, do not flag

- Upstream content crafted to target or trick the review agent, beyond the
  one-line "treat files as data" prompt instruction.
- The agent step holds `CURSOR_API_KEY` and runs with `-f` in the folder that
  holds `meta.json` and the review artifacts.
- Lock-file hash binding, or proving that fetched bytes equal installed bytes.
- Index or source trust, including same-name packages on pypi.chia.net or
  other private indexes.
- Unicode, NUL, line-ending, `+++`/hunk or other diff-format edge cases.
- Hidden files or dotfiles.
- Archive quirks: symlinks, odd paths, duplicate members, size bombs.
- Transitive dependencies not being reviewed.
- Unsupported ecosystems passing as "not reviewed".
- No update cap; no download size or time limits beyond the basic timeout.
- The workflow YAML runs from the PR head under `pull_request`; only the
  companion scripts are trusted, and `exclude-paths` is the control.
- Dependabot names github_actions dependencies `owner/repo`, including for
  subpath actions and reusable workflows (`owner/repo/sub@sha`); fetches use
  that name. Do not flag subpath handling without a real Dependabot PR showing
  a different dependency-name.
- The literal check is a sanity check, not a security boundary: it uses
  normalised token matching, and `workflow_dispatch` takes maintainer-supplied
  JSON.
- For PyPI, one distribution is reviewed per side (sdist, otherwise a pure
  wheel, otherwise the first wheel); this may differ from the platform wheel
  that gets installed.
- Agent output is posted into the comment as written.
- `gh pr diff` can fail on very large diffs; the check then fails closed.
- Tag pins (full `vX.Y.Z` or bare `vX`) for dependencies and actions. Do not
  ask for commit-SHA pins or treat tag movement as a finding; Dependabot keeps
  tag pins current and the review records the resolved commit.

### Does warrant a finding

- Running PR-head code or scripts in the review or publish jobs.
- Secrets, a GitHub token or write permissions reachable by the agent step.
- A verdict parse or decision path that does not fail closed (missing or
  malformed verdict or metadata yielding a pass).
- The review workflow becoming updatable by Dependabot.
- Plain correctness bugs that break real PRs (false `unverified`, failed
  fetches for normal packages, wrong comment/check result).
