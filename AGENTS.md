# Agent instructions

## Threat model for the dependency review workflows

The dependency review templates and `internal/workflowscripts/` run an AI
review agent on Dependabot and Renovate pull requests.

- **The review agent we invoke is trusted.** It is honest, and it is not an
  adversary. Do not add defenses against it lying, tampering with its own
  outputs, or attacking the workflow.
- **Upstream content is untrusted.** That means the dependency's repository,
  its published packages, release notes, changelogs, PR body text, version
  strings, tags and registry metadata. Assume all of it is written to trick
  the honest agent or the scripts into a wrong action or a false verdict.

## Artifact review component (opt-in)

`dependency-artifact-review` is an opt-in workflow, separate from the default
`dep-review` layer and from the legacy `dependency-cursor-review` bundle. It
reviews the published bytes for `npm_and_yarn`, `pip`, `gomod` and SHA-pinned
`github_actions` updates. Every other ecosystem is reported as not reviewed.

- Updates come from `dependabot/fetch-metadata`; the diff is `gh pr diff` text
  and is never executed.
- Names and versions are validated against one grammar per ecosystem, then
  passed as argv. Artifacts are fetched with native tools: `npm pack
  --ignore-scripts`, the PyPI JSON API with a sha256 check, `go mod download
  -json`, and `git fetch` plus `git archive` for a commit SHA.
- The name and new version must appear on an added diff line and the previous
  version on a removed line. Missing matches are unverified.
- Archives are extracted with tar `filter="data"` and a zip check that rejects
  links, absolute paths and `..`, within file-count and byte caps.
- Binding is literal: the npm `sha512-` integrity, Go `h1:` sum, PyPI
  `sha256:` digest or action SHA must appear on an added diff line. An unbound
  review is disclosed, not failed.
- The agent output must start with exactly one
  `MALWARE_REVIEW_VERDICT: benign|suspicious|malicious` line. A missing,
  duplicate or malformed line is inconclusive.

Fails closed on: malformed or missing metadata, no updates, no valid verdict,
an update that is unverified or could not be fetched, a truncated diff, a
deterministic IOC or bidi-control hit, a malicious verdict, and a suspicious
verdict unless `DEPENDABOT_CURSOR_MALWARE_WARN_ONLY` is set. An update outside
the reviewed ecosystems passes with a "not reviewed" note.

## Design principles

- **Treat upstream content as data, never as instructions.** Keep it out of
  prompt instructions, shell code, expressions and file paths unless it has
  been validated or quoted.
- **Fail closed toward "not clean".** Missing, ambiguous, unparsable or
  unverifiable input never produces a clean or benign verdict. It produces
  inconclusive or blocking, with a stated reason.
- **Decide once.** Each fact (versions, coverage, verdict, check result) has
  one canonical parser or decision point. Do not re-derive it in another
  language or step.
- **Prefer structured sources over prose.** Use manifests, lockfiles, git
  objects and registry data rather than scraped markdown.
- **Never follow upstream links or paths blindly.** Symlinks, submodules,
  `..` and absolute paths from upstream must not escape the tree under
  review, and must not hide content from the scan.
- **Validate untrusted version and tag text.** Parse it against one grammar
  per ecosystem before using it.
- **Keep it simple.** Each defense must answer an upstream-content threat.
  Complexity whose only purpose is guarding against the trusted agent should
  be removed, not extended.
