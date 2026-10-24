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

## Trusted package indexes

This is a deliberate decision: **packages from the organization's
configured package indexes are trusted and are not scanned.** The indexes
are listed only in `TRUSTED_PYTHON_INDEXES` in
`internal/workflowscripts/dependency_cursor_review_upstream.py`.

- A repository's Dependabot config can select among the listed indexes. It
  cannot add one. A config naming any other Python index, or one the
  scripts cannot read, leaves every pip change inconclusive.
- A requirements file's `--index-url`, `-i` and `--extra-index-url` options
  select indexes the same way for the pip changes in its directory, along
  with the files it includes. Any other index, `--find-links`, `--no-index`,
  an option filled from the environment, or an include outside the
  repository leaves those changes inconclusive.
- pip configuration outside the repository, such as `pip.conf` or
  `PIP_INDEX_URL`, is out of scope: the review reads only the pull request's
  tree.
- A pip change is trusted only when a listed, configured index serves that
  exact version and either every file hash its lock records matches a file
  downloaded from that index's own links, or the lock records no hashes and
  that index replaces PyPI for the change's directory. Otherwise it is
  looked up and scanned as usual.
- Trusted changes are disclosed in the review summary. They never block,
  and they are not counted as scanned.
- Do not "fix" this by scanning or blocking these packages. Changing the
  list or this rule needs the maintainers' explicit sign-off.
