# Agent instructions

## Threat model for the dependency review workflows

The dependency review templates and `internal/workflowscripts/` run an AI
review agent on Dependabot and Renovate pull requests.

- **The review agent we invoke is trusted.** It is honest, and it is not an
  adversary. Do not add defenses against it lying, tampering with its own
  outputs, or interfering with the workflow.
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

This is a deliberate decision: **a pip change is trusted and not scanned only
when its lock hashes prove the installed files come from the organization's
package indexes.** The indexes are listed only in
`TRUSTED_PYTHON_INDEXES` in
`internal/workflowscripts/dependency_cursor_review_upstream.py`.

- A pip change is trusted only when its name matches `_PYPI_NAME_RE`, its new
  version is at that version (compared in PEP 440 canonical form), every
  occurrence of that name in each lock beside the change and each changed
  hashed requirements file records hashes (a hashed requirements line, a
  poetry.lock `files` entry or a Pipfile.lock entry), and every recorded hash
  is `sha256:` and equals the sha256 of a file downloaded from a hard-coded
  trusted index for that version.
- A lock entry is hashed only from a poetry legacy source, a poetry url source
  with files, or a Pipfile index. Any other source is unhashed and scanned.
- The code downloads and hashes each file itself. A hash fragment on an index
  page is not accepted in place of the downloaded bytes.
- Each package check has its own time and byte limits for the index page and
  its files. A grouped update runs one check per package, so it can take up to
  N times those limits.
- Anything else is looked up and scanned exactly as on `main`: an unhashed
  occurrence, a non-sha256 algorithm, a hash option the parser cannot fully
  read, a hash no trusted index serves, or an index page that cannot be read.
- Only installs that consume the lock are covered. A `pip install .` or a
  downstream install from PyPI does not read those hashes, so those installs
  are not covered.
- Trusted changes are disclosed in the review summary. They never block, and
  they are not counted as scanned.
- Do not add an unhashed trust path. Changing the list or this rule needs the
  maintainers' explicit sign-off.
