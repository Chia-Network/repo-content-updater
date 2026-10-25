# Bugbot rules

Review against the threat model and principles in [`AGENTS.md`](../AGENTS.md).
The review agent is trusted. Upstream repository and package content is
adversarial.

## Raise

- Upstream text (PR body, release notes, file contents, tag or version
  strings) reaching a prompt instruction, shell command, expression or path
  without validation or quoting.
- A path where missing, malformed or ambiguous input yields a clean or
  benign verdict or a passing check.
- Following an upstream symlink, submodule or path outside the reviewed tree,
  or letting one hide files from the scan.
- Version or tag text accepted without the ecosystem's canonical grammar.
- A second parser or decision point for something that already has a
  canonical one.
- Anything that lets repository or upstream content add a trusted package
  index, or trust a package that a listed index does not serve at that
  exact version with matching downloaded file hashes, or, for an unhashed
  occurrence, without a requirements file whose effective index replaces
  PyPI for the whole install and names no other source. Any mention of the
  package in `pyproject.toml`, `setup.py`, `setup.cfg` or `Pipfile` in the
  changed package's own directory is unhashed with no index and never makes a
  change trusted; a mention in a manifest in another directory is not part
  of the change (see "Trusted package indexes" in `AGENTS.md`).
- A trusted index replacement while a tracked file sets pip settings outside
  the requirements files the check reads: a `pip.conf` or `pip.ini`, a `PIP_*`
  index environment name, an index key in a pip config section, or a pip
  command passing an index option (see "Trusted package indexes" in
  `AGENTS.md`).

## Do not raise

- "The review agent could lie, forge its output or tamper with artifacts."
  The agent is trusted.
- Requests for extra isolation, sealing or sandboxing whose only purpose is
  defending against the agent.
- Hypothetical attacks that need write access to the default branch or to
  repository secrets.
- "Packages from the organization's configured package indexes are not
  scanned." That trust is deliberate (see "Trusted package indexes" in
  `AGENTS.md`).
- An includer whose base filename is split across a continuation or built
  from quoted pieces is not detected. That limitation is documented in
  `AGENTS.md`.
- A requirements file left unable to replace PyPI by an unreadable include, a
  symlink alias, or a size or candidate cap is looked up and scanned, not
  left inconclusive. Only an unreadable Dependabot config is inconclusive.
- A `-i` or `-f` option of a non-pip command (`sed -i`, `grep -i`, `rm -f`),
  or prose that names an index option without a pip command.
- A nox `session.install` call, a YAML-folded option on a later line, or a
  quoted exec-form option that names an index source. Those are accepted
  limits, documented in `AGENTS.md`.
