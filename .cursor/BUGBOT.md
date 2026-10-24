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
  pin, with an index that replaces PyPI (see "Trusted package indexes" in
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
