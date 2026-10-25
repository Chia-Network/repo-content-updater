# Bugbot rules

Review against the threat model and principles in [`AGENTS.md`](../AGENTS.md).
The review agent is trusted. Upstream repository and package content is
untrusted.

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
- Anything that trusts a pip change without a hash proof: an unhashed
  occurrence, a non-sha256 hash, a hash option the parser cannot fully read,
  or a hash that does not match a file downloaded from a hard-coded trusted
  index at that exact version. Repository content never adds a trusted index
  (see "Trusted package indexes" in `AGENTS.md`).
- Treating a `pip install .` or a downstream install from PyPI as covered by
  a lock hash. Only installs that consume the lock are covered.

## Do not raise

- "The review agent could lie, forge its output or tamper with artifacts."
  The agent is trusted.
- Requests for extra isolation, sealing or sandboxing whose only purpose is
  defending against the agent.
- Hypothetical cases that need write access to the default branch or to
  repository secrets.
- "A pip change whose lock hashes match files from the organization's
  package indexes is not scanned." That trust is deliberate (see "Trusted
  package indexes" in `AGENTS.md`).
- A pip change left untrusted by an unhashed occurrence, a non-sha256 hash, an
  unreadable hash option or a hash no trusted index serves is looked up and
  scanned, not left inconclusive.
