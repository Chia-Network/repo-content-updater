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

## Do not raise

- "The review agent could lie, forge its output or tamper with artifacts."
  The agent is trusted.
- Requests for extra isolation, sealing or sandboxing whose only purpose is
  defending against the agent.
- Hypothetical attacks that need write access to the default branch or to
  repository secrets.
