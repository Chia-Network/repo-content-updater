"""Decide the artifact review check result and compose the PR comment.

The agent is trusted; its text is displayed as data. The verdict line is the
only machine-readable part of the agent output. Every other input is read from
`meta.json`, which `dcr_fetch.py` wrote from validated registry and diff data.

A missing, duplicate or malformed verdict line is inconclusive and fails. The
decision table below is the single place that maps facts to a conclusion.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

VERDICT_RE = re.compile(r"^MALWARE_REVIEW_VERDICT: (benign|suspicious|malicious)$")
VERDICT_PREFIX = "MALWARE_REVIEW_VERDICT:"
MARKER = "<!-- dcr-artifact-review sha256:{digest} -->"
MAX_AGENT_CHARS = 40000
MAX_COMMENT_CHARS = 64000
REVIEWED_STATUSES = frozenset({"reviewed", "not_reviewed"})
URL_RE = re.compile(r"(?i)https?://")


def parse_verdict(text: str) -> str | None:
    """Return the verdict only when the first line is the one valid verdict line."""
    lines = text.lstrip("\ufeff").splitlines() if text else []
    if not lines:
        return None
    exact = [line for line in lines if VERDICT_RE.fullmatch(line)]
    prefixed = [line for line in lines if line.strip().startswith(VERDICT_PREFIX)]
    if not VERDICT_RE.fullmatch(lines[0]) or len(exact) != 1 or len(prefixed) != 1:
        return None
    return exact[0].split(": ", 1)[1]


@dataclass(frozen=True)
class Facts:
    """The facts the decision table reads for one review."""

    meta_ok: bool
    updates: tuple[dict[str, object], ...]
    ioc_hits: tuple[dict[str, object], ...]
    truncated: bool
    verdict: str | None
    warn_only: bool


@dataclass(frozen=True)
class Decision:
    """A conclusion plus the reason shown in the comment."""

    conclusion: str
    reason: str


@dataclass(frozen=True)
class Rule:
    """One row of the decision table."""

    reason: str
    conclusion: str
    test: Callable[[Facts], bool]


def _blocking_update(facts: Facts) -> bool:
    return any(update.get("status") not in REVIEWED_STATUSES for update in facts.updates)


def _all_not_reviewed(facts: Facts) -> bool:
    return bool(facts.updates) and all(update.get("status") == "not_reviewed" for update in facts.updates)


RULES: tuple[Rule, ...] = (
    Rule("metadata is missing or malformed", "failure", lambda facts: not facts.meta_ok),
    Rule("the review diff was truncated", "failure", lambda facts: facts.truncated),
    Rule("a deterministic pattern matched", "failure", lambda facts: bool(facts.ioc_hits)),
    Rule("the agent verdict is malicious", "failure", lambda facts: facts.verdict == "malicious"),
    Rule("no valid verdict line", "failure", lambda facts: facts.verdict is None),
    Rule("an update was not reviewed to completion", "failure", _blocking_update),
    Rule("the PR listed no updates", "failure", lambda facts: not facts.updates),
    Rule(
        "the agent verdict is suspicious",
        "failure",
        lambda facts: facts.verdict == "suspicious" and not facts.warn_only,
    ),
    Rule("all updates are not reviewed (outside the reviewed ecosystems)", "success", _all_not_reviewed),
    Rule("the agent verdict is suspicious (warn only)", "success", lambda facts: facts.verdict == "suspicious"),
    Rule("the agent verdict is benign", "success", lambda facts: facts.verdict == "benign"),
)


def _facts(meta: dict[str, object] | None, verdict: str | None, warn_only: bool) -> Facts:
    if meta is None:
        return Facts(False, (), (), False, verdict, warn_only)
    raw_updates = meta.get("updates")
    raw_hits = meta.get("ioc_hits", [])
    if not isinstance(raw_updates, list) or not all(isinstance(item, dict) for item in raw_updates):
        return Facts(False, (), (), False, verdict, warn_only)
    if not isinstance(raw_hits, list) or not all(isinstance(item, dict) for item in raw_hits):
        return Facts(False, (), (), False, verdict, warn_only)
    updates = tuple(raw_updates)
    truncated = bool(meta.get("truncated")) or any(update.get("status") == "truncated" for update in updates)
    return Facts(True, updates, tuple(raw_hits), truncated, verdict, warn_only)


def decide(facts: Facts) -> Decision:
    """Return the first matching row of the decision table."""
    for rule in RULES:
        if rule.test(facts):
            return Decision(rule.conclusion, rule.reason)
    return Decision("failure", "the review state was not recognized")


def _neutralize(text: str) -> str:
    """Keep agent text inert: no mentions, autolinks, nested details or markers."""
    text = text.replace("\x00", "")
    text = text.replace("@", "@\u200b")
    text = URL_RE.sub(lambda match: match.group(0).replace(":", ":\u200b"), text)
    text = text.replace("](", "]\u200b(")
    text = text.replace("<details>", "&lt;details&gt;")
    text = text.replace("</details>", "&lt;/details&gt;")
    return text.replace("<!--", "&lt;!--")


def _inline(value: object) -> str:
    text = _neutralize(str(value)).replace("\n", " ")[:200].replace("`", "'")
    return f"`{text}`"


def _bounded(text: str) -> str:
    if len(text) <= MAX_AGENT_CHARS:
        return text
    return text[:MAX_AGENT_CHARS].rstrip() + "\n\n[Agent output truncated.]"


def _update_line(update: dict[str, object]) -> str:
    line = (
        f"- {_inline(update.get('name', ''))} "
        f"{_inline(update.get('prev_version', ''))} -> {_inline(update.get('new_version', ''))}: "
        f"{_inline(update.get('status', 'unknown'))}"
    )
    if update.get("status") == "reviewed" and update.get("bound") is False:
        line += " (not bound to the lockfile)"
    note = update.get("note")
    if isinstance(note, str) and note:
        line += f" - {_neutralize(note)[:300]}"
    return line


def comment_body(marker: str, facts: Facts, decision: Decision, agent_text: str) -> str:
    """Build the bounded PR comment, with agent text in a collapsed block."""
    lines = [
        marker,
        "## Dependency Artifact Review",
        "",
        f"**Result:** {decision.conclusion}",
        f"**Reason:** {decision.reason}",
        "",
    ]
    if facts.updates:
        lines += ["### Updates", *(_update_line(update) for update in facts.updates), ""]
    if facts.ioc_hits:
        lines.append("### Deterministic findings")
        for hit in facts.ioc_hits:
            lines.append(f"- {_inline(hit.get('kind', ''))}: {_inline(hit.get('pattern', ''))}")
        lines.append("")
    lines += [
        "<details>",
        "<summary>Agent review</summary>",
        "",
        _bounded(_neutralize(agent_text)),
        "",
        "</details>",
        "",
    ]
    body = "\n".join(lines)
    if len(body) > MAX_COMMENT_CHARS:
        body = body[:MAX_COMMENT_CHARS].rstrip() + "\n\n[Comment truncated.]\n"
    return body


def _read_bytes(path: str) -> bytes:
    try:
        return Path(path).read_bytes()
    except OSError:
        return b""


def _read_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _parse_meta(raw: bytes) -> dict[str, object] | None:
    if not raw:
        return None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _warn_only() -> bool:
    return os.environ.get("MALWARE_WARN_ONLY", "").strip().lower() in {"1", "true", "yes", "on"}


def _write_github_output(decision: Decision, marker: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with Path(path).open("a", encoding="utf-8") as handle:
        handle.write(f"conclusion={decision.conclusion}\n")
        handle.write(f"marker={marker}\n")


def main() -> int:
    """Read meta.json and agent output, then write the comment and verdict."""
    meta_bytes = _read_bytes(os.environ.get("DCR_META", "meta.json"))
    meta = _parse_meta(meta_bytes)
    agent_text = _read_text(os.environ.get("DCR_AGENT_OUTPUT", "agent_output.txt"))
    verdict = parse_verdict(agent_text)
    facts = _facts(meta, verdict, _warn_only())
    decision = decide(facts)
    marker = MARKER.format(digest=hashlib.sha256(meta_bytes).hexdigest())
    body = comment_body(marker, facts, decision, agent_text)

    comment_path = Path(os.environ.get("DCR_COMMENT", "comment.md"))
    comment_path.parent.mkdir(parents=True, exist_ok=True)
    comment_path.write_text(body, encoding="utf-8")
    verdict_path = Path(os.environ.get("DCR_VERDICT_JSON", "verdict.json"))
    verdict_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"conclusion": decision.conclusion, "reason": decision.reason, "marker": marker}
    verdict_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_github_output(decision, marker)
    print(f"conclusion={decision.conclusion}")
    print(f"reason={decision.reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
