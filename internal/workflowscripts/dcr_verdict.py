"""Decide the artifact review check result and compose the PR comment.

The agent is trusted and its text is displayed as data. A missing, duplicate or
malformed verdict line is inconclusive and fails; all other facts come from the
`meta.json` that `dcr_fetch.py` wrote from validated registry and diff data.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import NamedTuple

VERDICT_PREFIX = "MALWARE_REVIEW_VERDICT:"
VERDICT_RE = re.compile(rf"^{VERDICT_PREFIX} (benign|suspicious|malicious)$")
MARKER = "<!-- dcr-artifact-review sha256:{digest} -->"
TRANSITIVE_NOTE = "Dependencies added transitively and not listed as updates are not artifact-reviewed."
MAX_AGENT_CHARS, MAX_COMMENT_CHARS = 40000, 64000
URL_RE = re.compile(r"(?i)https?://")


class Facts(NamedTuple):
    meta_ok: bool
    updates: tuple[dict[str, object], ...]
    ioc_hits: tuple[dict[str, object], ...]
    truncated: bool
    verdict: str | None
    warn_only: bool


class Decision(NamedTuple):
    conclusion: str
    reason: str


def parse_verdict(text: str) -> str | None:
    """Return the verdict only when the first line is the one valid verdict line."""
    lines = text.lstrip("\ufeff").splitlines()
    match = VERDICT_RE.fullmatch(lines[0]) if lines else None
    if not match or sum(line.strip().startswith(VERDICT_PREFIX) for line in lines) != 1:
        return None
    return match.group(1)


def decide(facts: Facts) -> Decision:
    """Return the first matching row of the decision table."""
    statuses = {update.get("status") for update in facts.updates}
    checks = (
        (not facts.meta_ok, "metadata is missing or malformed"),
        (facts.truncated, "the review diff was truncated"),
        (bool(facts.ioc_hits), "a deterministic pattern matched"),
        (facts.verdict == "malicious", "the agent verdict is malicious"),
        (not statuses <= {"reviewed", "not_reviewed"}, "an update was not reviewed to completion"),
        (not facts.updates, "the PR listed no updates"),
    )
    for failed, reason in checks:
        if failed:
            return Decision("failure", reason)
    if statuses == {"not_reviewed"}:
        return Decision("success", "all updates are not reviewed (outside the reviewed ecosystems)")
    if facts.verdict is None:
        return Decision("failure", "no valid verdict line")
    if facts.verdict == "suspicious" and not facts.warn_only:
        return Decision("failure", "the agent verdict is suspicious")
    if facts.verdict not in {"benign", "suspicious"}:
        return Decision("failure", "the review state was not recognized")
    suffix = " (warn only)" if facts.verdict == "suspicious" else ""
    return Decision("success", f"the agent verdict is {facts.verdict}{suffix}")


def _neutralize(text: str) -> str:
    text = text.replace("\x00", "").replace("@", "@\u200b").replace("](", "]\u200b(")
    return URL_RE.sub(lambda match: match.group(0).replace(":", ":\u200b"), text)


def _escape_details(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _inline(value: object) -> str:
    text = _neutralize(str(value)).replace("\n", " ")[:200].replace("`", "'")
    return f"`{text}`"


def _update_line(update: dict[str, object]) -> str:
    name, old, new = (update.get(key, "") for key in ("name", "prev_version", "new_version"))
    line = f"- {_inline(name)} {_inline(old)} -> {_inline(new)}: {_inline(update.get('status', 'unknown'))}"
    if update.get("status") == "reviewed" and update.get("bound") is False:
        line += " (not bound to the lockfile)"
    note = update.get("note")
    return line + (f" - {_inline(note)}" if isinstance(note, str) and note else "")


def comment_body(marker: str, facts: Facts, decision: Decision, agent_text: str) -> str:
    """Build the bounded PR comment, with agent text in a collapsed block."""
    parts = [marker, "## Dependency Artifact Review"]
    parts.append(f"**Result:** {decision.conclusion}\n**Reason:** {decision.reason}")
    if facts.updates:
        parts.append("### Updates\n" + "\n".join(map(_update_line, facts.updates)))
    parts.append(TRANSITIVE_NOTE)
    if facts.ioc_hits:
        hits = "\n".join(f"- {_inline(h.get('kind', ''))}: {_inline(h.get('pattern', ''))}" for h in facts.ioc_hits)
        parts.append("### Deterministic findings\n" + hits)
    if agent_text:
        agent = _escape_details(_neutralize(agent_text))
        if len(agent) > MAX_AGENT_CHARS:
            agent = agent[:MAX_AGENT_CHARS].rstrip() + "\n\n[Agent output truncated.]"
        parts.append(f"<details>\n<summary>Agent review</summary>\n\n{agent}\n\n</details>")
    body = "\n\n".join(parts) + "\n"
    if len(body) > MAX_COMMENT_CHARS:
        body = body[:MAX_COMMENT_CHARS].rstrip() + "\n\n[Comment truncated.]\n"
    return body


def _read(path: str) -> bytes:
    try:
        return Path(path).read_bytes()
    except OSError:
        return b""


def _write(path: str, text: str, mode: str = "w") -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open(mode, encoding="utf-8") as handle:
        handle.write(text)


def _parse_meta(raw: bytes) -> tuple[tuple[dict[str, object], ...], tuple[dict[str, object], ...], bool] | None:
    """Return validated updates, IOC hits and the truncation flag, or None."""
    try:
        meta = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(meta, dict) or type(meta.get("schema")) is not int or meta["schema"] != 1:
        return None
    if "ioc_hits" not in meta or "truncated" not in meta or "updates" not in meta:
        return None
    updates, hits = meta["updates"], meta["ioc_hits"]
    if not isinstance(updates, list) or not isinstance(hits, list):
        return None
    if not all(isinstance(item, dict) for item in (*updates, *hits)):
        return None
    truncated = bool(meta["truncated"]) or any(update.get("status") == "truncated" for update in updates)
    return tuple(updates), tuple(hits), truncated


def comment_digest(meta_bytes: bytes, decision: Decision, agent_text: str) -> str:
    """Hash the metadata, decision and agent output that shaped the comment."""
    payload = {
        "meta": hashlib.sha256(meta_bytes).hexdigest(),
        "conclusion": decision.conclusion,
        "reason": decision.reason,
        "agent": hashlib.sha256(agent_text.encode("utf-8", "replace")).hexdigest(),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def main() -> int:
    """Read meta.json and agent output, then write the comment and verdict."""
    try:
        meta_bytes = Path(os.environ.get("DCR_META", "meta.json")).read_bytes()
    except OSError:
        meta_bytes = b""
    parsed = _parse_meta(meta_bytes)
    agent = _read(os.environ.get("DCR_AGENT_OUTPUT", "agent_output.txt")).decode("utf-8", "replace")
    warn_only = os.environ.get("MALWARE_WARN_ONLY", "").strip().lower() in {"1", "true", "yes", "on"}
    updates, hits, truncated = parsed if parsed else ((), (), False)
    facts = Facts(parsed is not None, updates, hits, truncated, parse_verdict(agent), warn_only)
    decision = decide(facts)
    marker = MARKER.format(digest=comment_digest(meta_bytes, decision, agent))
    _write(os.environ.get("DCR_COMMENT", "comment.md"), comment_body(marker, facts, decision, agent))
    payload = {"conclusion": decision.conclusion, "reason": decision.reason, "marker": marker}
    _write(os.environ.get("DCR_VERDICT_JSON", "verdict.json"), json.dumps(payload, indent=2, sort_keys=True) + "\n")
    if output := os.environ.get("GITHUB_OUTPUT"):
        _write(output, f"conclusion={decision.conclusion}\nmarker={marker}\n", "a")
    print(f"conclusion={decision.conclusion}\nreason={decision.reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
