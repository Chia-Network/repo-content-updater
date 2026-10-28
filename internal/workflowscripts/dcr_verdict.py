from __future__ import annotations

import json
import os
import re
from pathlib import Path

VERDICT_RE = re.compile(r"^MALWARE_REVIEW_VERDICT: (benign|suspicious|malicious)$")
RECOMMENDATION_RE = re.compile(r"^COMPATIBILITY_RECOMMENDATION: (Merge|Don't merge)$")
MARKER = "<!-- dcr-artifact-review -->"
TRANSITIVE_NOTE = "Dependencies added transitively and not listed as updates are not artifact-reviewed."
MAX_COMMENT_CHARS = 65536


def parse_verdict(text: str) -> str | None:
    lines = text.lstrip("\ufeff").splitlines()
    match = VERDICT_RE.fullmatch(lines[0]) if lines else None
    return match.group(1) if match else None


def parse_recommendation(text: str) -> str:
    lines = text.lstrip("\ufeff").splitlines()
    matches = [line for line in lines if RECOMMENDATION_RE.fullmatch(line)]
    if len(matches) == 1 and matches[0] == "COMPATIBILITY_RECOMMENDATION: Merge":
        return "Merge"
    return "Don't merge"


def _statuses(updates: tuple[dict[str, object], ...]) -> set[object]:
    return {update.get("status") for update in updates}


def all_updates_not_reviewed(updates: tuple[dict[str, object], ...]) -> bool:
    return bool(updates) and _statuses(updates) == {"not_reviewed"}


def decide(
    meta_ok: bool, updates: tuple[dict[str, object], ...], verdict: str | None, warn_only: bool
) -> tuple[str, str]:
    statuses = _statuses(updates)
    if not meta_ok:
        return ("failure", "metadata is missing or malformed")
    if not statuses <= {"reviewed", "not_reviewed"}:
        return ("failure", "an update was not reviewed to completion")
    if not updates:
        return ("failure", "the PR listed no updates")
    if all_updates_not_reviewed(updates):
        return ("success", "all updates are not reviewed (outside the reviewed ecosystems)")
    if verdict is None:
        return ("failure", "no valid verdict line")
    if verdict == "malicious":
        return ("failure", "the agent verdict is malicious")
    if verdict == "suspicious" and not warn_only:
        return ("failure", "the agent verdict is suspicious")
    suffix = " (warn only)" if verdict == "suspicious" else ""
    return ("success", f"the agent verdict is {verdict}{suffix}")


def display_verdict(updates: tuple[dict[str, object], ...], verdict: str | None, conclusion: str) -> str:
    if conclusion == "success" and all_updates_not_reviewed(updates):
        return "not reviewed"
    return verdict or "unknown"


def merge_verdict(conclusion: str, malware_verdict: str, recommendation: str) -> str:
    if conclusion == "success" and malware_verdict == "not reviewed":
        return "not assessed"
    if conclusion == "success" and malware_verdict == "benign" and recommendation == "Merge":
        return "Merge"
    return "Don't merge"


def _update_line(update: dict[str, object]) -> str:
    name, old, new = (update.get(key, "") for key in ("name", "prev_version", "new_version"))
    note = update.get("note")
    line = f"- `{name}` {old} -> {new}: {update.get('status', 'unknown')}"
    return line + (f" - {note}" if isinstance(note, str) and note else "")


def _message_body(updates: tuple[dict[str, object], ...], decision: tuple[str, str]) -> str:
    parts = [MARKER, "## Dependency Artifact Review"]
    parts.append(f"**Result:** {decision[0]}\n**Reason:** {decision[1]}")
    if updates:
        parts.append("### Updates\n" + "\n".join(map(_update_line, updates)))
    parts.append(TRANSITIVE_NOTE)
    return "\n\n".join(parts)


def comment_body(
    updates: tuple[dict[str, object], ...],
    decision: tuple[str, str],
    agent_text: str,
    malware_verdict: str,
    merge: str,
) -> str:
    head = _message_body(updates, decision)
    verdict_line = f"**Verdict:** Malware: {malware_verdict} | Merge: {merge}"
    tail = f"\n\n{verdict_line}\n"
    if not agent_text:
        return head + tail

    open_details = "\n\n<details>\n<summary>Agent review</summary>\n\n"
    close_details = "\n\n</details>"
    note = "\n\n[agent output truncated]"
    budget = MAX_COMMENT_CHARS - len(head) - len(open_details) - len(close_details) - len(tail)
    if budget <= 0:
        return head + tail
    if len(agent_text) > budget:
        close_fence = "\n```"
        if budget <= len(note) + len(close_fence):
            return head + tail
        agent_text = agent_text[: budget - len(note) - len(close_fence)]
        if sum(line.startswith("```") for line in agent_text.splitlines()) % 2:
            agent_text += close_fence
        agent_text += note
    return head + open_details + agent_text + close_details + tail


def main() -> int:
    try:
        raw = Path(os.environ.get("DCR_META", "meta.json")).read_bytes()
    except OSError:
        raw = b""
    try:
        updates = json.loads(raw).get("updates")
    except (json.JSONDecodeError, UnicodeDecodeError, AttributeError):
        updates = None
    if not isinstance(updates, list) or not all(isinstance(item, dict) for item in updates):
        updates = None
    try:
        agent = Path(os.environ.get("DCR_AGENT_OUTPUT", "agent_output.txt")).read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError:
        agent = ""
    warn_only = os.environ.get("MALWARE_WARN_ONLY", "").strip().lower() in {"1", "true", "yes", "on"}
    items = tuple(updates or ())
    verdict = parse_verdict(agent)
    recommendation = parse_recommendation(agent)
    decision = decide(updates is not None, items, verdict, warn_only)
    malware = display_verdict(items, verdict, decision[0])
    merge = merge_verdict(decision[0], malware, recommendation)
    comment = os.environ.get("DCR_COMMENT", "comment.md")
    Path(comment).write_text(comment_body(items, decision, agent, malware, merge), encoding="utf-8")
    if output := os.environ.get("GITHUB_OUTPUT"):
        with Path(output).open("a", encoding="utf-8") as handle:
            handle.write(f"conclusion={decision[0]}\nmerge_verdict={merge}\n")
    print(f"conclusion={decision[0]}\nreason={decision[1]}\nmerge_verdict={merge}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
