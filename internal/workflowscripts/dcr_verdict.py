from __future__ import annotations

import json
import os
import re
from pathlib import Path

VERDICT_RE = re.compile(r"^MALWARE_REVIEW_VERDICT: (benign|suspicious|malicious)$")
MARKER = "<!-- dcr-artifact-review -->"
TRANSITIVE_NOTE = "Dependencies added transitively and not listed as updates are not artifact-reviewed."
MAX_COMMENT_CHARS = 65536


def parse_verdict(text: str) -> str | None:
    lines = text.lstrip("\ufeff").splitlines()
    match = VERDICT_RE.fullmatch(lines[0]) if lines else None
    return match.group(1) if match else None


def decide(
    meta_ok: bool, updates: tuple[dict[str, object], ...], verdict: str | None, warn_only: bool
) -> tuple[str, str]:
    statuses = {update.get("status") for update in updates}
    if not meta_ok:
        return ("failure", "metadata is missing or malformed")
    if not statuses <= {"reviewed", "not_reviewed"}:
        return ("failure", "an update was not reviewed to completion")
    if not updates:
        return ("failure", "the PR listed no updates")
    if statuses == {"not_reviewed"}:
        return ("success", "all updates are not reviewed (outside the reviewed ecosystems)")
    if verdict is None:
        return ("failure", "no valid verdict line")
    if verdict == "malicious":
        return ("failure", "the agent verdict is malicious")
    if verdict == "suspicious" and not warn_only:
        return ("failure", "the agent verdict is suspicious")
    suffix = " (warn only)" if verdict == "suspicious" else ""
    return ("success", f"the agent verdict is {verdict}{suffix}")


def _update_line(update: dict[str, object]) -> str:
    name, old, new = (update.get(key, "") for key in ("name", "prev_version", "new_version"))
    note = update.get("note")
    line = f"- `{name}` {old} -> {new}: {update.get('status', 'unknown')}"
    return line + (f" - {note}" if isinstance(note, str) and note else "")


def comment_body(updates: tuple[dict[str, object], ...], decision: tuple[str, str], agent_text: str) -> str:
    parts = [MARKER, "## Dependency Artifact Review"]
    parts.append(f"**Result:** {decision[0]}\n**Reason:** {decision[1]}")
    if updates:
        parts.append("### Updates\n" + "\n".join(map(_update_line, updates)))
    parts.append(TRANSITIVE_NOTE)
    if agent_text:
        parts.append(f"<details>\n<summary>Agent review</summary>\n\n{agent_text}\n\n</details>")
    body = "\n\n".join(parts) + "\n"
    return body[:MAX_COMMENT_CHARS]


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
    decision = decide(updates is not None, items, parse_verdict(agent), warn_only)
    comment = os.environ.get("DCR_COMMENT", "comment.md")
    Path(comment).write_text(comment_body(items, decision, agent), encoding="utf-8")
    if output := os.environ.get("GITHUB_OUTPUT"):
        with Path(output).open("a", encoding="utf-8") as handle:
            handle.write(f"conclusion={decision[0]}\n")
    print(f"conclusion={decision[0]}\nreason={decision[1]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
