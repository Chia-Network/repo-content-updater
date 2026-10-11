"""Merge Cursor malware + compatibility JSON outputs; format malware verdict via trusted loader.

When this file runs from the trusted-dcr-scripts checkout, the malware scan
report must already sit at the root of that tree and TRUSTED_DCR_SCRIPTS_SHA256
must be the pre-agent sha256sum manifest of the tree. A mismatch or a missing
report fails closed. The workspace copy is ignored.
"""

from __future__ import annotations

import hashlib
import json
import os
import runpy
import sys
from pathlib import Path

_INSTALL = Path(__file__).resolve().parent
# The running script's directory is the trusted checkout (runner temp). Prefer it
# over the PR workspace .github/scripts so a PR-head formatter cannot win.
_SCRIPT_CANDIDATES = (
    _INSTALL,
    Path(".github/scripts"),
    Path("internal/workflowscripts"),
)
_COLD_START_PATH = _INSTALL / "trusted_formatter_loader_cold_start.py"


def _drop_pr_head_scripts_from_sys_path() -> None:
    """Keep the PR checkout's .github/scripts off sys.path.

    Trusted modules load by file path from this script's directory. A PR-head
    directory on sys.path can shadow stdlib (dataclasses, json) in the step
    that has CURSOR_API_KEY.
    """
    workspace_scripts = (Path.cwd() / ".github" / "scripts").resolve()
    if workspace_scripts == _INSTALL.resolve():
        return
    kept: list[str] = []
    for entry in sys.path:
        if not entry:
            kept.append(entry)
            continue
        try:
            resolved = Path(entry).resolve()
        except OSError:
            kept.append(entry)
            continue
        if resolved == workspace_scripts:
            continue
        kept.append(entry)
    sys.path[:] = kept


def _host_namespace() -> dict[str, object]:
    """Canonical python3 -I host entry (no sibling imports)."""
    return runpy.run_path(str(_COLD_START_PATH))


def _load_any(path: str) -> dict:
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return {"result": f"Missing output file: {path}"}
    try:
        return json.loads(raw)
    except Exception:
        return {"result": raw}


def _successful_analysis_text(path: str) -> str:
    """Non-empty analysis text from a successful agent JSON result, or ''."""
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""
    if not raw.strip():
        return ""
    try:
        payload = json.loads(raw)
    except Exception:
        return ""
    if not isinstance(payload, dict) or payload.get("error") or payload.get("is_error") is True:
        return ""
    for key in ("result", "output", "text", "message"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip() and not value.startswith("Missing output file:"):
            if value.startswith("Error: agent exited"):
                return ""
            return value.strip()
    return ""


def _extract_text(payload) -> str:
    if not isinstance(payload, dict):
        try:
            return json.dumps(payload, indent=2)
        except Exception:
            return str(payload)
    for key in ("result", "output", "text", "message"):
        val = payload.get(key)
        if isinstance(val, str) and val.strip():
            return val
    try:
        return json.dumps(payload, indent=2)
    except Exception:
        return str(payload)


_INCONCLUSIVE_HEADER = "**Verdict: inconclusive (needs human review)**"
_KNOWN_VERDICT_HEADERS = (
    "**Verdict: benign**",
    "**Verdict: malicious**",
    _INCONCLUSIVE_HEADER,
)
_TRUSTED_CHECKOUT_DIR = "trusted-dcr-scripts"
_TRUSTED_HASH_ENV = "TRUSTED_DCR_SCRIPTS_SHA256"
_SCAN_REPORT_NAME = "malware_scan_report.json"


def trusted_tree_manifest(root: Path) -> str:
    """sha256sum listing of regular files under root, without a trailing newline.

    Matches `find "$root" -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum`
    after command substitution strips the final newline. That is the workflow
    snapshot stored in TRUSTED_DCR_SCRIPTS_SHA256 before the agents run.
    """
    manifest, _files = _trusted_tree_snapshot(root)
    return manifest


def _trusted_tree_snapshot(root: Path) -> tuple[str, dict[str, bytes]]:
    """Manifest plus the bytes hashed for each relative path."""
    root = root.resolve()
    entries: list[tuple[bytes, str, bytes]] = []
    for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
        for name in filenames:
            path = Path(dirpath) / name
            if path.is_symlink() or not path.is_file():
                continue
            data = path.read_bytes()
            rel = path.relative_to(root).as_posix()
            entries.append((os.fsencode(path), rel, data))
    entries.sort(key=lambda item: item[0])
    lines: list[str] = []
    files: dict[str, bytes] = {}
    for encoded, rel, data in entries:
        digest = hashlib.sha256(data).hexdigest()
        lines.append(f"{digest}  {os.fsdecode(encoded)}")
        files[rel] = data
    return "\n".join(lines), files


def _trusted_checkout_root() -> Path | None:
    """Production layout is <trusted-dcr-scripts>/.github/scripts/<this file>."""
    script = Path(__file__).resolve()
    if script.parent.name != "scripts" or script.parent.parent.name != ".github":
        return None
    root = script.parents[2]
    if root.name != _TRUSTED_CHECKOUT_DIR:
        return None
    return root


def _report_forces_inconclusive(report: object) -> bool:
    if not isinstance(report, dict):
        return True
    if report.get("status") == "not_scanned":
        return True
    if report.get("scan_conclusive") is not True:
        return True
    return report.get("verdict_token_in_tree") is True


def _bytes_force_inconclusive(data: bytes) -> bool:
    try:
        report = json.loads(data.decode("utf-8"))
    except Exception:
        return True
    return _report_forces_inconclusive(report)


def _scan_forces_inconclusive(path: Path | None = None) -> bool:
    """Missing, unscanned, or tree-spoofed scanner reports cannot publish a verdict."""
    report_path = path or Path(_SCAN_REPORT_NAME)
    if not report_path.is_file():
        return True
    try:
        data = report_path.read_bytes()
    except OSError:
        return True
    return _bytes_force_inconclusive(data)


def _fail_closed(message: str) -> None:
    print(message, file=sys.stderr)
    sys.exit(1)


def _scan_gate_forces_inconclusive() -> bool:
    """Fail closed unless the pre-agent trusted-tree hash still matches.

    Unit tests that omit the freeze env and are not the trusted checkout keep
    the workspace-file gate. A freeze env outside that checkout cannot fall
    open onto the workspace report.
    """
    root = _trusted_checkout_root()
    expected = os.environ.get(_TRUSTED_HASH_ENV, "").rstrip("\n")
    if root is None and not expected:
        return _scan_forces_inconclusive()
    if root is None:
        _fail_closed("Trusted scan report checkout is missing before combine.")
    if not expected:
        _fail_closed("Trusted scan report hash missing before combine.")
    manifest, files = _trusted_tree_snapshot(root)
    if manifest != expected:
        _fail_closed("Trusted review scripts changed before combine.")
    report_bytes = files.get(_SCAN_REPORT_NAME)
    if report_bytes is None:
        _fail_closed("Malware scan report missing from trusted checkout.")
    return _bytes_force_inconclusive(report_bytes)


def _force_inconclusive_header(text: str) -> str:
    body = text
    for header in _KNOWN_VERDICT_HEADERS:
        prefix = header + "\n\n"
        if body.startswith(prefix):
            body = body[len(prefix) :]
            break
    return f"{_INCONCLUSIVE_HEADER}\n\n{body}"


def main() -> None:
    _drop_pr_head_scripts_from_sys_path()
    # Verify the frozen tree before loading any sibling module from it.
    force_inconclusive = _scan_gate_forces_inconclusive()
    ns = _host_namespace()
    resolve_loader_bundle = ns["resolve_loader_bundle"]
    loader, script_dir = resolve_loader_bundle(_SCRIPT_CANDIDATES)
    format_malware_review_verdict = loader.find_and_load_format_malware_review_verdict(script_dir)

    malware_payload = _load_any("cursor_output_malware.json")
    compatibility_payload = _load_any("cursor_output_compatibility.json")
    malware_text = format_malware_review_verdict(_extract_text(malware_payload))
    if force_inconclusive:
        malware_text = _force_inconclusive_header(malware_text)
    compatibility_text = _extract_text(compatibility_payload)

    combined_text = (
        f"## Supply-Chain Malware Review\n\n{malware_text}\n\n## Compatibility Analysis\n\n{compatibility_text}"
    )
    # complete is true only when both agent files were real analyses.
    # The post step stamps the skip marker only if this combined review
    # was written (complete, both section headings) and analysis succeeded.
    combined = {
        "result": combined_text,
        "complete": bool(_successful_analysis_text("cursor_output_malware.json"))
        and bool(_successful_analysis_text("cursor_output_compatibility.json")),
        "malware_review": malware_payload,
        "compatibility_review": compatibility_payload,
    }
    Path("cursor_output.json").write_text(json.dumps(combined, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
