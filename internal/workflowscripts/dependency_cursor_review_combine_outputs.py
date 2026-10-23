"""Merge Cursor malware + compatibility JSON outputs; format the malware verdict.

The verdict job passes DCR_SCAN_REPORT and MALWARE_SCAN_REPORT_SHA256 from the
scan job. Combine reads that report and exits unless hashlib.sha256 matches.
Agent JSON is untrusted data read from DCR_MALWARE_JSON and DCR_COMPAT_JSON.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import malware_verdict_formatter as formatter


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
    if payload.get("complete") is False:
        return ""
    for key in ("result", "output", "text", "message"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip() and not value.startswith("Missing output file:"):
            if value.startswith(("Error: agent exited", "CURSOR_API_KEY is not set", "No Cursor output generated")):
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


def _final_message(payload) -> str:
    """The final assistant message, written separately from the concatenated result."""
    if isinstance(payload, dict):
        value = payload.get("final_message")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


_REPORT_SHA256_ENV = "MALWARE_SCAN_REPORT_SHA256"


def _fail_closed(message: str) -> None:
    print(message, file=sys.stderr)
    sys.exit(1)


def _digest_is_sha256(value: str) -> bool:
    if len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return value == value.lower()


def _env_path(name: str) -> Path:
    value = os.environ.get(name, "").strip()
    if not value:
        _fail_closed(f"{name} is missing.")
    return Path(value)


def _sealed_report() -> object:
    """Fail closed unless the scan-job digest matches DCR_SCAN_REPORT."""
    expected = os.environ.get(_REPORT_SHA256_ENV, "").strip()
    if not _digest_is_sha256(expected):
        _fail_closed("Malware scan report digest is missing.")
    path = _env_path("DCR_SCAN_REPORT")
    try:
        data = path.read_bytes()
    except OSError:
        _fail_closed("Malware scan report is missing.")
    if hashlib.sha256(data).hexdigest() != expected:
        _fail_closed("Malware scan report digest mismatch.")
    try:
        report = json.loads(data.decode("utf-8"))
    except Exception:
        return None
    return report if isinstance(report, dict) else None


def main() -> None:
    report = _sealed_report()
    malware_path = str(_env_path("DCR_MALWARE_JSON"))
    compatibility_path = str(_env_path("DCR_COMPAT_JSON"))
    combined_path = _env_path("DCR_COMBINED_JSON")
    malware_payload = _load_any(malware_path)
    compatibility_payload = _load_any(compatibility_path)
    agent_text = _extract_text(malware_payload)
    compatibility_text = _final_message(compatibility_payload) or _extract_text(compatibility_payload)
    published = formatter.compose_published_review(
        report,
        agent_text,
        compatibility_text,
        agent_final_text=_final_message(malware_payload) or agent_text,
    )
    malware_text = published["malware_text"]
    compatibility_text = published["compatibility_text"]
    check = str(published.get("check") or "fail")
    agents_ok = bool(_successful_analysis_text(malware_path)) and bool(_successful_analysis_text(compatibility_path))
    # The patch-id marker is stamped only when the published check passed.
    complete = agents_ok and check == "pass" and published.get("may_complete") is True
    malware_review = {"result": malware_text}
    compatibility_review = {"result": compatibility_text}

    combined_text = (
        f"## Supply-Chain Malware Review\n\n{malware_text}\n\n## Compatibility Analysis\n\n{compatibility_text}"
    )
    combined = {
        "result": combined_text,
        "complete": complete,
        "check": check,
        "malware_review": malware_review,
        "compatibility_review": compatibility_review,
    }
    combined_path.write_text(json.dumps(combined, indent=2), encoding="utf-8")


def _optional_analysis(name: str) -> str:
    """Agent text when the file is present. A skipped agent leaves this empty."""
    value = os.environ.get(name, "").strip()
    if not value or not Path(value).is_file():
        return ""
    return _extract_text(_load_any(value))


def _optional_final_message(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value or not Path(value).is_file():
        return ""
    return _final_message(_load_any(value))


def _enforce_published_check() -> None:
    """Recompute the check from the sealed report. A stored check string is ignored."""
    report = _sealed_report()
    published = formatter.compose_published_review(
        report,
        _optional_analysis("DCR_MALWARE_JSON"),
        _optional_final_message("DCR_COMPAT_JSON") or _optional_analysis("DCR_COMPAT_JSON"),
        agent_final_text=_optional_final_message("DCR_MALWARE_JSON") or _optional_analysis("DCR_MALWARE_JSON"),
    )
    if published.get("check") != "pass":
        _fail_closed("Dependency review did not pass.")


if __name__ == "__main__":
    if "--enforce-check" in sys.argv:
        _enforce_published_check()
    else:
        main()
