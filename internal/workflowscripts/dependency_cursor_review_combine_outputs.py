#!/usr/bin/env python3
"""Merge Cursor malware + compatibility JSON outputs; format malware verdict via trusted loader."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_SCRIPT_CANDIDATES = (
    Path(".github/scripts"),
    Path("internal/workflowscripts"),
)


def _import_trusted_loader_entry():
    for base in _SCRIPT_CANDIDATES:
        path = base / "dependency_cursor_review_trusted_loader.py"
        if not path.is_file():
            continue
        spec = importlib.util.spec_from_file_location(
            "dependency_cursor_review_trusted_loader", path
        )
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Could not load module spec from {path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    raise RuntimeError(
        "dependency_cursor_review_trusted_loader.py not found under .github/scripts/."
    )


def _load_any(path: str) -> dict:
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return {"result": f"Missing output file: {path}"}
    try:
        return json.loads(raw)
    except Exception:
        return {"result": raw}


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


def main() -> None:
    trusted_loader = _import_trusted_loader_entry()
    loader = trusted_loader.resolve_trusted_formatter_loader_module(_SCRIPT_CANDIDATES)
    format_malware_review_verdict = loader.find_and_load_format_malware_review_verdict(
        *_SCRIPT_CANDIDATES
    )

    malware_payload = _load_any("cursor_output_malware.json")
    compatibility_payload = _load_any("cursor_output_compatibility.json")
    malware_text = format_malware_review_verdict(_extract_text(malware_payload))
    compatibility_text = _extract_text(compatibility_payload)

    combined_text = (
        "## Supply-Chain Malware Review\n\n"
        f"{malware_text}\n\n"
        "## Compatibility Analysis\n\n"
        f"{compatibility_text}"
    )
    combined = {
        "result": combined_text,
        "malware_review": malware_payload,
        "compatibility_review": compatibility_payload,
    }
    Path("cursor_output.json").write_text(
        json.dumps(combined, indent=2), encoding="utf-8"
    )


if __name__ == "__main__":
    main()
