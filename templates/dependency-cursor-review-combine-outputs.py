#!/usr/bin/env python3
"""Merge Cursor malware + compatibility JSON outputs; format malware verdict via trusted loader."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_SCRIPT_CANDIDATES = (
    Path(".github/scripts"),
    Path("internal/workflowscripts"),
)


def _bootstrap_module_for(script_dir: Path):
    bootstrap_path = script_dir / "trusted_formatter_loader_bootstrap.py"
    spec = importlib.util.spec_from_file_location(
        "trusted_formatter_loader_bootstrap", bootstrap_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {bootstrap_path}")
    bootstrap = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = bootstrap
    spec.loader.exec_module(bootstrap)
    return bootstrap


def _resolve_trusted_formatter_loader_module():
    """Single bootstrap entry: resolve_trusted_formatter_loader_module (stdlib bootstrap exec)."""
    for script_dir in _SCRIPT_CANDIDATES:
        if not (script_dir / "trusted_formatter_loader_bootstrap.py").is_file():
            continue
        bootstrap = _bootstrap_module_for(script_dir)
        return bootstrap.resolve_trusted_formatter_loader_module(*_SCRIPT_CANDIDATES)
    raise RuntimeError(
        "trusted_formatter_loader.py not found under .github/scripts/. "
        "Run repo-content-updater managed-files for dependency-cursor-review."
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
    loader = _resolve_trusted_formatter_loader_module()
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
