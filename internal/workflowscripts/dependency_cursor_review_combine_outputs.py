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


def _cold_start_module(install_dir: Path | None = None):
    """Load trusted_formatter_loader_cold_start under python3 -I (no sibling imports)."""
    install = (install_dir or Path(__file__).resolve().parent).resolve()
    name = "trusted_formatter_loader_cold_start"
    path = install / f"{name}.py"
    existing = sys.modules.get(name)
    if existing is not None:
        existing_file = getattr(existing, "__file__", None)
        if existing_file and Path(existing_file).resolve() == path.resolve():
            return existing
    if not path.is_file():
        raise RuntimeError(f"Missing {path}")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _load_trusted_formatter_loader_module(base: Path):
    """Resolve loader for one scripts directory (in-process / security tests)."""
    return _cold_start_module(base).resolve_loader_for_dir(base.resolve())


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
    cold_start = _cold_start_module()
    loader = None
    script_dirs: tuple[Path, ...] = ()
    for base in _SCRIPT_CANDIDATES:
        base = base.resolve()
        if (base / "trusted_formatter_loader_bootstrap.py").is_file():
            loader = cold_start.resolve_loader_for_dir(base)
            script_dirs = (base,)
            break
    if loader is None:
        loader = cold_start.resolve_loader_module(_SCRIPT_CANDIDATES)
        for base in _SCRIPT_CANDIDATES:
            base = base.resolve()
            if (base / "trusted_formatter_loader.py").is_file():
                script_dirs = (base,)
                break
    format_malware_review_verdict = loader.find_and_load_format_malware_review_verdict(
        *script_dirs
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
