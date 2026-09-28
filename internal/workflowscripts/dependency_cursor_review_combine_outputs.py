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


def _util_via_bootstrap(script_dir: Path):
    """Cold-start under python3 -I: bootstrap registers script_dir_isolated_load."""
    script_dir = script_dir.resolve()
    boot_name = "trusted_formatter_loader_bootstrap"
    boot_path = script_dir / "trusted_formatter_loader_bootstrap.py"
    boot = sys.modules.get(boot_name)
    if boot is not None:
        boot_file = getattr(boot, "__file__", None)
        if boot_file and Path(boot_file).resolve() == boot_path.resolve():
            return boot.cold_start_util(script_dir)
    if not boot_path.is_file():
        raise RuntimeError(f"Missing {boot_path}")
    spec = importlib.util.spec_from_file_location(boot_name, boot_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load module spec from {boot_path}")
    boot = importlib.util.module_from_spec(spec)
    sys.modules[boot_name] = boot
    spec.loader.exec_module(boot)
    return boot.cold_start_util(script_dir)


def _load_trusted_formatter_loader_module(base: Path):
    """Resolve loader for one scripts directory (canonical util.resolve path)."""
    util = _util_via_bootstrap(base)
    return util.resolve_trusted_formatter_loader_for_dir(base.resolve())


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
    loader = None
    script_dirs: tuple[Path, ...] = ()
    for base in _SCRIPT_CANDIDATES:
        base = base.resolve()
        if (base / "trusted_formatter_loader_bootstrap.py").is_file():
            loader = _load_trusted_formatter_loader_module(base)
            script_dirs = (base,)
            break
    if loader is None:
        raise RuntimeError(
            "trusted_formatter_loader bundle not found under .github/scripts/."
        )
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
