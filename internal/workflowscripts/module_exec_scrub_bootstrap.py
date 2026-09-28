"""Re-export the shared scripts-dir bootstrap loader (scrub-safe spine)."""

from __future__ import annotations

from scripts_dir_module_loader import bootstrap_module_from_scripts_dir

__all__ = ("bootstrap_module_from_scripts_dir",)
