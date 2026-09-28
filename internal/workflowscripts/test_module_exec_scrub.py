"""Regression: cold_start lazy scrub bootstrap matches module_exec_scrub."""

from __future__ import annotations

import inspect
import unittest
from pathlib import Path

import scripts_dir_module_loader
import trusted_formatter_loader_cold_start as cold_start

_SCRIPTS = Path(__file__).resolve().parent


class ModuleExecScrubTest(unittest.TestCase):
    def test_cold_start_loads_module_exec_scrub_via_bootstrap_spine(self) -> None:
        scrub_loader = inspect.getsource(cold_start._module_exec_scrub)
        self.assertIn("_bootstrap_spine", scrub_loader)
        self.assertIn("module_exec_scrub.py", scrub_loader)

    def test_cold_start_has_single_hop_for_scripts_dir_module_loader(self) -> None:
        src = inspect.getsource(cold_start)
        self.assertIn("_hop_load_scripts_dir_module_loader", src)
        self.assertNotIn("def _module_exec_scrub_bootstrap", src)

    def test_hop_matches_shared_loader_implementation(self) -> None:
        shared = inspect.getsource(
            scripts_dir_module_loader.bootstrap_module_from_scripts_dir
        )
        hop = inspect.getsource(cold_start._hop_load_scripts_dir_module_loader)
        self.assertIn(
            "sys.path = [entry for entry in sys.path if entry != script_dir_s]", shared
        )
        self.assertIn(
            "sys.path = [entry for entry in sys.path if entry != script_dir_s]", hop
        )


if __name__ == "__main__":
    unittest.main()
