"""Regression: cold_start scrub hop matches scripts_dir_module_loader primitive."""

from __future__ import annotations

import inspect
import unittest
from pathlib import Path

import scripts_dir_module_loader
import trusted_formatter_loader_cold_start as cold_start


class ModuleExecScrubTest(unittest.TestCase):
    def test_cold_start_uses_scripts_dir_loader_exec_for_isolated(self) -> None:
        src = inspect.getsource(cold_start._ensure_isolated_module_exec)
        self.assertIn("exec_module_scrubbing_script_dir", src)
        self.assertIn("_scripts_dir_loader", src)

    def test_cold_start_has_single_documented_hop(self) -> None:
        src = inspect.getsource(cold_start)
        self.assertIn("_cold_start_hop_load_scripts_dir_module_loader", src)
        self.assertNotIn("def _module_exec_scrub", src)
        self.assertNotIn("module_exec_scrub_bootstrap", src)

    def test_hop_matches_loader_exec_primitive(self) -> None:
        shared = inspect.getsource(scripts_dir_module_loader._exec_scripts_dir_module)
        hop = inspect.getsource(cold_start._cold_start_hop_load_scripts_dir_module_loader)
        self.assertIn(
            "sys.path = [entry for entry in sys.path if entry != script_dir_s]", shared
        )
        self.assertIn(
            "sys.path = [entry for entry in sys.path if entry != script_dir_s]", hop
        )


if __name__ == "__main__":
    unittest.main()
