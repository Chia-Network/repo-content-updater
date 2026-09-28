"""Regression: cold_start lazy scrub bootstrap matches module_exec_scrub."""

from __future__ import annotations

import inspect
import unittest
from pathlib import Path

import module_exec_scrub
import trusted_formatter_loader_cold_start as cold_start

_SCRIPTS = Path(__file__).resolve().parent


class ModuleExecScrubTest(unittest.TestCase):
    def test_cold_start_lazy_loader_matches_shared_bootstrap(self) -> None:
        shared = inspect.getsource(module_exec_scrub.bootstrap_module_from_scripts_dir)
        lazy = inspect.getsource(cold_start._module_exec_scrub)
        self.assertIn("sys.path = [entry for entry in sys.path if entry != script_dir_s]", lazy)
        self.assertIn("sys.path = [entry for entry in sys.path if entry != script_dir_s]", shared)


if __name__ == "__main__":
    unittest.main()
