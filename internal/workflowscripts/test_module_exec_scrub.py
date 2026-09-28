"""Regression: cold_start lazy scrub bootstrap matches module_exec_scrub."""

from __future__ import annotations

import inspect
import unittest

import module_exec_scrub_bootstrap
import trusted_formatter_loader_cold_start as cold_start


class ModuleExecScrubTest(unittest.TestCase):
    def test_cold_start_loads_module_exec_scrub_via_bootstrap_spine(self) -> None:
        scrub_loader = inspect.getsource(cold_start._module_exec_scrub)
        self.assertIn("bootstrap_module_from_scripts_dir", scrub_loader)
        self.assertIn("module_exec_scrub.py", scrub_loader)

    def test_bootstrap_spine_matches_shared_helper(self) -> None:
        shared = inspect.getsource(
            module_exec_scrub_bootstrap.bootstrap_module_from_scripts_dir
        )
        boot_loader = inspect.getsource(cold_start._module_exec_scrub_bootstrap)
        self.assertIn(
            "sys.path = [entry for entry in sys.path if entry != script_dir_s]", shared
        )
        self.assertIn(
            "sys.path = [entry for entry in sys.path if entry != script_dir_s]",
            boot_loader,
        )


if __name__ == "__main__":
    unittest.main()
