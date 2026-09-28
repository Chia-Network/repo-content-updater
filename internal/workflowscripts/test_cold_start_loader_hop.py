"""Regression: cold_start scrub hop matches scripts_dir_module_loader primitive."""

from __future__ import annotations

import inspect
import sys
import unittest
from pathlib import Path

import scripts_dir_module_loader
import trusted_formatter_loader_cold_start as cold_start

_SCRIPTS = Path(__file__).resolve().parent


class ColdStartLoaderHopTest(unittest.TestCase):
    def test_cold_start_hop_delegates_to_cold_start_hop_load_self(self) -> None:
        hop_src = inspect.getsource(cold_start._cold_start_hop_load_scripts_dir_module_loader)
        self.assertIn("cold_start_hop_load_self", hop_src)
        exec_src = inspect.getsource(scripts_dir_module_loader._exec_scripts_dir_module)
        for needle in (
            "sys.path = [entry for entry in sys.path if entry != script_dir_s]",
            "sys.path[:] = saved_path",
        ):
            self.assertIn(needle, hop_src, msg="hop scrub must match _exec_scripts_dir_module")
            self.assertIn(needle, exec_src)

    def test_cold_start_has_single_documented_hop(self) -> None:
        src = inspect.getsource(cold_start)
        self.assertIn("_cold_start_hop_load_scripts_dir_module_loader", src)
        self.assertNotIn("def _module_exec_scrub", src)

    def test_hop_matches_cold_start_hop_load_self_behavior(self) -> None:
        script_dir = _SCRIPTS
        loader_name = "scripts_dir_module_loader"
        saved = sys.modules.pop(loader_name, None)
        try:
            via_cold_start = cold_start._cold_start_hop_load_scripts_dir_module_loader(script_dir)
            sys.modules.pop(loader_name, None)
            via_loader = scripts_dir_module_loader.cold_start_hop_load_self(script_dir)
            self.assertEqual(
                Path(via_cold_start.__file__).resolve(),
                Path(via_loader.__file__).resolve(),
            )
            probe_name = "formatter_runtime_bundle"
            sys.modules.pop(probe_name, None)
            via_hop = via_cold_start.bootstrap_module_from_scripts_dir(
                script_dir, f"{probe_name}.py", probe_name
            )
            sys.modules.pop(probe_name, None)
            via_direct = via_loader.bootstrap_module_from_scripts_dir(
                script_dir, f"{probe_name}.py", probe_name
            )
            self.assertEqual(
                Path(via_hop.__file__).resolve(),
                Path(via_direct.__file__).resolve(),
            )
        finally:
            if saved is not None:
                sys.modules[loader_name] = saved

    def test_load_module_isolated_delegates_to_bootstrap(self) -> None:
        from isolated_module_exec import load_module_isolated

        src = inspect.getsource(load_module_isolated)
        self.assertIn("bootstrap_module_from_scripts_dir", src)


if __name__ == "__main__":
    unittest.main()
