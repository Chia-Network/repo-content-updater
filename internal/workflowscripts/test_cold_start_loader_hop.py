"""Regression: cold_start scrub hop matches scripts_dir_path_scrub primitive."""

from __future__ import annotations

import ast
import inspect
import sys
import unittest
from pathlib import Path

import formatter_runtime_bundle
import scripts_dir_path_scrub
import trusted_formatter_loader_cold_start as cold_start

_SCRIPTS = Path(__file__).resolve().parent


class ColdStartLoaderHopTest(unittest.TestCase):
    def test_cold_start_uses_scrub_bootstrap_module(self) -> None:
        cold_src = inspect.getsource(cold_start.resolve_loader_for_dir)
        self.assertIn("bootstrap_module_from_scripts_dir", cold_src)
        self.assertIn("_require_scrub", cold_src)
        self.assertNotIn("scripts_dir_module_loader", cold_src)
        self.assertNotIn("formatter_runtime_bundle", cold_src)

    def test_cold_start_marker_tuple_matches_runtime_bundle(self) -> None:
        self.assertEqual(
            cold_start.LOADER_RESOLVE_MARKER_FILENAMES,
            formatter_runtime_bundle.LOADER_RESOLVE_MARKER_FILENAMES,
        )

    def test_exec_helper_uses_shared_path_filter_primitive(self) -> None:
        exec_src = inspect.getsource(scripts_dir_path_scrub.exec_scripts_dir_module)
        self.assertIn("_exec_with_path_filter", exec_src)
        self.assertNotIn("spec_from_file_location", exec_src)
        tree = ast.parse(exec_src)
        calls_shared = any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_exec_with_path_filter"
            for node in ast.walk(tree)
        )
        self.assertTrue(calls_shared)

    def test_cached_trusted_module_canonical_in_disk_exec(self) -> None:
        import scripts_dir_disk_exec as disk_exec

        self.assertTrue(hasattr(disk_exec, "cached_trusted_module"))
        scrub_src = inspect.getsource(scripts_dir_path_scrub.load_scrub_from_disk_under_dash_i)
        exec_src = inspect.getsource(scripts_dir_path_scrub._exec_with_path_filter)
        self.assertIn("cached_trusted_module", scrub_src)
        self.assertIn("cached_trusted_module", exec_src)
        scrub_head = (_SCRIPTS / "scripts_dir_path_scrub.py").read_text(encoding="utf-8").split(
            "def ensure_disk_exec"
        )[0]
        self.assertNotIn("from scripts_dir_disk_exec import", scrub_head)

    def test_isolated_exec_has_no_public_bootstrap_duplicate(self) -> None:
        iso_src = (_SCRIPTS / "isolated_module_exec.py").read_text(encoding="utf-8")
        self.assertNotIn("def bootstrap_module_from_scripts_dir", iso_src)
        self.assertIn("_require_scripts_dir_path_scrub", iso_src)
        self.assertIn("_bootstrap_via_spine", iso_src)

    def test_scrub_cold_load_equivalence(self) -> None:
        script_dir = _SCRIPTS
        scrub_saved = sys.modules.pop("scripts_dir_path_scrub", None)
        try:
            via_cold = cold_start._require_scrub(script_dir)
            sys.modules.pop("scripts_dir_path_scrub", None)
            via_scrub = scripts_dir_path_scrub.load_scrub_from_disk_under_dash_i(script_dir)
            self.assertEqual(
                Path(via_cold.__file__).resolve(),
                Path(via_scrub.__file__).resolve(),
            )
            cold_src = inspect.getsource(cold_start._require_scrub)
            self.assertIn("cached_trusted_module", cold_src)
            self.assertIn("exec_trusted_module_from_disk", cold_src)
            self.assertNotIn("load_scrub_from_disk_under_dash_i", cold_src)
            self.assertNotIn("getattr", cold_src)
        finally:
            if scrub_saved is not None:
                sys.modules["scripts_dir_path_scrub"] = scrub_saved

    def test_hop_matches_scrub_bootstrap_behavior(self) -> None:
        script_dir = _SCRIPTS
        probe_name = "formatter_runtime_bundle"
        saved = sys.modules.pop(probe_name, None)
        scrub_saved = sys.modules.pop("scripts_dir_path_scrub", None)
        try:
            scrub = cold_start._require_scrub(script_dir)
            via_hop = scrub.bootstrap_module_from_scripts_dir(
                script_dir, f"{probe_name}.py", probe_name
            )
            sys.modules.pop(probe_name, None)
            via_direct = scripts_dir_path_scrub.bootstrap_module_from_scripts_dir(
                script_dir, f"{probe_name}.py", probe_name
            )
            self.assertEqual(
                Path(via_hop.__file__).resolve(),
                Path(via_direct.__file__).resolve(),
            )
        finally:
            if saved is not None:
                sys.modules[probe_name] = saved
            if scrub_saved is not None:
                sys.modules["scripts_dir_path_scrub"] = scrub_saved

    def test_load_module_isolated_delegates_to_spine_bootstrap(self) -> None:
        from isolated_module_exec import load_module_isolated

        src = inspect.getsource(load_module_isolated)
        self.assertIn("_bootstrap_via_spine", src)


if __name__ == "__main__":
    unittest.main()
