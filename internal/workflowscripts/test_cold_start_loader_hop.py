"""Regression: cold_start scrub hop matches scripts_dir_path_scrub primitive."""

from __future__ import annotations

import ast
import inspect
import sys
import unittest
from pathlib import Path

import scripts_dir_module_loader
import scripts_dir_path_scrub
import trusted_formatter_loader_cold_start as cold_start

_SCRIPTS = Path(__file__).resolve().parent


def _path_filter_try_body(source: str) -> ast.Try:
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            for stmt in node.body:
                if (
                    isinstance(stmt, ast.Assign)
                    and isinstance(stmt.value, ast.ListComp)
                ):
                    return node
    raise AssertionError("expected sys.path list-comp try/finally in source")


class ColdStartLoaderHopTest(unittest.TestCase):
    def test_cold_start_hop_delegates_to_path_scrub_exec(self) -> None:
        hop_src = inspect.getsource(cold_start._cold_start_hop_load_scripts_dir_module_loader)
        tree = ast.parse(hop_src)
        exec_calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "exec_scripts_dir_module"
        ]
        self.assertTrue(
            exec_calls,
            msg="loader cold-start hop must call scripts_dir_path_scrub.exec_scripts_dir_module",
        )
        self.assertNotIn("cold_start_hop_load_self", hop_src)

    def test_exec_helper_uses_shared_path_filter_primitive(self) -> None:
        exec_src = inspect.getsource(scripts_dir_path_scrub.exec_scripts_dir_module)
        self.assertIn("_exec_with_path_filter", exec_src)
        filter_src = inspect.getsource(scripts_dir_path_scrub._exec_with_path_filter)
        _path_filter_try_body(filter_src)
        tree = ast.parse(exec_src)
        calls_shared = any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_exec_with_path_filter"
            for node in ast.walk(tree)
        )
        self.assertTrue(calls_shared)

    def test_bootstrap_scrub_is_stdlib_only_disk_exec(self) -> None:
        bootstrap_src = inspect.getsource(cold_start.bootstrap_scripts_dir_path_scrub)
        self.assertNotIn("_exec_with_path_filter", bootstrap_src)
        self.assertIn("spec.loader.exec_module", bootstrap_src)
        filter_src = inspect.getsource(scripts_dir_path_scrub._exec_with_path_filter)
        self.assertIn("sys.path = [entry for entry in sys.path", filter_src)

    def test_isolated_exec_has_no_duplicate_bootstrap(self) -> None:
        iso_src = (_SCRIPTS / "isolated_module_exec.py").read_text(encoding="utf-8")
        self.assertNotIn("def _bootstrap_scripts_dir_path_scrub", iso_src)
        self.assertNotIn("def bootstrap_scripts_dir_path_scrub", iso_src)
        self.assertIn("_require_scripts_dir_path_scrub", iso_src)
        self.assertIn("_bootstrap_via_spine", iso_src)

    def test_hop_matches_exec_loader_behavior(self) -> None:
        script_dir = _SCRIPTS
        loader_name = "scripts_dir_module_loader"
        saved = sys.modules.pop(loader_name, None)
        scrub_saved = sys.modules.pop("scripts_dir_path_scrub", None)
        try:
            via_cold_start = cold_start._cold_start_hop_load_scripts_dir_module_loader(script_dir)
            sys.modules.pop(loader_name, None)
            scrub = cold_start.bootstrap_scripts_dir_path_scrub(script_dir)
            via_direct = scrub.exec_scripts_dir_module(
                script_dir,
                script_dir / "scripts_dir_module_loader.py",
                loader_name,
            )
            self.assertEqual(
                Path(via_cold_start.__file__).resolve(),
                Path(via_direct.__file__).resolve(),
            )
            probe_name = "formatter_runtime_bundle"
            sys.modules.pop(probe_name, None)
            via_hop = via_cold_start.bootstrap_module_from_scripts_dir(
                script_dir, f"{probe_name}.py", probe_name
            )
            sys.modules.pop(probe_name, None)
            via_loader = via_direct.bootstrap_module_from_scripts_dir(
                script_dir, f"{probe_name}.py", probe_name
            )
            self.assertEqual(
                Path(via_hop.__file__).resolve(),
                Path(via_loader.__file__).resolve(),
            )
        finally:
            if saved is not None:
                sys.modules[loader_name] = saved
            if scrub_saved is not None:
                sys.modules["scripts_dir_path_scrub"] = scrub_saved

    def test_load_module_isolated_delegates_to_spine_bootstrap(self) -> None:
        from isolated_module_exec import load_module_isolated

        src = inspect.getsource(load_module_isolated)
        self.assertIn("_bootstrap_via_spine", src)


if __name__ == "__main__":
    unittest.main()
