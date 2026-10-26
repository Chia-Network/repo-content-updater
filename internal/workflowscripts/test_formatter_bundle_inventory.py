"""Regression: single authoritative managed companion inventory."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

from formatter_bundle_inventory import sync_canonical_to_template

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CONFIG = _REPO_ROOT / "config.yaml"


class FormatterBundleInventoryTest(unittest.TestCase):
    def test_sync_covers_every_consumer_script_entry(self) -> None:
        config = _CONFIG.read_text(encoding="utf-8")
        expected = (
            ("check_node_runtime.sh", "check-node-runtime.sh"),
            ("github_scripts_init.py", "github-scripts-init.py"),
            ("dcr_fetch.py", "dcr-fetch.py"),
            ("dcr_sources.py", "dcr-sources.py"),
            ("dcr_lock.py", "dcr-lock.py"),
            ("dcr_verdict.py", "dcr-verdict.py"),
            ("dcr_prompt.md", "dcr-prompt.md"),
        )
        self.assertEqual(sync_canonical_to_template(config), expected)

    def test_every_local_module_a_shipped_script_imports_is_shipped(self) -> None:
        """A consumer runs the scripts with `python3 -I` from one directory, so each sibling module must ship too."""
        shipped = {
            canonical for canonical, _template in sync_canonical_to_template(_CONFIG.read_text(encoding="utf-8"))
        }
        scripts = _REPO_ROOT / "internal" / "workflowscripts"
        local = {path.stem for path in scripts.glob("*.py")}
        for name in sorted(item for item in shipped if item.endswith(".py")):
            tree = ast.parse((scripts / name).read_text(encoding="utf-8"))
            imported = {
                alias.name.split(".")[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.Import)
                for alias in node.names
            }
            imported |= {
                node.module.split(".")[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom) and node.module and not node.level
            }
            with self.subTest(script=name):
                self.assertLessEqual({f"{module}.py" for module in imported & local}, shipped)


if __name__ == "__main__":
    unittest.main()
