"""Manifest and lockfile parsing: operators, Python manifests, sections, renames, Go and Yarn locks."""

from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import dependency_manifest_diff as manifest
import dependency_update_coverage as coverage
from test_dependency_update_coverage import _commit, _git, _git_repo


def _update(name: str, old: str, new: str) -> dict:
    return {"packageName": name, "fromVersion": old, "toVersion": new, "upstreamRepo": f"{name}/{name}"}


class VersionOperatorTest(unittest.TestCase):
    def test_python_operators_strip_whole(self) -> None:
        for operator in ("==", "===", "~=", "!=", ">=", "^", "~"):
            self.assertEqual(manifest._VERSION_PREFIX_RE.sub("", f"{operator}2.0"), "2.0", operator)

    def test_uppercase_v_listed_version_matches_manifest(self) -> None:
        listed = {"tool": {("V1.0", "V1.1")}}
        for old, new in (("v1.0", "v1.1"), ("1.0", "1.1"), ("V1.0", "V1.1")):
            self.assertTrue(manifest._reached_listed_version("tool", old, new, listed), (old, new))
        self.assertFalse(manifest._reached_listed_version("tool", "^1.0", "1.1", listed))


class PythonManifestTest(unittest.TestCase):
    def test_python_manifests_are_requirements(self) -> None:
        for path in (
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            "Pipfile",
            "requirements/dev.txt",
            "tools/requirements/base.txt",
        ):
            self.assertEqual(manifest._manifest_kind(path), "requirements", path)

    def test_pyproject_bump_is_explained(self) -> None:
        old = '[project]\nname = "demo"\nrequires-python = ">=3.9"\ndependencies = [\n  "chia-rs==0.2.0",\n]\n'
        new = old.replace("0.2.0", "0.3.0")
        self.assertEqual(manifest._changed_names("requirements", old, new), {"chia-rs"})
        self.assertTrue(manifest._entries_explain("requirements", old, new, [_update("chia-rs", "0.2.0", "0.3.0")]))
        other = old.replace("0.2.0", "0.4.0")
        self.assertFalse(manifest._entries_explain("requirements", old, other, [_update("chia-rs", "0.2.0", "0.3.0")]))

    def test_setup_py_and_poetry_and_pipfile_entries(self) -> None:
        setup = 'setup(\n    name="demo",\n    install_requires=["clvm==0.9.7", "blspy>=2.0"],\n)\n'
        self.assertEqual(set(manifest._req_parts(setup)[0]), {"clvm", "blspy"})
        poetry = '[tool.poetry.dependencies]\npython = "^3.10"\nclick = "^8.0"\nrich = { version = "^13.0" }\n'
        self.assertEqual(set(manifest._req_parts(poetry)[0]), {"click", "rich"})
        pipfile = '[packages]\nrequests = "==2.31.0"\n\n[requires]\npython_version = "3.11"\n'
        self.assertEqual(set(manifest._req_parts(pipfile)[0]), {"requests"})

    def test_requirements_marker_line_stays_an_entry(self) -> None:
        entries, residue = manifest._req_parts('foo==1.0 ; python_version < "3.8"\n')
        self.assertEqual(set(entries), {"foo"})
        self.assertEqual(residue, "")


class PackageJsonSectionsTest(unittest.TestCase):
    def test_bump_in_one_section_is_not_hidden_by_another(self) -> None:
        old = json.dumps({"dependencies": {"left-pad": "^1.0.0"}, "devDependencies": {"left-pad": "^1.0.0"}})
        new = json.dumps({"dependencies": {"left-pad": "^9.0.0"}, "devDependencies": {"left-pad": "^1.0.0"}})
        self.assertFalse(manifest._entries_explain("json", old, new, []))
        self.assertEqual(manifest._multi_entry_names("json", old, new, []), {"left-pad"})


class GoAndYarnLockTest(unittest.TestCase):
    def test_go_mod_indirect_bump_is_transitive(self) -> None:
        old = "module x\n\nrequire (\n\tgithub.com/a/a v1.0.0\n\tgithub.com/b/b v1.0.0 // indirect\n)\n"
        new = old.replace("a v1.0.0", "a v1.1.0").replace("b v1.0.0", "b v1.2.0")
        names = manifest._changed_names("go.mod", old, new)
        updates = [_update("github.com/a/a", "1.0.0", "1.1.0")]
        self.assertTrue(manifest._lock_covers_listed("go.mod", old, new, updates, names))
        direct = new.replace("b v1.2.0 // indirect", "b v1.2.0")
        self.assertFalse(manifest._lock_covers_listed("go.mod", old, direct, updates, names | {"github.com/b/b"}))

    def test_go_sum_transitive_versions_keep_their_hashes(self) -> None:
        def line(mod: str, version: str, digest: str) -> str:
            return f"{mod} {version} h1:{digest}=\n{mod} {version}/go.mod h1:{digest}m=\n"

        old = line("github.com/a/a", "v1.0.0", "a1") + line("github.com/b/b", "v1.0.0", "b1")
        new = line("github.com/a/a", "v1.1.0", "a2") + line("github.com/b/b", "v1.0.0", "b1")
        new += line("github.com/b/b", "v1.2.0", "b2")
        updates = [_update("github.com/a/a", "1.0.0", "1.1.0")]
        names = manifest._changed_names("go.sum", old, new)
        self.assertTrue(manifest._lock_covers_listed("go.sum", old, new, updates, names))
        rehashed = new.replace("v1.0.0 h1:b1=", "v1.0.0 h1:zz=")
        self.assertFalse(manifest._lock_covers_listed("go.sum", old, rehashed, updates, names))
        self.assertIn("go.mod", manifest.TRANSITIVE_LOCK_NAMES)
        self.assertIn("go.sum", manifest.TRANSITIVE_LOCK_NAMES)

    def test_yarn_header_keeps_every_descriptor_name(self) -> None:
        header = '"@babel/core@^7.0.0", "@babel/core@^7.1.0", left-pad@^1.0.0:'
        self.assertEqual(manifest._yarn_names(header), ["@babel/core", "left-pad"])
        self.assertEqual(manifest._yarn_names('"lodash@npm:^4.17.21":'), ["lodash"])


class RenamedManifestTest(unittest.TestCase):
    def test_renamed_manifest_change_is_seen(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            _git_repo(root)
            body = "".join(f"pkg{index}==1.0.{index}\n" for index in range(12))
            _commit(root, "requirements.txt", body + "shady==1.0.0\n", "base")
            base = _git(root, "rev-parse", "HEAD")
            _git(root, "mv", "requirements.txt", "requirements-main.txt")
            _commit(root, "requirements-main.txt", body + "shady==6.6.6\n", "rename")
            previous = os.getcwd()
            os.chdir(root)
            try:
                with patch.dict(os.environ, {"PR_BASE_SHA": base}):
                    gaps = coverage.manifest_gaps([])
            finally:
                os.chdir(previous)
            self.assertIn("shady", {item["package_name"] for item in gaps}, msg=gaps)


if __name__ == "__main__":
    unittest.main()
