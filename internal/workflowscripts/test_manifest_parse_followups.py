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
    def test_only_exact_pins_lose_their_operator(self) -> None:
        for operator in ("==", "===", "v", "V"):
            self.assertEqual(manifest._exact_body(f"{operator}2.0"), "2.0", operator)
        for operator in ("~=", "!=", ">=", "<=", ">", "<", "^", "~", "=", "vv"):
            self.assertEqual(manifest._exact_body(f"{operator}2.0"), "", operator)

    def test_range_listed_version_is_not_explained(self) -> None:
        old, new = "clvm==0.9.7\n", "clvm>=0.9.8\n"
        for listed in (_update("clvm", "0.9.7", "0.9.8"), _update("clvm", "==0.9.7", ">=0.9.8")):
            self.assertFalse(manifest._entries_explain("requirements", old, new, [listed]), listed)
        widened = "clvm>=0.9.7\n", "clvm>=0.9.8\n"
        self.assertFalse(manifest._entries_explain("requirements", *widened, [_update("clvm", "0.9.7", "0.9.8")]))

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


class SameLineChangeTest(unittest.TestCase):
    def test_line_must_match_once_the_version_is_removed(self) -> None:
        update = [_update("requests", "2.31.0", "2.32.0")]
        cases = {
            "poetry git": (
                '[tool.poetry.dependencies]\nrequests = { version = "2.31.0" }\n',
                '[tool.poetry.dependencies]\nrequests = { git = "https://example.invalid/r", version = "2.32.0" }\n',
            ),
            "poetry path": (
                '[tool.poetry.dependencies]\nrequests = { version = "2.31.0" }\n',
                '[tool.poetry.dependencies]\nrequests = { path = "../r", version = "2.32.0" }\n',
            ),
            "hash trailer": ("requests==2.31.0\n", "requests==2.32.0 --hash=sha256:abc\n"),
            "setup.py code": (
                'install_requires=["requests==2.31.0"],\n',
                'install_requires=["requests==2.32.0"] + [__import__("os").getcwd()],\n',
            ),
        }
        for label, (old, new) in cases.items():
            self.assertFalse(manifest._entries_explain("requirements", old, new, update), label)
        plain = ("requests==2.31.0\n", "requests==2.32.0\n")
        self.assertTrue(manifest._entries_explain("requirements", *plain, update))

    def test_same_line_change_is_named_in_manifest_gaps(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            _git_repo(root)
            _commit(root, "requirements.txt", "requests==2.31.0\n", "base")
            base = _git(root, "rev-parse", "HEAD")
            _commit(root, "requirements.txt", "requests==2.32.0 --hash=sha256:abc\n", "bump")
            gaps = _gaps_at(root, base, [_update("requests", "2.31.0", "2.32.0")])
            self.assertIn("requirements.txt", {item["package_name"] for item in gaps}, msg=gaps)


def _gaps_at(root: Path, base: str | None, updates: list[dict]) -> list[dict]:
    previous = os.getcwd()
    os.chdir(root)
    env = {"PR_BASE_SHA": base} if base else {}
    try:
        with patch.dict(os.environ, env, clear=False):
            if base is None:
                os.environ.pop("PR_BASE_SHA", None)
                os.environ.pop("GITHUB_BASE_REF", None)
            return coverage.manifest_gaps(updates)
    finally:
        os.chdir(previous)


class ChangedPathGapTest(unittest.TestCase):
    def _repo(self, tmp: str) -> tuple[Path, str]:
        root = Path(tmp) / "repo"
        _git_repo(root)
        _commit(root, "requirements.txt", "requests==2.31.0\n", "base")
        _commit(root, "poetry.lock", "[[package]]\nname = 'requests'\n", "lock")
        _commit(root, ".github/workflows/ci.yml", "on: push\n", "ci")
        return root, _git(root, "rev-parse", "HEAD")

    def test_opaque_lock_and_other_paths_are_gaps(self) -> None:
        with TemporaryDirectory() as tmp:
            root, base = self._repo(tmp)
            _commit(root, "requirements.txt", "requests==2.32.0\n", "bump")
            _commit(root, "poetry.lock", "[[package]]\nname = 'requests'\nversion = '2.32.0'\n", "lock")
            _commit(root, ".github/workflows/ci.yml", "on: [push, pull_request]\n", "ci")
            gaps = {item["package_name"] for item in _gaps_at(root, base, [_update("requests", "2.31.0", "2.32.0")])}
            self.assertEqual(gaps, {"poetry.lock", ".github/workflows/ci.yml"})

    def test_missing_base_is_a_gap(self) -> None:
        with TemporaryDirectory() as tmp:
            root, _base = self._repo(tmp)
            gaps = _gaps_at(root, None, [_update("requests", "2.31.0", "2.32.0")])
            self.assertEqual([item["package_name"] for item in gaps], ["manifest-diff"])

    def test_type_change_and_rename_off_a_manifest_are_gaps(self) -> None:
        with TemporaryDirectory() as tmp:
            root, base = self._repo(tmp)
            _git(root, "mv", "requirements.txt", "NOTES.md")
            _git(root, "commit", "-qm", "rename")
            gaps = {item["package_name"] for item in _gaps_at(root, base, [])}
            self.assertIn("requirements.txt", gaps)
        with TemporaryDirectory() as tmp:
            root, base = self._repo(tmp)
            (root / "requirements.txt").unlink()
            os.symlink("NOTES.md", root / "requirements.txt")
            _git(root, "add", "requirements.txt")
            _git(root, "commit", "-qm", "link")
            gaps = {item["package_name"] for item in _gaps_at(root, base, [])}
            self.assertIn("requirements.txt", gaps)


class PackageJsonSectionsTest(unittest.TestCase):
    def test_bump_in_one_section_is_not_hidden_by_another(self) -> None:
        old = json.dumps({"dependencies": {"left-pad": "^1.0.0"}, "devDependencies": {"left-pad": "^1.0.0"}})
        new = json.dumps({"dependencies": {"left-pad": "^9.0.0"}, "devDependencies": {"left-pad": "^1.0.0"}})
        self.assertFalse(manifest._entries_explain("json", old, new, []))
        self.assertEqual(manifest._multi_entry_names("json", old, new, []), {"left-pad"})


class GoAndYarnLockTest(unittest.TestCase):
    def test_go_mod_new_indirect_module_is_a_gap(self) -> None:
        old = "module x\n\nrequire (\n\tgithub.com/a/a v1.0.0\n)\n"
        new = old.replace("a v1.0.0", "a v1.1.0\n\tgithub.com/b/b v1.2.0 // indirect")
        names = manifest._changed_names("go.mod", old, new)
        updates = [_update("github.com/a/a", "1.0.0", "1.1.0")]
        self.assertFalse(manifest._lock_covers_listed("go.mod", old, new, updates, names))
        self.assertNotIn("go.mod", manifest.TRANSITIVE_LOCK_NAMES)

    def test_go_sum_new_module_is_a_gap(self) -> None:
        def line(mod: str, version: str, digest: str) -> str:
            return f"{mod} {version} h1:{digest}=\n{mod} {version}/go.mod h1:{digest}m=\n"

        old = line("github.com/a/a", "v1.0.0", "a1")
        new = line("github.com/a/a", "v1.1.0", "a2") + line("github.com/b/b", "v1.2.0", "b2")
        updates = [_update("github.com/a/a", "1.0.0", "1.1.0")]
        names = manifest._changed_names("go.sum", old, new)
        self.assertFalse(manifest._lock_covers_listed("go.sum", old, new, updates, names))
        self.assertFalse(manifest._entries_explain("go.sum", old, new, updates))
        self.assertNotIn("go.sum", manifest.TRANSITIVE_LOCK_NAMES)

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


class ScannableTest(unittest.TestCase):
    def test_only_exact_versions_with_a_github_repository_are_scannable(self) -> None:
        def update(frm: str, to: str, repo: str = "o/r") -> dict:
            return {"packageName": "p", "fromVersion": frm, "toVersion": to, "upstreamRepo": repo}

        for frm, to in (("1.0", "1.1"), ("v1.0", "V1.1"), ("", "1.1")):
            self.assertTrue(coverage.scannable(update(frm, to)), (frm, to))
        for frm, to in (
            (">=1.0", "1.1"),
            ("1.0", ">=1.1"),
            ("1.0", "^1.1"),
            ("1.0", "~=1.1"),
            ("1.0", "1.*"),
            ("1.0", "latest"),
        ):
            self.assertFalse(coverage.scannable(update(frm, to)), (frm, to))
        self.assertFalse(coverage.scannable(update("1.0", "1.1", "")))
