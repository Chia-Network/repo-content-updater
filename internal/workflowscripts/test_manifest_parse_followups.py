"""Manifest and lockfile parsing: operators, Python manifests, sections, renames, Go and Yarn locks."""

from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import dependency_manifest_diff as manifest
import dependency_manifest_npm as npm_manifest
import dependency_manifest_python as python_manifest
import dependency_manifest_versions as version_manifest
import dependency_update_coverage as coverage
from test_dependency_update_coverage import _commit, _git, _git_repo


def _update(name: str, old: str, new: str) -> dict:
    return {"packageName": name, "fromVersion": old, "toVersion": new, "upstreamRepo": f"{name}/{name}"}


class VersionOperatorTest(unittest.TestCase):
    def test_only_exact_pins_lose_their_operator(self) -> None:
        for operator in ("==", "===", "v", "V"):
            self.assertEqual(version_manifest._exact_body(f"{operator}2.0"), "2.0", operator)
        for operator in ("~=", "!=", ">=", "<=", ">", "<", "^", "~", "=", "vv"):
            self.assertEqual(version_manifest._exact_body(f"{operator}2.0"), "", operator)

    def test_range_listed_version_is_not_explained(self) -> None:
        old, new = "clvm==0.9.7\n", "clvm>=0.9.8\n"
        for listed in (_update("clvm", "0.9.7", "0.9.8"), _update("clvm", "==0.9.7", ">=0.9.8")):
            self.assertFalse(manifest._entries_explain("requirements", old, new, [listed]), listed)
        widened = "clvm>=0.9.7\n", "clvm>=0.9.8\n"
        self.assertFalse(manifest._entries_explain("requirements", *widened, [_update("clvm", "0.9.7", "0.9.8")]))

    def test_uppercase_v_listed_version_matches_manifest(self) -> None:
        listed = {"tool": {("V1.0", "V1.1")}}
        for old, new in (("v1.0", "v1.1"), ("1.0", "1.1"), ("V1.0", "V1.1")):
            self.assertTrue(version_manifest._reached_listed_version("tool", old, new, listed), (old, new))
        self.assertFalse(version_manifest._reached_listed_version("tool", "^1.0", "1.1", listed))

    def test_x_wildcard_parts_are_not_exact(self) -> None:
        for token in ("1.x", "2.x", "1.2.x", "1.X", "1.x.3", "X", "*", "1.*", "1.2.*"):
            self.assertEqual(version_manifest._exact_body(token), "", token)
        self.assertFalse(version_manifest._reached_listed_version("tool", "1.x", "2.x", {"tool": {("1.x", "2.x")}}))
        self.assertEqual(version_manifest._exact_body("1.2.3-xyz"), "1.2.3-xyz")
        self.assertEqual(version_manifest._exact_body("v1.2.3-xyz"), "1.2.3-xyz")
        self.assertEqual(version_manifest._exact_body("1.2.3+build.x"), "1.2.3+build.x")

    def test_spec_mode_rejects_bare_major_minor_and_python_operators(self) -> None:
        for token in ("1", "1.2", "v1", "v1.2", "1.2.3.4", "==1.2.3", "===1.2.3", "vv1.2.3"):
            self.assertEqual(version_manifest._exact_body(token, mode="spec"), "", token)
        self.assertEqual(version_manifest._exact_body("1.2.3", mode="spec"), "1.2.3")
        self.assertEqual(version_manifest._exact_body("V1.2.3", mode="spec"), "1.2.3")
        self.assertEqual(version_manifest._exact_body("1.2.3-rc.1", mode="spec"), "1.2.3-rc.1")
        listed = {"lodash": {("1.0.0", "2.0.0")}}
        self.assertFalse(version_manifest._reached_listed_version("lodash", "1", "2", listed, mode="spec"))
        self.assertFalse(version_manifest._reached_listed_version("lodash", "1.2", "1.3", listed, mode="spec"))

    def test_caret_and_tilde_ranges_use_npm_membership(self) -> None:
        for spec, version in (
            ("^1.0.0", "1.5.0"),
            ("^0.2.3", "0.2.9"),
            ("^0.0.3", "0.0.3"),
            ("^0", "0.9.9"),
            ("^0.0", "0.0.9"),
            ("~1.2.3", "1.2.9"),
            ("~1", "1.9.0"),
        ):
            self.assertTrue(version_manifest._in_range(spec, version), (spec, version))
        for spec, version in (
            ("^1.0.0", "2.0.0"),
            ("^0.2.3", "0.3.0"),
            ("^0.0.3", "0.0.4"),
            ("^0", "1.0.0"),
            ("^0.0", "0.1.0"),
            ("~1.2.3", "1.3.0"),
            ("~1", "2.0.0"),
            ("1.5.0", "1.5.0"),
        ):
            self.assertFalse(version_manifest._in_range(spec, version), (spec, version))

    def test_shared_range_bump_requires_the_listed_locked_version(self) -> None:
        listed = {"tool": {("1.0.0", "1.3.0")}}
        self.assertFalse(
            version_manifest._reached_listed_version("tool", "^1.0.0", "^1.2.0", listed, locked={"1.2.0"})
        )
        self.assertTrue(
            version_manifest._reached_listed_version("tool", "^1.0.0", "^1.2.0", listed, locked={"1.3.0"})
        )

    def test_dependabot_mode_takes_any_multi_part_version_without_an_operator(self) -> None:
        for token in ("2024.1", "24.2", "1.2.3.4", "v1.2", "V2024.2", "1.2.3-rc.1"):
            self.assertEqual(version_manifest._exact_body(token, mode="dependabot"), token.lstrip("vV"), token)
        for token in ("1", "v4", "==1.2.3", "===1.2.3", "^1.2.3", "~1.2.3", ">=1.2", "~=1.2", "1.x", "1.X", "1.*", "*"):
            self.assertEqual(version_manifest._exact_body(token, mode="dependabot"), "", token)


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
        self.assertEqual(set(python_manifest._req_parts(setup)[0]), {"clvm", "blspy"})
        poetry = '[tool.poetry.dependencies]\npython = "^3.10"\nclick = "^8.0"\nrich = { version = "^13.0" }\n'
        self.assertEqual(set(python_manifest._req_parts(poetry)[0]), {"click", "rich"})
        pipfile = '[packages]\nrequests = "==2.31.0"\n\n[requires]\npython_version = "3.11"\n'
        self.assertEqual(set(python_manifest._req_parts(pipfile)[0]), {"requests"})

    def test_requirements_marker_line_stays_an_entry(self) -> None:
        entries, residue = python_manifest._req_parts('foo==1.0 ; python_version < "3.8"\n')
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

    def test_unnamed_base_is_an_unresolved_gap(self) -> None:
        with TemporaryDirectory() as tmp:
            root, _base = self._repo(tmp)
            gaps = _gaps_at(root, None, [_update("requests", "2.31.0", "2.32.0")])
            self.assertEqual(
                [(item["package_name"], item["not_scanned_reason"]) for item in gaps],
                [("manifest-diff", "unresolved")],
            )

    def test_unreadable_named_base_is_a_gap(self) -> None:
        with TemporaryDirectory() as tmp:
            root, _base = self._repo(tmp)
            previous = os.getcwd()
            os.chdir(root)
            try:
                with patch.dict(os.environ, {"PR_BASE_SHA": "abc123"}, clear=False):
                    os.environ.pop("GITHUB_BASE_REF", None)
                    gaps = coverage.manifest_gaps([_update("requests", "2.31.0", "2.32.0")])
            finally:
                os.chdir(previous)
            self.assertEqual([item["package_name"] for item in gaps], ["manifest-diff"])
            self.assertEqual(gaps[0]["not_scanned_reason"], "unresolved")

    def test_worktree_git_file_resolves_the_named_base(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            _git_repo(root)
            _commit(root, "requirements.txt", "requests==2.31.0\n", "base")
            base = _git(root, "rev-parse", "HEAD")
            _commit(root, "requirements.txt", "requests==2.32.0\n", "bump")
            bump = _git(root, "rev-parse", "HEAD")
            worktree = Path(tmp) / "wt"
            _git(root, "worktree", "add", "--detach", "-q", str(worktree), bump)
            self.assertTrue((worktree / ".git").is_file())
            previous = os.getcwd()
            os.chdir(worktree)
            try:
                with patch.dict(os.environ, {"PR_BASE_SHA": base}, clear=False):
                    os.environ.pop("GITHUB_BASE_REF", None)
                    gaps = coverage.manifest_gaps([_update("requests", "2.31.0", "2.32.0")])
            finally:
                os.chdir(previous)
            self.assertEqual(gaps, [])

    def test_unparsable_manifest_uses_unparsed_manifest_reason(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            _git_repo(root)
            _commit(root, ".github/workflows/ci.yml", "on: push\n", "base")
            base = _git(root, "rev-parse", "HEAD")
            _commit(root, ".github/workflows/ci.yml", "on: [push, pull_request]\n", "change")
            gaps = _gaps_at(root, base, [])
            self.assertEqual(
                [(item["package_name"], item["not_scanned_reason"]) for item in gaps],
                [(".github/workflows/ci.yml", "unparsed_manifest")],
            )

    def test_unparsed_manifest_recognizes_nuget_actions_swift_and_terraform_locks(self) -> None:
        for path in (
            "src/App.csproj",
            "packages.config",
            "Directory.Packages.props",
            "action.yml",
            ".github/actions/setup/action.yaml",
            "Package.resolved",
            "infra/.terraform.lock.hcl",
        ):
            self.assertTrue(manifest._unparsed_manifest(path), path)
        for path in ("README.md", "action.json", "src/App.cs", "config.yml"):
            self.assertFalse(manifest._unparsed_manifest(path), path)

    def test_only_real_manifests_are_unparsed_everything_else_unresolved(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            _git_repo(root)
            for path in (
                "README.md",
                "src/lib.go",
                "poetry.lock",
                "Cargo.toml",
                "Dockerfile",
                "main.tf",
                "Package.swift",
            ):
                _commit(root, path, f"base {path}\n", f"base {path}")
            base = _git(root, "rev-parse", "HEAD")
            for path in (
                "README.md",
                "src/lib.go",
                "poetry.lock",
                "Cargo.toml",
                "Dockerfile",
                "main.tf",
                "Package.swift",
            ):
                _commit(root, path, f"changed {path}\n", f"change {path}")
            gaps = {item["package_name"]: item["not_scanned_reason"] for item in _gaps_at(root, base, [])}
            self.assertEqual(
                gaps,
                {
                    "README.md": "unresolved",
                    "src/lib.go": "unresolved",
                    "poetry.lock": "unresolved",
                    "Cargo.toml": "unparsed_manifest",
                    "Dockerfile": "unparsed_manifest",
                    "main.tf": "unparsed_manifest",
                    "Package.swift": "unparsed_manifest",
                },
            )

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

    def test_deleted_lockfile_after_a_caret_bump_is_a_gap(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            _git_repo(root)
            _commit(root, "package.json", json.dumps({"dependencies": {"lodash": "^4.17.20"}}) + "\n", "base manifest")
            _commit(
                root,
                "package-lock.json",
                json.dumps({"lockfileVersion": 3, "packages": {"node_modules/lodash": {"version": "4.17.20"}}}) + "\n",
                "base lock",
            )
            base = _git(root, "rev-parse", "HEAD")
            _commit(root, "package.json", json.dumps({"dependencies": {"lodash": "^4.17.21"}}) + "\n", "caret bump")
            _git(root, "rm", "-q", "package-lock.json")
            _git(root, "commit", "-qm", "delete lock")
            gaps = {item["package_name"] for item in _gaps_at(root, base, [_update("lodash", "4.17.20", "4.17.21")])}
            self.assertIn("package-lock.json", gaps, msg=gaps)

    def test_deleted_poetry_lock_after_an_exact_pin_is_a_gap(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            _git_repo(root)
            _commit(root, "requirements.txt", "requests==2.31.0\n", "base manifest")
            _commit(root, "poetry.lock", "[[package]]\nname = 'requests'\nversion = '2.31.0'\n", "base lock")
            base = _git(root, "rev-parse", "HEAD")
            _commit(root, "requirements.txt", "requests==2.32.0\n", "exact pin bump")
            _git(root, "rm", "-q", "poetry.lock")
            _git(root, "commit", "-qm", "delete lock")
            gaps = {item["package_name"] for item in _gaps_at(root, base, [_update("requests", "2.31.0", "2.32.0")])}
            self.assertIn("poetry.lock", gaps, msg=gaps)


class PackageJsonSectionsTest(unittest.TestCase):
    def test_bump_in_one_section_is_not_hidden_by_another(self) -> None:
        old = json.dumps({"dependencies": {"left-pad": "^1.0.0"}, "devDependencies": {"left-pad": "^1.0.0"}})
        new = json.dumps({"dependencies": {"left-pad": "^9.0.0"}, "devDependencies": {"left-pad": "^1.0.0"}})
        self.assertFalse(manifest._entries_explain("json", old, new, []))
        self.assertEqual(manifest._multi_entry_names("json", old, new, []), {"left-pad"})


def _npm_lock(spec: str, top: str, nested: str) -> str:
    def meta(version: str) -> dict:
        return {"version": version, "resolved": f"https://registry.npmjs.org/lodash/-/lodash-{version}.tgz"}

    packages = {
        "": {"name": "root", "dependencies": {"lodash": spec}},
        "node_modules/lodash": meta(top),
        "node_modules/a/node_modules/lodash": meta(nested),
    }
    return json.dumps({"lockfileVersion": 3, "packages": packages}) + "\n"


def _yarn_stanza(descriptor: str, version: str) -> str:
    return f'{descriptor}:\n  version "{version}"\n'


class LockWitnessTest(unittest.TestCase):
    def test_locked_versions_keep_only_the_top_level_npm_copy(self) -> None:
        lock = _npm_lock("^4.0.0", "4.17.21", "3.0.0")
        self.assertEqual(manifest._locked_versions("json", lock), {"lodash": frozenset({"4.17.21"})})
        legacy = json.dumps({"lockfileVersion": 1, "dependencies": {"lodash": {"version": "4.17.21"}}})
        self.assertEqual(manifest._locked_versions("json", legacy), {"lodash": frozenset({"4.17.21"})})

    def test_locked_versions_key_yarn_stanzas_by_descriptor(self) -> None:
        lock = '"lodash@^4.0.0", lodash@^4.17.0:\n  version "4.17.21"\n'
        self.assertEqual(
            manifest._locked_versions("yarn", lock),
            {"lodash@^4.0.0": frozenset({"4.17.21"}), "lodash@^4.17.0": frozenset({"4.17.21"})},
        )

    def test_nested_copy_does_not_witness_a_changed_lockfile(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            _git_repo(root)
            _commit(root, "package-lock.json", _npm_lock("^4.17.20", "4.17.20", "4.17.20"), "base")
            base = _git(root, "rev-parse", "HEAD")
            _commit(root, "package-lock.json", _npm_lock("^4.17.21", "4.17.20", "4.17.21"), "nested only")
            gaps = _gaps_at(root, base, [_update("lodash", "4.17.20", "4.17.21")])
            self.assertIn("package-lock.json", {item["package_name"] for item in gaps}, msg=gaps)

    def test_only_the_new_spec_yarn_stanza_witnesses_a_range_bump(self) -> None:
        for descriptor, witnessed in (("lodash@^4.0.0", False), ("lodash@^4.17.21", True)):
            with TemporaryDirectory() as tmp:
                root = Path(tmp) / "repo"
                _git_repo(root)
                _commit(root, "yarn.lock", _yarn_stanza(descriptor, "4.17.21"), "lock")
                _commit(root, "package.json", json.dumps({"dependencies": {"lodash": "^4.17.20"}}), "base")
                base = _git(root, "rev-parse", "HEAD")
                _commit(root, "package.json", json.dumps({"dependencies": {"lodash": "^4.17.21"}}), "caret bump")
                gaps = {
                    item["package_name"] for item in _gaps_at(root, base, [_update("lodash", "4.17.20", "4.17.21")])
                }
                self.assertEqual(gaps, set() if witnessed else {"package.json"}, descriptor)

    def test_v1_nested_copy_does_not_witness_its_parent_under_a_caret_bump(self) -> None:
        def lock(nested: str) -> str:
            return (
                json.dumps(
                    {
                        "lockfileVersion": 1,
                        "dependencies": {
                            "foo": {
                                "version": "1.0.0",
                                "dependencies": {
                                    "bar": {
                                        "version": "2.0.0",
                                        "dependencies": {"foo": {"version": nested}},
                                    }
                                },
                            }
                        },
                    }
                )
                + "\n"
            )

        witnesses = npm_manifest._json_witnesses(lock("1.3.0"))
        self.assertEqual(witnesses.get("foo"), frozenset({"1.0.0"}))
        self.assertNotIn("1.3.0", witnesses.get("foo", frozenset()))
        old_spec = json.dumps({"dependencies": {"foo": "^1.0.0"}})
        new_spec = json.dumps({"dependencies": {"foo": "^1.3.0"}})
        updates = [_update("foo", "1.0.0", "1.3.0")]
        self.assertFalse(manifest._lock_covers_listed("json", old_spec, new_spec, updates, {"foo"}, witnesses))
        self.assertTrue(
            manifest._lock_covers_listed("json", old_spec, new_spec, updates, {"foo"}, {"foo": frozenset({"1.3.0"})})
        )


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
        self.assertEqual(npm_manifest._yarn_names(header), ["@babel/core", "left-pad"])
        self.assertEqual(npm_manifest._yarn_names('"lodash@npm:^4.17.21":'), ["lodash"])


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


class ScannableTest(unittest.TestCase):
    def test_pep_440_pre_post_and_dev_releases_are_exact(self) -> None:
        def update(frm: str, to: str) -> dict:
            return {"packageName": "p", "fromVersion": frm, "toVersion": to, "upstreamRepo": "o/r"}

        for version in ("1.2.3rc1", "1.2.3a1", "1.2.3.post1", "1.2.3.dev0", "1.2.3rc1.post1.dev0"):
            self.assertEqual(version_manifest._exact_body(version), version)
            self.assertEqual(version_manifest._exact_body(f"=={version}"), version)
            self.assertEqual(version_manifest._exact_body(version, mode="spec"), version)
            self.assertEqual(version_manifest._exact_body(version, mode="dependabot"), version)
        for frm, to in (("1.2.3rc1", "1.2.3"), ("1.2.3", "1.2.3.post1"), ("1.2.3.dev0", "1.2.3.post1")):
            self.assertTrue(coverage.scannable(update(frm, to)), (frm, to))

    def test_only_exact_versions_with_a_github_repository_are_scannable(self) -> None:
        def update(frm: str, to: str, repo: str = "o/r") -> dict:
            return {"packageName": "p", "fromVersion": frm, "toVersion": to, "upstreamRepo": repo}

        for frm, to in (
            ("1.2.3", "1.2.4"),
            ("v1.2.3", "V1.2.4"),
            ("", "1.2.4"),
            ("1.2.3", "1.2.4-rc.1"),
            ("2024.1", "2024.2"),
            ("24.1", "24.2"),
            ("1.2.3.4", "1.2.3.5"),
        ):
            self.assertTrue(coverage.scannable(update(frm, to)), (frm, to))
        for frm, to in (
            (">=1.2.3", "1.2.4"),
            ("1.2.3", ">=1.2.4"),
            ("1.2.3", "^1.2.4"),
            ("1.2.3", "~=1.2.4"),
            ("1.2.3", "1.*"),
            ("1.2.3", "1.x"),
            ("1.2.3", "1.2.x"),
            ("1.2.3", "latest"),
            ("1", "1.2.4"),
            ("v4", "v5"),
            ("1.2.3", "==1.2.4"),
            ("1.2.3", "===1.2.4"),
        ):
            self.assertFalse(coverage.scannable(update(frm, to)), (frm, to))
        self.assertFalse(coverage.scannable(update("1.2.3", "1.2.4", "")))


if __name__ == "__main__":
    unittest.main()
