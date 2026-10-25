"""Requirements-file includer discovery over a real tracked tree."""

from __future__ import annotations

import contextlib
import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import dependency_cursor_review_upstream as upstream
import dependency_update_coverage as coverage
from test_dependency_update_coverage import _clean, _found, _git, _git_repo, _plan

_CHIA = "https://pypi.chia.net/simple/"
_BASE = f"-i {_CHIA}\nchiapos==2.0.4 --hash=sha256:abc\n"
_UNHASHED_BASE = f"-i {_CHIA}\nchiapos==2.0.4\n"
_PLAIN = "chiapos==2.0.4\n"


def _write(repo: Path, rel: str, data: bytes, message: str) -> None:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    _git(repo, "add", rel)
    _git(repo, "commit", "-m", message)


def _write_many(repo: Path, files: dict[str, bytes], message: str) -> None:
    for rel, data in files.items():
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", message)


def _symlink(repo: Path, rel: str, target: str, message: str) -> None:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(target, path)
    _git(repo, "add", rel)
    _git(repo, "commit", "-m", message)


def _run(repo: Path, *, trusted_host: str = "") -> dict:
    root = repo.parent
    output = root / "github_output.txt"
    plan = _plan(("pip", ".", "chiapos", "2.0.3", "2.0.4"), hashed=("requirements.txt",))
    with (
        contextlib.chdir(repo),
        patch.dict(os.environ, {"GITHUB_OUTPUT": str(output), "DCR_OUT": str(root)}),
        patch.object(coverage, "_plan", return_value=plan),
        patch.object(
            coverage._ecosystems,
            "upstream_repo",
            lambda _ecosystem, name, _version: _found(f"upstream/{name}"),
        ),
        patch.object(
            coverage,
            "_scan_one",
            lambda target, *_args: _clean(target.package, target.repo.slug),
        ),
        patch.object(
            upstream,
            "trusted_python_index",
            lambda _name, _version, locked, _configured: trusted_host if any(item.index for item in locked) else "",
        ),
    ):
        coverage.main()
    return json.loads((root / "malware_scan_report.json").read_text(encoding="utf-8"))


def _run_settings(repo: Path) -> tuple[dict, list[str]]:
    """coverage.main() over the real tree: (report, each package that was looked up)."""
    root = repo.parent
    output = root / "github_output.txt"
    plan = _plan(("pip", ".", "chiapos", "2.0.3", "2.0.4"), hashed=("requirements.txt",))
    looked_up: list[str] = []

    def find(_ecosystem: str, name: str, _version: str) -> upstream.Repo:
        looked_up.append(name)
        return _found(f"upstream/{name}")

    def trusted(_name: str, _version: str, locked: tuple[upstream.Locked, ...], _configured: frozenset[str]) -> str:
        return "pypi.chia.net" if locked and all(item.index for item in locked) else ""

    with (
        contextlib.chdir(repo),
        patch.dict(os.environ, {"GITHUB_OUTPUT": str(output), "DCR_OUT": str(root)}),
        patch.object(coverage, "_plan", return_value=plan),
        patch.object(coverage._ecosystems, "upstream_repo", find),
        patch.object(coverage, "_scan_one", lambda target, *_args: _clean(target.package, target.repo.slug)),
        patch.object(upstream, "trusted_python_index", trusted),
    ):
        coverage.main()
    report = json.loads((root / "malware_scan_report.json").read_text(encoding="utf-8"))
    return report, looked_up


class IncluderDiscoveryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(self.enterContext(TemporaryDirectory())) / "repo"
        _git_repo(self.root)

    def _assert_scanned(self, report: dict) -> None:
        self.assertEqual(report["trusted_packages"], [])
        self.assertIs(report["scan_conclusive"], True)

    def _assert_trusted(self, report: dict) -> None:
        self.assertEqual(
            [(item["name"], item["index"]) for item in report["trusted_packages"]],
            [("chiapos", "pypi.chia.net")],
        )

    def test_a_symlink_alias_of_the_base_leaves_it_unable_to_replace(self) -> None:
        _write(self.root, "requirements.txt", _BASE.encode(), "base")
        _symlink(self.root, "link.txt", "requirements.txt", "alias")
        _write(self.root, "dev.txt", b"-r link.txt\n", "dev")
        self._assert_scanned(_run(self.root, trusted_host="pypi.chia.net"))

    def test_a_symlink_alias_with_no_trusted_index_is_scanned(self) -> None:
        _write(self.root, "requirements.txt", _PLAIN.encode(), "base")
        _symlink(self.root, "link.txt", "requirements.txt", "alias")
        _write(self.root, "dev.txt", b"-r link.txt\n", "dev")
        self._assert_scanned(_run(self.root))

    def test_a_utf16_requirements_file_that_does_not_name_the_base_is_ignored(
        self,
    ) -> None:
        _write(self.root, "requirements.txt", _BASE.encode(), "base")
        _write(
            self.root,
            "dev-requirements.txt",
            "chiapos==2.0.4\n".encode("utf-16"),
            "dev",
        )
        self._assert_trusted(_run(self.root, trusted_host="pypi.chia.net"))

    def test_a_utf16_requirements_file_that_names_the_base_leaves_it_unable_to_replace(
        self,
    ) -> None:
        _write(self.root, "requirements.txt", _BASE.encode(), "base")
        _write(
            self.root,
            "dev-requirements.txt",
            "-r requirements.txt\n".encode("utf-16"),
            "dev",
        )
        self._assert_scanned(_run(self.root, trusted_host="pypi.chia.net"))

    def test_a_nul_byte_in_a_requirements_file_that_does_not_name_the_base_is_ignored(
        self,
    ) -> None:
        _write(self.root, "requirements.txt", _BASE.encode(), "base")
        _write(self.root, "dev-requirements.txt", b"# note\x00\n", "dev")
        self._assert_trusted(_run(self.root, trusted_host="pypi.chia.net"))

    def test_a_binary_text_fixture_that_does_not_name_the_base_is_ignored(self) -> None:
        _write(self.root, "requirements.txt", _BASE.encode(), "base")
        _write(self.root, "fixture.txt", b"\x00\x01binary fixture\n", "fixture")
        self._assert_trusted(_run(self.root, trusted_host="pypi.chia.net"))

    def test_a_latin1_license_that_does_not_name_the_base_is_ignored(self) -> None:
        _write(self.root, "requirements.txt", _BASE.encode(), "base")
        _write(self.root, "LICENSE.txt", b"caf\xe9 license text\n", "license")
        self._assert_trusted(_run(self.root, trusted_host="pypi.chia.net"))

    def test_ordinary_utf8_text_files_keep_the_base_trusted(self) -> None:
        _write(self.root, "requirements.txt", _BASE.encode(), "base")
        _write(self.root, "LICENSE.txt", b"license text\n", "license")
        _write(self.root, "docs/notes.txt", b"ordinary notes\n", "notes")
        self._assert_trusted(_run(self.root, trusted_host="pypi.chia.net"))

    def test_a_non_utf8_readme_mention_is_scanned(self) -> None:
        _write(self.root, "requirements.txt", _BASE.encode(), "base")
        _write(self.root, "README.md", b"See requirements.txt for caf\xe9.\n", "readme")
        self._assert_scanned(_run(self.root, trusted_host="pypi.chia.net"))

    def test_a_readme_bullet_that_names_the_base_is_scanned(self) -> None:
        _write(self.root, "requirements.txt", _BASE.encode(), "base")
        _write(self.root, "README.md", b"- Don't edit requirements.txt\n", "readme")
        self._assert_scanned(_run(self.root, trusted_host="pypi.chia.net"))

    def test_a_readme_with_an_unrelated_bullet_and_a_pip_command_keeps_the_base_trusted(
        self,
    ) -> None:
        _write(self.root, "requirements.txt", _BASE.encode(), "base")
        _write(
            self.root,
            "README.md",
            b"- Don't do X\n\nRun `pip install -r requirements.txt`.\n",
            "readme",
        )
        self._assert_trusted(_run(self.root, trusted_host="pypi.chia.net"))

    def test_a_binary_text_fixture_with_no_trusted_index_is_scanned(self) -> None:
        _write(self.root, "requirements.txt", _PLAIN.encode(), "base")
        _write(self.root, "fixture.txt", b"\x00\x01binary fixture\n", "fixture")
        self._assert_scanned(_run(self.root))

    def test_a_latin1_file_that_names_pip_with_no_trusted_index_is_scanned(
        self,
    ) -> None:
        _write(self.root, "requirements.txt", _PLAIN.encode(), "base")
        _write(self.root, "notes.txt", b"run pip install caf\xe9\n", "notes")
        self._assert_scanned(_run(self.root))

    def test_a_latin1_file_that_names_pip_is_scanned(self) -> None:
        _write(self.root, "requirements.txt", _BASE.encode(), "base")
        _write(self.root, "README.md", b"run pip install caf\xe9\n", "readme")
        self._assert_scanned(_run(self.root, trusted_host="pypi.chia.net"))

    def test_more_pip_candidates_than_the_cap_with_no_trusted_index_is_scanned(
        self,
    ) -> None:
        _write(self.root, "requirements.txt", _PLAIN.encode(), "base")
        _write_many(
            self.root,
            {f"docs/pip{index}.txt": b"pip\n" for index in range(300)},
            "pip candidates",
        )
        self._assert_scanned(_run(self.root))

    def test_more_pip_candidates_than_the_cap_with_a_trusted_index_is_scanned(
        self,
    ) -> None:
        _write(self.root, "requirements.txt", _BASE.encode(), "base")
        _write_many(
            self.root,
            {f"docs/pip{index}.txt": b"pip\n" for index in range(300)},
            "pip candidates",
        )
        self._assert_scanned(_run(self.root, trusted_host="pypi.chia.net"))

    def test_many_files_containing_pipe_keep_the_base_trusted(self) -> None:
        _write(self.root, "requirements.txt", _BASE.encode(), "base")
        _write_many(
            self.root,
            {f"docs/pipe{index}.txt": b"pipe\n" for index in range(300)},
            "pipes",
        )
        self._assert_trusted(_run(self.root, trusted_host="pypi.chia.net"))

    def test_a_latin1_readme_containing_pipeline_keeps_the_base_trusted(self) -> None:
        _write(self.root, "requirements.txt", _BASE.encode(), "base")
        _write(self.root, "README.md", "pipeline caf\xe9\n".encode("latin-1"), "readme")
        self._assert_trusted(_run(self.root, trusted_host="pypi.chia.net"))

    def test_more_than_the_byte_cap_of_text_is_scanned(self) -> None:
        _write(self.root, "requirements.txt", _BASE.encode(), "base")
        _write(self.root, "notes.txt", b"x" * (9 * 1024 * 1024), "large text")
        self._assert_scanned(_run(self.root, trusted_host="pypi.chia.net"))

    def test_a_latin1_dependabot_config_is_inconclusive(self) -> None:
        _write(self.root, "requirements.txt", _BASE.encode(), "base")
        _write(self.root, ".github/dependabot.yml", b"version: 2\n# caf\xe9\n", "config")
        report = _run(self.root, trusted_host="pypi.chia.net")
        self.assertEqual(report["trusted_packages"], [])
        self.assertIs(report["scan_conclusive"], False)


class PipSettingsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(self.enterContext(TemporaryDirectory())) / "repo"
        _git_repo(self.root)
        _write(self.root, "requirements.txt", _UNHASHED_BASE.encode(), "base")

    def _assert_scanned(self, report: dict, looked_up: list[str]) -> None:
        self.assertEqual(looked_up, ["chiapos"])
        self.assertEqual(report["trusted_packages"], [])

    def test_a_repository_pip_conf_is_scanned(self) -> None:
        _write(self.root, "pip.conf", b"[global]\nindex-url = https://pypi.org/simple/\n", "pip config")
        report, looked_up = _run_settings(self.root)
        self._assert_scanned(report, looked_up)

    def test_a_uv_environment_is_scanned(self) -> None:
        _write(
            self.root,
            ".github/workflows/ci.yml",
            b"env:\n  UV_INDEX_URL: https://pypi.org/simple/\n",
            "uv workflow",
        )
        report, looked_up = _run_settings(self.root)
        self._assert_scanned(report, looked_up)

    def test_a_pip_config_command_is_scanned(self) -> None:
        _write(
            self.root,
            ".github/workflows/ci.yml",
            b"jobs:\n  test:\n    steps:\n      - run: pip config set global.index-url https://pypi.org/simple/\n",
            "pip config command",
        )
        report, looked_up = _run_settings(self.root)
        self._assert_scanned(report, looked_up)

    def test_a_case_variant_pip_conf_is_scanned(self) -> None:
        _write(self.root, "PIP.CONF", b"[global]\nindex-url = https://pypi.org/simple/\n", "pip config")
        report, looked_up = _run_settings(self.root)
        self._assert_scanned(report, looked_up)

    def test_a_tox_indexserver_is_scanned(self) -> None:
        _write(
            self.root,
            "tox.ini",
            b"[testenv]\nindexserver = https://pypi.org/simple/\n",
            "tox indexserver",
        )
        report, looked_up = _run_settings(self.root)
        self._assert_scanned(report, looked_up)

    def test_a_tox_setenv_is_scanned(self) -> None:
        _write(
            self.root,
            "tox.ini",
            b"[testenv]\nsetenv = PIP_EXTRA_INDEX_URL=https://pypi.org/simple/\n",
            "tox",
        )
        report, looked_up = _run_settings(self.root)
        self._assert_scanned(report, looked_up)

    def test_a_workflow_environment_is_scanned(self) -> None:
        _write(
            self.root,
            ".github/workflows/ci.yml",
            b"env:\n  PIP_INDEX_URL: https://pypi.org/simple/\n",
            "workflow",
        )
        report, looked_up = _run_settings(self.root)
        self._assert_scanned(report, looked_up)

    def test_a_workflow_pip_command_is_scanned(self) -> None:
        _write(
            self.root,
            ".github/workflows/ci.yml",
            b"jobs:\n  test:\n    steps:\n"
            b"      - run: pip install -r requirements.txt --extra-index-url https://pypi.org/simple/\n",
            "workflow",
        )
        report, looked_up = _run_settings(self.root)
        self._assert_scanned(report, looked_up)

    def test_a_dockerfile_short_option_is_scanned(self) -> None:
        _write(
            self.root,
            "Dockerfile",
            b"FROM python:3.12\nRUN pip install -i https://pypi.org/simple/ -r requirements.txt\n",
            "dockerfile",
        )
        report, looked_up = _run_settings(self.root)
        self._assert_scanned(report, looked_up)

    def test_a_makefile_continuation_is_scanned(self) -> None:
        _write(
            self.root,
            "Makefile",
            b"install:\n\tpython -m pip install \\\n\t\t--find-links dist/ -r requirements.txt\n",
            "makefile",
        )
        report, looked_up = _run_settings(self.root)
        self._assert_scanned(report, looked_up)

    def test_another_tool_and_prose_keep_the_change_trusted(self) -> None:
        _write(
            self.root,
            ".github/workflows/ci.yml",
            b"jobs:\n  test:\n    steps:\n"
            b"      - run: |\n          sed -i s/a/b/ f\n          grep -i x f\n"
            b"          pip install -r requirements.txt\n",
            "workflow",
        )
        _write(self.root, "Makefile", b"clean:\n\trm -f x\n", "makefile")
        _write(self.root, "README.md", b"Use --no-index when offline.\n", "readme")
        _write(
            self.root,
            "package.json",
            b'{"scripts": {"install": "npm install --registry https://registry.npmjs.org/"}}\n',
            "npm",
        )
        report, looked_up = _run_settings(self.root)
        self.assertEqual(looked_up, [])
        self.assertEqual(
            [(item["name"], item["index"]) for item in report["trusted_packages"]],
            [("chiapos", "pypi.chia.net")],
        )

    def test_a_pip_command_inside_a_requirements_file_keeps_the_change_trusted(self) -> None:
        _write(
            self.root,
            "requirements.txt",
            (_UNHASHED_BASE + "# pip install --extra-index-url https://pypi.org/simple/\n").encode(),
            "base",
        )
        report, looked_up = _run_settings(self.root)
        self.assertEqual(looked_up, [])
        self.assertEqual(
            [(item["name"], item["index"]) for item in report["trusted_packages"]],
            [("chiapos", "pypi.chia.net")],
        )

    def test_a_later_pip_install_on_one_line_is_scanned(self) -> None:
        _write(
            self.root,
            "Makefile",
            b"install:\n\tpip install setuptools && pip install -i https://pypi.org/simple/ -r requirements.txt\n",
            "makefile",
        )
        report, looked_up = _run_settings(self.root)
        self._assert_scanned(report, looked_up)

    def test_a_yaml_folded_option_is_scanned(self) -> None:
        _write(
            self.root,
            ".github/workflows/ci.yml",
            b"jobs:\n  test:\n    steps:\n      - run: >\n"
            b"          pip install -r requirements.txt\n          -i https://pypi.org/simple/\n",
            "workflow",
        )
        report, looked_up = _run_settings(self.root)
        self._assert_scanned(report, looked_up)

    def test_a_dockerfile_exec_form_option_is_scanned(self) -> None:
        _write(
            self.root,
            "Dockerfile",
            b'FROM python:3.12\nRUN ["pip", "install", "-i", "https://pypi.org/simple/", "-r", "requirements.txt"]\n',
            "dockerfile",
        )
        report, looked_up = _run_settings(self.root)
        self._assert_scanned(report, looked_up)

    def test_a_nox_session_install_is_scanned(self) -> None:
        _write(
            self.root,
            "noxfile.py",
            b"session.install('-i', 'https://pypi.org/simple/', '-r', 'requirements.txt')\n",
            "nox",
        )
        report, looked_up = _run_settings(self.root)
        self._assert_scanned(report, looked_up)

    def test_a_uv_default_index_is_scanned(self) -> None:
        _write(
            self.root,
            ".github/workflows/ci.yml",
            b"env:\n  UV_DEFAULT_INDEX: https://pypi.org/simple/\n",
            "uv workflow",
        )
        report, looked_up = _run_settings(self.root)
        self._assert_scanned(report, looked_up)

    def test_a_latin1_manifest_that_names_the_package_is_scanned(self) -> None:
        for name, text in {
            "setup.py": b"install_requires=['chiapos']  # caf\xe9\n",
            "setup.cfg": b"[options]\ninstall_requires =\n    chiapos  # caf\xe9\n",
            "Pipfile": b'[packages]\nchiapos = "*"  # caf\xe9\n',
        }.items():
            with self.subTest(name):
                path = self.root / name
                path.write_bytes(text)
                _git(self.root, "add", name)
                _git(self.root, "commit", "-m", f"latin-1 {name}")
                report, looked_up = _run_settings(self.root)
                self.assertEqual(looked_up, ["chiapos"])
                self.assertEqual(report["trusted_packages"], [])
                path.unlink()
                _git(self.root, "add", name)
                _git(self.root, "commit", "-m", f"remove {name}")


if __name__ == "__main__":
    unittest.main()
