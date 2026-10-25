"""A sourced Python lock entry reaches the trust check only from an index source."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import dependency_cursor_review_upstream as upstream
import dependency_update_coverage as coverage
from test_dependency_update_coverage import _clean, _commit, _git, _git_repo

_CHIA = "https://pypi.chia.net/simple/"
_PAGE_URL = f"{_CHIA}chiapos/"
_SDIST = b"chiapos sdist"
_WHEEL = b"chiapos wheel"
_SDIST_URL = "https://download.chia.net/files/chiapos-2.0.4.tar.gz"
_WHEEL_URL = "https://download.chia.net/files/chiapos-2.0.4-cp312-cp312-manylinux_2_28_x86_64.whl"
_PAGE = f'<a href="{_SDIST_URL}">s</a>\n<a href="{_WHEEL_URL}">w</a>\n'.encode()
_NEXT_PAGE = "https://download.chia.net/simple/chiapos/"
_MANIFEST = {"pyproject.toml": '[tool.poetry.dependencies]\nchiapos = "*"\n'}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _poetry_lock(version: str, source: str, *hashes: str) -> str:
    files = ",\n".join(f'    {{file = "chiapos-{version}.tar.gz", hash = "sha256:{value}"}}' for value in hashes)
    return (
        f'[[package]]\nname = "chiapos"\nversion = "{version}"\nfiles = [\n{files}\n]\n'
        f'{source}\n[metadata]\nlock-version = "2.0"\ncontent-hash = "abc"\n'
    )


def _pipfile_lock(version: str, record: dict) -> str:
    meta = {"hash": {"sha256": "abc"}, "pipfile-spec": 6, "sources": [{"name": "pypi", "url": _CHIA}]}
    block = {"chiapos": {"version": f"=={version}", **record}}
    return json.dumps({"_meta": meta, "default": block, "develop": {}}, indent=2) + "\n"


class _Response:
    def __init__(self, body: bytes, status: int = 200) -> None:
        self.status = status
        self.body = body

    def getheader(self, _name: str) -> None:
        return None

    def read1(self, size: int = -1) -> bytes:
        if size < 0:
            size = len(self.body)
        chunk, self.body = self.body[:size], self.body[size:]
        return chunk


class _Socket:
    def settimeout(self, _value: float) -> None:
        return None


class _Connection:
    def __init__(self) -> None:
        self.sock = _Socket()

    def close(self) -> None:
        return None


class SourcedLockEntryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.scanned: list[coverage.Target] = []

    def run_main(self, base: dict[str, str], head: dict[str, str]) -> tuple[dict, list[str]]:
        """coverage.main() over the real diff of `base` and `head`, and the URLs it requested."""
        self.scanned = []
        root = Path(self.enterContext(TemporaryDirectory())) / "repo"
        _git_repo(root)
        for path, text in base.items():
            _commit(root, path, text, f"base {path}")
        base_sha = _git(root, "rev-parse", "HEAD")
        _git(root, "checkout", "-q", "-b", "pr")
        for path, text in head.items():
            if base.get(path) != text:
                _commit(root, path, text, f"head {path}")
        requested: list[str] = []

        def get_response(url: str, _accept: str, _budget: object = None) -> tuple[_Connection, _Response]:
            requested.append(url)
            answers = {_PAGE_URL: _PAGE, _SDIST_URL: _SDIST, _WHEEL_URL: _WHEEL}
            return _Connection(), _Response(answers.get(url, b""), 200 if url in answers else 404)

        def repo(_ecosystem: str, name: str, _version: str) -> upstream.Repo:
            return upstream.Repo(f"upstream/{name}", upstream.IDENTITY)

        def scan(update: coverage.Target, *_args: object) -> dict:
            self.scanned.append(update)
            return _clean(update.package, update.repo.slug)

        out = root.parent / "out"
        out.mkdir(exist_ok=True)
        variables = {"PR_BASE_SHA": base_sha, "DCR_OUT": str(out), "GITHUB_OUTPUT": str(out / "github_output.txt")}
        with (
            contextlib.chdir(root),
            patch.dict(os.environ, variables),
            patch.object(upstream, "_get_response", get_response),
            patch.object(coverage._ecosystems, "upstream_repo", repo),
            patch.object(coverage, "_scan_one", scan),
        ):
            os.environ.pop("GITHUB_BASE_REF", None)
            coverage.main()
        report = json.loads((out / "malware_scan_report.json").read_text(encoding="utf-8"))
        return report, requested

    def assert_trusted(self, report: dict, requested: list[str]) -> None:
        self.assertEqual(
            [(item["name"], item["index"]) for item in report["trusted_packages"]],
            [("chiapos", "pypi.chia.net")],
        )
        self.assertEqual(self.scanned, [])
        self.assertEqual(requested, [_PAGE_URL, _SDIST_URL])

    def assert_scanned(self, report: dict, requested: list[str]) -> None:
        self.assertEqual(report["trusted_packages"], [])
        self.assertEqual([(target.package, target.new) for target in self.scanned], [("chiapos", "2.0.4")])
        self.assertEqual(requested, [])

    def bump_poetry(self, source: str, *hashes: str) -> tuple[dict, list[str]]:
        base = {**_MANIFEST, "poetry.lock": _poetry_lock("2.0.3", source, *hashes)}
        head = {**_MANIFEST, "poetry.lock": _poetry_lock("2.0.4", source, *hashes)}
        return self.run_main(base, head)

    def test_a_poetry_legacy_source_with_trusted_index_hashes_is_trusted(self) -> None:
        source = '[package.source]\ntype = "legacy"\nurl = "https://pypi.chia.net/simple"\nreference = "chia"\n'
        report, requested = self.bump_poetry(source, _sha(_SDIST))
        self.assert_trusted(report, requested)

    def test_a_poetry_url_source_with_files_is_trusted(self) -> None:
        source = '[package.source]\ntype = "url"\nurl = "https://example.com/chiapos-2.0.4.tar.gz"\n'
        report, requested = self.bump_poetry(source, _sha(_SDIST))
        self.assert_trusted(report, requested)

    def test_a_poetry_url_source_without_files_is_scanned(self) -> None:
        source = '[package.source]\ntype = "url"\nurl = "https://example.com/chiapos-2.0.4.tar.gz"\n'
        report, requested = self.bump_poetry(source)
        self.assert_scanned(report, requested)

    def test_a_poetry_source_the_installer_does_not_hash_check_is_scanned(self) -> None:
        for kind, extra in (
            ("git", 'url = "https://github.com/example/chiapos.git"\nreference = "abc"\n'),
            ("directory", 'url = "../chiapos"\n'),
            ("file", 'url = "chiapos-2.0.4.tar.gz"\n'),
        ):
            with self.subTest(kind=kind):
                source = f'[package.source]\ntype = "{kind}"\n{extra}'
                report, requested = self.bump_poetry(source, _sha(_SDIST))
                self.assert_scanned(report, requested)

    def test_a_pipfile_index_source_with_hashes_is_trusted(self) -> None:
        record = {"hashes": [f"sha256:{_sha(_SDIST)}"], "index": "chia"}
        base = {"Pipfile": '[packages]\nchiapos = "*"\n', "Pipfile.lock": _pipfile_lock("2.0.3", record)}
        head = {"Pipfile": '[packages]\nchiapos = "*"\n', "Pipfile.lock": _pipfile_lock("2.0.4", record)}
        report, requested = self.run_main(base, head)
        self.assert_trusted(report, requested)

    def test_a_pipfile_git_source_with_hashes_is_scanned(self) -> None:
        record = {
            "hashes": [f"sha256:{_sha(_SDIST)}"],
            "git": "https://github.com/example/chiapos.git",
            "ref": "abc",
        }
        base = {"Pipfile": '[packages]\nchiapos = "*"\n', "Pipfile.lock": _pipfile_lock("2.0.3", record)}
        head = {"Pipfile": '[packages]\nchiapos = "*"\n', "Pipfile.lock": _pipfile_lock("2.0.4", record)}
        report, requested = self.run_main(base, head)
        self.assert_scanned(report, requested)


if __name__ == "__main__":
    unittest.main()
