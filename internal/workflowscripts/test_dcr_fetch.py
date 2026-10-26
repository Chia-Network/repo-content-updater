"""Tests for dcr_fetch: updates, literal checks, fetchers, extraction and diff."""

from __future__ import annotations

import io
import json
import os
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

_SCRIPTS = Path(__file__).resolve().parent
_TESTDATA = _SCRIPTS / "testdata"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import dcr_fetch
from dcr_fetch import FetchError, Update


def _tar_bytes(files):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as handle:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            handle.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _zip_bytes(files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as handle:
        for name, data in files.items():
            handle.writestr(name, data)
    return buffer.getvalue()


def _update(name="left-pad", ecosystem="npm_and_yarn", prev="1.0.0", new="1.0.1"):
    return Update(name, ecosystem, "/", prev, new)


def _dep(name, ecosystem="npm_and_yarn", prev="1.0.0", new="1.0.1"):
    return {
        "dependencyName": name,
        "packageEcosystem": ecosystem,
        "prevVersion": prev,
        "newVersion": new,
        "directory": "/",
    }


def _environment(tmp, updates, added="left-pad 1.0.1"):
    diff = Path(tmp) / "pr.diff"
    diff.write_text(f"--- a\n+++ b\n+{added}\n", encoding="utf-8")
    return {
        "DCR_OUT": str(Path(tmp) / "out"),
        "PR_DIFF_PATH": str(diff),
        "UPDATED_DEPENDENCIES_JSON": json.dumps(updates),
        "GITHUB_OUTPUT": str(Path(tmp) / "github-output"),
    }


class ParseUpdatesTest(unittest.TestCase):
    def test_go_modules_alias_and_leading_v(self):
        update = dcr_fetch._parse_updates(json.dumps([_dep("example.com/mod", "go_modules")]))[0]
        self.assertEqual((update.ecosystem, update.prev_version, update.new_version), ("gomod", "v1.0.0", "v1.0.1"))


class LiteralCheckTest(unittest.TestCase):
    def _fixture(self, name):
        return dcr_fetch.added_lines((_TESTDATA / name).read_text(encoding="utf-8"))

    def test_poetry_fixtures_pass(self):
        cases = (
            ("poetry_miniupnpc.diff", "miniupnpc", "2.3.2", "2.3.3"),
            ("poetry_chia_rs.diff", "chia-rs", "0.50.0", "0.52.0"),
        )
        for filename, name, prev, new in cases:
            self.assertTrue(dcr_fetch.literal_ok(_update(name, "pip", prev, new), self._fixture(filename)))

    def test_npm_go_and_wrong_version(self):
        self.assertTrue(dcr_fetch.literal_ok(_update(), ['"left-pad": "1.0.1",']))
        mod = _update("example.com/mod", "gomod", "v1.0.0", "v1.0.1")
        self.assertTrue(dcr_fetch.literal_ok(mod, ["example.com/mod v1.0.1 h1:abc"]))
        wrong = _update("miniupnpc", "pip", "2.3.2", "2.3.4")
        self.assertFalse(dcr_fetch.literal_ok(wrong, self._fixture("poetry_miniupnpc.diff")))


class StatusTest(unittest.TestCase):
    def test_cargo_and_tag_actions_are_not_reviewed(self):
        cargo = dcr_fetch._status(_update("tokio", "cargo"), ["tokio 1.0.1"])
        action = dcr_fetch._status(_update("owner/repo", "github_actions", "v1.0.0", "v1.1.0"), ["x"])
        self.assertEqual((cargo.status, action.status), ("not_reviewed", "not_reviewed"))

    def test_unsafe_name_and_wrong_literal_are_unverified(self):
        unsafe = dcr_fetch._status(_update("-bad"), ["-bad 1.0.1"])
        mismatch = dcr_fetch._status(_update(), ["other-package 1.0.1"])
        self.assertEqual((unsafe.status, mismatch.status), ("unverified", "unverified"))


class FetcherTest(unittest.TestCase):
    def test_npm_pack_disables_scripts(self):
        calls = []

        def run(args, **kwargs):
            calls.append(args)
            Path(kwargs["cwd"]).joinpath("package.tgz").write_bytes(b"tar")
            return mock.Mock()

        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(dcr_fetch, "_run", side_effect=run):
            archive = dcr_fetch.fetch_npm(Path(tmp), "left-pad", "1.0.1")
            self.assertEqual(archive.read_bytes(), b"tar")
        self.assertEqual(calls, [["npm", "pack", "--ignore-scripts", "left-pad@1.0.1"]])

    def test_pypi_chooses_the_sdist_and_downloads_it(self):
        tarball = _tar_bytes({"package/setup.py": b"VALUE = 1\n"})
        payload = {
            "urls": [
                {"packagetype": "bdist_wheel", "filename": "example.whl", "url": "w"},
                {"packagetype": "sdist", "filename": "example.tar.gz", "url": "s"},
            ]
        }

        def fake(url, timeout=0):
            return io.BytesIO(json.dumps(payload).encode() if url.endswith("/json") else tarball)

        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(dcr_fetch, "urlopen", side_effect=fake):
            archive = dcr_fetch.fetch_pypi(Path(tmp), "example", "1.0.1")
            self.assertEqual(archive.name, "example.tar.gz")
            self.assertEqual(archive.read_bytes(), tarball)

    def test_go_mod_download_returns_the_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "module.zip"
            archive.write_bytes(_zip_bytes({"go.mod": b"module example.com/mod\n"}))
            result = mock.Mock(stdout=json.dumps({"Zip": str(archive)}))
            with mock.patch.object(dcr_fetch, "_run", return_value=result) as run:
                self.assertEqual(dcr_fetch.fetch_gomod(Path(tmp), "example.com/mod", "v1.0.1"), archive)
            self.assertIn("example.com/mod@v1.0.1", run.call_args.args[0])

    def test_action_fetch_uses_the_sha_and_removes_git(self):
        calls = []
        sha = "a" * 40

        def run(args, **kwargs):
            calls.append(args)
            Path(kwargs["cwd"]).joinpath("action.yml").write_text("name: test\n", encoding="utf-8")
            return mock.Mock()

        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(dcr_fetch, "_run", side_effect=run):
            source = dcr_fetch.fetch_action(Path(tmp), "owner/repo", sha)
            self.assertTrue((source / "action.yml").is_file())
        self.assertEqual(calls[1], ["git", "fetch", "--depth", "1", "https://github.com/owner/repo", sha])
        self.assertEqual(calls[-1], ["rm", "-rf", ".git"])


class ExtractTest(unittest.TestCase):
    def test_tar_and_zip_extraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tar = root / "package.tar.gz"
            tar.write_bytes(_tar_bytes({"one.txt": b"1"}))
            dcr_fetch.extract(tar, root / "tar")
            self.assertEqual((root / "tar" / "one.txt").read_bytes(), b"1")
            archive = root / "package.zip"
            archive.write_bytes(_zip_bytes({"two.txt": b"2"}))
            dcr_fetch.extract(archive, root / "zip")
            self.assertEqual((root / "zip" / "two.txt").read_bytes(), b"2")


class MainTest(unittest.TestCase):
    def test_meta_shape_and_github_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = _environment(tmp, [_dep("tokio", "cargo")], added="tokio 1.0.1")
            with (
                mock.patch.dict(os.environ, env),
                mock.patch.object(dcr_fetch, "_run", return_value=mock.Mock(stdout=b"")),
            ):
                self.assertEqual(dcr_fetch.main(), 0)
            meta = json.loads((Path(env["DCR_OUT"]) / "meta.json").read_text(encoding="utf-8"))
            self.assertEqual(
                (set(meta), meta["schema"], meta["updates"][0]["status"]),
                ({"schema", "updates"}, 1, "not_reviewed"),
            )
            self.assertEqual(Path(env["GITHUB_OUTPUT"]).read_text(encoding="utf-8"), "reviewable=false\n")

    def test_diff_error_marks_reviewed_fetch_failed(self):
        def fetch(work, name, version):
            archive = work / "package.tgz"
            archive.write_bytes(_tar_bytes({"index.js": b"module.exports = 1;\n"}))
            return archive

        def run(args, **kwargs):
            if args[0] == "diff":
                raise FetchError("boom")
            raise AssertionError(args)

        with tempfile.TemporaryDirectory() as tmp:
            env = _environment(tmp, [_dep("left-pad")])
            with (
                mock.patch.dict(os.environ, env),
                mock.patch.dict(dcr_fetch.FETCHERS, {"npm_and_yarn": fetch}),
                mock.patch.object(dcr_fetch, "_run", side_effect=run),
            ):
                self.assertEqual(dcr_fetch.main(), 0)
            meta = json.loads((Path(env["DCR_OUT"]) / "meta.json").read_text(encoding="utf-8"))
            self.assertEqual(meta["updates"][0]["status"], "fetch_failed")
            self.assertTrue(meta["updates"][0]["note"].startswith("diff failed:"))
            self.assertEqual(Path(env["GITHUB_OUTPUT"]).read_text(encoding="utf-8"), "reviewable=false\n")


if __name__ == "__main__":
    unittest.main()
