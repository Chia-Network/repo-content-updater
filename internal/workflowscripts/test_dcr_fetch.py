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


def _uses(marker, pin):
    return f"{marker} uses: owner/repo@{pin} # v\n"


def _environment(tmp, updates, added="left-pad 1.0.1", diff=None):
    path = Path(tmp) / "pr.diff"
    path.write_text(diff or f"--- a\n+++ b\n+{added}\n", encoding="utf-8")
    return {
        "DCR_OUT": str(Path(tmp) / "out"),
        "PR_DIFF_PATH": str(path),
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

    def test_version_matches_require_token_boundaries(self):
        cases = (
            ("7", "left-pad ^7.0.1", False),
            ("1.2", "left-pad 1.20.0", False),
            ("1.0.1", "left-pad 1.0.1", True),
        )
        for version, line, expected in cases:
            self.assertEqual(dcr_fetch.literal_ok(_update(new=version), [line]), expected, line)


class StatusTest(unittest.TestCase):
    def test_cargo_and_tag_actions_are_not_reviewed(self):
        cargo = dcr_fetch._status(_update("tokio", "cargo"), "")
        action = dcr_fetch._status(_update("owner/repo", "github_actions", "v1", "v2"), "+uses: owner/repo@v2")
        self.assertEqual((cargo.status, action.status), ("not_reviewed", "not_reviewed"))

    def test_unsafe_name_and_wrong_literal_are_unverified(self):
        unsafe = dcr_fetch._status(_update("-bad"), "+-bad 1.0.1")
        mismatch = dcr_fetch._status(_update(), "+other-package 1.0.1")
        self.assertEqual((unsafe.status, mismatch.status), ("unverified", "unverified"))


class FetcherTest(unittest.TestCase):
    def test_npm_pack_disables_scripts(self):
        calls = []

        def run(args, **kwargs):
            calls.append(args)
            Path(kwargs["cwd"]).joinpath("left-pad-1.0.1.tgz").write_bytes(b"tar")
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
            result = mock.Mock(stdout=json.dumps({"Zip": str(archive), "Version": "v1.0.1"}))
            with mock.patch.object(dcr_fetch, "_run", return_value=result) as run:
                self.assertEqual(dcr_fetch.fetch_gomod(Path(tmp), "example.com/mod", "v1.0.1"), archive)
            self.assertIn("example.com/mod@v1.0.1", run.call_args.args[0])

    def test_npm_and_go_reject_a_different_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "left-pad-9.9.9.tgz").write_bytes(b"tar")
            with mock.patch.object(dcr_fetch, "_run", return_value=mock.Mock()), self.assertRaises(FetchError):
                dcr_fetch.fetch_npm(root, "left-pad", "1.0.1")
            result = mock.Mock(stdout=json.dumps({"Zip": "module.zip", "Version": "v9.9.9"}))
            with mock.patch.object(dcr_fetch, "_run", return_value=result), self.assertRaises(FetchError):
                dcr_fetch.fetch_gomod(root, "example.com/mod", "v1.0.1")

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

    def test_a_single_top_level_directory_is_flattened(self):
        cases = (
            ("example-1.0.1.tar.gz", _tar_bytes({"example-1.0.1/setup.py": b"1"}), "setup.py", b"1"),
            ("module@v1.0.1.zip", _zip_bytes({"module@v1.0.1/go.mod": b"2"}), "go.mod", b"2"),
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index, (filename, data, leaf, expected) in enumerate(cases):
                source = root / filename
                source.write_bytes(data)
                dest = root / f"out{index}"
                dcr_fetch.extract(source, dest)
                self.assertEqual((dest / leaf).read_bytes(), expected)

    def test_go_module_prefix_with_slashes_is_flattened(self):
        members = {
            "github.com/org/mod@v1.2.3/go.mod": b"1",
            "github.com/org/mod@v1.2.3/pkg/file.go": b"2",
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "mod.zip"
            source.write_bytes(_zip_bytes(members))
            dcr_fetch.extract(source, root / "out")
            self.assertEqual((root / "out" / "go.mod").read_bytes(), b"1")
            self.assertEqual((root / "out" / "pkg" / "file.go").read_bytes(), b"2")

    def test_collapse_handles_a_folder_matching_its_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "pkg.zip"
            source.write_bytes(_zip_bytes({"pkg/pkg/file": b"1"}))
            dcr_fetch.extract(source, root / "out")
            self.assertEqual((root / "out" / "file").read_bytes(), b"1")


class ActionDiffTest(unittest.TestCase):
    def _review(self, diff, update):
        with tempfile.TemporaryDirectory() as tmp:
            env = _environment(tmp, [update], diff=diff)
            with (
                mock.patch.dict(os.environ, env),
                mock.patch.dict(dcr_fetch.FETCHERS, {"github_actions": lambda work, name, version: work}),
                mock.patch.object(dcr_fetch, "_run", return_value=mock.Mock(stdout=b"")),
            ):
                self.assertEqual(dcr_fetch.main(), 0)
            return json.loads((Path(env["DCR_OUT"]) / "meta.json").read_text(encoding="utf-8"))["updates"][0]

    def test_sha_pins_come_from_the_diff(self):
        old, new, update = "a" * 40, "b" * 40, _dep("owner/repo", "github_actions", "v1", "2")
        cases = (
            (_uses("-", old) + _uses("+", new), "reviewed", old, new),
            (_uses("-", old) + _uses("+", new) + _uses("+", "c" * 40), "unverified", "v1", "2"),
            (_uses("-", "v1") + _uses("+", "v2"), "not_reviewed", "v1", "2"),
        )
        for body, status, prev, new in cases:
            with self.subTest(status=status):
                result = self._review(f"--- a\n+++ b\n{body}", update)
                self.assertEqual((result["status"], result["prev_version"], result["new_version"]), (status, prev, new))

    def test_matching_comment_selects_the_old_sha(self):
        old_a, old_b, new = "a" * 40, "b" * 40, "c" * 40
        body = (
            f"- uses: owner/repo@{old_a} # v3.0.0\n"
            f"- uses: owner/repo@{old_b} # v4.1.0\n"
            f"+ uses: owner/repo@{new} # v5.0.0\n"
        )
        result = self._review(f"--- a\n+++ b\n{body}", _dep("owner/repo", "github_actions", "v4.1.0", "5.0.0"))
        self.assertEqual((result["status"], result["prev_version"], result["new_version"]), ("reviewed", old_b, new))

    def test_first_sorted_sha_is_used_without_a_matching_comment(self):
        old_a, old_b, new = "a" * 40, "b" * 40, "c" * 40
        body = (
            f"- uses: owner/repo@{old_b} # v1.0.0\n"
            f"- uses: owner/repo@{old_a} # v2.0.0\n"
            f"+ uses: owner/repo@{new} # v5.0.0\n"
        )
        result = self._review(f"--- a\n+++ b\n{body}", _dep("owner/repo", "github_actions", "v4.1.0", "5.0.0"))
        self.assertEqual((result["status"], result["prev_version"], result["new_version"]), ("reviewed", old_a, new))

    def test_quoted_uses_lines_are_matched(self):
        old, new = "a" * 40, "b" * 40
        body = f'- uses: "owner/repo@{old}" # v1\n+ uses: "owner/repo@{new}" # v2\n'
        result = self._review(f"--- a\n+++ b\n{body}", _dep("owner/repo", "github_actions", "v1", "2"))
        self.assertEqual((result["status"], result["prev_version"], result["new_version"]), ("reviewed", old, new))


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

    def test_empty_previous_version_only_marks_that_update_unverified(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = _environment(tmp, [_dep("broken", prev=""), _dep("tokio", "cargo")], added="broken 1.0.1")
            data = mock.patch.object(dcr_fetch, "_run", return_value=mock.Mock(stdout=b""))
            with mock.patch.dict(os.environ, env), data:
                self.assertEqual(dcr_fetch.main(), 0)
            items = json.loads((Path(env["DCR_OUT"]) / "meta.json").read_text(encoding="utf-8"))["updates"]
            self.assertEqual([item["status"] for item in items], ["unverified", "not_reviewed"])
            self.assertIn("previous version", items[0]["note"])


if __name__ == "__main__":
    unittest.main()
