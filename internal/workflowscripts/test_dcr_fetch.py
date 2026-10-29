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
    def test_cargo_and_branch_actions_are_not_reviewed(self):
        cargo = dcr_fetch._status(_update("tokio", "cargo"), "")
        diff = "-uses: owner/repo@main\n+uses: owner/repo@release\n"
        action = dcr_fetch._status(_update("owner/repo", "github_actions", "main", "release"), diff)
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
            (_uses("-", "main") + _uses("+", "dev"), "not_reviewed", "v1", "2"),
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


class TagKeyTest(unittest.TestCase):
    def test_numeric_order(self):
        tags = ["v10", "v4.10", "v4", "v4.1"]
        self.assertEqual(sorted(tags, key=dcr_fetch._tag_key), ["v4", "v4.1", "v4.10", "v10"])
        self.assertEqual(min(["v10", "v9"], key=dcr_fetch._tag_key), "v9")

    def test_non_numeric_tag_fails_closed(self):
        for tag in ("v4-beta", "vx", "v4..1", "v"):
            with self.assertRaises(FetchError):
                dcr_fetch._tag_key(tag)


def _ls_remote(refs):
    """Mimic git ls-remote: a pattern matches a ref exactly or as its trailing path components."""

    def run(args, **kwargs):
        if args[:2] == ["git", "ls-remote"]:
            patterns = args[3:]
            lines = [
                f"{sha}\t{ref}" for ref, sha in refs.items() if any(ref == p or ref.endswith("/" + p) for p in patterns)
            ]
            return mock.Mock(stdout="".join(line + "\n" for line in lines))
        return mock.Mock(stdout=b"")

    return run


class ActionTagTest(unittest.TestCase):
    OLD, NEW, TAG_OBJECT = "a" * 40, "b" * 40, "c" * 40

    def _review(self, old_pin, new_pin, refs, prev="4.1.0", new="4.2.0"):
        fetched = []

        def fetch(work, name, version):
            fetched.append((name, version))
            return work

        diff = f"--- a\n+++ b\n- uses: owner/repo/sub@{old_pin}\n+ uses: owner/repo/sub@{new_pin}\n"
        with tempfile.TemporaryDirectory() as tmp:
            env = _environment(tmp, [_dep("owner/repo", "github_actions", prev, new)], diff=diff)
            with (
                mock.patch.dict(os.environ, env),
                mock.patch.dict(dcr_fetch.FETCHERS, {"github_actions": fetch}),
                mock.patch.object(dcr_fetch, "_run", side_effect=_ls_remote(refs)),
            ):
                self.assertEqual(dcr_fetch.main(), 0)
            meta = json.loads((Path(env["DCR_OUT"]) / "meta.json").read_text(encoding="utf-8"))
        return meta["updates"][0], meta["facts"], fetched

    def test_full_tags_resolve_and_fetch_commits(self):
        refs = {"refs/tags/v4.1.0": self.OLD, "refs/tags/v4.2.0": self.NEW}
        update, facts, fetched = self._review("v4.1.0", "v4.2.0", refs)
        self.assertEqual(
            (update["status"], update["prev_commit"], update["new_commit"]), ("reviewed", self.OLD, self.NEW)
        )
        self.assertEqual(fetched, [("owner/repo", self.OLD), ("owner/repo", self.NEW)])
        self.assertEqual(facts, [f"owner/repo: tag v4.1.0 resolved to {self.OLD}, v4.2.0 to {self.NEW}"])

    def test_bare_tag_adds_a_moving_fact(self):
        refs = {"refs/tags/v4": self.OLD, "refs/tags/v5": self.NEW}
        update, facts, _ = self._review("v4", "v5", refs, "4", "5")
        self.assertEqual((update["status"], update["new_version"]), ("reviewed", "v5"))
        self.assertIn(f"owner/repo: v5 can move after review; the reviewed commit was {self.NEW}", facts)

    def test_annotated_tag_is_peeled(self):
        refs = {"refs/tags/v4.1.0": self.OLD, "refs/tags/v4.2.0": self.TAG_OBJECT, "refs/tags/v4.2.0^{}": self.NEW}
        update, facts, fetched = self._review("v4.1.0", "v4.2.0", refs)
        self.assertEqual((update["new_commit"], fetched[1][1]), (self.NEW, self.NEW))
        self.assertEqual(facts, [f"owner/repo: tag v4.1.0 resolved to {self.OLD}, v4.2.0 to {self.NEW}"])

    def test_ls_remote_mock_matches_real_output(self):
        refs = {"refs/tags/v4.39.1": self.TAG_OBJECT, "refs/tags/v4.39.1^{}": self.NEW}
        run = _ls_remote(refs)
        url = "https://github.com/github/codeql-action"
        self.assertEqual(run(["git", "ls-remote", url, "v4.39.1"]).stdout, f"{self.TAG_OBJECT}\trefs/tags/v4.39.1\n")
        self.assertEqual(
            run(["git", "ls-remote", url, "v4.39.1", "refs/tags/v4.39.1^{}"]).stdout,
            f"{self.TAG_OBJECT}\trefs/tags/v4.39.1\n{self.NEW}\trefs/tags/v4.39.1" + "^{}\n",
        )

    def test_unmatched_prev_version_falls_back_to_numerically_oldest_tag(self):
        diff_pins = "- uses: owner/repo@v10\n- uses: owner/repo@v9\n+ uses: owner/repo@v11\n"
        refs = {"refs/tags/v9": self.OLD, "refs/tags/v10": self.TAG_OBJECT, "refs/tags/v11": self.NEW}
        with tempfile.TemporaryDirectory() as tmp:
            env = _environment(
                tmp, [_dep("owner/repo", "github_actions", "8", "11")], diff=f"--- a\n+++ b\n{diff_pins}"
            )
            with (
                mock.patch.dict(os.environ, env),
                mock.patch.dict(dcr_fetch.FETCHERS, {"github_actions": lambda work, name, version: work}),
                mock.patch.object(dcr_fetch, "_run", side_effect=_ls_remote(refs)),
            ):
                dcr_fetch.main()
            update = json.loads((Path(env["DCR_OUT"]) / "meta.json").read_text(encoding="utf-8"))["updates"][0]
        self.assertEqual((update["prev_version"], update["prev_commit"]), ("v9", self.OLD))

    def test_unresolvable_or_ambiguous_tag_is_unverified(self):
        cases = (
            {"refs/tags/v4.1.0": self.OLD},
            {"refs/tags/v4.1.0": self.OLD, "refs/tags/v4.2.0": self.NEW, "refs/heads/v4.2.0": self.TAG_OBJECT},
        )
        for refs in cases:
            update, facts, fetched = self._review("v4.1.0", "v4.2.0", refs)
            self.assertEqual((update["status"], fetched, facts), ("unverified", [], []))
            self.assertIn("tag did not resolve", update["note"])

    def test_sha_pins_are_fetched_unchanged(self):
        update, facts, fetched = self._review(self.OLD, self.NEW, {})
        self.assertEqual((update["status"], update["new_commit"], facts), ("reviewed", "", []))
        self.assertEqual(fetched, [("owner/repo", self.OLD), ("owner/repo", self.NEW)])


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
                ({"facts", "schema", "updates"}, 1, "not_reviewed"),
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


class FactsTest(unittest.TestCase):
    def _facts(self, results, tree):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            for side, files in tree.items():
                for name, data in files.items():
                    (out / side / name).parent.mkdir(parents=True, exist_ok=True)
                    (out / side / name).write_bytes(data)
            files = dcr_fetch.write_diff(out)
            changes = (out / "changes.diff").read_text(encoding="utf-8")
            excluded = (out / "excluded.diff").read_text(encoding="utf-8")
        return dcr_fetch.collect_facts(results, files), changes, excluded

    def test_lists_major_bumps_manifests_and_binaries(self) -> None:
        results = [
            dcr_fetch.Update("a", "npm_and_yarn", "/", "1.2.0", "2.0.0"),
            dcr_fetch.Update("b", "pip", "/", "1.0.0", "1.1.0"),
            dcr_fetch.Update("c", "npm_and_yarn", "/", "1.0.0", "3.0.0", status="unverified"),
        ]
        tree = {
            "old": {"00-a/package.json": b"1", "00-a/x.node": b"\0a"},
            "new": {"00-a/package.json": b"2", "00-a/x.node": b"\0b"},
        }
        facts, _, _ = self._facts(results, tree)
        self.assertEqual(
            facts[:3],
            [
                "a: major version change 1.2.0 -> 2.0.0",
                "manifest or build file changed: package.json",
                "binary file changed: 00-a/x.node",
            ],
        )
        self.assertEqual(dcr_fetch.collect_facts(results[1:], []), [])

    def test_excluded_files_are_listed_with_sizes(self) -> None:
        tree = {
            "new": {
                "00-a/src/main.py": b"x = 1\n",
                "00-a/tests/test_main.py": b"assert 1\n",
                "00-a/pkg/fixtures/data.json": b"{}\n",
                "00-a/foo-stubs/a.pyi": b"x: int\n",
                "00-a/poetry.lock": b"lock\n",
                "00-a/.github/workflows/ci.yml": b"on: push\n",
                "00-a/src/fast.c": b"/* Generated by Cython 3.1 */\n",
            }
        }
        facts, changes, excluded = self._facts([], tree)
        self.assertIn("src/main.py", changes)
        self.assertNotIn("tests/test_main.py", changes)
        reasons = sorted(f.split("(")[1].split(",")[0] for f in facts if f.startswith("excluded"))
        self.assertEqual(
            reasons, [".github", "generated", "lockfile", "test or fixture", "test or fixture", "type stubs"]
        )
        self.assertIn("foo-stubs/a.pyi", excluded)
        self.assertTrue(any(f.startswith("diff size: ") for f in facts))
        self.assertIn("largest change: 00-a/src/main.py", " ".join(facts))

    def test_metadata_requires_changes(self) -> None:
        old = b"Requires-Python: >=3.10\nRequires-Dist: yarl>=1.17\nRequires-Dist: attrs\n"
        new = b"Requires-Python: >=3.11\nRequires-Dist: yarl>=1.20\nRequires-Dist: attrs\n"
        new += b"Requires-Dist: idna; extra == 'x'\n"
        tree = {side: {"00-a/PKG-INFO": data} for side, data in (("old", old), ("new", new))}
        facts, _, _ = self._facts([], tree)
        self.assertIn("manifest or build file changed: PKG-INFO", facts)
        self.assertIn("00-a/PKG-INFO: Requires-Python changed: >=3.10 -> >=3.11", facts)
        self.assertIn("00-a/PKG-INFO: Requires-Dist changed: yarl>=1.17 -> yarl>=1.20", facts)
        self.assertIn("00-a/PKG-INFO: new Requires-Dist: idna; extra == 'x'", facts)

    def test_real_diff_with_spaces_in_paths(self) -> None:
        tree = {
            side: {"00-a/sub dir/pyproject.toml": text, "00-a/my file.txt": text}
            for side, text in (("old", b"a"), ("new", b"b"))
        }
        facts, _, _ = self._facts([], tree)
        self.assertIn("manifest or build file changed: pyproject.toml", facts)
        self.assertIn("largest change: 00-a/my file.txt", " ".join(facts))

    def test_actions_major_bump_is_not_a_fact(self) -> None:
        results = [dcr_fetch.Update("o/r", "github_actions", "/", "v1", "v2")]
        self.assertEqual(dcr_fetch.collect_facts(results, []), [])


if __name__ == "__main__":
    unittest.main()
