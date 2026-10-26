"""Tests for dcr_fetch bundle helpers: diff writes, file lists, IOC scans, file scope."""

from __future__ import annotations

import io
import json
import os
import re
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import dcr_fetch
import dcr_lock
import dcr_sources
from dcr_fetch import FetchError, Update


def _tar_bytes(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as handle:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            handle.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _zip_bytes(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as handle:
        for name, data in files.items():
            handle.writestr(name, data)
    return buffer.getvalue()


class _Completed:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "", data: bytes | None = None) -> None:
        self.returncode = returncode
        self.stdout = data if data is not None else stdout
        self.stderr = stderr


def _npm_runner(tarball: bytes):
    def run(args: list[str], **kwargs: object) -> _Completed:
        if args[:3] != ["npm", "pack", "--ignore-scripts"]:
            raise AssertionError(args)
        Path(kwargs["cwd"]).joinpath("package.tgz").write_bytes(tarball)
        return _Completed(stdout="package.tgz\n")

    return run


def _go_runner(zip_bytes: bytes, sum_value: str, calls: list[list[str]] | None = None):
    def run(args: list[str], **kwargs: object) -> _Completed:
        if calls is not None:
            calls.append(args)
        if args[:4] != ["go", "mod", "download", "-json"]:
            raise AssertionError(args)
        zip_path = Path(kwargs["cwd"]).joinpath("module.zip")
        zip_path.write_bytes(zip_bytes)
        return _Completed(stdout=json.dumps({"Zip": str(zip_path), "Sum": sum_value}))

    return run


def _diff_runner(data: bytes, returncode: int = 1):
    def run(args: list[str], **kwargs: object) -> _Completed:
        if args != ["diff", "-ruNa", "old", "new"]:
            raise AssertionError(args)
        return _Completed(returncode=returncode, data=data)

    return run


def _update(
    name: str = "left-pad",
    ecosystem: str = "npm_and_yarn",
    prev: str = "1.0.0",
    new: str = "1.0.1",
) -> Update:
    return Update(name, ecosystem, "/", prev, new)


def _metadata(name: str, ecosystem: str, prev: str, new: str) -> dict[str, object]:
    return {
        "dependencyName": name,
        "dependencyType": "direct:production",
        "updateType": "version-update:semver-patch",
        "directory": "/",
        "packageEcosystem": ecosystem,
        "targetBranch": "main",
        "prevVersion": prev,
        "newVersion": new,
        "alertState": "",
        "ghsaId": "",
        "cvss": "",
        "compatScore": "",
        "maintainerChanges": False,
        "dependencyGroup": "",
    }


def _no_fetch_runner(args: list[str], **kwargs: object) -> _Completed:
    raise AssertionError(f"unexpected command: {args}")


def _hunks(added: list[str], removed: list[str]) -> tuple[dcr_lock.Hunk, ...]:
    text = f"@@ -1,{len(removed)} +1,{len(added)} @@\n"
    text += "".join(f"+{line}\n" for line in added)
    text += "".join(f"-{line}\n" for line in removed)
    return dcr_lock.parse_hunks(text)


def _process(
    update: Update,
    out: Path,
    added: list[str],
    removed: list[str],
) -> dcr_fetch.UpdateResult:
    return dcr_fetch._process_update(0, update, out, _hunks(added, removed))


class LiteralPresenceTest(unittest.TestCase):
    def test_name_and_new_version_must_be_on_an_added_line(self) -> None:
        update = _update()
        with tempfile.TemporaryDirectory() as tmp:
            result = _process(update, Path(tmp), ["left-pad"], ["left-pad@1.0.0"])
            self.assertEqual(result.status, "unverified")
            self.assertIn("diff lines", result.note)

    def test_previous_version_must_be_on_a_removed_line(self) -> None:
        update = _update()
        with tempfile.TemporaryDirectory() as tmp:
            result = _process(update, Path(tmp), ["left-pad@1.0.1"], ["other@2.0.0"])
            self.assertEqual(result.status, "unverified")

    def test_header_lines_do_not_count(self) -> None:
        update = _update()
        hunks = dcr_lock.parse_hunks("--- left-pad@1.0.1\n+++ left-pad@1.0.1\n--- left-pad@1.0.0\n")
        with tempfile.TemporaryDirectory() as tmp:
            result = dcr_fetch._process_update(0, update, Path(tmp), hunks)
            self.assertEqual(result.status, "unverified")

    def test_version_prefix_is_not_a_match(self) -> None:
        update = _update(prev="0.9", new="1.0")
        note = dcr_fetch._check(
            update,
            dcr_fetch.ECOSYSTEMS["npm_and_yarn"],
            _hunks(["left-pad@11.0.3"], ["left-pad@0.9"]),
        )
        self.assertIsNotNone(note)

    def test_name_must_match_a_whole_token(self) -> None:
        update = _update()
        note = dcr_fetch._check(
            update,
            dcr_fetch.ECOSYSTEMS["npm_and_yarn"],
            _hunks(["my-left-pad@1.0.1"], ["my-left-pad@1.0.0"]),
        )
        self.assertIsNotNone(note)

    def test_name_and_version_may_be_on_nearby_lines(self) -> None:
        update = _update()
        note = dcr_fetch._check(
            update,
            dcr_fetch.ECOSYSTEMS["npm_and_yarn"],
            _hunks(["node_modules/left-pad", "version: 1.0.1"], ["node_modules/left-pad", "version: 1.0.0"]),
        )
        self.assertIsNone(note)

    def test_version_far_from_the_named_entry_is_not_a_match(self) -> None:
        update = _update()
        added = ["left-pad@1.0.0", "a", "b", "c", "d", "other@1.0.1"]
        note = dcr_fetch._check(
            update,
            dcr_fetch.ECOSYSTEMS["npm_and_yarn"],
            _hunks(added, ["left-pad@1.0.0"]),
        )
        self.assertIsNotNone(note)


class DiffAndIocTest(unittest.TestCase):
    def test_added_lines_are_scanned_and_removed_lines_are_not(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "changes.diff"
            path.write_text(
                "--- old/a\n+++ new/a\n+axios@1.14.1\n-axios@1.14.1\n+safe\n+bidi\u202e\n",
                encoding="utf-8",
            )
            patterns = [("axios", re.compile(r"axios@1\.14\.1"))]
            hits = dcr_fetch.scan_diff(path, patterns)
            self.assertEqual([hit["kind"] for hit in hits], ["ioc", "bidi"])

    def test_file_list_keeps_artifact_files_with_output_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "old" / "pkg").mkdir(parents=True)
            (out / "old" / "pkg" / "meta.json").write_text("{}", encoding="utf-8")
            (out / "new").mkdir()
            (out / "new" / "files.txt").write_text("package file", encoding="utf-8")
            (out / "meta.json").write_text("{}", encoding="utf-8")
            paths = dcr_fetch.write_file_list(out)
            self.assertEqual(paths, ["new/files.txt", "old/pkg/meta.json"])

    def test_empty_ioc_list_is_an_error(self) -> None:
        with (
            mock.patch.dict(os.environ, {"DEPENDABOT_CURSOR_MALWARE_IOC_PATTERNS": "[]"}),
            self.assertRaises(SystemExit),
        ):
            dcr_fetch.ioc_patterns()

    def test_invalid_ioc_regex_is_an_error(self) -> None:
        with (
            mock.patch.dict(os.environ, {"DEPENDABOT_CURSOR_MALWARE_IOC_PATTERNS": '["("]'}),
            self.assertRaises(SystemExit),
        ):
            dcr_fetch.ioc_patterns()

    def test_diff_is_written_and_truncated_at_the_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            with mock.patch.object(dcr_sources.subprocess, "run", side_effect=_diff_runner(b"+small\n")):
                self.assertFalse(dcr_fetch.write_diff(out))
            self.assertEqual((out / "changes.diff").read_text(encoding="utf-8"), "+small\n")

            big = b"+" + b"x" * (dcr_fetch.MAX_DIFF_BYTES + 1)
            with mock.patch.object(dcr_sources.subprocess, "run", side_effect=_diff_runner(big)):
                self.assertTrue(dcr_fetch.write_diff(out))
            self.assertIn("truncated", (out / "changes.diff").read_text(encoding="utf-8"))

    def test_diff_failure_is_a_fetch_failure(self) -> None:
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(
                dcr_sources.subprocess,
                "run",
                side_effect=_diff_runner(b"", returncode=2),
            ),
            self.assertRaises(FetchError),
        ):
            dcr_fetch.write_diff(Path(tmp))


class WriteDiffTest(unittest.TestCase):
    def test_nul_byte_file_content_is_scanned_as_text(self) -> None:
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.dict(os.environ, {"DEPENDABOT_CURSOR_MALWARE_IOC_PATTERNS": '["EVIL_MARKER"]'}),
        ):
            out = Path(tmp)
            (out / "new" / "pkg").mkdir(parents=True)
            (out / "new" / "pkg" / "x.js").write_bytes(b"safe\x00line\nEVIL_MARKER\n")
            self.assertFalse(dcr_fetch.write_diff(out))
            text = (out / "changes.diff").read_text(encoding="utf-8")
            self.assertNotIn("Binary files", text)
            hits = dcr_fetch.scan_diff(out / "changes.diff", dcr_fetch.ioc_patterns())
            self.assertEqual([hit["kind"] for hit in hits], ["ioc"])


class FileScopeTest(unittest.TestCase):
    def _run(
        self, tmp: Path, diff_text: str, updates: list[dict[str, object]], head_ref: str, runner
    ) -> dict[str, object]:
        diff = tmp / "pr.diff"
        diff.write_text(diff_text, encoding="utf-8")
        out = tmp / "out"
        env = {
            "DCR_OUT": str(out),
            "PR_DIFF_PATH": str(diff),
            "UPDATED_DEPENDENCIES_JSON": json.dumps(updates),
            "DEPENDABOT_CURSOR_MALWARE_IOC_PATTERNS": '["never-match"]',
            "DCR_HEAD_REF": head_ref,
        }
        with (
            mock.patch.dict(os.environ, env),
            mock.patch.object(dcr_fetch, "write_diff", return_value=False),
            mock.patch.object(dcr_fetch, "scan_diff", return_value=[]),
            mock.patch.object(dcr_sources.subprocess, "run", side_effect=runner),
        ):
            self.assertEqual(dcr_fetch.main(), 0)
        return json.loads((out / "meta.json").read_text(encoding="utf-8"))

    def _meta(self, diff_text: str, updates: list[dict[str, object]], head_ref: str, runner) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as tmp:
            return self._run(Path(tmp), diff_text, updates, head_ref, runner)

    def test_npm_transitive_lock_changes_add_no_updates(self) -> None:
        tarball = _tar_bytes({"package/index.js": b"module.exports = 1;\n"})
        diff_text = (
            "diff --git a/package.json b/package.json\n"
            "--- a/package.json\n"
            "+++ b/package.json\n"
            "@@ -1,4 +1,4 @@\n"
            '   "dependencies": {\n'
            '-    "left-pad": "1.0.0",\n'
            '+    "left-pad": "1.0.1",\n'
            "   }\n"
            "diff --git a/package-lock.json b/package-lock.json\n"
            "--- a/package-lock.json\n"
            "+++ b/package-lock.json\n"
            "@@ -1,9 +1,9 @@\n"
            '     "node_modules/left-pad": {\n'
            '-      "version": "1.0.0",\n'
            '+      "version": "1.0.1",\n'
            '     "node_modules/right-pad": {\n'
            '-      "version": "2.0.0",\n'
            '+      "version": "2.0.1",\n'
            '     "node_modules/other-pad": {\n'
            '-      "version": "3.0.0",\n'
            '+      "version": "3.0.1",\n'
        )
        updates = [_metadata("left-pad", "npm_and_yarn", "1.0.0", "1.0.1")]
        meta = self._meta(diff_text, updates, "dependabot/npm_and_yarn/left-pad-1.0.1", _npm_runner(tarball))
        self.assertEqual(len(meta["updates"]), 1)
        self.assertEqual(meta["updates"][0]["status"], "reviewed")
        self.assertNotIn("missing from update metadata", json.dumps(meta))

    def test_go_versions_are_v_prefixed_for_matching_and_fetching(self) -> None:
        sum_value = "h1:" + "A" * 43 + "="
        diff_text = (
            "diff --git a/go.mod b/go.mod\n"
            "--- a/go.mod\n"
            "+++ b/go.mod\n"
            "@@ -1,2 +1,2 @@\n"
            "-\texample.com/mod v1.4.0\n"
            "+\texample.com/mod v1.5.0\n"
            "diff --git a/go.sum b/go.sum\n"
            "--- a/go.sum\n"
            "+++ b/go.sum\n"
            "@@ -1,1 +1,1 @@\n"
            f"-example.com/mod v1.4.0 {sum_value}\n"
            f"+example.com/mod v1.5.0 {sum_value}\n"
        )
        for ecosystem in ("go_modules", "gomod"):
            with self.subTest(ecosystem=ecosystem):
                zip_bytes = _zip_bytes({"example.com/mod@v1.5.0/go.mod": b"module example.com/mod\n"})
                calls: list[list[str]] = []
                updates = [_metadata("example.com/mod", ecosystem, "1.4.0", "1.5.0")]
                runner = _go_runner(zip_bytes, sum_value, calls)
                meta = self._meta(diff_text, updates, "dependabot/go_modules/example.com/mod-1.5.0", runner)
                recorded = meta["updates"][0]
                self.assertEqual(recorded["status"], "reviewed")
                self.assertEqual(recorded["ecosystem"], "gomod")
                self.assertEqual(recorded["prev_version"], "v1.4.0")
                self.assertEqual(recorded["new_version"], "v1.5.0")
                self.assertTrue(any("example.com/mod@v1.5.0" in call for call in calls))

    def test_cargo_lock_transitive_changes_stay_not_reviewed(self) -> None:
        diff_text = (
            "diff --git a/Cargo.lock b/Cargo.lock\n"
            "--- a/Cargo.lock\n"
            "+++ b/Cargo.lock\n"
            "@@ -1,8 +1,8 @@\n"
            " [[package]]\n"
            ' name = "serde"\n'
            '-version = "1.0.0"\n'
            '+version = "1.0.1"\n'
            " [[package]]\n"
            ' name = "tokio"\n'
            '-version = "1.0.0"\n'
            '+version = "1.0.1"\n'
        )
        updates = [_metadata("tokio", "cargo", "1.0.0", "1.0.1")]
        meta = self._meta(diff_text, updates, "dependabot/cargo/tokio-1.0.1", _no_fetch_runner)
        self.assertEqual(meta["updates"][0]["status"], "not_reviewed")
        self.assertIn("not reviewed", meta["updates"][0]["note"])
        self.assertFalse(meta["reviewable"])
        self.assertFalse(any(update["status"] == "unverified" for update in meta["updates"]))

    def test_tag_pinned_action_bump_stays_not_reviewed(self) -> None:
        diff_text = (
            "diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml\n"
            "--- a/.github/workflows/ci.yml\n"
            "+++ b/.github/workflows/ci.yml\n"
            "@@ -1,1 +1,1 @@\n"
            "-      - uses: actions/checkout@v4\n"
            "+      - uses: actions/checkout@v7\n"
        )
        updates = [_metadata("actions/checkout", "github_actions", "4", "7")]
        meta = self._meta(diff_text, updates, "dependabot/github_actions/actions/checkout-7", _no_fetch_runner)
        self.assertEqual(meta["updates"][0]["status"], "not_reviewed")
        self.assertIn("moving ref", meta["updates"][0]["note"])
        self.assertFalse(meta["reviewable"])
        self.assertFalse(any(update["status"] == "unverified" for update in meta["updates"]))

    def test_changed_file_outside_the_head_ecosystem_is_unverified(self) -> None:
        diff_text = (
            "diff --git a/package.json b/package.json\n"
            "--- a/package.json\n"
            "+++ b/package.json\n"
            "@@ -1,2 +1,2 @@\n"
            '-  "left-pad": "1.0.0",\n'
            '+  "left-pad": "1.0.1",\n'
            "diff --git a/src/index.js b/src/index.js\n"
            "--- a/src/index.js\n"
            "+++ b/src/index.js\n"
            "@@ -1,1 +1,1 @@\n"
            "-export const version = '1.0.0';\n"
            "+export const version = '1.0.1';\n"
        )
        updates = [_metadata("left-pad", "npm_and_yarn", "1.0.0", "1.0.1")]
        meta = self._meta(diff_text, updates, "dependabot/npm_and_yarn/left-pad-1.0.1", _no_fetch_runner)
        self.assertEqual(meta["updates"][0]["status"], "unverified")
        self.assertEqual(meta["updates"][0]["note"], "changed file outside the update ecosystem: src/index.js")
        self.assertTrue(meta["reviewable"])


if __name__ == "__main__":
    unittest.main()
