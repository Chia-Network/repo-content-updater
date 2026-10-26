"""Tests for dcr_fetch: literal checks, native fetches, safe extraction, diff caps."""

from __future__ import annotations

import base64
import io
import json
import os
import sys
import tarfile
import tempfile
import unittest
import zipfile
from hashlib import sha256, sha512
from pathlib import Path
from typing import Self
from unittest import mock

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import dcr_fetch
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


def _git_runner(tar_bytes: bytes, calls: list[list[str]] | None = None):
    def run(args: list[str], **kwargs: object) -> _Completed:
        if calls is not None:
            calls.append(args)
        if args[0] != "git":
            raise AssertionError(args)
        if "archive" in args:
            return _Completed(data=tar_bytes)
        return _Completed()

    return run


def _diff_runner(data: bytes, returncode: int = 1):
    def run(args: list[str], **kwargs: object) -> _Completed:
        if args != ["diff", "-ruNa", "old", "new"]:
            raise AssertionError(args)
        return _Completed(returncode=returncode, data=data)

    return run


class _Response:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self.headers = {"Content-Length": str(len(data))}

    def read(self, size: int = -1) -> bytes:
        return self._data if size < 0 else self._data[:size]

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> bool:
        return False


def _pypi_urlopen(payload: dict[str, object], file_bytes: bytes):
    encoded = json.dumps(payload).encode()

    def fake(url: str, timeout: int = 30) -> _Response:
        del timeout
        return _Response(encoded if url.endswith("/json") else file_bytes)

    return fake


def _pypi_files_urlopen(payload: dict[str, object], files: dict[str, bytes]):
    encoded = json.dumps(payload).encode()

    def fake(url: str, timeout: int = 30) -> _Response:
        del timeout
        return _Response(encoded if url.endswith("/json") else files[url])

    return fake


def _pypi_distribution(kind: str, filename: str, data: bytes) -> dict[str, object]:
    return {
        "packagetype": kind,
        "url": f"https://files.pythonhosted.org/packages/{filename}",
        "digests": {"sha256": sha256(data).hexdigest()},
        "filename": filename,
    }


def _update(
    name: str = "left-pad",
    ecosystem: str = "npm_and_yarn",
    prev: str = "1.0.0",
    new: str = "1.0.1",
) -> Update:
    return Update(name, ecosystem, "/", prev, new)


def _process(
    update: Update,
    out: Path,
    added: list[str],
    removed: list[str],
) -> dcr_fetch.UpdateResult:
    return dcr_fetch._process_update(0, update, out, added, removed)


class NpmFetchTest(unittest.TestCase):
    def test_npm_pack_binds_the_computed_sha512_integrity(self) -> None:
        tarball = _tar_bytes({"package/package.json": b'{"name":"left-pad","version":"1.0.1"}'})
        binding = "sha512-" + base64.b64encode(sha512(tarball).digest()).decode("ascii")
        update = _update()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            with mock.patch.object(dcr_sources.subprocess, "run", side_effect=_npm_runner(tarball)):
                result = _process(update, out, [f"left-pad@1.0.1 {binding}"], ["left-pad@1.0.0"])
            self.assertEqual(result.status, "reviewed")
            self.assertTrue(result.bound)
            self.assertTrue((out / "new" / "00-left-pad@1.0.1" / "package" / "package.json").is_file())

    def test_missing_integrity_is_disclosed_not_failed(self) -> None:
        tarball = _tar_bytes({"package/index.js": b"module.exports = 1;\n"})
        update = _update()
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(dcr_sources.subprocess, "run", side_effect=_npm_runner(tarball)):
                result = _process(update, Path(tmp), ["left-pad@1.0.1"], ["left-pad@1.0.0"])
            self.assertEqual(result.status, "reviewed")
            self.assertFalse(result.bound)
            self.assertIn("not bound", result.note)

    def test_invalid_npm_name_is_unverified_before_any_command(self) -> None:
        update = Update("../left-pad", "npm_and_yarn", "/", "1.0.0", "1.0.1")
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(dcr_sources.subprocess, "run") as run:
            result = _process(update, Path(tmp), ["../left-pad@1.0.1"], ["1.0.0"])
            self.assertEqual(result.status, "unverified")
            run.assert_not_called()


class PypiFetchTest(unittest.TestCase):
    def _payload(self, file_bytes: bytes, digest: str) -> dict[str, object]:
        return {
            "urls": [
                {
                    "packagetype": "sdist",
                    "url": "https://files.pythonhosted.org/packages/example-1.0.1.tar.gz",
                    "digests": {"sha256": digest},
                    "filename": "example-1.0.1.tar.gz",
                },
            ],
        }

    def test_sdist_download_checks_the_registry_sha256_and_binds_it(self) -> None:
        file_bytes = _tar_bytes({"example-1.0.1/setup.py": b"print('ok')\n"})
        digest = sha256(file_bytes).hexdigest()
        update = _update("example-pkg", "pip")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            with mock.patch.object(
                dcr_sources, "_urlopen", side_effect=_pypi_urlopen(self._payload(file_bytes, digest), file_bytes)
            ):
                result = _process(
                    update,
                    out,
                    [f"example-pkg==1.0.1 --hash=sha256:{digest}"],
                    ["example-pkg==1.0.0"],
                )
            self.assertEqual(result.status, "reviewed")
            self.assertTrue(result.bound)
            self.assertTrue((out / "new" / "00-example-pkg@1.0.1" / "example-1.0.1" / "setup.py").is_file())

    def test_digest_mismatch_is_a_fetch_failure(self) -> None:
        file_bytes = _tar_bytes({"pkg/setup.py": b"print('ok')\n"})
        payload = self._payload(file_bytes, "0" * 64)
        update = _update("example-pkg", "pip")
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(
                dcr_sources,
                "_urlopen",
                side_effect=_pypi_urlopen(payload, file_bytes),
            ),
        ):
            result = _process(update, Path(tmp), ["example-pkg==1.0.1"], ["example-pkg==1.0.0"])
            self.assertEqual(result.status, "fetch_failed")
            self.assertIn("sha256", result.note)

    def test_download_host_outside_pypi_is_a_fetch_failure(self) -> None:
        file_bytes = _tar_bytes({"pkg/setup.py": b"print('ok')\n"})
        payload = self._payload(file_bytes, sha256(file_bytes).hexdigest())
        payload["urls"][0]["url"] = "https://example.invalid/pkg.tar.gz"  # type: ignore[index]
        update = _update("example-pkg", "pip")
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(
                dcr_sources,
                "_urlopen",
                side_effect=_pypi_urlopen(payload, file_bytes),
            ),
        ):
            result = _process(update, Path(tmp), ["example-pkg==1.0.1"], ["example-pkg==1.0.0"])
            self.assertEqual(result.status, "fetch_failed")
            self.assertIn("expected host", result.note)

    def test_new_release_reviews_the_sdist_and_every_listed_wheel(self) -> None:
        sdist = _tar_bytes({"example-1.0.1/setup.py": b"print('ok')\n"})
        wheel = _zip_bytes({"example/__init__.py": b"VALUE = 1\n"})
        payload = {
            "urls": [
                _pypi_distribution("sdist", "example-1.0.1.tar.gz", sdist),
                _pypi_distribution("bdist_wheel", "example-1.0.1-py3-none-any.whl", wheel),
            ],
        }
        files = {str(item["url"]): data for item, data in zip(payload["urls"], (sdist, wheel))}
        update = _update("example-pkg", "pip")
        hashes = " ".join(f"--hash=sha256:{sha256(data).hexdigest()}" for data in (sdist, wheel))
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            with mock.patch.object(dcr_sources, "_urlopen", side_effect=_pypi_files_urlopen(payload, files)):
                result = _process(update, out, [f"example-pkg==1.0.1 {hashes}"], ["example-pkg==1.0.0"])
            self.assertEqual(result.status, "reviewed")
            self.assertTrue(result.bound)
            artifact = out / "new" / "00-example-pkg@1.0.1"
            self.assertTrue((artifact / "example-1.0.1.tar.gz" / "example-1.0.1" / "setup.py").is_file())
            self.assertTrue((artifact / "example-1.0.1-py3-none-any.whl" / "example" / "__init__.py").is_file())

    def test_lock_hash_without_a_registry_file_is_partially_bound(self) -> None:
        sdist = _tar_bytes({"example-1.0.1/setup.py": b"print('ok')\n"})
        payload = {"urls": [_pypi_distribution("sdist", "example-1.0.1.tar.gz", sdist)]}
        files = {str(payload["urls"][0]["url"]): sdist}
        update = _update("example-pkg", "pip")
        missing = "f" * 64
        hashes = f"--hash=sha256:{sha256(sdist).hexdigest()} --hash=sha256:{missing}"
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(dcr_sources, "_urlopen", side_effect=_pypi_files_urlopen(payload, files)):
                result = _process(update, Path(tmp), [f"example-pkg==1.0.1 {hashes}"], ["example-pkg==1.0.0"])
            self.assertEqual(result.status, "unverified")
            self.assertFalse(result.bound)
            self.assertEqual(result.note, "partially bound")

    def test_non_default_index_in_the_lock_entry_is_unverified(self) -> None:
        update = _update("example-pkg", "pip")
        note = dcr_fetch._check(
            update,
            dcr_fetch.ECOSYSTEMS["pip"],
            [
                "example-pkg==1.0.1 --hash=sha256:" + "a" * 64,
                "example-pkg @ https://packages.example/example-pkg-1.0.1.tar.gz",
            ],
            ["example-pkg==1.0.0"],
        )
        self.assertEqual(note, "non-default package index")

    def test_public_pypi_urls_are_allowed(self) -> None:
        update = _update("example-pkg", "pip")
        note = dcr_fetch._check(
            update,
            dcr_fetch.ECOSYSTEMS["pip"],
            ["example-pkg==1.0.1 --index-url https://pypi.org/simple"],
            ["example-pkg==1.0.0"],
        )
        self.assertIsNone(note)


class GoFetchTest(unittest.TestCase):
    def test_go_zip_binds_the_h1_sum(self) -> None:
        zip_bytes = _zip_bytes({"example.com/mod@v1.0.1/go.mod": b"module example.com/mod\n"})
        sum_value = "h1:" + "A" * 43 + "="
        calls: list[list[str]] = []
        update = _update("example.com/mod", "gomod", "v1.0.0", "v1.0.1")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            with mock.patch.object(
                dcr_sources.subprocess,
                "run",
                side_effect=_go_runner(zip_bytes, sum_value, calls),
            ):
                result = _process(update, out, [f"example.com/mod v1.0.1 {sum_value}"], ["example.com/mod v1.0.0"])
            self.assertEqual(result.status, "reviewed")
            self.assertTrue(result.bound)
            self.assertTrue(any("example.com/mod@v1.0.1" in call for call in calls))
            self.assertTrue((out / "new" / "00-example.com_mod@v1.0.1" / "example.com/mod@v1.0.1" / "go.mod").is_file())

    def test_go_path_traversal_is_unverified(self) -> None:
        update = Update("example.com/../mod", "gomod", "/", "v1.0.0", "v1.0.1")
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(dcr_sources.subprocess, "run") as run:
            result = _process(update, Path(tmp), ["example.com/../mod v1.0.1"], ["v1.0.0"])
            self.assertEqual(result.status, "unverified")
            run.assert_not_called()


class ActionFetchTest(unittest.TestCase):
    def test_fetch_by_sha_and_bind_the_new_sha(self) -> None:
        tar_bytes = _tar_bytes({"action.yml": b"name: test\n", "index.js": b"console.log(1);\n"})
        old_sha = "b" * 40
        new_sha = "a" * 40
        calls: list[list[str]] = []
        update = _update("owner/repo", "github_actions", old_sha, new_sha)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            with mock.patch.object(dcr_sources.subprocess, "run", side_effect=_git_runner(tar_bytes, calls)):
                result = _process(update, out, [f"uses: owner/repo@{new_sha}"], [f"uses: owner/repo@{old_sha}"])
            self.assertEqual(result.status, "reviewed")
            self.assertTrue(result.bound)
            self.assertTrue(any("https://github.com/owner/repo" in call for call in calls))
            self.assertTrue(any(new_sha in call for call in calls))
            self.assertTrue((out / "new" / f"00-owner_repo@{new_sha}" / "action.yml").is_file())

    def test_archive_attributes_disable_upstream_export_rules(self) -> None:
        tar_bytes = _tar_bytes({"action.yml": b"name: test\n"})
        old_sha = "b" * 40
        new_sha = "a" * 40
        seen: list[str] = []

        def run(args: list[str], **kwargs: object) -> _Completed:
            if "archive" in args:
                attributes = Path(kwargs["cwd"]) / "repo" / ".git" / "info" / "attributes"
                seen.append(attributes.read_text(encoding="utf-8"))
                return _Completed(data=tar_bytes)
            return _Completed()

        update = _update("owner/repo", "github_actions", old_sha, new_sha)
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(dcr_sources.subprocess, "run", side_effect=run):
                result = _process(update, Path(tmp), [f"uses: owner/repo@{new_sha}"], [f"uses: owner/repo@{old_sha}"])
        self.assertEqual(result.status, "reviewed")
        self.assertEqual(seen, ["* -export-ignore -export-subst\n"] * 2)

    def test_tag_only_pin_is_not_reviewed_as_a_moving_ref(self) -> None:
        update = _update("owner/repo", "github_actions", "v1.0.0", "v1.1.0")
        with tempfile.TemporaryDirectory() as tmp:
            result = _process(update, Path(tmp), ["uses: owner/repo@v1.1.0"], ["uses: owner/repo@v1.0.0"])
            self.assertEqual(result.status, "not_reviewed")
            self.assertIn("moving ref", result.note)

    def test_previous_tag_pin_is_unverified(self) -> None:
        update = _update("owner/repo", "github_actions", "v1.0.0", "a" * 40)
        with tempfile.TemporaryDirectory() as tmp:
            result = _process(update, Path(tmp), [f"uses: owner/repo@{'a' * 40}"], ["uses: owner/repo@v1.0.0"])
            self.assertEqual(result.status, "unverified")


class ScopeTest(unittest.TestCase):
    def test_unknown_ecosystem_is_not_reviewed(self) -> None:
        update = _update("tokio", "cargo", "1.0.0", "1.0.1")
        with tempfile.TemporaryDirectory() as tmp:
            result = _process(update, Path(tmp), ["tokio 1.0.1"], ["tokio 1.0.0"])
            self.assertEqual(result.status, "not_reviewed")
            self.assertIn("ecosystem", result.note)

    def test_unknown_ecosystem_is_not_reviewed_without_presence(self) -> None:
        update = _update("tokio", "cargo", "1.0.0", "1.0.1")
        with tempfile.TemporaryDirectory() as tmp:
            result = _process(update, Path(tmp), [], [])
            self.assertEqual(result.status, "not_reviewed")

    def test_moving_action_ref_is_not_reviewed_without_presence(self) -> None:
        update = _update("owner/repo", "github_actions", "v1.0.0", "v1.1.0")
        with tempfile.TemporaryDirectory() as tmp:
            result = _process(update, Path(tmp), [], [])
            self.assertEqual(result.status, "not_reviewed")
            self.assertIn("moving ref", result.note)


class SafeExtractionTest(unittest.TestCase):
    def _extract_zip(self, payload: bytes) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "package.zip"
            archive.write_bytes(payload)
            dcr_fetch.extract(archive, Path(tmp) / "out")

    def test_zip_parent_traversal_is_rejected(self) -> None:
        with self.assertRaises(FetchError):
            self._extract_zip(_zip_bytes({"../escape": b"x"}))

    def test_zip_absolute_path_is_rejected(self) -> None:
        with self.assertRaises(FetchError):
            self._extract_zip(_zip_bytes({"/escape": b"x"}))

    def test_zip_symlink_is_rejected(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as handle:
            info = zipfile.ZipInfo("link")
            info.external_attr = 0o120777 << 16
            handle.writestr(info, "target")
        with self.assertRaises(FetchError):
            self._extract_zip(buffer.getvalue())

    def test_tar_symlink_is_rejected(self) -> None:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as handle:
            info = tarfile.TarInfo("link")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            handle.addfile(info)
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "package.tgz"
            archive.write_bytes(buffer.getvalue())
            with self.assertRaises(FetchError):
                dcr_fetch.extract(archive, Path(tmp) / "out")

    def test_file_count_cap(self) -> None:
        payload = _zip_bytes({f"file-{index}": b"x" for index in range(3)})
        with mock.patch.object(dcr_sources, "MAX_FILES", 2), self.assertRaises(FetchError):
            self._extract_zip(payload)

    def test_extracted_byte_cap(self) -> None:
        payload = _zip_bytes({"file": b"x" * 10})
        with mock.patch.object(dcr_sources, "MAX_BYTES", 5), self.assertRaises(FetchError):
            self._extract_zip(payload)

    def test_explicit_archive_format_is_not_sniffed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "package.tar"
            archive.write_bytes(_tar_bytes({"file": b"x"}))
            with self.assertRaises(FetchError):
                dcr_fetch.extract(archive, Path(tmp) / "out", "zip")


class ParseUpdatesTest(unittest.TestCase):
    def test_malformed_update_lists_fail_closed(self) -> None:
        for raw in ("", "{}", "[1]", "[{}]", '[{"dependencyName": "x"}]'):
            with self.subTest(raw=raw), self.assertRaises(SystemExit):
                dcr_fetch._parse_updates(raw)


class HeadRefTest(unittest.TestCase):
    def test_dependabot_head_prefixes_map_to_update_ecosystems(self) -> None:
        prefixes = {
            "dependabot/npm_and_yarn/left-pad-1.0.1": "npm_and_yarn",
            "dependabot/pip/requests-2.1.0": "pip",
            "dependabot/go_modules/example.com/mod-1.0.1": "gomod",
            "dependabot/github_actions/actions/checkout-1.0.1": "github_actions",
        }
        for head_ref, ecosystem in prefixes.items():
            with self.subTest(head_ref=head_ref):
                self.assertEqual(dcr_fetch._head_ecosystem(head_ref), ecosystem)

    def test_unknown_head_branch_has_no_ecosystem(self) -> None:
        self.assertIsNone(dcr_fetch._head_ecosystem(""))
        self.assertIsNone(dcr_fetch._head_ecosystem("renovate/left-pad-1.x"))

    def test_head_note_rejects_a_missing_or_different_ecosystem(self) -> None:
        update = Update("left-pad", "npm_and_yarn", "", "1.0.0", "1.0.1")
        self.assertEqual(dcr_fetch._head_note(update, "npm_and_yarn"), None)
        self.assertIn("different", dcr_fetch._head_note(update, "pip") or "")
        self.assertIn("does not name", dcr_fetch._head_note(update, None) or "")


class MainTest(unittest.TestCase):
    def test_updates_over_the_cap_are_not_reviewed(self) -> None:
        updates = [
            {
                "dependencyName": f"pkg-{index}",
                "packageEcosystem": "cargo",
                "prevVersion": "1.0.0",
                "newVersion": "1.0.1",
                "directory": "/",
            }
            for index in range(dcr_fetch.MAX_UPDATES + 1)
        ]
        added = "\n".join(f"+pkg-{index} 1.0.1" for index in range(len(updates)))
        removed = "\n".join(f"-pkg-{index} 1.0.0" for index in range(len(updates)))
        with tempfile.TemporaryDirectory() as tmp:
            diff = Path(tmp) / "pr.diff"
            diff.write_text(f"--- a\n+++ b\n{added}\n{removed}\n", encoding="utf-8")
            out = Path(tmp) / "out"
            env = {
                "DCR_OUT": str(out),
                "PR_DIFF_PATH": str(diff),
                "UPDATED_DEPENDENCIES_JSON": json.dumps(updates),
                "DEPENDABOT_CURSOR_MALWARE_IOC_PATTERNS": '["never-match"]',
                "DCR_HEAD_REF": "dependabot/cargo/pkg-0",
            }
            with (
                mock.patch.dict(os.environ, env),
                mock.patch.object(
                    dcr_fetch,
                    "write_diff",
                    return_value=False,
                ),
                mock.patch.object(dcr_fetch, "scan_diff", return_value=[]),
            ):
                self.assertEqual(dcr_fetch.main(), 0)
            meta = json.loads((out / "meta.json").read_text(encoding="utf-8"))
            self.assertEqual(len(meta["updates"]), dcr_fetch.MAX_UPDATES + 1)
            self.assertEqual(meta["updates"][-1]["status"], "not_reviewed")
            self.assertIn("cap", meta["updates"][-1]["note"])

    def test_reviewable_updates_over_the_cap_are_unverified(self) -> None:
        updates = [
            {
                "dependencyName": f"pkg-{index}",
                "packageEcosystem": "cargo",
                "prevVersion": "1.0.0",
                "newVersion": "1.0.1",
                "directory": "/",
            }
            for index in range(dcr_fetch.MAX_UPDATES)
        ]
        updates.append(
            {
                "dependencyName": "left-pad",
                "packageEcosystem": "npm_and_yarn",
                "prevVersion": "1.0.0",
                "newVersion": "1.0.1",
                "directory": "/",
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            diff = Path(tmp) / "pr.diff"
            diff.write_text("--- a\n+++ b\n", encoding="utf-8")
            out = Path(tmp) / "out"
            env = {
                "DCR_OUT": str(out),
                "PR_DIFF_PATH": str(diff),
                "UPDATED_DEPENDENCIES_JSON": json.dumps(updates),
                "DEPENDABOT_CURSOR_MALWARE_IOC_PATTERNS": '["never-match"]',
                "DCR_HEAD_REF": "dependabot/npm_and_yarn/left-pad-1.0.1",
            }
            with (
                mock.patch.dict(os.environ, env),
                mock.patch.object(dcr_fetch, "write_diff", return_value=False),
                mock.patch.object(dcr_fetch, "scan_diff", return_value=[]),
            ):
                self.assertEqual(dcr_fetch.main(), 0)
            meta = json.loads((out / "meta.json").read_text(encoding="utf-8"))
            self.assertEqual(meta["updates"][-1]["status"], "unverified")
            self.assertIn("cap", meta["updates"][-1]["note"])
            self.assertEqual(meta["schema"], 1)
            self.assertIn("ioc_hits", meta)
            self.assertIn("truncated", meta)

    def test_truncated_diff_marks_reviewed_updates_truncated(self) -> None:
        tarball = _tar_bytes({"package/index.js": b"module.exports = 1;\n"})
        binding = "sha512-" + base64.b64encode(sha512(tarball).digest()).decode("ascii")
        update = {
            "dependencyName": "left-pad",
            "packageEcosystem": "npm_and_yarn",
            "prevVersion": "1.0.0",
            "newVersion": "1.0.1",
            "directory": "/",
        }
        big = b"+" + b"x" * (dcr_fetch.MAX_DIFF_BYTES + 1)

        def runner(args: list[str], **kwargs: object) -> _Completed:
            if args[0] == "npm":
                return _npm_runner(tarball)(args, **kwargs)
            return _diff_runner(big)(args, **kwargs)

        with tempfile.TemporaryDirectory() as tmp:
            diff = Path(tmp) / "pr.diff"
            diff.write_text(f"--- a\n+++ b\n+left-pad 1.0.1 {binding}\n-left-pad 1.0.0\n", encoding="utf-8")
            out = Path(tmp) / "out"
            env = {
                "DCR_OUT": str(out),
                "PR_DIFF_PATH": str(diff),
                "UPDATED_DEPENDENCIES_JSON": json.dumps([update]),
                "DEPENDABOT_CURSOR_MALWARE_IOC_PATTERNS": '["never-match"]',
                "DCR_HEAD_REF": "dependabot/npm_and_yarn/left-pad-1.0.1",
            }
            with mock.patch.dict(os.environ, env), mock.patch.object(dcr_sources.subprocess, "run", side_effect=runner):
                self.assertEqual(dcr_fetch.main(), 0)
            meta = json.loads((out / "meta.json").read_text(encoding="utf-8"))
            self.assertTrue(meta["truncated"])
            self.assertEqual(meta["updates"][0]["status"], "truncated")

    def test_mismatched_head_ref_skips_the_fetch(self) -> None:
        update = {
            "dependencyName": "left-pad",
            "packageEcosystem": "npm_and_yarn",
            "prevVersion": "1.0.0",
            "newVersion": "1.0.1",
            "directory": "/",
        }
        with tempfile.TemporaryDirectory() as tmp:
            diff = Path(tmp) / "pr.diff"
            diff.write_text("--- a\n+++ b\n+left-pad 1.0.1\n-left-pad 1.0.0\n", encoding="utf-8")
            out = Path(tmp) / "out"
            env = {
                "DCR_OUT": str(out),
                "PR_DIFF_PATH": str(diff),
                "UPDATED_DEPENDENCIES_JSON": json.dumps([update]),
                "DEPENDABOT_CURSOR_MALWARE_IOC_PATTERNS": '["never-match"]',
                "DCR_HEAD_REF": "dependabot/pip/left-pad-1.0.1",
            }
            with (
                mock.patch.dict(os.environ, env),
                mock.patch.object(dcr_fetch, "write_diff", return_value=False),
                mock.patch.object(dcr_fetch, "scan_diff", return_value=[]),
                mock.patch.object(
                    dcr_sources.subprocess,
                    "run",
                    side_effect=AssertionError("the fetch should not run"),
                ),
            ):
                self.assertEqual(dcr_fetch.main(), 0)
            meta = json.loads((out / "meta.json").read_text(encoding="utf-8"))
            self.assertEqual(meta["updates"][0]["status"], "unverified")
            self.assertIn("different", meta["updates"][0]["note"])
            self.assertTrue(meta["reviewable"])

    def test_reviewable_meta_and_github_output_follow_the_statuses(self) -> None:
        update = {
            "dependencyName": "tokio",
            "packageEcosystem": "cargo",
            "prevVersion": "1.0.0",
            "newVersion": "1.0.1",
            "directory": "/",
        }
        scenarios = (
            ("dependabot/cargo/tokio-1.0.1", "not_reviewed", False),
            ("dependabot/npm_and_yarn/tokio-1.0.1", "unverified", True),
        )
        for head_ref, status, expected in scenarios:
            with self.subTest(head_ref=head_ref), tempfile.TemporaryDirectory() as tmp:
                diff = Path(tmp) / "pr.diff"
                diff.write_text("--- a\n+++ b\n", encoding="utf-8")
                output = Path(tmp) / "github-output"
                output.write_text("", encoding="utf-8")
                out = Path(tmp) / "out"
                env = {
                    "DCR_OUT": str(out),
                    "PR_DIFF_PATH": str(diff),
                    "UPDATED_DEPENDENCIES_JSON": json.dumps([update]),
                    "DEPENDABOT_CURSOR_MALWARE_IOC_PATTERNS": '["never-match"]',
                    "DCR_HEAD_REF": head_ref,
                    "GITHUB_OUTPUT": str(output),
                }
                with (
                    mock.patch.dict(os.environ, env),
                    mock.patch.object(dcr_fetch, "write_diff", return_value=False),
                    mock.patch.object(dcr_fetch, "scan_diff", return_value=[]),
                ):
                    self.assertEqual(dcr_fetch.main(), 0)
                meta = json.loads((out / "meta.json").read_text(encoding="utf-8"))
                self.assertIs(meta["reviewable"], expected)
                self.assertEqual(meta["updates"][0]["status"], status)
                self.assertEqual(output.read_text(encoding="utf-8"), f"reviewable={str(expected).lower()}\n")


if __name__ == "__main__":
    unittest.main()
