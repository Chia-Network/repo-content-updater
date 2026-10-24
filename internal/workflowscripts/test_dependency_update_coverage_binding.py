"""coverage.main() binds each covered primary scan to the artifact it installs; decide() reads that binding."""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch

import dependency_cursor_review_binding as binding
import dependency_cursor_review_upstream as upstream
import dependency_update_coverage as coverage
import malware_verdict_formatter as formatter
from test_dependency_cursor_review_binding import (
    _CONTEXT_H1,
    _DATA,
    _NPM_ATTESTATIONS,
    _NPM_COMMIT,
    _NPM_DOC,
    _NPM_INTEGRITY,
    _PYPI_COMMIT,
    _PYPI_DOC,
    _SDIST,
    _SDIST_SHA256,
    _integrity_url,
)
from test_dependency_update_coverage import _clean
from test_dependency_update_coverage_diff import _BENIGN, _GO, _MERGE, GoBump, _Diff, _package


def _lock(version: str, integrity: str | None) -> str:
    record = {"version": version, "resolved": f"https://registry.npmjs.org/sigstore/-/sigstore-{version}.tgz"}
    if integrity:
        record["integrity"] = integrity
    packages = {"": {"name": "app"}, "node_modules/sigstore": record}
    return json.dumps({"name": "app", "lockfileVersion": 3, "packages": packages}, indent=2) + "\n"


class NpmBindingTest(_Diff):
    def _run(self, integrity: str | None, attestations: bytes | None) -> tuple[dict, str]:
        def scan(update: coverage.Target, *_args: object) -> dict:
            self.scanned.append(update)
            return {**_clean(update.package, update.repo.slug), "resolved_to": _NPM_COMMIT}

        doc = {"repository": "github:sigstore/sigstore-js", "dist": {"integrity": _NPM_INTEGRITY}}
        return self.run_main(
            {"package.json": _package({"sigstore": "2.3.1"}), "package-lock.json": _lock("2.3.1", None)},
            {"package.json": _package({"sigstore": "3.0.0"}), "package-lock.json": _lock("3.0.0", integrity)},
            fetch={_NPM_DOC: json.dumps(doc).encode(), _NPM_ATTESTATIONS: attestations},
            scan=scan,
        )

    def test_a_clean_scan_with_provenance_for_the_lock_hash_is_benign(self) -> None:
        attestations = (_DATA / "npm-sigstore-3.0.0.json").read_bytes()
        report, summary = self._run(_NPM_INTEGRITY, attestations)
        self.assertEqual([(u.package, u.repo.slug) for u in self.scanned], [("sigstore", "sigstore/sigstore-js")])
        self.assertEqual(report["binding"], {"kind": "provenance", "reason": ""})
        self.assertEqual(report["repo_source"], "attested")
        self.assertIn("covered, artifact binding `provenance`", summary)
        published = formatter.compose_published_review(report, _BENIGN, _MERGE)
        self.assertEqual((published["verdict"], published["check"]), ("benign", "pass"))

    def test_a_clean_scan_without_provenance_or_a_lock_hash_is_inconclusive_and_passes(self) -> None:
        for integrity, reason in ((_NPM_INTEGRITY, "no_provenance"), (None, "no_lock_hash")):
            with self.subTest(reason=reason):
                self.setUp()
                report, summary = self._run(integrity, b"")
                self.assertEqual(report["binding"], {"kind": "unbound", "reason": reason})
                self.assertIn(f"covered, artifact not bound (`{reason}`), repository named only by", summary)
                self.assertEqual(report["repo_source"], "publisher")
                for warn_only in (True, False):
                    published = formatter.compose_published_review(report, _BENIGN, _MERGE, warn_only=warn_only)
                    self.assertEqual((published["verdict"], published["check"]), ("inconclusive", "pass"))
                    self.assertIn(f"artifact_unbound({reason})", published["malware_text"])
                    self.assertIn(formatter._REPO_UNVERIFIED_WARNING, published["malware_text"])

    def test_an_unreadable_attestation_answer_is_registry_unavailable(self) -> None:
        report, summary = self._run(_NPM_INTEGRITY, None)
        self.assertEqual(report["binding"], {"kind": "unbound", "reason": "registry_unavailable"})
        self.assertIn("covered, artifact not bound (`registry_unavailable`)", summary)
        published = formatter.compose_published_review(report, _BENIGN, _MERGE)
        self.assertEqual((published["verdict"], published["check"]), ("inconclusive", "pass"))
        self.assertIn("artifact_unbound(registry_unavailable)", published["malware_text"])


def _inconclusive(test: unittest.TestCase, report: dict, summary: str, reason: str) -> None:
    """A covered clean scan whose artifact is not bound for `reason`: inconclusive, and the check still passes."""
    test.assertEqual(report["binding"], {"kind": "unbound", "reason": reason})
    test.assertIn(f"covered, artifact not bound (`{reason}`)", summary)
    for warn_only in (True, False):
        published = formatter.compose_published_review(report, _BENIGN, _MERGE, warn_only=warn_only)
        test.assertEqual((published["verdict"], published["check"]), ("inconclusive", "pass"))
        test.assertIn(f"artifact_unbound({reason})", published["malware_text"])


class GoBindingTest(GoBump):
    """The go.sum entry the pull request records must be the proxy zip's hash, and the zip the scanned commit's."""

    def test_a_go_sum_hash_that_is_not_the_proxy_zip_is_inconclusive(self) -> None:
        report, summary = self.bump(self.HEAD_SUM.replace(self.HEAD_SUM.split()[2], _CONTEXT_H1))
        _inconclusive(self, report, summary, "hash_mismatch")

    def test_no_go_sum_entry_for_the_module_tree_is_inconclusive(self) -> None:
        report, summary = self.bump(self.HEAD_SUM.splitlines(keepends=True)[1])
        _inconclusive(self, report, summary, "no_lock_hash")


class RepoSourceTest(GoBump):
    """A bound scan is benign only when its repository is verified; go-get metadata alone does not verify it."""

    def _bump_named_by(self, found: upstream.Repo) -> tuple[dict, str]:
        with patch.object(coverage._ecosystems, "upstream_repo", lambda *_args: found):
            return self.bump(self.HEAD_SUM)

    def test_a_github_module_path_names_its_repository(self) -> None:
        report, _summary = self.bump(self.HEAD_SUM)
        self.assertEqual((report["binding"]["kind"], report["repo_source"]), ("checksum", "identity"))

    def test_a_repository_named_only_by_publisher_metadata_is_inconclusive_and_passes(self) -> None:
        report, summary = self._bump_named_by(upstream.Repo(_GO.repo, upstream.PUBLISHER))
        self.assertEqual((report["binding"]["kind"], report["repo_source"]), ("checksum", "publisher"))
        self.assertIn("covered, artifact binding `checksum`, repository named only by publisher metadata", summary)
        for warn_only in (True, False):
            published = formatter.compose_published_review(report, _BENIGN, _MERGE, warn_only=warn_only)
            self.assertEqual((published["verdict"], published["check"]), ("inconclusive", "pass"))
            self.assertIn(formatter._REPO_UNVERIFIED_WARNING, published["malware_text"])
            self.assertNotIn("benign", published["malware_text"])

    def test_an_allowlisted_repository_is_verified(self) -> None:
        report, _summary = self._bump_named_by(upstream.Repo(_GO.repo, upstream.ALLOWLISTED))
        published = formatter.compose_published_review(report, _BENIGN, _MERGE)
        self.assertEqual((published["verdict"], published["check"]), ("benign", "pass"))

    def test_a_list_or_object_repository_source_is_unverified(self) -> None:
        for source in (["identity"], {"identity": True}, None, 1, "publisher"):
            with self.subTest(source=source):
                self.assertIs(coverage._verified({"repo_source": source}), False)
        self.assertIs(coverage._verified({"repo_source": "identity"}), True)

    def test_only_provenance_attests_a_publisher_named_repository(self) -> None:
        for kind, want in (("provenance", "attested"), ("checksum", "publisher"), ("unbound", "publisher")):
            with self.subTest(kind=kind):
                self.assertEqual(binding.repo_source(upstream.PUBLISHER, binding.Binding(kind)), want)
        self.assertEqual(binding.repo_source(upstream.IDENTITY, binding.Binding("unbound")), "identity")

    def test_a_zip_the_proxy_built_from_another_commit_is_inconclusive(self) -> None:
        report, summary = self.bump(self.HEAD_SUM, origin="c" * 40)
        _inconclusive(self, report, summary, "commit_mismatch")


_POETRY = 'name = "sigstore"\nversion = "{0}"\nfiles = [{{file = "{1}", hash = "sha256:{2}"}}]\n'


class PypiBindingTest(_Diff):
    _MANIFEST = '[tool.poetry.dependencies]\npython = "^3.11"\nsigstore = "^3.5"\n'

    def _run(self, files: dict[str, tuple[str, str]], sha256: str = _SDIST_SHA256) -> tuple[dict, str]:
        """sigstore 3.5.0 -> 3.6.1, with `files` mapping each path to its (base, head) text, against the real release."""

        def scan(update: coverage.Target, *_args: object) -> dict:
            self.scanned.append(update)
            return {**_clean(update.package, update.repo.slug), "resolved_to": _PYPI_COMMIT}

        doc = {
            "info": {"project_urls": {"Source": "https://github.com/sigstore/sigstore-python"}},
            "urls": [{"filename": _SDIST, "digests": {"sha256": sha256}}],
        }
        provenance = (_DATA / f"pypi-{_SDIST}.json").read_bytes()
        report, summary = self.run_main(
            {path: base for path, (base, _head) in files.items()},
            {path: head for path, (_base, head) in files.items()},
            fetch={_PYPI_DOC: json.dumps(doc).encode(), _integrity_url(_SDIST): provenance},
            scan=scan,
        )
        self.assertEqual([(u.package, u.repo.slug) for u in self.scanned], [("sigstore", "sigstore/sigstore-python")])
        return report, summary

    def _poetry(self, sha256: str = _SDIST_SHA256) -> dict[str, tuple[str, str]]:
        lock = "[[package]]\n" + _POETRY + '\n[metadata]\nlock-version = "2.0"\ncontent-hash = "x"\n'
        return {
            "pyproject.toml": (self._MANIFEST, self._MANIFEST),
            "poetry.lock": (
                lock.format("3.5.0", "sigstore-3.5.0.tar.gz", "0" * 64),
                lock.format("3.6.1", _SDIST, sha256),
            ),
        }

    def test_a_poetry_lock_hash_with_provenance_for_the_scan_is_benign(self) -> None:
        report, summary = self._run(self._poetry())
        self.assertEqual(report["binding"], {"kind": "provenance", "reason": ""})
        self.assertIn("covered, artifact binding `provenance`", summary)
        published = formatter.compose_published_review(report, _BENIGN, _MERGE)
        self.assertEqual((published["verdict"], published["check"]), ("benign", "pass"))

    def test_a_poetry_lock_hash_that_is_not_the_registry_file_is_inconclusive(self) -> None:
        report, summary = self._run(self._poetry("1" * 64))
        _inconclusive(self, report, summary, "hash_mismatch")

    def test_a_pin_with_no_lock_hash_is_inconclusive_even_with_provenance(self) -> None:
        report, summary = self._run({"requirements.txt": ("sigstore==3.5.0\n", "sigstore==3.6.1\n")})
        _inconclusive(self, report, summary, "no_lock_hash")

    def _requirements(self, sha256: str) -> dict[str, tuple[str, str]]:
        pin = "sigstore=={0} \\\n    --hash=sha256:{1}\n    # via app\n"
        return {"requirements/base.txt": (pin.format("3.5.0", "0" * 64), pin.format("3.6.1", sha256))}

    def test_a_requirements_hash_with_provenance_for_the_scan_is_benign(self) -> None:
        report, _summary = self._run(self._requirements(_SDIST_SHA256))
        self.assertEqual(report["binding"], {"kind": "provenance", "reason": ""})
        published = formatter.compose_published_review(report, _BENIGN, _MERGE)
        self.assertEqual((published["verdict"], published["check"]), ("benign", "pass"))

    def test_a_requirements_hash_that_is_not_the_registry_file_is_inconclusive(self) -> None:
        report, summary = self._run(self._requirements("1" * 64))
        _inconclusive(self, report, summary, "hash_mismatch")

    def test_a_requirements_hash_pip_does_not_enforce_or_the_review_does_not_read_is_no_lock_hash(self) -> None:
        digest = f"sha256:{_SDIST_SHA256}"
        heads = {
            "a quoted marker, tab-separated": f'sigstore==3.6.1 ; platform_machine == "\t--hash={digest}\t"\n',
            "a comment before the continuation": f"sigstore==3.6.1 # c \\\n    --hash={digest}\n",
            "an abbreviated option": f"sigstore==3.6.1 --has={digest}\n",
            "an unread option": f"sigstore==3.6.1 --hash={digest} -i https://example.org/simple\n",
            "an unread hash beside it": f"sigstore==3.6.1 --hash={digest} --hash=sha512:{'a' * 128}\n",
            "a duplicate without a hash": f"sigstore==3.6.1 --hash={digest}\nsigstore==3.6.1\n",
        }
        for value in (f"md5:{'a' * 32}", f"sha384:{'a' * 96}", f"sha512:{'a' * 128}", digest.upper(), "sha256", ""):
            heads[value or "empty"] = f"sigstore==3.6.1 --hash={value}\n"
        for case, head in heads.items():
            with self.subTest(case=case):
                self.setUp()
                report, summary = self._run({"requirements.txt": (head.replace("3.6.1", "3.5.0"), head)})
                _inconclusive(self, report, summary, "no_lock_hash")

    def test_an_arbitrary_equality_pin_is_read_as_exact(self) -> None:
        pin = "sigstore==={} --hash=sha256:{}\n"
        report, _summary = self._run(
            {"requirements.txt": (pin.format("3.5.0", "0" * 64), pin.format("3.6.1", _SDIST_SHA256))}
        )
        self.assertEqual(report["binding"], {"kind": "provenance", "reason": ""})

    def test_the_space_spelling_of_a_requirements_hash_is_read(self) -> None:
        pin = "sigstore=={} --hash sha256:{}\n"
        report, _summary = self._run(
            {"requirements.txt": (pin.format("3.5.0", "0" * 64), pin.format("3.6.1", _SDIST_SHA256))}
        )
        self.assertEqual(report["binding"], {"kind": "provenance", "reason": ""})

    def test_a_requirements_pin_beside_a_hashed_one_without_a_hash_is_inconclusive(self) -> None:
        files = self._requirements(_SDIST_SHA256)
        files["requirements/dev.txt"] = ("sigstore==3.5.0\n", "sigstore==3.6.1\n")
        report, summary = self._run(files)
        _inconclusive(self, report, summary, "no_lock_hash")


class PooledBindingTest(_Diff):
    def test_each_covered_scan_gets_its_own_binding_once_every_scan_is_done(self) -> None:
        bound: list[str] = []

        def bind(_change: object, target: coverage.Target, record: dict, _hashed: tuple) -> binding.Binding:
            self.assertEqual(len(self.scanned), 3, "a binding ran before every scan was done")
            bound.append(target.package)
            return binding.Binding("unbound", f"for-{target.package}")

        names = {"a": "1.0.0", "b": "2.0.0", "c": "3.0.0"}
        doc = json.dumps({"repository": "github:o/r"}).encode()
        fetch = {f"https://registry.npmjs.org/{name}/{version}": doc for name, version in names.items()}
        with patch.object(coverage, "_bind", bind):
            report, _summary = self.run_main(
                {"package.json": _package({name: "0.0.1" for name in names})},
                {"package.json": _package(names)},
                fetch=fetch,
            )
        self.assertEqual(sorted(bound), ["a", "b", "c"])
        self.assertEqual(
            [(item["package_name"], item["binding"]["reason"]) for item in report["dependencies"]],
            [("a", "for-a"), ("b", "for-b"), ("c", "for-c")],
        )


class GroupBindingTest(unittest.TestCase):
    def test_a_group_carries_its_first_unbound_binding(self) -> None:
        bound = {**_clean("a", "o/a"), "binding": {"kind": "intrinsic", "reason": ""}}
        unbound = {**_clean("b", "o/b"), "binding": {"kind": "unbound", "reason": "no_provenance"}}
        self.assertEqual(coverage.aggregate([bound, unbound])["binding"], unbound["binding"])
        self.assertEqual(coverage.aggregate([bound, bound])["binding"], bound["binding"])
        self.assertEqual(coverage.aggregate([unbound])["binding"], unbound["binding"])
        report = coverage.aggregate([bound, unbound])
        self.assertEqual([item["binding"] for item in report["dependencies"]], [bound["binding"], unbound["binding"]])
        published = formatter.compose_published_review(report, _BENIGN, _MERGE)
        self.assertEqual((published["verdict"], published["check"]), ("inconclusive", "pass"))

    def test_a_group_carries_its_first_unverified_repository_source(self) -> None:
        verified = {**_clean("a", "o/a"), "repo_source": "identity"}
        named = {**_clean("b", "o/b"), "repo_source": "publisher"}
        self.assertEqual(coverage.aggregate([verified, named])["repo_source"], "publisher")
        self.assertEqual(coverage.aggregate([verified, verified])["repo_source"], "identity")


if __name__ == "__main__":
    unittest.main()
