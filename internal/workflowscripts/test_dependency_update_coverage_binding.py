"""coverage.main() binds each covered primary scan to the artifact it installs; decide() reads that binding."""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch

import dependency_update_coverage as coverage
import malware_verdict_formatter as formatter
from test_dependency_cursor_review_binding import _DATA, _NPM_ATTESTATIONS, _NPM_COMMIT, _NPM_DOC, _NPM_INTEGRITY
from test_dependency_update_coverage import _clean
from test_dependency_update_coverage_diff import _BENIGN, _MERGE, _Diff, _package


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
            return {**_clean(update.package, update.repo), "resolved_to": _NPM_COMMIT}

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
        self.assertEqual([(u.package, u.repo) for u in self.scanned], [("sigstore", "sigstore/sigstore-js")])
        self.assertEqual(report["binding"], {"kind": "provenance", "reason": ""})
        self.assertIn("covered, artifact binding `provenance`", summary)
        published = formatter.compose_published_review(report, _BENIGN, _MERGE)
        self.assertEqual((published["verdict"], published["check"]), ("benign", "pass"))

    def test_a_clean_scan_without_provenance_or_a_lock_hash_is_inconclusive_and_passes(self) -> None:
        for integrity, reason in ((_NPM_INTEGRITY, "no_provenance"), (None, "no_lock_hash")):
            with self.subTest(reason=reason):
                self.setUp()
                report, summary = self._run(integrity, b"")
                self.assertEqual(report["binding"], {"kind": "unbound", "reason": reason})
                self.assertIn(f"covered, artifact not bound (`{reason}`)", summary)
                for warn_only in (True, False):
                    published = formatter.compose_published_review(report, _BENIGN, _MERGE, warn_only=warn_only)
                    self.assertEqual((published["verdict"], published["check"]), ("inconclusive", "pass"))
                    self.assertIn(f"artifact_unbound({reason})", published["malware_text"])

    def test_an_unreadable_attestation_answer_is_registry_unavailable(self) -> None:
        report, summary = self._run(_NPM_INTEGRITY, None)
        self.assertEqual(report["binding"], {"kind": "unbound", "reason": "registry_unavailable"})
        self.assertIn("covered, artifact not bound (`registry_unavailable`)", summary)
        published = formatter.compose_published_review(report, _BENIGN, _MERGE)
        self.assertEqual((published["verdict"], published["check"]), ("inconclusive", "pass"))
        self.assertIn("artifact_unbound(registry_unavailable)", published["malware_text"])


class PooledBindingTest(_Diff):
    def test_each_covered_scan_gets_its_own_binding_once_every_scan_is_done(self) -> None:
        bound: list[str] = []

        def bind(_change: object, target: coverage.Target, record: dict) -> dict:
            self.assertEqual(len(self.scanned), 3, "a binding ran before every scan was done")
            bound.append(target.package)
            return {"kind": "unbound", "reason": f"for-{target.package}"}

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


if __name__ == "__main__":
    unittest.main()
