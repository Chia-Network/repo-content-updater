"""Artifact binding: lock hashes, registry hashes, provenance attestations and Go proxy origins, recorded offline."""

from __future__ import annotations

import base64
import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

import dependency_cursor_review_binding as binding
import dependency_cursor_review_upstream as upstream
from test_dependency_manifest_grammars import _CONTEXT, _CONTEXT_H1, _UTFBOM, _UTFBOM_H1

_DATA = Path(__file__).resolve().parent / "testdata" / "provenance"
# sigstore@3.0.0 on npm and sigstore 3.6.1 on PyPI, as the registries served them.
_NPM_COMMIT = "3a57a741bfb9f7c3bca69b63e170fc28e9432e69"
_NPM_INTEGRITY = "sha512-PHMifhh3EN4loMcHCz6l3v/luzgT3za+9f8subGgeMNjbJjzH4Ij/YoX3Gvu+kaouJRIlVdTHHCREADYf+ZteA=="
_PYPI_COMMIT = "896cfe13105495e6dc6f8faf23e1007da35edeeb"
_SDIST = "sigstore-3.6.1.tar.gz"
_SDIST_SHA256 = "ee60fdc9236fd6709271ad53b44027461360c3fde155d2af15482e4c451ff865"
_NPM_DOC = "https://registry.npmjs.org/sigstore/3.0.0"
_NPM_ATTESTATIONS = "https://registry.npmjs.org/-/npm/v1/attestations/sigstore@3.0.0"
_PYPI_DOC = "https://pypi.org/pypi/sigstore/3.6.1/json"
_FULCIO = bytes.fromhex("2b0601040183bf3001")


def _der(tag: int, body: bytes) -> bytes:
    size = len(body)
    length = bytes([size]) if size < 0x80 else bytes([0x80 | 2]) + size.to_bytes(2, "big")
    return bytes([tag]) + length + body


def _certificate(repo: str, commit: str) -> str:
    """A certificate shaped like Fulcio's, carrying the source repository URI and digest extensions."""

    def extension(number: int, value: str) -> bytes:
        return _der(0x30, _der(0x06, _FULCIO + bytes([number])) + _der(0x04, _der(0x0C, value.encode())))

    algorithm = _der(0x30, _der(0x06, bytes.fromhex("2a8648ce3d040303")))
    extensions = _der(0xA3, _der(0x30, extension(12, f"https://github.com/{repo}") + extension(13, commit)))
    tbs = _der(0x30, _der(0xA0, _der(0x02, b"\x02")) + algorithm + extensions)
    return base64.b64encode(_der(0x30, tbs + algorithm + _der(0x03, b"\x00signature"))).decode()


def _statement(algorithm: str, digest: str) -> str:
    doc = {"_type": "https://in-toto.io/Statement/v1", "subject": [{"name": "artifact", "digest": {algorithm: digest}}]}
    return base64.b64encode(json.dumps(doc).encode()).decode()


def _npm_attestations(*pairs: tuple[str, str]) -> dict:
    return {
        "attestations": [
            {
                "predicateType": "https://slsa.dev/provenance/v1",
                "bundle": {
                    "verificationMaterial": {"certificate": {"rawBytes": cert}},
                    "dsseEnvelope": {"payload": statement},
                },
            }
            for cert, statement in pairs
        ]
    }


def _fixture(name: str) -> dict:
    return json.loads((_DATA / name).read_text(encoding="utf-8"))


class _Registry(unittest.TestCase):
    def bind(self, check, subject: binding.Subject, answers: dict[str, object]) -> binding.Binding:
        """A URL with no answer is a 404; None is no readable answer; bytes are the body as served."""
        self.urls: list[str] = []

        def fetch(url: str, *_limit: int) -> bytes | None:
            self.urls.append(url)
            answer = answers.get(url, b"")
            return answer if answer is None or isinstance(answer, bytes) else json.dumps(answer).encode()

        with patch.object(upstream, "_fetch", fetch):
            return check(subject)


_NPM = binding.Subject("sigstore", "3.0.0", "sigstore/sigstore-js", _NPM_COMMIT, (_NPM_INTEGRITY,))
_NPM_DIGEST = base64.b64decode(_NPM_INTEGRITY.removeprefix("sha512-")).hex()
_UNBOUND = binding.UNBOUND


class NpmTest(_Registry):
    def _answers(self, attestations: object) -> dict[str, object]:
        return {_NPM_DOC: {"dist": {"integrity": _NPM_INTEGRITY}}, _NPM_ATTESTATIONS: attestations}

    def test_registry_provenance_for_the_lock_hash_and_the_scanned_commit_is_provenance(self) -> None:
        found = self.bind(binding.npm, _NPM, self._answers(_fixture("npm-sigstore-3.0.0.json")))
        self.assertEqual(found, binding.Binding(binding.PROVENANCE))
        self.assertEqual(self.urls, [_NPM_DOC, _NPM_ATTESTATIONS])

    def test_another_repository_commit_or_digest_is_a_mismatch(self) -> None:
        real = _fixture("npm-sigstore-3.0.0.json")
        good = (_certificate("sigstore/sigstore-js", _NPM_COMMIT), _statement("sha512", _NPM_DIGEST))
        for name, subject, attestations in (
            ("benign repository named", _NPM._replace(repo="sigstore/other"), real),
            ("another commit", _NPM._replace(commit="f" * 40), real),
            ("another digest", _NPM, _npm_attestations((good[0], _statement("sha512", "00" * 64)))),
            (
                "one of two attestations is for another repository",
                _NPM,
                _npm_attestations(good, (_certificate("evil/fork", _NPM_COMMIT), good[1])),
            ),
            ("statement only, no certificate", _NPM, _npm_attestations(("", good[1]))),
            ("truncated certificate", _NPM, _npm_attestations((good[0][:40], good[1]))),
            ("not base64", _NPM, _npm_attestations(("@@@", good[1]))),
        ):
            with self.subTest(name):
                found = self.bind(binding.npm, subject, self._answers(attestations))
                self.assertEqual(found, binding.Binding(_UNBOUND, binding.PROVENANCE_MISMATCH))

    def test_no_slsa_provenance_is_no_provenance(self) -> None:
        publish = {
            "attestations": [{"predicateType": "https://github.com/npm/attestation/tree/main/specs/publish/v0.1"}]
        }
        for attestations in ({}, {"attestations": []}, publish):
            with self.subTest(attestations=attestations):
                found = self.bind(binding.npm, _NPM, self._answers(attestations))
                self.assertEqual(found, binding.Binding(_UNBOUND, binding.NO_PROVENANCE))
        not_found = {_NPM_DOC: {"dist": {"integrity": _NPM_INTEGRITY}}}
        self.assertEqual(self.bind(binding.npm, _NPM, not_found), binding.Binding(_UNBOUND, binding.NO_PROVENANCE))
        self.assertEqual(self.urls, [_NPM_DOC, _NPM_ATTESTATIONS])

    def test_the_lock_must_record_one_sha512_integrity(self) -> None:
        for locked in (
            (),
            ("",),
            ("sha1-AAAA",),
            (_NPM_INTEGRITY, "sha512-" + "B" * 86 + "=="),
            ("sha512-not base64",),
        ):
            with self.subTest(locked=locked):
                found = self.bind(binding.npm, _NPM._replace(locked=locked), self._answers(None))
                self.assertEqual(found, binding.Binding(_UNBOUND, binding.NO_LOCK_HASH))
                self.assertEqual(self.urls, [])

    def test_the_registry_integrity_must_be_the_lock_hash(self) -> None:
        found = self.bind(binding.npm, _NPM, {_NPM_DOC: {"dist": {"integrity": "sha512-" + "A" * 86 + "=="}}})
        self.assertEqual(found, binding.Binding(_UNBOUND, binding.HASH_MISMATCH))
        self.assertEqual(self.urls, [_NPM_DOC])

    def test_a_404_or_a_version_with_no_integrity_is_registry_unavailable_not_a_mismatch(self) -> None:
        """No registry hash was read, so there is nothing for the lock hash to mismatch."""
        for name, answers in (
            ("404", {}),
            ("empty body", {_NPM_DOC: b""}),
            ("empty document", {_NPM_DOC: {}}),
            ("no dist", {_NPM_DOC: {"version": "3.0.0"}}),
            ("empty integrity", {_NPM_DOC: {"dist": {"integrity": ""}}}),
            ("integrity not a string", {_NPM_DOC: {"dist": {"integrity": [_NPM_INTEGRITY]}}}),
        ):
            with self.subTest(name):
                found = self.bind(binding.npm, _NPM, answers)
                self.assertEqual(found, binding.Binding(_UNBOUND, binding.REGISTRY_UNAVAILABLE))
                self.assertEqual(self.urls, [_NPM_DOC])

    def test_an_unreadable_registry_answer_is_registry_unavailable_not_a_mismatch(self) -> None:
        good = self._answers(_fixture("npm-sigstore-3.0.0.json"))
        for url in (_NPM_DOC, _NPM_ATTESTATIONS):
            for body in (None, b"not json", b"[]", b"null"):
                with self.subTest(url=url, body=body):
                    found = self.bind(binding.npm, _NPM, {**good, url: body})
                    self.assertEqual(found, binding.Binding(_UNBOUND, binding.REGISTRY_UNAVAILABLE))

    def test_duplicate_lock_entries_with_one_integrity_read_as_one(self) -> None:
        subject = _NPM._replace(locked=(_NPM_INTEGRITY, "", _NPM_INTEGRITY))
        found = self.bind(binding.npm, subject, self._answers(_fixture("npm-sigstore-3.0.0.json")))
        self.assertEqual(found, binding.Binding(binding.PROVENANCE))

    def test_a_scoped_name_is_escaped_in_the_registry_and_attestation_urls(self) -> None:
        subject = _NPM._replace(name="@scope/pkg")
        self.bind(
            binding.npm,
            subject,
            {"https://registry.npmjs.org/@scope%2Fpkg/3.0.0": {"dist": {"integrity": _NPM_INTEGRITY}}},
        )
        self.assertEqual(
            self.urls,
            [
                "https://registry.npmjs.org/@scope%2Fpkg/3.0.0",
                "https://registry.npmjs.org/-/npm/v1/attestations/@scope%2Fpkg@3.0.0",
            ],
        )

    def test_a_name_that_is_not_an_npm_package_name_is_unavailable_and_reads_nothing(self) -> None:
        for name in ("", "@scope", "scope/name", "../name", "a b"):
            with self.subTest(name=name):
                found = self.bind(binding.npm, _NPM._replace(name=name), self._answers(None))
                self.assertEqual(found, binding.Binding(_UNBOUND, binding.REGISTRY_UNAVAILABLE))
                self.assertEqual(self.urls, [])


class ExactCommitTest(_Registry):
    def test_only_the_scanned_commit_itself_is_provenance(self) -> None:
        """An ancestor, a descendant or an abbreviation of the scanned commit is another commit."""
        parent, child = "1" * 40, "2" * 40
        for name, attested, scanned, want in (
            ("the scanned commit", child, child, binding.Binding(binding.PROVENANCE)),
            ("an ancestor", parent, child, binding.Binding(_UNBOUND, binding.PROVENANCE_MISMATCH)),
            ("a descendant", child, parent, binding.Binding(_UNBOUND, binding.PROVENANCE_MISMATCH)),
            ("an abbreviation", child[:12], child, binding.Binding(_UNBOUND, binding.PROVENANCE_MISMATCH)),
            ("no scanned commit", "", "", binding.Binding(_UNBOUND, binding.PROVENANCE_MISMATCH)),
        ):
            with self.subTest(name):
                pair = (_certificate("a/b", attested), _statement("sha512", _NPM_DIGEST))
                answers = {
                    _NPM_DOC: {"dist": {"integrity": _NPM_INTEGRITY}},
                    _NPM_ATTESTATIONS: _npm_attestations(pair),
                }
                found = self.bind(binding.npm, _NPM._replace(repo="a/b", commit=scanned), answers)
                self.assertEqual(found, want)


_PYPI = binding.Subject("sigstore", "3.6.1", "sigstore/sigstore-python", _PYPI_COMMIT)
_WHEEL = "sigstore-3.6.1-py3-none-any.whl"


def _integrity_url(filename: str) -> str:
    return f"https://pypi.org/integrity/sigstore/3.6.1/{filename}/provenance"


def _pypi_provenance(*pairs: tuple[str, str]) -> dict:
    attestations = [{"verification_material": {"certificate": c}, "envelope": {"statement": s}} for c, s in pairs]
    return {"attestation_bundles": [{"attestations": attestations}]}


_SDIST_LOCK = f"sha256:{_SDIST_SHA256}"
_WHEEL_SHA256 = hashlib.sha256(b"wheel").hexdigest()


class PypiTest(_Registry):
    def _files(self, *files: tuple[str, str]) -> dict:
        return {"urls": [{"filename": name, "digests": {"sha256": digest}} for name, digest in files]}

    def _answers(self, **extra: object) -> dict[str, object]:
        return {
            _PYPI_DOC: self._files((_SDIST, _SDIST_SHA256), (_WHEEL, _WHEEL_SHA256)),
            _integrity_url(_SDIST): _fixture(f"pypi-{_SDIST}.json"),
            **extra,
        }

    def test_a_locked_file_with_provenance_for_its_hash_and_the_scan_is_provenance(self) -> None:
        found = self.bind(binding.pypi, _PYPI._replace(locked=(_SDIST_LOCK,)), self._answers())
        self.assertEqual(found, binding.Binding(binding.PROVENANCE))
        self.assertEqual(self.urls, [_PYPI_DOC, _integrity_url(_SDIST)])

    def test_every_locked_file_needs_provenance_and_an_unlocked_file_is_not_read(self) -> None:
        both = _PYPI._replace(locked=(f"{_SDIST_LOCK} sha256:{_WHEEL_SHA256}",))
        self.assertEqual(
            self.bind(binding.pypi, both, self._answers()), binding.Binding(_UNBOUND, binding.NO_PROVENANCE)
        )
        wheel = _pypi_provenance(
            (_certificate("sigstore/sigstore-python", _PYPI_COMMIT), _statement("sha256", _WHEEL_SHA256))
        )
        found = self.bind(binding.pypi, both, self._answers(**{_integrity_url(_WHEEL): wheel}))
        self.assertEqual(found, binding.Binding(binding.PROVENANCE))
        # Two locks for the version: the files either one locks are checked.
        two = _PYPI._replace(locked=(_SDIST_LOCK, f"sha256:{_WHEEL_SHA256}"))
        self.assertEqual(
            self.bind(binding.pypi, two, self._answers()), binding.Binding(_UNBOUND, binding.NO_PROVENANCE)
        )

    def test_no_usable_lock_hash_is_no_lock_hash_and_reads_nothing(self) -> None:
        for locked in (
            (),
            ("",),
            (_SDIST_LOCK, ""),
            (f"md5:{'0' * 32}",),
            (f"sha512:{'0' * 128}",),
            (_SDIST_LOCK.upper(),),
            ("sha256:abc",),
            (f"{_SDIST_LOCK} sha384:{'0' * 96}",),
        ):
            with self.subTest(locked=locked):
                found = self.bind(binding.pypi, _PYPI._replace(locked=locked), self._answers())
                self.assertEqual(found, binding.Binding(_UNBOUND, binding.NO_LOCK_HASH))
                self.assertEqual(self.urls, [])

    def test_a_lock_hash_that_is_no_file_of_the_release_is_a_hash_mismatch(self) -> None:
        for name, answers in (
            ("another file hash", self._answers(**{_PYPI_DOC: self._files((_SDIST, "0" * 64))})),
            ("one of two locked files", self._answers(**{_PYPI_DOC: self._files((_WHEEL, _WHEEL_SHA256))})),
        ):
            with self.subTest(name):
                found = self.bind(binding.pypi, _PYPI._replace(locked=(_SDIST_LOCK,)), answers)
                self.assertEqual(found, binding.Binding(_UNBOUND, binding.HASH_MISMATCH))
                self.assertEqual(self.urls, [_PYPI_DOC])

    def test_a_404_or_a_release_with_no_file_hash_is_registry_unavailable_not_a_mismatch(self) -> None:
        """No registry hash was read, so there is nothing for the lock hash to mismatch."""
        for name, answers in (
            ("404", {}),
            ("empty body", {_PYPI_DOC: b""}),
            ("empty document", {_PYPI_DOC: {}}),
            ("no files", {_PYPI_DOC: {"urls": []}}),
            ("unreadable files", {_PYPI_DOC: {"urls": "x"}}),
            ("a file with no sha256", {_PYPI_DOC: {"urls": [{"filename": _SDIST}]}}),
        ):
            with self.subTest(name):
                found = self.bind(binding.pypi, _PYPI._replace(locked=(_SDIST_LOCK,)), answers)
                self.assertEqual(found, binding.Binding(_UNBOUND, binding.REGISTRY_UNAVAILABLE))
                self.assertEqual(self.urls, [_PYPI_DOC])

    def test_another_repository_commit_or_attested_digest_is_a_mismatch(self) -> None:
        zero = "0" * 64
        for name, subject, files in (
            ("benign repository named", _PYPI._replace(repo="psf/requests", locked=(_SDIST_LOCK,)), _SDIST_SHA256),
            ("another commit", _PYPI._replace(commit="f" * 40, locked=(_SDIST_LOCK,)), _SDIST_SHA256),
            ("attested for another digest", _PYPI._replace(locked=(f"sha256:{zero}",)), zero),
        ):
            with self.subTest(name):
                found = self.bind(binding.pypi, subject, self._answers(**{_PYPI_DOC: self._files((_SDIST, files))}))
                self.assertEqual(found, binding.Binding(_UNBOUND, binding.PROVENANCE_MISMATCH))

    def test_an_unreadable_registry_answer_is_registry_unavailable(self) -> None:
        for url in (_PYPI_DOC, _integrity_url(_SDIST)):
            for body in (None, b"not json", b"[]"):
                with self.subTest(url=url, body=body):
                    subject = _PYPI._replace(locked=(_SDIST_LOCK,))
                    found = self.bind(binding.pypi, subject, self._answers(**{url: body}))
                    self.assertEqual(found, binding.Binding(_UNBOUND, binding.REGISTRY_UNAVAILABLE))


_GO_COMMIT = "c" * 40
_GO = binding.Subject("github.com/dimchansky/utfbom", "1.1.1", "dimchansky/utfbom", _GO_COMMIT, (_UTFBOM_H1,))
_GO_ZIP = "https://proxy.golang.org/github.com/dimchansky/utfbom/@v/v1.1.1.zip"
_GO_INFO = "https://proxy.golang.org/github.com/dimchansky/utfbom/@v/v1.1.1.info"


def _origin(commit: str) -> dict:
    return {"Version": "v1.1.1", "Origin": {"VCS": "git", "Ref": "refs/tags/v1.1.1", "Hash": commit}}


class GoTest(_Registry):
    def _answers(self, **extra: object) -> dict[str, object]:
        return {_GO_ZIP: _UTFBOM, _GO_INFO: _origin(_GO_COMMIT), **extra}

    def test_a_proxy_zip_hashing_to_go_sum_built_from_the_scanned_commit_is_checksum_bound(self) -> None:
        self.assertEqual(self.bind(binding.go, _GO, self._answers()), binding.Binding(binding.CHECKSUM))
        self.assertEqual(self.urls, [_GO_ZIP, _GO_INFO])

    def test_a_proxy_zip_served_from_its_storage_is_checksum_bound(self) -> None:
        stored = "https://storage.googleapis.com/proxy/utfbom.zip"
        answers = {
            _GO_ZIP: (302, stored, b""),
            stored: (200, "", _UTFBOM),
            _GO_INFO: (200, "", json.dumps(_origin(_GO_COMMIT)).encode()),
        }
        with patch.object(upstream, "_get", lambda url, _limit, _accept: answers[url]):
            self.assertEqual(binding.go(_GO), binding.Binding(binding.CHECKSUM))

    def test_a_proxy_zip_that_does_not_hash_to_go_sum_is_a_hash_mismatch(self) -> None:
        for name, subject, answers in (
            ("another go.sum hash", _GO._replace(locked=(_CONTEXT_H1,)), self._answers()),
            ("another zip", _GO, self._answers(**{_GO_ZIP: _CONTEXT})),
        ):
            with self.subTest(name):
                self.assertEqual(
                    self.bind(binding.go, subject, answers), binding.Binding(_UNBOUND, binding.HASH_MISMATCH)
                )
                self.assertEqual(self.urls, [_GO_ZIP])

    def test_no_single_go_sum_entry_is_no_lock_hash_and_reads_nothing(self) -> None:
        for locked in ((), ("",), (_UTFBOM_H1, _CONTEXT_H1), ("h2:abc",)):
            with self.subTest(locked=locked):
                found = self.bind(binding.go, _GO._replace(locked=locked), self._answers())
                self.assertEqual(found, binding.Binding(_UNBOUND, binding.NO_LOCK_HASH))
                self.assertEqual(self.urls, [])
        found = self.bind(binding.go, _GO._replace(locked=(_UTFBOM_H1, "", _UTFBOM_H1)), self._answers())
        self.assertEqual(found, binding.Binding(binding.CHECKSUM))

    def test_only_the_scanned_commit_itself_as_the_zip_origin_is_bound(self) -> None:
        for name, subject, info in (
            ("another commit", _GO, _origin("d" * 40)),
            ("an abbreviation", _GO, _origin(_GO_COMMIT[:12])),
            ("an upper-case spelling", _GO, _origin(_GO_COMMIT.upper())),
            ("no origin", _GO, {"Version": "v1.1.1"}),
            ("unknown to the proxy", _GO, {}),
            ("no scanned commit", _GO._replace(commit=""), _origin("")),
        ):
            with self.subTest(name):
                found = self.bind(binding.go, subject, self._answers(**{_GO_INFO: info}))
                self.assertEqual(found, binding.Binding(_UNBOUND, binding.COMMIT_MISMATCH))
                self.assertEqual(self.urls, [_GO_ZIP, _GO_INFO])

    def test_an_unreadable_proxy_answer_is_registry_unavailable(self) -> None:
        for url, body in (
            (_GO_ZIP, None),
            (_GO_ZIP, b""),
            (_GO_ZIP, b"not a zip"),
            (_GO_INFO, None),
            (_GO_INFO, b"not json"),
            (_GO_INFO, b"[]"),
        ):
            with self.subTest(url=url, body=body):
                found = self.bind(binding.go, _GO, self._answers(**{url: body}))
                self.assertEqual(found, binding.Binding(_UNBOUND, binding.REGISTRY_UNAVAILABLE))

    def test_upper_case_letters_are_escaped_in_proxy_urls(self) -> None:
        subject = _GO._replace(name="github.com/Azure/go-autorest", version="14.2.0+incompatible")
        self.bind(binding.go, subject, {})
        self.assertEqual(
            self.urls, ["https://proxy.golang.org/github.com/!azure/go-autorest/@v/v14.2.0+incompatible.zip"]
        )


if __name__ == "__main__":
    unittest.main()
