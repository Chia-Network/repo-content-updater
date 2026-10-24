"""Artifact binding: lock hashes, registry integrity and provenance attestations, with recorded registry answers."""

from __future__ import annotations

import base64
import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import dependency_cursor_review_binding as binding
import dependency_cursor_review_upstream as upstream
from upstream_malware_scan_case import _commit_file, _git, _init_repo

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


def _lock_record(integrity: str) -> str:
    record = {"version": "3.0.0", "resolved": "https://registry.npmjs.org/sigstore/-/sigstore-3.0.0.tgz"}
    return json.dumps(["node_modules/sigstore", {**record, "integrity": integrity}])


def _fixture(name: str) -> dict:
    return json.loads((_DATA / name).read_text(encoding="utf-8"))


class _Registry(unittest.TestCase):
    def bind(self, check, subject: binding.Subject, answers: dict[str, object]) -> binding.Binding:
        self.urls: list[str] = []

        def fetch(url: str) -> bytes:
            self.urls.append(url)
            return json.dumps(answers[url]).encode() if url in answers else b""

        with patch.object(upstream, "_fetch", fetch):
            return check(subject)


_NPM = binding.Subject("sigstore", "3.0.0", "sigstore/sigstore-js", _NPM_COMMIT, ".", (_lock_record(_NPM_INTEGRITY),))
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
        for attestations in (None, {}, {"attestations": []}, publish):
            with self.subTest(attestations=attestations):
                found = self.bind(binding.npm, _NPM, self._answers(attestations))
                self.assertEqual(found, binding.Binding(_UNBOUND, binding.NO_PROVENANCE))

    def test_the_lock_must_record_one_sha512_integrity(self) -> None:
        for locked in (
            (),
            (json.dumps(["dependencies", "^3.0.0"]),),
            (_lock_record("sha1-AAAA"),),
            (_lock_record(_NPM_INTEGRITY), _lock_record("sha512-" + "B" * 86 + "==")),
            (_lock_record("sha512-not base64"),),
        ):
            with self.subTest(locked=locked):
                found = self.bind(binding.npm, _NPM._replace(locked=locked), self._answers(None))
                self.assertIn(found.reason, {binding.NO_LOCK_HASH, binding.HASH_MISMATCH})
                self.assertEqual(found.kind, _UNBOUND)

    def test_the_registry_integrity_must_be_the_lock_hash(self) -> None:
        for doc in ({"dist": {"integrity": "sha512-" + "A" * 86 + "=="}}, {}, None):
            with self.subTest(doc=doc):
                found = self.bind(binding.npm, _NPM, {_NPM_DOC: doc})
                self.assertEqual(found, binding.Binding(_UNBOUND, binding.HASH_MISMATCH))
                self.assertEqual(self.urls, [_NPM_DOC])

    def test_a_yarn_stanza_and_a_duplicate_lock_record_read_as_one_integrity(self) -> None:
        stanza = f'sigstore@^3.0.0:\n  version "3.0.0"\n  integrity {_NPM_INTEGRITY}\n'
        subject = _NPM._replace(locked=(stanza, _lock_record(_NPM_INTEGRITY)))
        found = self.bind(binding.npm, subject, self._answers(_fixture("npm-sigstore-3.0.0.json")))
        self.assertEqual(found, binding.Binding(binding.PROVENANCE))

    def test_a_scoped_name_is_escaped_in_the_attestation_url(self) -> None:
        subject = _NPM._replace(name="@scope/pkg")
        self.bind(
            binding.npm,
            subject,
            {"https://registry.npmjs.org/@scope/pkg/3.0.0": {"dist": {"integrity": _NPM_INTEGRITY}}},
        )
        self.assertEqual(self.urls[-1], "https://registry.npmjs.org/-/npm/v1/attestations/@scope%2Fpkg@3.0.0")


class AncestorTest(_Registry):
    def test_an_attested_commit_the_scanned_commit_descends_from_is_provenance(self) -> None:
        with TemporaryDirectory() as tmp:
            repo = Path(tmp) / "upstream"
            _init_repo(repo)
            commits = []
            for content in ("1", "2"):
                _commit_file(repo, "index.js", content, content)
                commits.append(_git(repo, "rev-parse", "HEAD"))
            subject = _NPM._replace(repo="a/b", checkout=str(repo))
            for attested, scanned, want in (
                (commits[0], commits[1], binding.Binding(binding.PROVENANCE)),
                (commits[1], commits[0], binding.Binding(_UNBOUND, binding.PROVENANCE_MISMATCH)),
                ("--output=x" + "0" * 30, commits[1], binding.Binding(_UNBOUND, binding.PROVENANCE_MISMATCH)),
            ):
                with self.subTest(attested=attested, scanned=scanned):
                    pair = (_certificate("a/b", attested), _statement("sha512", _NPM_DIGEST))
                    answers = {
                        _NPM_DOC: {"dist": {"integrity": _NPM_INTEGRITY}},
                        _NPM_ATTESTATIONS: _npm_attestations(pair),
                    }
                    self.assertEqual(self.bind(binding.npm, subject._replace(commit=scanned), answers), want)


_PYPI = binding.Subject("sigstore", "3.6.1", "sigstore/sigstore-python", _PYPI_COMMIT, ".")
_WHEEL = "sigstore-3.6.1-py3-none-any.whl"


def _integrity_url(filename: str) -> str:
    return f"https://pypi.org/integrity/sigstore/3.6.1/{filename}/provenance"


def _pypi_provenance(*pairs: tuple[str, str]) -> dict:
    attestations = [{"verification_material": {"certificate": c}, "envelope": {"statement": s}} for c, s in pairs]
    return {"attestation_bundles": [{"attestations": attestations}]}


class PypiTest(_Registry):
    def _files(self, *files: tuple[str, str]) -> dict:
        return {"urls": [{"filename": name, "digests": {"sha256": digest}} for name, digest in files]}

    def test_every_file_of_the_release_needs_provenance_for_its_hash_and_the_scan(self) -> None:
        sdist = {
            _PYPI_DOC: self._files((_SDIST, _SDIST_SHA256)),
            _integrity_url(_SDIST): _fixture(f"pypi-{_SDIST}.json"),
        }
        self.assertEqual(self.bind(binding.pypi, _PYPI, sdist), binding.Binding(binding.PROVENANCE))
        wheel_sha = hashlib.sha256(b"wheel").hexdigest()
        both = {**sdist, _PYPI_DOC: self._files((_SDIST, _SDIST_SHA256), (_WHEEL, wheel_sha))}
        self.assertEqual(self.bind(binding.pypi, _PYPI, both), binding.Binding(_UNBOUND, binding.NO_PROVENANCE))
        wheel = _pypi_provenance(
            (_certificate("sigstore/sigstore-python", _PYPI_COMMIT), _statement("sha256", wheel_sha))
        )
        found = self.bind(binding.pypi, _PYPI, {**both, _integrity_url(_WHEEL): wheel})
        self.assertEqual(found, binding.Binding(binding.PROVENANCE))

    def test_another_repository_commit_or_file_hash_is_a_mismatch(self) -> None:
        real = {_integrity_url(_SDIST): _fixture(f"pypi-{_SDIST}.json")}
        for name, subject, digest in (
            ("benign repository named", _PYPI._replace(repo="psf/requests"), _SDIST_SHA256),
            ("another commit", _PYPI._replace(commit="f" * 40), _SDIST_SHA256),
            ("another file hash", _PYPI, "0" * 64),
        ):
            with self.subTest(name):
                answers = {**real, _PYPI_DOC: self._files((_SDIST, digest))}
                found = self.bind(binding.pypi, subject, answers)
                self.assertEqual(found, binding.Binding(_UNBOUND, binding.PROVENANCE_MISMATCH))

    def test_a_release_with_no_files_or_unreadable_files_is_no_provenance(self) -> None:
        for doc in (None, {"urls": []}, {"urls": [{"filename": _SDIST}]}, {"urls": "x"}):
            with self.subTest(doc=doc):
                found = self.bind(binding.pypi, _PYPI, {_PYPI_DOC: doc})
                self.assertEqual(found, binding.Binding(_UNBOUND, binding.NO_PROVENANCE))


if __name__ == "__main__":
    unittest.main()
