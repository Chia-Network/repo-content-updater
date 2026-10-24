"""The Fulcio certificate parser: the source repository and commit extensions, and malformed DER."""

from __future__ import annotations

import base64
import json
import unittest

import dependency_cursor_review_certificate as certificate
from test_dependency_cursor_review_binding import _DATA, _NPM_COMMIT, _certificate, _der


def _source(cert: str) -> certificate.Source:
    return certificate.source(base64.b64decode(cert))


class SourceTest(unittest.TestCase):
    def test_a_registry_certificate_names_its_source_repository_and_commit(self) -> None:
        doc = json.loads((_DATA / "npm-sigstore-3.0.0.json").read_text(encoding="utf-8"))
        bundle = doc["attestations"][0]["bundle"]
        raw = bundle["verificationMaterial"]["x509CertificateChain"]["certificates"][0]["rawBytes"]
        self.assertEqual(_source(raw), certificate.Source("https://github.com/sigstore/sigstore-js", _NPM_COMMIT))

    def test_the_two_extensions_are_read_wherever_they_nest(self) -> None:
        self.assertEqual(_source(_certificate("a/b", "c" * 40)), certificate.Source("https://github.com/a/b", "c" * 40))

    def test_a_certificate_without_the_extensions_names_nothing(self) -> None:
        other = _der(0x30, _der(0x06, bytes.fromhex("551d0f")) + _der(0x04, _der(0x0C, b"https://github.com/a/b")))
        self.assertEqual(certificate.source(_der(0x30, _der(0xA3, _der(0x30, other)))), certificate.Source())
        self.assertEqual(certificate.source(b""), certificate.Source())

    def test_a_source_extension_that_is_not_one_utf8_string_is_not_read(self) -> None:
        oid = _der(0x06, bytes.fromhex("2b0601040183bf30010c"))
        url = b"https://github.com/a/b"
        for value in (_der(0x04, _der(0x13, url)), _der(0x04, _der(0x0C, url) + _der(0x0C, url))):
            with self.subTest(value=value):
                self.assertEqual(certificate.source(_der(0x30, oid + value)), certificate.Source())
        with self.assertRaises(ValueError):
            certificate.source(_der(0x30, oid + _der(0x04, url)))

    def test_truncated_der_is_a_value_error(self) -> None:
        der = base64.b64decode(_certificate("a/b", "c" * 40))
        for cut in (1, 2, len(der) // 2, len(der) - 1):
            with self.subTest(cut=cut), self.assertRaises(ValueError):
                certificate.source(der[:cut])


if __name__ == "__main__":
    unittest.main()
