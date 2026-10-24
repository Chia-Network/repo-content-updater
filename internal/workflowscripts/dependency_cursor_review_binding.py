"""Whether the scanned release is the artifact a primary dependency installs.

The scan reads a commit in the GitHub repository the registry names, and the
publisher controls that name. A binding ties the installed artifact back to
the scanned commit:

- intrinsic: the ecosystem installs that git content itself. A Go module zip
  is built from the tag and pinned by go.sum; an action runs the commit its
  full tag or commit SHA resolves to in the action's own repository, which is
  the commit scanned.
- provenance: the lockfile's artifact hash equals the registry's, and every
  provenance attestation the registry serves for the artifact names the
  scanned repository, the scanned commit itself and the artifact's digest.
- unbound: anything else, with a reason. decide() never reports it benign.

Provenance is read, not verified: the registry checks the Sigstore signature
when the attestation is published, and this module reads the repository and
commit from the Fulcio certificate's extensions and the digest from the
signed statement.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import urllib.parse
from typing import NamedTuple

import dependency_cursor_review_upstream as upstream

INTRINSIC, PROVENANCE, UNBOUND = "intrinsic", "provenance", "unbound"
BOUND = frozenset({INTRINSIC, PROVENANCE})
# Why a scan is unbound.
NO_LOCK_HASH = "no_lock_hash"  # no lockfile records one sha512 integrity for the version
HASH_MISMATCH = "hash_mismatch"  # the registry's integrity for the version is not the lockfile's
NO_PROVENANCE = "no_provenance"  # the registry serves no provenance attestation for the artifact
PROVENANCE_MISMATCH = "provenance_mismatch"  # an attestation names another repository, commit or digest
UNSUPPORTED = "unsupported"  # the ecosystem has no binding
REASONS = frozenset({NO_LOCK_HASH, HASH_MISMATCH, NO_PROVENANCE, PROVENANCE_MISMATCH, UNSUPPORTED})

_SLSA_V1 = "https://slsa.dev/provenance/v1"
# Fulcio certificate extensions 1.3.6.1.4.1.57264.1.12 (source repository URI) and .13 (source repository digest).
_FULCIO = bytes.fromhex("2b0601040183bf3001")
_SOURCE_REPO, _SOURCE_COMMIT = _FULCIO + b"\x0c", _FULCIO + b"\x0d"
_YARN_INTEGRITY_RE = re.compile(r"^  integrity (\S+)$", re.MULTILINE)


class Binding(NamedTuple):
    kind: str
    reason: str = ""


class Subject(NamedTuple):
    """A covered primary change: what was installed and what was scanned."""

    name: str
    version: str
    repo: str  # owner/repo that was scanned
    commit: str  # the scanned commit (the peeled to tag)
    locked: tuple[str, ...] = ()  # the text of each top lock entry for name at version


_INTRINSIC = Binding(INTRINSIC)
_PROVENANCE = Binding(PROVENANCE)


def _unbound(reason: str) -> Binding:
    return Binding(UNBOUND, reason)


def intrinsic(_subject: Subject) -> Binding:
    return _INTRINSIC


def unsupported(_subject: Subject) -> Binding:
    return _unbound(UNSUPPORTED)


def _tlvs(data: bytes) -> list[tuple[int, bytes]]:
    """The DER (tag, value) items in `data`. ValueError when they do not fill it exactly."""
    items, index = [], 0
    while index < len(data):
        if index + 2 > len(data):
            raise ValueError("truncated DER")
        tag, length, index = data[index], data[index + 1], index + 2
        if length & 0x80:
            width = length & 0x7F
            length, index = int.from_bytes(data[index : index + width], "big"), index + width
        if index + length > len(data):
            raise ValueError("truncated DER")
        items.append((tag, data[index : index + length]))
        index += length
    return items


def _extensions(der: bytes, found: dict[bytes, str]) -> dict[bytes, str]:
    """The source repository extensions of a Fulcio certificate as OID bytes -> UTF8String value.

    Older Fulcio extensions hold raw strings, not DER, so only these two are decoded.
    """
    for tag, value in _tlvs(der):
        if not tag & 0x20:
            continue
        children = _tlvs(value)
        (oid_tag, oid), (last_tag, last) = (children[0], children[-1]) if children else ((0, b""), (0, b""))
        if tag == 0x30 and oid_tag == 0x06 and oid in {_SOURCE_REPO, _SOURCE_COMMIT} and last_tag == 0x04:
            inner = _tlvs(last)
            if len(inner) == 1 and inner[0][0] == 0x0C:
                found[oid] = inner[0][1].decode("utf-8")
        else:
            _extensions(value, found)
    return found


def _decoded(text: object) -> bytes:
    return base64.b64decode(text, validate=True) if isinstance(text, str) else b""


def _attested(subject: Subject, certificate: object, statement: object, algorithm: str, digest: str) -> bool:
    """One attestation names the scanned repository, the scanned commit and the artifact digest."""
    try:
        found = _extensions(_decoded(certificate), {})
        doc = json.loads(_decoded(statement))
    except (ValueError, UnicodeDecodeError, binascii.Error, IndexError, RecursionError):
        return False
    items = doc.get("subject") if isinstance(doc, dict) else None
    digests = [item.get("digest") for item in items if isinstance(item, dict)] if isinstance(items, list) else []
    return (
        found.get(_SOURCE_REPO, "").lower() == f"https://github.com/{subject.repo}".lower()
        and bool(subject.commit)
        and found.get(_SOURCE_COMMIT) == subject.commit
        and any(isinstance(item, dict) and item.get(algorithm) == digest for item in digests)
    )


def _provenance(subject: Subject, attestations: list[tuple[object, object]], algorithm: str, digest: str) -> Binding:
    if not attestations:
        return _unbound(NO_PROVENANCE)
    if all(_attested(subject, cert, statement, algorithm, digest) for cert, statement in attestations):
        return _PROVENANCE
    return _unbound(PROVENANCE_MISMATCH)


def _dig(doc: object, *keys: str | int) -> object:
    for key in keys:
        if isinstance(key, int) and isinstance(doc, list) and len(doc) > key:
            doc = doc[key]
        elif isinstance(key, str) and isinstance(doc, dict):
            doc = doc.get(key)
        else:
            return None
    return doc


def _lock_integrity(text: str) -> str:
    """The integrity of one lock entry: a package-lock record, or a yarn.lock stanza."""
    try:
        record = json.loads(text)
    except ValueError:
        match = _YARN_INTEGRITY_RE.search(text)
        return match.group(1) if match else ""
    integrity = _dig(record, 1, "integrity")
    return integrity if isinstance(integrity, str) else ""


def npm(subject: Subject) -> Binding:
    """The lock's sha512 integrity is the registry's, and the SLSA attestations are for it and the scan."""
    integrities = {_lock_integrity(text) for text in subject.locked} - {""}
    integrity = integrities.pop() if len(integrities) == 1 else ""
    if not integrity.startswith("sha512-"):
        return _unbound(NO_LOCK_HASH)
    version = urllib.parse.quote(subject.version, safe="")
    doc = upstream.fetch_json(f"https://registry.npmjs.org/{subject.name}/{version}")
    if _dig(doc, "dist", "integrity") != integrity:
        return _unbound(HASH_MISMATCH)
    try:
        digest = base64.b64decode(integrity.removeprefix("sha512-"), validate=True).hex()
    except binascii.Error:
        return _unbound(NO_LOCK_HASH)
    escaped = urllib.parse.quote(subject.name, safe="@")
    found = upstream.fetch_json(f"https://registry.npmjs.org/-/npm/v1/attestations/{escaped}@{version}")
    bundles = [
        _dig(item, "bundle")
        for item in _dig(found, "attestations") or []
        if isinstance(item, dict) and item.get("predicateType") == _SLSA_V1
    ]
    pairs = [
        (
            _dig(bundle, "verificationMaterial", "x509CertificateChain", "certificates", 0, "rawBytes")
            or _dig(bundle, "verificationMaterial", "certificate", "rawBytes"),
            _dig(bundle, "dsseEnvelope", "payload"),
        )
        for bundle in bundles
    ]
    return _provenance(subject, pairs, "sha512", digest)


def pypi(subject: Subject) -> Binding:
    """Every file of the release has publish attestations for its sha256 and the scan.

    pip may install any file of the release, so each one is checked.
    """
    project, version = subject.name, urllib.parse.quote(subject.version, safe="")
    files = _dig(upstream.fetch_json(f"https://pypi.org/pypi/{project}/{version}/json"), "urls")
    if not isinstance(files, list) or not files:
        return _unbound(NO_PROVENANCE)
    for item in files:
        filename, sha256 = _dig(item, "filename"), _dig(item, "digests", "sha256")
        if not isinstance(filename, str) or not isinstance(sha256, str):
            return _unbound(NO_PROVENANCE)
        quoted = urllib.parse.quote(filename, safe="")
        found = upstream.fetch_json(f"https://pypi.org/integrity/{project}/{version}/{quoted}/provenance")
        pairs = [
            (_dig(attestation, "verification_material", "certificate"), _dig(attestation, "envelope", "statement"))
            for bundle in _dig(found, "attestation_bundles") or []
            for attestation in _dig(bundle, "attestations") or []
        ]
        binding = _provenance(subject, pairs, "sha256", sha256)
        if binding != _PROVENANCE:
            return binding
    return _PROVENANCE
