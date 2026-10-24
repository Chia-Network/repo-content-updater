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
signed statement. A registry that gives no readable answer is
registry_unavailable, never a hash or provenance result.
"""

from __future__ import annotations

import base64
import binascii
import json
import urllib.parse
from typing import NamedTuple

import dependency_cursor_review_certificate as certificate
import dependency_cursor_review_upstream as upstream

INTRINSIC, PROVENANCE, UNBOUND = "intrinsic", "provenance", "unbound"
BOUND = frozenset({INTRINSIC, PROVENANCE})
# Why a scan is unbound.
NO_LOCK_HASH = "no_lock_hash"  # no lockfile records one sha512 integrity for the version
HASH_MISMATCH = "hash_mismatch"  # the registry's integrity for the version is not the lockfile's
NO_PROVENANCE = "no_provenance"  # the registry serves no provenance attestation for the artifact
PROVENANCE_MISMATCH = "provenance_mismatch"  # an attestation names another repository, commit or digest
REGISTRY_UNAVAILABLE = "registry_unavailable"  # the registry gave no readable answer
UNSUPPORTED = "unsupported"  # the ecosystem has no binding
REASONS = frozenset(
    {NO_LOCK_HASH, HASH_MISMATCH, NO_PROVENANCE, PROVENANCE_MISMATCH, REGISTRY_UNAVAILABLE, UNSUPPORTED}
)

_SLSA_V1 = "https://slsa.dev/provenance/v1"


class Binding(NamedTuple):
    kind: str
    reason: str = ""


class Subject(NamedTuple):
    """A covered primary change: what was installed and what was scanned."""

    name: str
    version: str
    repo: str  # owner/repo that was scanned
    commit: str  # the scanned commit (the peeled to tag)
    locked: tuple[str, ...] = ()  # the integrity each top lock entry for name at version records, "" for none


_INTRINSIC = Binding(INTRINSIC)
_PROVENANCE = Binding(PROVENANCE)


def _unbound(reason: str) -> Binding:
    return Binding(UNBOUND, reason)


_UNAVAILABLE = _unbound(REGISTRY_UNAVAILABLE)


def intrinsic(_subject: Subject) -> Binding:
    return _INTRINSIC


def unsupported(_subject: Subject) -> Binding:
    return _unbound(UNSUPPORTED)


def _decoded(text: object) -> bytes:
    return base64.b64decode(text, validate=True) if isinstance(text, str) else b""


def _attested(subject: Subject, cert: object, statement: object, algorithm: str, digest: str) -> bool:
    """One attestation names the scanned repository, the scanned commit and the artifact digest."""
    try:
        source = certificate.source(_decoded(cert))
        doc = json.loads(_decoded(statement))
    except (ValueError, UnicodeDecodeError, binascii.Error, IndexError, RecursionError):
        return False
    items = doc.get("subject") if isinstance(doc, dict) else None
    digests = [item.get("digest") for item in items if isinstance(item, dict)] if isinstance(items, list) else []
    return (
        source.repo_uri.lower() == f"https://github.com/{subject.repo}".lower()
        and bool(subject.commit)
        and source.commit == subject.commit
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


def npm(subject: Subject) -> Binding:
    """The lock's sha512 integrity is the registry's, and the SLSA attestations are for it and the scan."""
    integrities = set(subject.locked) - {""}
    integrity = integrities.pop() if len(integrities) == 1 else ""
    if not integrity.startswith("sha512-"):
        return _unbound(NO_LOCK_HASH)
    try:
        digest = base64.b64decode(integrity.removeprefix("sha512-"), validate=True).hex()
    except binascii.Error:
        return _unbound(NO_LOCK_HASH)
    version = urllib.parse.quote(subject.version, safe="")
    doc = upstream.fetch_json(f"https://registry.npmjs.org/{subject.name}/{version}")
    if doc is None:
        return _UNAVAILABLE
    if _dig(doc, "dist", "integrity") != integrity:
        return _unbound(HASH_MISMATCH)
    escaped = urllib.parse.quote(subject.name, safe="@")
    found = upstream.fetch_json(f"https://registry.npmjs.org/-/npm/v1/attestations/{escaped}@{version}")
    if found is None:
        return _UNAVAILABLE
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
    doc = upstream.fetch_json(f"https://pypi.org/pypi/{project}/{version}/json")
    if doc is None:
        return _UNAVAILABLE
    files = _dig(doc, "urls")
    if not isinstance(files, list) or not files:
        return _unbound(NO_PROVENANCE)
    for item in files:
        filename, sha256 = _dig(item, "filename"), _dig(item, "digests", "sha256")
        if not isinstance(filename, str) or not isinstance(sha256, str):
            return _unbound(NO_PROVENANCE)
        quoted = urllib.parse.quote(filename, safe="")
        found = upstream.fetch_json(f"https://pypi.org/integrity/{project}/{version}/{quoted}/provenance")
        if found is None:
            return _UNAVAILABLE
        pairs = [
            (_dig(attestation, "verification_material", "certificate"), _dig(attestation, "envelope", "statement"))
            for bundle in _dig(found, "attestation_bundles") or []
            for attestation in _dig(bundle, "attestations") or []
        ]
        binding = _provenance(subject, pairs, "sha256", sha256)
        if binding != _PROVENANCE:
            return binding
    return _PROVENANCE
