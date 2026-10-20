"""Registry locators that must not compare equal."""

from __future__ import annotations

import json
import unittest

import dependency_manifest_diff as manifest

_TRAVERSAL = (
    "https://registry.npmjs.org/left-pad/-/left-pad-1.2.4/../../../lodash/-/lodash-4.17.21.tgz"
)


def _bump(frm: str, to: str) -> dict[str, str]:
    return {
        "packageName": "left-pad",
        "fromVersion": frm,
        "toVersion": to,
        "upstreamRepo": "left-pad/left-pad",
    }


def _npm(version: str, resolved: str, integrity: str) -> str:
    entry = {"version": version, "resolved": resolved, "integrity": integrity}
    return json.dumps({"lockfileVersion": 3, "packages": {"node_modules/left-pad": entry}})


def _yarn(version: str, resolved: list[str]) -> str:
    lines = ["left-pad@^1.2.3:", f'  version "{version}"']
    lines.extend(f'  resolved "{url}"' for url in resolved)
    return "\n".join(lines) + "\n"


class LockLocatorCanonicalTest(unittest.TestCase):
    def test_tarball_version_cannot_contain_a_slash(self) -> None:
        real = "https://registry.npmjs.org/left-pad/-/left-pad-1.2.3.tgz"
        old = _npm("1.2.3", real, "sha-old")
        slash = "1.2.4/../../../lodash/-/lodash-4.17.21"
        for version, updates in (
            ("1.2.4", [_bump("1.2.3", "1.2.4")]),
            (slash, [_bump("1.2.3", slash)]),
        ):
            new = _npm(version, _TRAVERSAL, "sha-new")
            self.assertFalse(manifest._entries_explain("json", old, new, updates), version)
            self.assertFalse(
                manifest._lock_covers_listed("json", old, new, updates, {"left-pad"}),
                version,
            )

    def test_yarn_second_resolved_line_is_not_canonical(self) -> None:
        registry = "https://registry.npmjs.org/left-pad/-/left-pad-{}.tgz"
        old = _yarn("1.2.3", [registry.format("1.2.3")])
        new = _yarn("1.2.4", [registry.format("1.2.4"), "file:../pwned"])
        updates = [_bump("1.2.3", "1.2.4")]
        self.assertFalse(manifest._entries_explain("yarn", old, new, updates))
        self.assertFalse(manifest._lock_covers_listed("yarn", old, new, updates, {"left-pad"}))
