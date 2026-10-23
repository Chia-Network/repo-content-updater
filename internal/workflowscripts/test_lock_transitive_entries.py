"""Unlisted npm and Yarn lock entries that move alongside a listed bump."""

from __future__ import annotations

import json
import unittest

import dependency_manifest_diff as manifest

_UPDATES = [
    {
        "packageName": "left-pad",
        "fromVersion": "1.2.3",
        "toVersion": "1.2.4",
        "upstreamRepo": "left-pad/left-pad",
    }
]


def _tarball(name: str, version: str) -> str:
    return f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"


def _npm(packages: dict[str, str], hosts: dict[str, str] | None = None) -> str:
    hosts = hosts or {}
    entries = {
        f"node_modules/{name}": {
            "version": version,
            "resolved": hosts.get(name, _tarball(name, version)),
            "integrity": f"sha512-{name}-{version}",
        }
        for name, version in packages.items()
    }
    return json.dumps({"lockfileVersion": 3, "packages": entries}, indent=2)


def _yarn(packages: dict[str, str]) -> str:
    stanzas = [
        f'{name}@^1.0.0:\n  version "{version}"\n  resolved "{_tarball(name, version)}"\n'
        for name, version in sorted(packages.items())
    ]
    return "\n".join(stanzas)


class TransitiveLockEntriesTest(unittest.TestCase):
    def _covers(self, kind: str, old: str, new: str) -> bool:
        names = manifest._changed_names(kind, old, new)
        self.assertIsNotNone(names)
        return manifest._lock_covers_listed(kind, old, new, _UPDATES, names)

    def test_added_transitive_entry(self) -> None:
        for kind, render in (("json", _npm), ("yarn", _yarn)):
            old = render({"left-pad": "1.2.3"})
            new = render({"left-pad": "1.2.4", "tiny-dep": "2.0.0"})
            self.assertTrue(self._covers(kind, old, new), kind)

    def test_removed_transitive_entry(self) -> None:
        for kind, render in (("json", _npm), ("yarn", _yarn)):
            old = render({"left-pad": "1.2.3", "tiny-dep": "2.0.0"})
            new = render({"left-pad": "1.2.4"})
            self.assertTrue(self._covers(kind, old, new), kind)

    def test_bumped_transitive_entry(self) -> None:
        for kind, render in (("json", _npm), ("yarn", _yarn)):
            old = render({"left-pad": "1.2.3", "tiny-dep": "2.0.0"})
            new = render({"left-pad": "1.2.4", "tiny-dep": "2.0.1"})
            self.assertTrue(self._covers(kind, old, new), kind)

    def test_added_entry_from_another_host_stays_unresolved(self) -> None:
        old = _npm({"left-pad": "1.2.3"})
        new = _npm(
            {"left-pad": "1.2.4", "tiny-dep": "2.0.0"},
            {"tiny-dep": "https://example.com/tiny-dep-2.0.0.tgz"},
        )
        self.assertFalse(self._covers("json", old, new))
        yarn_new = _yarn({"left-pad": "1.2.4", "tiny-dep": "2.0.0"}).replace(
            _tarball("tiny-dep", "2.0.0"), "https://example.com/tiny-dep-2.0.0.tgz"
        )
        self.assertFalse(self._covers("yarn", _yarn({"left-pad": "1.2.3"}), yarn_new))

    def test_added_entry_needs_a_listed_bump(self) -> None:
        old = _npm({"left-pad": "1.2.3"})
        new = _npm({"left-pad": "1.2.3", "tiny-dep": "2.0.0"})
        self.assertFalse(self._covers("json", old, new))


if __name__ == "__main__":
    unittest.main()
