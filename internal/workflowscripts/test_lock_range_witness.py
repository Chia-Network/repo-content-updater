"""A shared range spec in package-lock counts as the listed bump with a witness."""

from __future__ import annotations

import json
import unittest

import dependency_manifest_diff as manifest

_REG = "https://registry.npmjs.org"


def _lock(left_pad: str, dep: str, spec: str = "") -> str:
    return json.dumps(
        {
            "name": "app",
            "lockfileVersion": 3,
            "requires": True,
            "packages": {
                "": {"name": "app", "dependencies": {"left-pad": spec or f"^{left_pad}"}},
                "node_modules/left-pad": {
                    "version": left_pad,
                    "resolved": f"{_REG}/left-pad/-/left-pad-{left_pad}.tgz",
                    "integrity": f"sha512-lp{left_pad}",
                    "dependencies": {"dep": "^1.0.0"},
                },
                "node_modules/dep": {
                    "version": dep,
                    "resolved": f"{_REG}/dep/-/dep-{dep}.tgz",
                    "integrity": f"sha512-dep{dep}",
                },
            },
        }
    )


_UPDATES = [{"packageName": "left-pad", "fromVersion": "1.2.3", "toVersion": "1.2.4", "upstreamRepo": "x/left-pad"}]


class LockRangeWitnessTest(unittest.TestCase):
    def test_root_range_with_witness_covers_listed_and_transitive(self) -> None:
        old, new = _lock("1.2.3", "1.0.0"), _lock("1.2.4", "1.0.1")
        names = manifest._changed_names("json", old, new)
        locked = {"left-pad": frozenset({"1.2.4"})}
        self.assertTrue(manifest._lock_covers_listed("json", old, new, _UPDATES, names, locked))

    def test_root_range_without_witness_does_not_cover(self) -> None:
        old, new = _lock("1.2.3", "1.0.0"), _lock("1.2.4", "1.0.1")
        names = manifest._changed_names("json", old, new)
        locked = {"left-pad": frozenset({"1.2.9"})}
        self.assertFalse(manifest._lock_covers_listed("json", old, new, _UPDATES, names, locked))

    def test_from_version_inside_the_old_range_is_explained(self) -> None:
        old = _lock("1.5.0", "1.0.0", spec="^1.0.0")
        new = _lock("2.0.0", "1.0.1", spec="^2.0.0")
        names = manifest._changed_names("json", old, new)
        updates = [
            {
                "packageName": "left-pad",
                "fromVersion": "1.5.0",
                "toVersion": "2.0.0",
                "upstreamRepo": "x/left-pad",
            }
        ]
        self.assertTrue(
            manifest._lock_covers_listed("json", old, new, updates, names, {"left-pad": frozenset({"2.0.0"})})
        )


if __name__ == "__main__":
    unittest.main()
