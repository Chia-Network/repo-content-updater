"""Tests for the pnpm lock grammar, through the dependency review plan."""

from __future__ import annotations

import unittest

from dependency_manifest_diff import Change
from dependency_manifest_pnpm import pnpm_lock, pnpm_lock_integrity, pnpm_lock_unsupported_version
from test_dependency_manifest_diff import _package, _plan

_PACKAGE = _package(dependencies={"zod": "^3.22.0"}, devDependencies={"react-dom": "18.2.0"})


def _lock(
    zod: str = "3.25.76", integrity: str = "{integrity: sha512-zod}", peer: str = "react@18.3.1", extra: str = ""
) -> str:
    return f"""lockfileVersion: '9.0'

settings:
  autoInstallPeers: true

importers:

  .:
    dependencies:
      zod:
        specifier: ^3.22.0
        version: {zod}
    devDependencies:
      react-dom:
        specifier: 18.2.0
        version: 18.2.0({peer})

packages:

  react@18.3.1:
    resolution: {{integrity: sha512-react}}

  react-dom@18.2.0:
    resolution: {{integrity: sha512-rd}}
    peerDependencies:
      react: ^18.2.0

  zod@{zod}:
    resolution: {integrity}{extra}

snapshots:

  react@18.3.1: {{}}

  react-dom@18.2.0({peer}):
    dependencies:
      react: 18.3.1

  zod@{zod}: {{}}
"""


def _files(lock: str) -> dict[str, str]:
    return {"package.json": _PACKAGE, "pnpm-lock.yaml": lock}


def _stanza_lock(foo_dependency: str) -> str:
    return f"""lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      foo:
        specifier: ^1.0.0
        version: 1.0.0

packages:

  foo@1.0.0:
    resolution: {{integrity: sha512-foo}}
  bar@1.0.0:
    resolution: {{integrity: sha512-bar1}}
  bar@2.0.0:
    resolution: {{integrity: sha512-bar2}}

snapshots:

  foo@1.0.0:
    dependencies:
      bar: {foo_dependency}
  bar@1.0.0: {{}}
  bar@2.0.0: {{}}
"""


def _shared_stanza_lock(foo_bar: str) -> str:
    """A lock where foo, qux and baz each resolve bar, and bar has two stanzas."""
    return f"""lockfileVersion: '9.0'

packages:

  foo@1.0.0:
    resolution: {{integrity: sha512-foo}}
  qux@1.0.0:
    resolution: {{integrity: sha512-qux}}
  baz@1.0.0:
    resolution: {{integrity: sha512-baz}}
  bar@1.0.0:
    resolution: {{integrity: sha512-bar1}}
  bar@2.0.0:
    resolution: {{integrity: sha512-bar2}}

snapshots:

  foo@1.0.0:
    dependencies:
      bar: {foo_bar}
  qux@1.0.0:
    dependencies:
      bar: 1.0.0
  baz@1.0.0:
    dependencies:
      bar: 2.0.0
  bar@1.0.0: {{}}
  bar@2.0.0: {{}}
"""


class PnpmLockTest(unittest.TestCase):
    def test_a_lockfile_only_bump_is_a_primary_change(self) -> None:
        plan = _plan(_files(_lock()), _files(_lock(zod="3.25.77", integrity="{integrity: sha512-new}")))
        self.assertEqual(plan.primary, (Change("npm", ".", "zod", "3.25.76", "3.25.77"),))
        self.assertEqual((plan.gaps, plan.unparsed_locks), ((), ()))

    def test_a_manifest_bump_beside_the_lock_is_a_primary_change(self) -> None:
        bumped = _package(dependencies={"zod": "^3.25.77"}, devDependencies={"react-dom": "18.2.0"})
        head = {"package.json": bumped, "pnpm-lock.yaml": _lock(zod="3.25.77").replace("^3.22.0", "^3.25.77")}
        plan = _plan(_files(_lock()), head)
        self.assertEqual(plan.primary, (Change("npm", ".", "zod", "3.25.76", "3.25.77"),))
        self.assertEqual(plan.gaps, ())

    def test_a_changed_integrity_at_one_version_is_a_gap(self) -> None:
        plan = _plan(_files(_lock()), _files(_lock(integrity="{integrity: sha512-other}")))
        self.assertEqual((plan.primary, plan.gaps), ((), (("pnpm-lock.yaml", "unresolved"),)))

    def test_a_peer_suffix_that_moves_is_not_a_gap_of_its_dependent(self) -> None:
        plan = _plan(_files(_lock()), _files(_lock(peer="react@18.3.2")))
        self.assertEqual((plan.primary, plan.unchecked, plan.gaps), ((), (), ()))

    def test_a_dependency_value_change_with_unmoved_stanzas_is_a_gap(self) -> None:
        package = _package(dependencies={"foo": "^1.0.0"})
        base = {"package.json": package, "pnpm-lock.yaml": _stanza_lock("1.0.0")}
        head = {"package.json": package, "pnpm-lock.yaml": _stanza_lock("2.0.0")}
        plan = _plan(base, head)
        self.assertEqual((plan.primary, plan.unchecked), ((), ()))
        self.assertEqual(plan.gaps, (("pnpm-lock.yaml", "unresolved"),))

    def test_a_dependency_reference_to_a_version_with_no_stanza_is_not_parsed(self) -> None:
        self.assertIsNone(pnpm_lock(_stanza_lock("3.0.0")))

    def test_a_changed_dependency_reference_with_no_stanza_is_a_gap(self) -> None:
        package = _package(dependencies={"foo": "^1.0.0"})
        base = {"package.json": package, "pnpm-lock.yaml": _stanza_lock("3.0.0")}
        head = {"package.json": package, "pnpm-lock.yaml": _stanza_lock("4.0.0")}
        plan = _plan(base, head)
        self.assertEqual((plan.primary, plan.unchecked), ((), ()))
        self.assertEqual(plan.gaps, (("pnpm-lock.yaml", "unresolved"),))

    def test_a_dependency_value_change_between_shared_versions_is_a_gap(self) -> None:
        base = {"pnpm-lock.yaml": _shared_stanza_lock("1.0.0")}
        head = {"pnpm-lock.yaml": _shared_stanza_lock("2.0.0")}
        plan = _plan(base, head)
        self.assertEqual((plan.primary, plan.unchecked), ((), ()))
        self.assertEqual(plan.gaps, (("pnpm-lock.yaml", "unresolved"),))

    def test_a_lockfile_version_it_does_not_read_is_not_parsed(self) -> None:
        old = _lock().replace("'9.0'", "'5.4'")
        self.assertIsNone(pnpm_lock(old))
        self.assertIsNotNone(pnpm_lock(_lock()))
        self.assertIsNone(pnpm_lock(_lock() + "\n  zod@3.25.76: {}\n"))

    def test_an_importer_dependency_line_that_is_not_a_block_is_not_parsed(self) -> None:
        self.assertIsNone(pnpm_lock(_lock().replace("      zod:\n", "      - zod:\n")))

    def test_the_lockfile_version_it_does_not_read_is_named(self) -> None:
        self.assertEqual(pnpm_lock_unsupported_version(_lock().replace("'9.0'", "'5.4'")), "5.4")
        self.assertEqual(pnpm_lock_unsupported_version("lockfileVersion: 5.3\n#\n"), "5.3")
        for text in (_lock(), "", "lockfileVersion: 5.4\nlockfileVersion: 5.3\n", "lockfileVersion: next\n"):
            self.assertEqual(pnpm_lock_unsupported_version(text), "", text)
        self.assertEqual(pnpm_lock_unsupported_version("lockfileVersion: " + "5." * 9 + "4\n"), "")

    def test_only_a_registry_resolution_is_an_exact_version(self) -> None:
        def zod(lock: str) -> list[str]:
            return sorted(version for name, version, _top, _text in pnpm_lock(lock)[0] if name == "zod")

        tarball = zod(_lock(integrity="{tarball: https://example.com/zod.tgz}"))
        self.assertEqual(tarball, ["3.25.76", "3.25.76", "3.25.76 ({tarball: https://example.com/zod.tgz})"])
        self.assertEqual(zod(_lock()), ["3.25.76"] * 3)

    def test_the_integrity_is_read_from_a_registry_stanza(self) -> None:
        texts = [text for name, _v, _t, text in pnpm_lock(_lock(integrity="{integrity: sha512-x}"))[0] if name == "zod"]
        self.assertEqual(sorted(pnpm_lock_integrity(text) for text in texts), ["", "", "sha512-x"])


if __name__ == "__main__":
    unittest.main()
