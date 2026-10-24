"""The per-file grammars: (name, version, top, text) entries and the residue left once they are taken out."""

from __future__ import annotations

import json
import unittest

from dependency_manifest_go import go_mod
from dependency_manifest_lines import dockerfile_from, terraform_config, terraform_lock, workflow_uses
from dependency_manifest_npm import package_json, package_lock, yarn_lock
from dependency_manifest_python import requirements


def _entries(parsed: tuple[list, str] | None) -> set[tuple[str, str, bool]]:
    """(name, version, top) of each entry."""
    assert parsed is not None
    return {entry[:3] for entry in parsed[0]}


def _texts(parsed: tuple[list, str] | None) -> dict[str, str]:
    assert parsed is not None
    return {entry[0]: entry[3] for entry in parsed[0]}


def _meta(name: str, version: str, **extra: object) -> dict:
    """A lock record installed from the registry tarball."""
    tarball = f"https://registry.npmjs.org/{name}/-/{name.rsplit('/', 1)[-1]}-{version}.tgz"
    return {"version": version, "resolved": tarball, **extra}


class NpmGrammarTest(unittest.TestCase):
    def test_package_json_specs_are_declarations_in_every_section(self) -> None:
        text = json.dumps(
            {"dependencies": {"a": "^1.0.0"}, "devDependencies": {"a": "1.2.0", "b": "~2.0.0"}, "scripts": {"t": "x"}}
        )
        parsed = package_json(text)
        self.assertEqual(_entries(parsed), {("a", "^1.0.0", True), ("a", "1.2.0", True), ("b", "~2.0.0", True)})
        self.assertEqual(json.loads(parsed[1]), {"scripts": {"t": "x"}})

    def test_lock_v3_top_copy_nested_copy_and_workspace_residue(self) -> None:
        text = json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"a": "^1.0.0"}},
                    "node_modules/a": _meta("a", "1.0.1"),
                    "node_modules/@scope/b": _meta("@scope/b", "2.0.0"),
                    "node_modules/a/node_modules/c": _meta("c", "3.0.0"),
                    "packages/gui/node_modules/a": _meta("a", "0.9.0"),
                    "packages/gui": {"dependencies": {"a": "^0.9.0"}},
                },
            }
        )
        parsed = package_lock(text)
        self.assertEqual(
            _entries(parsed),
            {("a", "1.0.1", True), ("@scope/b", "2.0.0", True), ("c", "3.0.0", False), ("a", "0.9.0", False)},
        )
        self.assertIn("packages/gui", parsed[1])
        self.assertNotIn("^1.0.0", parsed[1])

    def test_lock_v1_top_level_records_are_top_and_nested_records_are_not(self) -> None:
        text = json.dumps(
            {
                "lockfileVersion": 1,
                "dependencies": {"a": _meta("a", "1.0.0", dependencies={"b": _meta("b", "2.0.0")})},
            }
        )
        self.assertEqual(_entries(package_lock(text)), {("a", "1.0.0", True), ("b", "2.0.0", False)})

    def test_empty_text_has_no_entries_and_bad_json_does_not_parse(self) -> None:
        self.assertEqual(package_lock(""), ([], ""))
        self.assertIsNone(package_json("[1, 2]"))
        self.assertIsNone(package_lock("{"))

    def test_yarn_header_names_every_package_once(self) -> None:
        text = '"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.2.0"\n'
        self.assertEqual(_entries(yarn_lock(text)), {("@babel/core", "7.2.0 (no resolved source)", True)})
        self.assertEqual(_texts(yarn_lock(text)), {"@babel/core": '  version "7.2.0"'})

    def test_only_the_registry_tarball_for_the_name_and_version_is_a_registry_copy(self) -> None:
        def lock(meta: dict) -> str:
            return json.dumps({"lockfileVersion": 3, "packages": {"node_modules/lodash": meta}})

        registry = _meta("lodash", "4.17.21")
        self.assertEqual(_entries(package_lock(lock(registry))), {("lodash", "4.17.21", True)})
        for meta in (
            {**registry, "resolved": "https://evil.example/lodash/-/lodash-4.17.21.tgz"},
            {**registry, "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"},
            {**registry, "name": "evil"},
            {"version": "4.17.21"},
            {"version": "4.17.21", "resolved": "git+ssh://git@github.com/lodash/lodash.git#" + "a" * 40},
        ):
            with self.subTest(meta=meta):
                (entry,) = _entries(package_lock(lock(meta)))
                self.assertTrue(entry[1].startswith("4.17.21 ("), entry)
        yarn = 'lodash@^4:\n  version "4.17.21"\n  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#abc"\n'
        self.assertEqual(_entries(yarn_lock(yarn)), {("lodash", "4.17.21", True)})

    def test_a_yarn_stanza_without_a_quoted_version_does_not_parse(self) -> None:
        self.assertIsNone(yarn_lock('lodash@^4:\n  resolved "x"\n'))
        self.assertIsNone(yarn_lock("lodash@^4:\n  version: 4.17.21\n"))


class GoGrammarTest(unittest.TestCase):
    def test_indirect_marks_a_require_as_not_top(self) -> None:
        text = (
            "module example.com/app\n"
            "require github.com/a/b v1.0.0\n"
            "require (\n"
            "\tgithub.com/c/d v2.0.0 // indirect\n"
            "\tgithub.com/e/f v3.0.0 // indirect; pinned for a fix\n"
            "\tgithub.com/g/h v4.0.0 // keep: not indirect\n"
            ")\n"
        )
        entries, residue = go_mod(text)
        self.assertEqual(
            _entries((entries, residue)),
            {
                ("github.com/a/b", "v1.0.0", True),
                ("github.com/c/d", "v2.0.0", False),
                ("github.com/e/f", "v3.0.0", False),
                ("github.com/g/h", "v4.0.0", True),
            },
        )
        self.assertEqual(residue, "module example.com/app\nrequire (\n)\n")

    def test_replace_and_exclude_lines_stay_residue(self) -> None:
        entries, residue = go_mod(
            "replace github.com/a/b => github.com/x/b v1.0.0\nexclude (\n\tgithub.com/a/b v0.9.0\n)\n"
        )
        self.assertEqual(entries, [])
        self.assertIn("github.com/x/b", residue)


class PythonGrammarTest(unittest.TestCase):
    def test_requirement_lines_keep_their_operator(self) -> None:
        text = "Django[argon2]==4.2.7 ; python_version >= '3.10'\nurllib3>=2,<3\n# comment\n-r base.txt\n"
        entries, residue = requirements(text)
        self.assertEqual(_entries((entries, residue)), {("django", "==4.2.7", True), ("urllib3", ">=2", True)})
        self.assertEqual(_texts((entries, residue))["django"], "Django[argon2]\0 ; python_version >= '3.10'")
        self.assertEqual(residue, "# comment\n-r base.txt\n")

    def test_a_quoted_string_that_is_not_a_pin_keeps_the_whole_line_in_residue(self) -> None:
        line = '    "newpkg==1.0.0", "evil @ https://evil.example/e.tar.gz",\n'
        self.assertEqual(requirements(line), ([], line))

    def test_toml_dependency_tables_and_quoted_pep_508_strings(self) -> None:
        text = (
            "[project]\n"
            'dependencies = ["httpx==0.27.0"]\n'
            "[tool.poetry.dependencies]\n"
            'python = "^3.11"\n'
            'rich = { version = "13.7.0", extras = ["jupyter"] }\n'
        )
        self.assertEqual(_entries(requirements(text)), {("httpx", "==0.27.0", True), ("rich", "13.7.0", True)})


class LineGrammarTest(unittest.TestCase):
    def test_uses_lines(self) -> None:
        text = (
            "steps:\n"
            "  - uses: actions/checkout@v4\n"
            "  - uses: 'actions/setup-go@v5.0.1'\n"
            "    uses: github/codeql-action/init@0123456789abcdef0123456789abcdef01234567 # v3.25.0\n"
            "  - uses: ./.github/actions/local\n"
            "  - uses: docker://alpine:3.19\n"
            "  # uses: commented/out@v1\n"
        )
        entries, residue = workflow_uses(text)
        self.assertEqual(
            _texts((entries, residue))["github/codeql-action/init"], "uses: github/codeql-action/init@\0 # v3.25.0"
        )
        self.assertEqual(
            _entries((entries, residue)),
            {
                ("actions/checkout", "v4", True),
                ("actions/setup-go", "v5.0.1", True),
                ("github/codeql-action/init", "0123456789abcdef0123456789abcdef01234567", True),
            },
        )
        self.assertIn("./.github/actions/local", residue)
        self.assertIn("docker://alpine", residue)
        self.assertIn("commented/out", residue)

    def test_from_lines(self) -> None:
        text = (
            "FROM --platform=$BUILDPLATFORM golang:1.22-alpine AS build\n"
            "FROM registry.example.com:5000/team/app:2.1@sha256:abc\n"
            "from scratch\n"
            "FROM ghcr.io/org/tool\n"
            "RUN make\n"
        )
        entries, residue = dockerfile_from(text)
        self.assertEqual(_texts((entries, residue))["golang"], "FROM --platform=$BUILDPLATFORM golang\0 AS build")
        self.assertEqual(
            _entries((entries, residue)),
            {
                ("golang", "1.22-alpine", True),
                ("registry.example.com:5000/team/app", "2.1@sha256:abc", True),
                ("scratch", "", True),
                ("ghcr.io/org/tool", "", True),
            },
        )
        self.assertEqual(residue, "RUN make\n")

    def test_terraform_lock_provider_blocks(self) -> None:
        text = (
            '# This file is maintained automatically by "terraform init".\n'
            'provider "registry.terraform.io/hashicorp/aws" {\n'
            '  version     = "5.31.0"\n'
            '  constraints = "~> 5.0"\n'
            "  hashes = [\n"
            '    "h1:abc=",\n'
            "  ]\n"
            "}\n"
        )
        entries, residue = terraform_lock(text)
        self.assertEqual(_entries((entries, residue)), {("registry.terraform.io/hashicorp/aws", "5.31.0", True)})
        self.assertIn("h1:abc=", entries[0][3])
        self.assertTrue(residue.startswith("# This file"))

    def test_a_continuation_line_is_never_a_from(self) -> None:
        entries, residue = dockerfile_from("FROM debian:12\nRUN apt-get install -y \\\n    from evilpkg\n")
        self.assertEqual(_entries((entries, residue)), {("debian", "12", True)})
        self.assertIn("from evilpkg", residue)
        commented = dockerfile_from("FROM debian:12\nRUN apt-get install -y \\\n# note\n    from evilpkg\n")
        self.assertEqual(_entries(commented), {("debian", "12", True)})

    def test_terraform_version_lines_are_named_by_their_source(self) -> None:
        text = (
            'module "vpc" {\n'
            '  source  = "terraform-aws-modules/vpc/aws"\n'
            '  version = "5.1.2"\n'
            "}\n"
            "terraform {\n"
            "  required_providers {\n"
            '    aws = { source = "hashicorp/aws", version = "~> 5.0" }\n'
            "  }\n"
            "}\n"
        )
        entries, residue = terraform_config(text)
        self.assertEqual(_entries((entries, residue)), {("terraform-aws-modules/vpc/aws", "5.1.2", True)})
        self.assertIn('aws = { source = "hashicorp/aws", version = "~> 5.0" }', residue)

    def test_an_unclosed_or_versionless_provider_block_does_not_parse(self) -> None:
        self.assertIsNone(terraform_lock('provider "registry.terraform.io/hashicorp/aws" {\n  version = "5.31.0"\n'))
        self.assertIsNone(terraform_lock('provider "registry.terraform.io/hashicorp/aws" {\n  hashes = []\n}\n'))


if __name__ == "__main__":
    unittest.main()
