"""Python package indexes a pip change may install from."""

from __future__ import annotations

import unittest

import dependency_python_indexes as indexes

_CHIA = "https://pypi.chia.net/simple/"
_DOWNLOAD = "https://download.chia.net/simple/"
_PYPI = "https://pypi.org/simple/"


def _read(texts: dict[str, str]):
    return lambda _rev, path: texts.get(path, "")


def _listing(*paths: str, mode: str = "100644"):
    tree: dict[str, list[tuple[str, str]]] = {}
    for path in paths:
        directory = path.rsplit("/", 1)[0] if "/" in path else ""
        tree.setdefault(directory, []).append((path, mode))
    return tree.get


def _requirements(mode: str = "100644"):
    return lambda directory: [(f"{directory}/requirements.txt", mode)]


def _facts(directory: str, configured: indexes.Indexes, texts: dict[str, str], tree) -> indexes.Indexes:
    return indexes.for_directory(directory, configured, _read(texts), tree).for_path(f"{directory}/requirements.txt")


class PythonIndexesTest(unittest.TestCase):
    def test_each_requirements_file_decides_its_own_index(self) -> None:
        tree = _listing(
            "plain/requirements.txt",
            "other/requirements.txt",
            "other/README.md",
            "chia/requirements.txt",
            "chained/requirements.txt",
            "chained/base/requirements-base.txt",
            "outside/requirements.txt",
            "sibling/requirements.txt",
        )
        texts = {
            "plain/requirements.txt": "attrs==23.2.0\n",
            "other/requirements.txt": "--extra-index-url=https://example.com/simple\nattrs==23.2.0\n",
            "chia/requirements.txt": f"-i {_CHIA.rstrip('/')}\nattrs==23.2.0\n",
            "chained/requirements.txt": "-r base/requirements-base.txt\n",
            "chained/base/requirements-base.txt": "-ihttps://example.com/simple/\n",
            "outside/requirements.txt": "-r ../../shared/requirements.txt\n",
            "sibling/requirements.txt": "-c ../other/requirements.txt\n",
        }
        expected = {
            "plain": indexes.Indexes(),
            "other": indexes.Indexes(other=True),
            "chia": indexes.Indexes(frozenset({_CHIA}), index=_CHIA),
            "chained": indexes.Indexes(other=True),
            "outside": indexes.Indexes(other=True),
            "sibling": indexes.Indexes(other=True),
            "unlisted": indexes.Indexes(other=True),
        }
        for directory, found in expected.items():
            with self.subTest(directory):
                self.assertEqual(_facts(directory, indexes.Indexes(), texts, tree), found)
        download = indexes.Indexes(frozenset({_DOWNLOAD}))
        self.assertEqual(
            _facts("chia", download, texts, tree),
            indexes.Indexes(frozenset({_CHIA, _DOWNLOAD}), index=_CHIA),
        )
        self.assertTrue(
            indexes.for_directory("plain", indexes.Indexes(other=True), _read(texts), tree)
            .for_path("plain/requirements.txt")
            .other
        )

    def test_an_include_that_is_not_a_repository_path_is_unread(self) -> None:
        contents = {
            "url": "-r https://example.com/r.txt\n",
            "constraint": "-c https://example.com/c.txt\n",
            "network": "-r //example.com/r.txt\n",
            "absolute": "-r /tmp/r.txt\n",
            "home": "-r ~/r.txt\n",
            "backslash": "-r '..\\r.txt'\n",
            "escape": "-r ../../r.txt\n",
            "empty": '-r ""\n',
        }
        texts = {f"{directory}/requirements.txt": text for directory, text in contents.items()}
        listing = _listing(*texts)
        for directory in contents:
            with self.subTest(directory):
                self.assertTrue(_facts(directory, indexes.Indexes(), texts, listing).other)

    def test_a_requirements_extra_index_means_the_index_does_not_replace_pypi(
        self,
    ) -> None:
        cases = {
            "index": (
                f"-i {_CHIA}\nattrs==23.2.0\n",
                indexes.Indexes(frozenset({_CHIA}), index=_CHIA),
            ),
            "extra": (
                f"--extra-index-url {_CHIA}\nattrs==23.2.0\n",
                indexes.Indexes(frozenset({_CHIA})),
            ),
            "both": (
                f"-i {_CHIA}\n--extra-index-url {_CHIA}\nattrs==23.2.0\n",
                indexes.Indexes(frozenset({_CHIA})),
            ),
        }
        for label, (text, expected) in cases.items():
            with self.subTest(label):
                self.assertEqual(
                    _facts(
                        "app",
                        indexes.Indexes(),
                        {"app/requirements.txt": text},
                        _requirements(),
                    ),
                    expected,
                )

    def test_an_extra_index_in_an_included_file_keeps_pypi_as_a_source(self) -> None:
        texts = {
            "app/requirements.txt": f"-i {_CHIA}\n-r base/requirements-base.txt\n",
            "app/base/requirements-base.txt": f"--extra-index-url {_DOWNLOAD}\n",
        }
        tree = _listing("app/requirements.txt", "app/base/requirements-base.txt")
        self.assertEqual(
            _facts("app", indexes.Indexes(), texts, tree),
            indexes.Indexes(frozenset({_CHIA, _DOWNLOAD})),
        )

    def test_other_registry_scalar_fields_are_accepted_and_ignored(self) -> None:
        text = (
            "registries:\n"
            "  chia:\n"
            "    type: python-index\n"
            f"    url: {_CHIA}\n"
            "    username: chia-user\n"
            "    password: ${{secrets.PW}}\n"
            "    token: token value\n"
            "    key: key\n"
            "    organization: chia\n"
            "    replaces-base: true\n"
            "    auth-key: auth\n"
            "    public-key-fingerprint: fingerprint\n"
        )
        self.assertEqual(indexes._dependabot_indexes(text), indexes.Indexes(frozenset({_CHIA})))

    def test_a_registry_field_that_is_a_flow_value_or_list_leaves_the_config_unread(self) -> None:
        for field in ("    options: {a: b}\n", "    tags: [a, b]\n", "    tags:\n      - a\n", "    type:\n"):
            with self.subTest(field=field):
                text = f"registries:\n  chia:\n    type: python-index\n    url: {_CHIA}\n{field}"
                self.assertEqual(indexes._dependabot_indexes(text), indexes.Indexes(other=True))

    def test_a_dependabot_replaces_base_does_not_replace_pypi(self) -> None:
        def config(replaces: str) -> str:
            return f"registries:\n  chia:\n    type: python-index\n    url: {_CHIA}\n    replaces-base: {replaces}\n"

        self.assertEqual(
            indexes._dependabot_indexes(config("true")),
            indexes.Indexes(frozenset({_CHIA})),
        )
        self.assertEqual(
            indexes._dependabot_indexes(config("false")),
            indexes.Indexes(frozenset({_CHIA})),
        )

    def test_a_registry_name_or_comment_does_not_hide_a_trusted_registry(self) -> None:
        text = (
            "# python-index\n"
            "registries:\n"
            "  my-python-index:  # python-index\n"
            "    type: python-index\n"
            f"    url: {_CHIA}\n"
        )
        self.assertEqual(indexes._dependabot_indexes(text), indexes.Indexes(frozenset({_CHIA})))

    def test_an_unreadable_type_field_leaves_the_config_unread(self) -> None:
        text = "registries:\n  r:\n    type:\n    url: https://pypi.chia.net/simple/\n"
        self.assertTrue(indexes._dependabot_indexes(text).other)

    def test_a_flow_mapping_registry_leaves_the_config_unread(self) -> None:
        text = (
            "registries:\n"
            "  chia:\n"
            "    type: python-index\n"
            f"    url: {_CHIA}\n"
            '  private:  {type: python-index, url: "https://example.com/simple", replaces-base: true}\n'
        )
        self.assertEqual(indexes._dependabot_indexes(text), indexes.Indexes(other=True))

    def test_a_registry_key_with_an_inline_value_leaves_the_config_unread(self) -> None:
        text = f"registries:\n  chia:\n    type: python-index\n    url: {_CHIA}\n  private: python-index\n"
        self.assertEqual(indexes._dependabot_indexes(text), indexes.Indexes(other=True))

    def test_unknown_registry_indentation_leaves_the_config_unread(self) -> None:
        for indent in ("\t", " ", "   "):
            with self.subTest(indent=repr(indent)):
                text = f"registries:\n{indent}chia:\n{indent}{indent}type: python-index\n"
                self.assertEqual(indexes._dependabot_indexes(text), indexes.Indexes(other=True))

    def test_python_index_outside_a_parsed_type_field_leaves_the_config_unread(
        self,
    ) -> None:
        text = (
            "registries:\n"
            "  chia:\n"
            "    type: python-index\n"
            f"    url: {_CHIA}\n"
            "updates:\n"
            "  - package-ecosystem: pip\n"
            "    python-index: true\n"
        )
        self.assertEqual(indexes._dependabot_indexes(text), indexes.Indexes(other=True))

    def test_pypi_own_simple_index_is_the_default(self) -> None:
        cases = {
            "index": "-i https://pypi.org/simple\nattrs==23.2.0\n",
            "index slash": "-i https://pypi.org/simple/\nattrs==23.2.0\n",
            "extra": "--extra-index-url https://pypi.org/simple/\nattrs==23.2.0\n",
            "legacy": "-i https://pypi.python.org/simple\nattrs==23.2.0\n",
        }
        for label, text in cases.items():
            with self.subTest(label):
                self.assertEqual(
                    _facts(
                        "app",
                        indexes.Indexes(),
                        {"app/requirements.txt": text},
                        _requirements(),
                    ),
                    indexes.Indexes(),
                )

    def test_the_last_index_url_wins(self) -> None:
        cases = {
            "trusted then pypi": (
                f"-i {_CHIA}\n-i {_PYPI}\nattrs==23.2.0\n",
                indexes.Indexes(frozenset({_CHIA})),
            ),
            "pypi then trusted": (
                f"-i {_PYPI}\n-i {_CHIA}\nattrs==23.2.0\n",
                indexes.Indexes(frozenset({_CHIA}), index=_CHIA),
            ),
            "trusted then trusted": (
                f"-i {_CHIA}\n-i {_DOWNLOAD}\nattrs==23.2.0\n",
                indexes.Indexes(frozenset({_CHIA, _DOWNLOAD}), index=_DOWNLOAD),
            ),
        }
        for label, (text, expected) in cases.items():
            with self.subTest(label):
                self.assertEqual(
                    _facts(
                        "app",
                        indexes.Indexes(),
                        {"app/requirements.txt": text},
                        _requirements(),
                    ),
                    expected,
                )

    def test_a_trusted_index_in_one_file_does_not_trust_another_file_in_the_same_directory(
        self,
    ) -> None:
        tree = _listing("app/requirements.txt", "app/requirements-dev.txt")
        texts = {
            "app/requirements.txt": f"-i {_CHIA}\nattrs==23.2.0\n",
            "app/requirements-dev.txt": "attrs==23.2.0\n",
        }
        found = indexes.for_directory("app", indexes.Indexes(), _read(texts), tree)
        self.assertEqual(
            found.for_path("app/requirements.txt"),
            indexes.Indexes(frozenset({_CHIA}), index=_CHIA),
        )
        self.assertEqual(found.for_path("app/requirements-dev.txt"), indexes.Indexes())
        self.assertEqual(found.for_path("app/poetry.lock"), indexes.Indexes())

    def test_a_dependabot_pypi_index_is_the_default(self) -> None:
        text = "registries:\n  pypi:\n    type: python-index\n    url: https://pypi.org/simple\n"
        self.assertEqual(indexes._dependabot_indexes(text), indexes.Indexes())

    def test_a_trusted_index_with_pypi_as_an_extra_index_does_not_replace_pypi(
        self,
    ) -> None:
        text = f"-i {_CHIA}\n--extra-index-url https://pypi.org/simple\nattrs==23.2.0\n"
        self.assertEqual(
            _facts(
                "app",
                indexes.Indexes(),
                {"app/requirements.txt": text},
                _requirements(),
            ),
            indexes.Indexes(frozenset({_CHIA})),
        )

    def test_an_include_cycle_leaves_the_file_unread(self) -> None:
        texts = {
            "app/requirements.txt": "-r base/requirements-base.txt\n",
            "app/base/requirements-base.txt": "-r ../requirements.txt\n",
        }
        tree = _listing("app/requirements.txt", "app/base/requirements-base.txt")
        self.assertTrue(_facts("app", indexes.Indexes(), texts, tree).other)

    def test_a_linked_requirements_file_is_unread(self) -> None:
        for mode in ("120000", "160000", "040000"):
            with self.subTest(mode):
                self.assertTrue(_facts("app", indexes.Indexes(), {}, _requirements(mode)).other)

    def test_a_linked_include_is_unread(self) -> None:
        texts = {"app/requirements.txt": "-r base/base.txt\n"}
        for mode in ("120000", "160000", "040000"):
            with self.subTest(mode):
                tree = {
                    "app": [("app/requirements.txt", "100644")],
                    "app/base": [("app/base/base.txt", mode)],
                }
                self.assertTrue(_facts("app", indexes.Indexes(), texts, tree.get).other)

    def test_only_listed_indexes_are_trusted_and_anything_else_trusts_none(
        self,
    ) -> None:
        def config(*entries: tuple[str, str]) -> str:
            blocks = "".join(
                f"  r{i}:\n    type: {kind}\n    url: {url}  # note\n" for i, (kind, url) in enumerate(entries)
            )
            return f"version: 2\nregistries:\n{blocks}updates:\n  - package-ecosystem: pip\n    registries: '*'\n"

        cases = {
            "both": (
                config(("python-index", _CHIA), ("python-index", _DOWNLOAD.rstrip("/"))),
                {_CHIA, _DOWNLOAD},
                False,
            ),
            "none": ("version: 2\n", set(), False),
            "other kind": (
                config(("npm-registry", "https://npm.example.com")),
                set(),
                False,
            ),
            "lookalike": (
                config(("python-index", "https://pypi.chia.net.evil/simple/")),
                set(),
                True,
            ),
            "plain http": (
                config(("python-index", "http://pypi.chia.net/simple/")),
                set(),
                True,
            ),
            "beside unknown": (
                config(
                    ("python-index", _CHIA),
                    ("python-index", "https://example.com/simple/"),
                ),
                set(),
                True,
            ),
            "unread form": (
                'registries: {x: {type: python-index, url: "https://pypi.chia.net/simple/"}}\n',
                set(),
                True,
            ),
        }
        for label, (text, trusted, other) in cases.items():
            with self.subTest(label):
                self.assertEqual(
                    indexes._dependabot_indexes(text),
                    indexes.Indexes(frozenset(trusted), other),
                )


if __name__ == "__main__":
    unittest.main()
