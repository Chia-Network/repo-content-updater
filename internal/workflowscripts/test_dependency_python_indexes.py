"""Python package indexes a pip change may install from."""

from __future__ import annotations

import unittest

import dependency_python_indexes as indexes

_CHIA = "https://pypi.chia.net/simple/"
_DOWNLOAD = "https://download.chia.net/simple/"


def _read(texts: dict[str, str]):
    return lambda _rev, path: texts.get(path, "")


def _listing(*paths: str):
    tree: dict[str, list[str]] = {}
    for path in paths:
        directory = path.rsplit("/", 1)[0] if "/" in path else ""
        tree.setdefault(directory, []).append(path)
    return tree.get


def _requirements():
    return lambda directory: [f"{directory}/requirements.txt"]


class PythonIndexesTest(unittest.TestCase):
    def test_a_requirements_index_option_decides_its_directory(self) -> None:
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
            "chia": indexes.Indexes(frozenset({_CHIA}), replaces_pypi=True),
            "chained": indexes.Indexes(other=True),
            "outside": indexes.Indexes(other=True),
            "sibling": indexes.Indexes(other=True),
            "unlisted": indexes.Indexes(other=True),
        }
        for directory, found in expected.items():
            with self.subTest(directory):
                self.assertEqual(
                    indexes.for_directory(directory, indexes.Indexes(), _read(texts), tree),
                    found,
                )
        download = indexes.Indexes(frozenset({_DOWNLOAD}))
        self.assertEqual(
            indexes.for_directory("chia", download, _read(texts), tree),
            indexes.Indexes(frozenset({_CHIA, _DOWNLOAD}), replaces_pypi=True),
        )
        self.assertTrue(indexes.for_directory("plain", indexes.Indexes(other=True), _read(texts), tree).other)

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
                self.assertTrue(indexes.for_directory(directory, indexes.Indexes(), _read(texts), listing).other)

    def test_a_requirements_extra_index_means_the_index_does_not_replace_pypi(
        self,
    ) -> None:
        cases = {
            "index": (
                f"-i {_CHIA}\nattrs==23.2.0\n",
                indexes.Indexes(frozenset({_CHIA}), replaces_pypi=True),
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
                    indexes.for_directory(
                        "app",
                        indexes.Indexes(),
                        _read({"app/requirements.txt": text}),
                        _requirements(),
                    ),
                    expected,
                )

    def test_an_extra_index_in_a_requirements_file_keeps_pypi_as_a_source(self) -> None:
        configured = indexes.Indexes(frozenset({_CHIA}), replaces_pypi=True)
        text = f"--extra-index-url {_CHIA}\nattrs==23.2.0\n"
        self.assertEqual(
            indexes.for_directory(
                "app",
                configured,
                _read({"app/requirements.txt": text}),
                _requirements(),
            ),
            indexes.Indexes(frozenset({_CHIA})),
        )

    def test_a_dependabot_index_replaces_pypi_only_when_it_says_so(self) -> None:
        def config(replaces: str) -> str:
            return f"registries:\n  chia:\n    type: python-index\n    url: {_CHIA}\n    replaces-base: {replaces}\n"

        self.assertEqual(
            indexes._dependabot_indexes(config("true")),
            indexes.Indexes(frozenset({_CHIA}), replaces_pypi=True),
        )
        self.assertEqual(
            indexes._dependabot_indexes(config("false")),
            indexes.Indexes(frozenset({_CHIA})),
        )

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
                config(("python-index", _CHIA), ("python-index", "https://example.com/simple/")),
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
                self.assertEqual(indexes._dependabot_indexes(text), indexes.Indexes(frozenset(trusted), other))


if __name__ == "__main__":
    unittest.main()
