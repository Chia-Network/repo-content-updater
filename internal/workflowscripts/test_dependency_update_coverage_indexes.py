"""Package-index trust decides whether a pip change is covered."""

from __future__ import annotations

import hashlib
import unittest
from unittest.mock import patch

import dependency_cursor_review_upstream as upstream
import dependency_update_coverage as coverage
import malware_verdict_formatter as formatter
from test_dependency_update_coverage import _clean, _found, _plan, _run_main


class DependencyUpdateCoverageIndexTest(unittest.TestCase):
    def test_a_pip_change_beside_another_configured_package_index_is_not_looked_up(self) -> None:
        config = "registries:\n  extra:\n    type: 'python-index'\n    url: https://example.com/simple/\n"
        looked_up: list[str] = []

        def repo(_ecosystem: str, name: str, _version: str) -> upstream.Repo:
            looked_up.append(name)
            return _found(f"upstream/{name}")

        plan = _plan(("pip", ".", "attrs", "23.1.0", "23.2.0"), ("npm", ".", "lodash", "4.17.20", "4.17.21"))
        texts = {".github/dependabot.yml": config}
        with patch.object(coverage, "_git_text", lambda _rev, path: texts.get(path, "")):
            report, summary, _output = _run_main(
                plan, repo=repo, scan=lambda target, *_args: _clean(target.package, target.repo.slug)
            )
        self.assertEqual(looked_up, ["lodash"])
        self.assertIs(report["scan_conclusive"], False)
        self.assertIn("configured_index", summary)
        self.assertIn(
            "not covered (configured_index). pip may install this from a package index the review does not read.",
            summary,
        )
        published = formatter.compose_published_review(
            report, "MALWARE_REVIEW_VERDICT: benign\n\nNo issues.\n", "COMPATIBILITY_RECOMMENDATION: Merge\n"
        )
        self.assertNotEqual(published["verdict"], "benign")

    def test_a_pip_change_a_trusted_index_serves_is_trusted_and_the_rest_are_looked_up(self) -> None:
        config = "registries:\n  chia:\n    type: python-index\n    url: https://pypi.chia.net/simple\n"
        looked_up: list[str] = []
        asked: list[tuple[str, str, frozenset[str], tuple[upstream.Locked, ...]]] = []

        def repo(_ecosystem: str, name: str, _version: str) -> upstream.Repo:
            looked_up.append(name)
            return _found(f"upstream/{name}")

        def trusted(name: str, version: str, locked: tuple[upstream.Locked, ...], configured: frozenset[str]) -> str:
            asked.append((name, version, configured, locked))
            return "pypi.chia.net" if name == "chiapos" else ""

        plan = _plan(
            ("pip", ".", "chiapos", "2.0.3", "2.0.4"),
            ("pip", ".", "attrs", "23.1.0", "23.2.0"),
            ("npm", ".", "lodash", "4.17.20", "4.17.21"),
            hashed=("requirements.txt",),
        )
        texts = {
            ".github/dependabot.yml": config,
            "requirements.txt": "-i https://pypi.chia.net/simple/\nchiapos==2.0.4\nattrs==23.2.0\n",
        }
        with (
            patch.object(coverage, "_git_text", lambda _rev, path: texts.get(path, "")),
            patch.object(upstream, "trusted_python_index", trusted),
        ):
            report, summary, _output = _run_main(
                plan,
                repo=repo,
                scan=lambda target, *_args: _clean(target.package, target.repo.slug),
                files=lambda directory: [("requirements.txt", "100644")] if directory == "." else [],
            )
        self.assertEqual(sorted(looked_up), ["attrs", "lodash"])
        occurrence = (upstream.Locked("", "https://pypi.chia.net/simple/"),)
        self.assertEqual(
            sorted(asked),
            [
                (
                    name,
                    "2.0.4" if name == "chiapos" else "23.2.0",
                    frozenset({"https://pypi.chia.net/simple/"}),
                    occurrence,
                )
                for name in ("attrs", "chiapos")
            ],
        )
        self.assertEqual(
            [(item["name"], item["index"]) for item in report["trusted_packages"]], [("chiapos", "pypi.chia.net")]
        )
        self.assertNotIn("configured_index", summary)
        self.assertIn("configured package indexes are trusted", summary)
        self.assertIn("`chiapos 2.0.3 -> 2.0.4`", summary)
        published = formatter.compose_published_review(
            report, "MALWARE_REVIEW_VERDICT: benign\n\nNo issues.\n", "COMPATIBILITY_RECOMMENDATION: Merge\n"
        )
        without = formatter.compose_published_review(
            {**report, "trusted_packages": []},
            "MALWARE_REVIEW_VERDICT: benign\n\nNo issues.\n",
            "COMPATIBILITY_RECOMMENDATION: Merge\n",
        )
        self.assertEqual((published["verdict"], published["check"]), (without["verdict"], without["check"]))

    def test_pip_index_trust_end_to_end_over_http(self) -> None:
        sdist = b"chiapos sdist"
        page_url = "https://pypi.chia.net/simple/chiapos/"
        file_url = "https://download.chia.net/files/chiapos-2.0.4.tar.gz"
        page = f'<a href="{file_url}">s</a>\n'.encode()
        digest = hashlib.sha256(sdist).hexdigest()
        hashed_pin = f"chiapos==2.0.4 --hash=sha256:{digest}\n"
        config = (
            "registries:\n  chia:\n    type: python-index\n    url: https://pypi.chia.net/simple/\n"
            "    replaces-base: true\n"
        )
        cases = {
            "dependabot replaces-base alone": (
                {"requirements.txt": "chiapos==2.0.4\n"},
                ("requirements.txt",),
                False,
            ),
            "last index is pypi": (
                {
                    "requirements.txt": (
                        "-i https://pypi.chia.net/simple/\n-i https://pypi.org/simple/\nchiapos==2.0.4\n"
                    )
                },
                ("requirements.txt",),
                False,
            ),
            "trusted index in another file": (
                {
                    "requirements.txt": "-i https://pypi.chia.net/simple/\nchiapos==2.0.4\n",
                    "requirements-dev.txt": "chiapos==2.0.4\n",
                },
                ("requirements.txt", "requirements-dev.txt"),
                False,
            ),
            "hashed and unhashed occurrence": (
                {"requirements.txt": hashed_pin, "requirements-dev.txt": "chiapos==2.0.4\n"},
                ("requirements.txt", "requirements-dev.txt"),
                False,
            ),
            "every unhashed occurrence replaces": (
                {
                    "requirements.txt": hashed_pin,
                    "requirements-dev.txt": "-i https://pypi.chia.net/simple/\nchiapos==2.0.4\n",
                },
                ("requirements.txt", "requirements-dev.txt"),
                True,
            ),
            "hashed pin served by the index": (
                {"requirements.txt": hashed_pin},
                ("requirements.txt",),
                True,
            ),
            "outer include adds an extra source": (
                {
                    "requirements.txt": "-i https://pypi.chia.net/simple/\nchiapos==2.0.4\n",
                    "requirements-dev.txt": "-r requirements.txt\n--extra-index-url https://pypi.org/simple/\n",
                },
                ("requirements.txt",),
                False,
            ),
            "outer include ends at pypi": (
                {
                    "requirements.txt": "-i https://pypi.chia.net/simple/\nchiapos==2.0.4\n",
                    "requirements-dev.txt": "-r requirements.txt\n-i https://pypi.org/simple/\n",
                },
                ("requirements.txt",),
                False,
            ),
            "outer constraint adds an extra source": (
                {
                    "requirements.txt": "-i https://pypi.chia.net/simple/\nchiapos==2.0.4\n",
                    "requirements-dev.txt": "-c requirements.txt\n--extra-index-url https://pypi.org/simple/\n",
                },
                ("requirements.txt",),
                False,
            ),
            "outer include keeps the index": (
                {
                    "requirements.txt": f"-i https://pypi.chia.net/simple/\n{hashed_pin}",
                    "requirements-dev.txt": "-r requirements.txt\n",
                },
                ("requirements.txt",),
                True,
            ),
            "pyproject pin has no index": (
                {
                    "requirements.txt": "-i https://pypi.chia.net/simple/\nchiapos==2.0.4\n",
                    "pyproject.toml": '[project]\ndependencies = ["chiapos==2.0.4"]\n',
                },
                ("requirements.txt",),
                False,
            ),
            "setup.cfg pin has no index": (
                {
                    "requirements.txt": "-i https://pypi.chia.net/simple/\nchiapos==2.0.4\n",
                    "setup.cfg": "[options]\ninstall_requires =\n    chiapos==2.0.4\n",
                },
                ("requirements.txt",),
                False,
            ),
            "Pipfile pin has no index": (
                {
                    "requirements.txt": "-i https://pypi.chia.net/simple/\nchiapos==2.0.4\n",
                    "Pipfile": '[packages]\nchiapos = "==2.0.4"\n',
                },
                ("requirements.txt",),
                False,
            ),
            "setup.py pin has no index": (
                {
                    "requirements.txt": "-i https://pypi.chia.net/simple/\nchiapos==2.0.4\n",
                    "setup.py": 'setup(install_requires=["chiapos==2.0.4"])\n',
                },
                ("requirements.txt",),
                False,
            ),
            "short index option joined with equals": (
                {"requirements.txt": f"-i=https://pypi.chia.net/simple/\n{hashed_pin}"},
                ("requirements.txt",),
                True,
            ),
            "upper case trusted host": (
                {"requirements.txt": f"-i https://PYPI.CHIA.NET/simple/\n{hashed_pin}"},
                ("requirements.txt",),
                True,
            ),
        }

        class Response:
            def __init__(self, body: bytes) -> None:
                self.status = 200
                self.body = body

            def getheader(self, _name: str) -> None:
                return None

            def read1(self, size: int = -1) -> bytes:
                if size < 0:
                    size = len(self.body)
                chunk, self.body = self.body[:size], self.body[size:]
                return chunk

        class Socket:
            def settimeout(self, _value: float) -> None:
                return None

        class Connection:
            def __init__(self) -> None:
                self.sock = Socket()

            def close(self) -> None:
                return None

        answers = {page_url: page, file_url: sdist}
        requested: list[str] = []

        def get_response(url: str, _accept: str, _budget: object = None) -> tuple[Connection, Response]:
            requested.append(url)
            if url not in answers:
                raise AssertionError(f"unexpected request {url}")
            return Connection(), Response(answers[url])

        for label, (texts, hashed, trusted) in cases.items():
            with self.subTest(label):
                requested.clear()
                looked_up: list[str] = []

                def repo(_ecosystem: str, name: str, _version: str, seen: list[str] = looked_up) -> upstream.Repo:
                    seen.append(name)
                    return _found(f"upstream/{name}")

                plan = _plan(("pip", ".", "chiapos", "2.0.3", "2.0.4"), hashed=hashed)
                all_texts = {".github/dependabot.yml": config, **texts}
                entries = [(path, "100644") for path in texts]
                with (
                    patch.object(coverage, "_git_text", lambda _rev, path, texts=all_texts: texts.get(path, "")),
                    patch.object(upstream, "_get_response", get_response),
                ):
                    report, _summary, _output = _run_main(
                        plan,
                        repo=repo,
                        scan=lambda target, *_args: _clean(target.package, target.repo.slug),
                        files=lambda directory, entries=entries: entries if directory in {"", "."} else [],
                    )
                self.assertEqual(looked_up, [] if trusted else ["chiapos"])
                self.assertEqual(
                    [(item["name"], item["index"]) for item in report["trusted_packages"]],
                    [("chiapos", "pypi.chia.net")] if trusted else [],
                )
                self.assertEqual(requested, [page_url, file_url] if trusted else [])

    def test_a_requirements_index_makes_only_its_directory_inconclusive(self) -> None:
        looked_up: list[str] = []

        def repo(_ecosystem: str, name: str, _version: str) -> upstream.Repo:
            looked_up.append(name)
            return _found(f"upstream/{name}")

        plan = _plan(("pip", "app", "attrs", "23.1.0", "23.2.0"), ("pip", "tools", "six", "1.15.0", "1.16.0"))
        texts = {"app/requirements.txt": "--index-url https://example.com/simple/\nattrs==23.2.0\n"}
        with patch.object(coverage, "_git_text", lambda _rev, path: texts.get(path, "")):
            report, summary, _output = _run_main(
                plan,
                repo=repo,
                scan=lambda target, *_args: _clean(target.package, target.repo.slug),
                files=lambda directory: [(f"{directory}/requirements.txt", "100644")],
            )
        self.assertEqual(looked_up, ["six"])
        self.assertIs(report["scan_conclusive"], False)
        self.assertIn("`attrs 23.1.0 -> 23.2.0` (no repository): not covered (configured_index)", summary)


if __name__ == "__main__":
    unittest.main()
