"""The ecosystem table: file kinds, the warn policy, and where a primary dependency's repository comes from."""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch

import dependency_cursor_review_ecosystems as ecosystems
import dependency_cursor_review_upstream as upstream
import malware_verdict_formatter as formatter


class FileKindTest(unittest.TestCase):
    def test_each_dependency_file_has_one_row(self) -> None:
        cases = {
            "package.json": ("npm", ecosystems.MANIFEST, True),
            "web/npm-shrinkwrap.json": ("npm", ecosystems.LOCK, True),
            "yarn.lock": ("npm", ecosystems.LOCK, True),
            "pnpm-lock.yaml": ("npm", ecosystems.LOCK, False),
            "go.mod": ("go", ecosystems.MANIFEST, True),
            "go.sum": ("go", ecosystems.CHECKSUMS, False),
            "requirements-dev.txt": ("pip", ecosystems.MANIFEST, True),
            "requirements/base.txt": ("pip", ecosystems.MANIFEST, True),
            "pyproject.toml": ("pip", ecosystems.MANIFEST, True),
            "poetry.lock": ("pip", ecosystems.LOCK, False),
            ".github/workflows/ci.yaml": ("github-actions", ecosystems.MANIFEST, True),
            "actions/setup/action.yml": ("github-actions", ecosystems.MANIFEST, True),
            "Dockerfile": ("docker", ecosystems.MANIFEST, True),
            "build/Dockerfile.ci": ("docker", ecosystems.MANIFEST, True),
            ".terraform.lock.hcl": ("terraform", ecosystems.MANIFEST, True),
            "infra/main.tf": ("terraform", ecosystems.MANIFEST, True),
            "Cargo.lock": ("cargo", ecosystems.LOCK, False),
            "src/App.csproj": ("nuget", ecosystems.MANIFEST, False),
        }
        for path, (ecosystem, role, parsed) in cases.items():
            with self.subTest(path=path):
                row = ecosystems.file_kind(path)
                self.assertIsNotNone(row)
                self.assertEqual((row.ecosystem.name, row.role, row.parse is not None), (ecosystem, role, parsed))

    def test_other_paths_are_not_dependency_files(self) -> None:
        for path in ("README.md", "notes.txt", "workflows/ci.yml", "docs/requirements.md", "src/index.js"):
            with self.subTest(path=path):
                self.assertIsNone(ecosystems.file_kind(path))


class WarnPolicyTest(unittest.TestCase):
    def test_docker_and_terraform_are_unscannable(self) -> None:
        for ecosystem in ("docker", "terraform"):
            with self.subTest(ecosystem=ecosystem):
                self.assertEqual(ecosystems.warn_reason(ecosystem, "1.0", "1.1"), ecosystems.UNSCANNABLE_ECOSYSTEM)

    def test_major_and_major_minor_action_tags_and_branches_are_moving_refs(self) -> None:
        for old, new in (("v4", "v5"), ("v4.1", "v4.2"), ("v4.1", "v4.2.0"), ("v4.1.0", "v4.2"), ("main", "v4.2.0")):
            with self.subTest(old=old, new=new):
                self.assertEqual(ecosystems.warn_reason("github-actions", old, new), ecosystems.MOVING_REF)

    def test_full_action_tags_shas_and_other_ecosystems_are_scanned(self) -> None:
        sha = "0123456789abcdef0123456789abcdef01234567"
        for ecosystem, old, new in (
            ("github-actions", "v4.1.0", "v4.2.0"),
            ("github-actions", sha, sha[::-1]),
            ("github-actions", "", "v4.2.0"),
            ("npm", "1", "2"),
            ("go", "v1", "v2"),
            ("cargo", "1", "2"),
        ):
            with self.subTest(ecosystem=ecosystem, old=old, new=new):
                self.assertEqual(ecosystems.warn_reason(ecosystem, old, new), "")

    def test_every_warn_reason_has_a_named_warning(self) -> None:
        self.assertEqual(set(formatter._POLICY_WARNINGS), set(ecosystems.WARN_REASONS))


class _Fetch:
    """Fake fetch: answers by URL and records every request."""

    def __init__(self, answers: dict[str, object]) -> None:
        self.answers = answers
        self.urls: list[str] = []

    def __call__(self, url: str) -> bytes:
        self.urls.append(url)
        answer = self.answers.get(url, b"")
        return answer if isinstance(answer, bytes) else json.dumps(answer).encode()


class UpstreamRepoTest(unittest.TestCase):
    def _repo(self, ecosystem: str, name: str, version: str, answers: dict[str, object]) -> tuple[str, list[str]]:
        fetch = _Fetch(answers)
        with patch.object(upstream, "_fetch", fetch):
            return ecosystems.upstream_repo(ecosystem, name, version), fetch.urls

    def test_actions_and_github_go_modules_name_their_repository(self) -> None:
        for ecosystem, name, want in (
            ("github-actions", "actions/checkout", "actions/checkout"),
            ("github-actions", "github/codeql-action/init", "github/codeql-action"),
            ("go", "github.com/spf13/cobra", "spf13/cobra"),
            ("go", "github.com/jackc/pgx/v5", "jackc/pgx"),
        ):
            with self.subTest(name=name):
                self.assertEqual(self._repo(ecosystem, name, "1.0.0", {}), (want, []))

    def test_npm_repository_spellings(self) -> None:
        url = "https://registry.npmjs.org/@babel/core/7.24.0"
        for repository in (
            "git+https://github.com/babel/babel.git",
            {"type": "git", "url": "https://github.com/babel/babel/tree/main/packages/babel-core"},
            "github:babel/babel",
            "babel/babel",
            "git@github.com:babel/babel.git",
            "git://github.com/babel/babel",
        ):
            with self.subTest(repository=repository):
                self.assertEqual(
                    self._repo("npm", "@babel/core", "7.24.0", {url: {"repository": repository}}),
                    ("babel/babel", [url]),
                )
        for repository in ("https://gitlab.com/a/b", "", {"url": 7}, "https://github.com/../b", None):
            with self.subTest(repository=repository):
                self.assertEqual(self._repo("npm", "@babel/core", "7.24.0", {url: {"repository": repository}})[0], "")

    def test_pypi_prefers_source_labels_over_the_home_page(self) -> None:
        url = "https://pypi.org/pypi/requests/2.32.0/json"
        info = {
            "home_page": "https://github.com/someone/mirror",
            "project_urls": {
                "Documentation": "https://github.com/psf/requests-docs",
                "Source": "https://github.com/psf/requests",
            },
        }
        self.assertEqual(self._repo("pip", "requests", "2.32.0", {url: {"info": info}}), ("psf/requests", [url]))
        home_only = {"home_page": "https://github.com/psf/requests", "project_urls": None}
        self.assertEqual(self._repo("pip", "requests", "2.32.0", {url: {"info": home_only}})[0], "psf/requests")
        self.assertEqual(self._repo("pip", "requests", "2.32.0", {url: {"info": "x"}})[0], "")

    def test_other_go_hosts_use_go_import_then_go_source(self) -> None:
        url = "https://golang.org/x/net?go-get=1"
        page = (
            b'<meta name="go-import" content="golang.org/x/net git https://go.googlesource.com/net">\n'
            b'<meta name="go-source" content="golang.org/x/net https://github.com/golang/net/ '
            b'https://github.com/golang/net/tree/master{/dir}">\n'
        )
        self.assertEqual(self._repo("go", "golang.org/x/net", "v0.21.0", {url: page}), ("golang/net", [url]))
        grpc = b'<meta name="go-import" content="google.golang.org/grpc git https://github.com/grpc/grpc-go">'
        found = self._repo("go", "google.golang.org/grpc", "v1.62.0", {"https://google.golang.org/grpc?go-get=1": grpc})
        self.assertEqual(found[0], "grpc/grpc-go")
        other = b'<meta name="go-import" content="example.com/other git https://github.com/evil/other">'
        self.assertEqual(
            self._repo("go", "example.com/mod", "v1.0.0", {"https://example.com/mod?go-get=1": other})[0], ""
        )

    def test_names_outside_each_grammar_are_never_fetched(self) -> None:
        for ecosystem, name in (
            ("npm", "a b"),
            ("npm", "../../evil"),
            ("pip", "requests/../x"),
            ("go", "evil.com:8080/mod"),
            ("go", "169.254.169.254/latest"),
            ("go", "localhost/mod"),
            ("go", "github.com/only"),
            ("docker", "nginx"),
            ("terraform", "registry.terraform.io/hashicorp/aws"),
        ):
            with self.subTest(ecosystem=ecosystem, name=name):
                self.assertEqual(self._repo(ecosystem, name, "1.0.0", {}), ("", []))

    def test_fetch_takes_only_https(self) -> None:
        for url in ("http://registry.npmjs.org/a/1.0.0", "file:///etc/passwd", "ftp://example.com/x", "https:///x"):
            with self.subTest(url=url):
                self.assertEqual(upstream._fetch(url), b"")


if __name__ == "__main__":
    unittest.main()
