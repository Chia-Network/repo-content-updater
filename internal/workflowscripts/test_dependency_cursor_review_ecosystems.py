"""The ecosystem table: file kinds, the warn policy, and where a primary dependency's repository comes from."""

from __future__ import annotations

import hashlib
import http.client
import json
import socket
import threading
import time
import unittest
import urllib.parse
from collections.abc import Callable
from typing import ClassVar
from unittest.mock import patch

import dependency_cursor_review_binding as binding
import dependency_cursor_review_ecosystems as ecosystems
import dependency_cursor_review_upstream as upstream
import malware_verdict_formatter as formatter
from test_dependency_manifest_grammars import pipfile_lock_text, poetry_lock_text


class FileKindTest(unittest.TestCase):
    def test_each_dependency_file_has_one_row(self) -> None:
        cases = {
            "package.json": ("npm", ecosystems.MANIFEST, True),
            "web/npm-shrinkwrap.json": ("npm", ecosystems.LOCK, True),
            "yarn.lock": ("npm", ecosystems.LOCK, True),
            "pnpm-lock.yaml": ("npm", ecosystems.LOCK, True),
            "go.mod": ("go", ecosystems.MANIFEST, True),
            "go.sum": ("go", ecosystems.CHECKSUMS, True),
            "requirements-dev.txt": ("pip", ecosystems.MANIFEST, True),
            "requirements/base.txt": ("pip", ecosystems.MANIFEST, True),
            "pyproject.toml": ("pip", ecosystems.MANIFEST, True),
            "poetry.lock": ("pip", ecosystems.LOCK, True),
            "Pipfile.lock": ("pip", ecosystems.LOCK, True),
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

    def test_a_requirements_file_is_a_manifest_that_records_hashes_and_other_python_manifests_are_not(self) -> None:
        self.assertIsNotNone(ecosystems.file_kind("requirements/base.txt").hashes)
        for path in ("pyproject.toml", "setup.py", "setup.cfg", "Pipfile"):
            with self.subTest(path=path):
                self.assertIsNone(ecosystems.file_kind(path).hashes)

    def test_other_paths_are_not_dependency_files(self) -> None:
        for path in ("README.md", "notes.txt", "workflows/ci.yml", "docs/requirements.md", "src/index.js"):
            with self.subTest(path=path):
                self.assertIsNone(ecosystems.file_kind(path))


_SHA = "0123456789abcdef0123456789abcdef01234567"


class WarnPolicyTest(unittest.TestCase):
    def test_docker_and_terraform_are_unscannable_and_grammarless_ecosystems_are_unread(self) -> None:
        for ecosystem in ("docker", "terraform"):
            with self.subTest(ecosystem=ecosystem):
                self.assertEqual(ecosystems.warn_reason(ecosystem, "1.0", "1.1"), ecosystems.UNSCANNABLE_ECOSYSTEM)
        for ecosystem in ("cargo", "bundler", "composer", "swift", "nuget"):
            with self.subTest(ecosystem=ecosystem):
                self.assertEqual(ecosystems.warn_reason(ecosystem, "1.0", "1.1"), ecosystems.UNREAD_ECOSYSTEM)

    def test_major_and_major_minor_action_tags_and_branches_are_moving_refs(self) -> None:
        for old, new in (
            ("v4", "v5"),
            ("v4.1", "v4.2"),
            ("v4.1", "v4.2.0"),
            ("v4.1.0", "v4.2"),
            ("main", "v4.2.0"),
            (_SHA, "v4"),
            (_SHA[:39], _SHA),
        ):
            with self.subTest(old=old, new=new):
                self.assertEqual(ecosystems.warn_reason("github-actions", old, new), ecosystems.MOVING_REF)

    def test_a_commit_to_commit_action_bump_is_scanned_and_is_unresolved_sha_only_when_the_scan_cannot_resolve_it(
        self,
    ) -> None:
        for reason in ("from_ref_unresolved", "to_ref_unresolved"):
            unresolved = {"status": "not_scanned", "not_scanned_reason": reason}
            for old, new in ((_SHA, _SHA[::-1]), (_SHA, _SHA.upper()), (_SHA.upper(), _SHA[::-1])):
                with self.subTest(old=old, new=new, reason=reason):
                    self.assertEqual(ecosystems.warn_reason("github-actions", old, new), "")
                    found = ecosystems.unresolved_reason("github-actions", old, new, unresolved)
                    self.assertEqual(found, ecosystems.UNRESOLVED_SHA)
        unresolved = {"status": "not_scanned", "not_scanned_reason": "to_ref_unresolved"}
        for ecosystem, old, new in (
            ("github-actions", _SHA, "v4.2.0"),
            ("github-actions", "v4.1.0", _SHA),
            ("github-actions", "v4.1.0", "v4.2.0"),
            ("npm", _SHA, _SHA[::-1]),
            ("docker", _SHA, _SHA[::-1]),
        ):
            with self.subTest(ecosystem=ecosystem, old=old, new=new):
                self.assertEqual(ecosystems.unresolved_reason(ecosystem, old, new, unresolved), "")

    def test_a_commit_to_commit_record_that_is_not_an_unresolved_ref_stands(self) -> None:
        """A failed clone, an incomplete or failed scan, or a scan with findings is not an unresolved commit."""
        for record in (
            {"status": "not_scanned", "not_scanned_reason": "unresolved"},
            {"status": "not_scanned", "not_scanned_reason": "incomplete_coverage"},
            {"status": "not_scanned", "not_scanned_reason": "scanner_error"},
            {"status": "fail", "not_scanned_reason": "to_ref_unresolved"},
            {"status": "warn", "not_scanned_reason": "from_ref_unresolved"},
            {"status": "clean", "scan_conclusive": True, "not_scanned_reason": ""},
            {},
        ):
            with self.subTest(record=record):
                self.assertEqual(ecosystems.unresolved_reason("github-actions", _SHA, _SHA[::-1], record), "")

    def test_full_action_tags_commit_bumps_and_other_ecosystems_have_no_warn_reason(self) -> None:
        for ecosystem, old, new in (
            ("github-actions", _SHA, _SHA[::-1]),
            ("github-actions", "v4.1.0", "v4.2.0"),
            ("github-actions", _SHA, "v4.2.0"),
            ("github-actions", "v4.1.0", _SHA),
            ("github-actions", "", _SHA),
            ("github-actions", "", "v4.2.0"),
            ("npm", "1", "2"),
            ("go", "v1", "v2"),
        ):
            with self.subTest(ecosystem=ecosystem, old=old, new=new):
                self.assertEqual(ecosystems.warn_reason(ecosystem, old, new), "")

    def test_every_warn_reason_has_a_named_warning(self) -> None:
        self.assertEqual(set(formatter._POLICY_WARNINGS), set(ecosystems.WARN_REASONS))


class BindTest(unittest.TestCase):
    def _bind(self, ecosystem: str, version: str) -> binding.Binding:
        return ecosystems.bind(ecosystem, binding.Subject("a/b", version, "a/b", _SHA))

    def test_actions_pinned_to_a_full_tag_or_commit_are_intrinsic(self) -> None:
        for ecosystem, version in (
            ("github-actions", _SHA),
            ("github-actions", _SHA.upper()),
            ("github-actions", "4.2.0"),
        ):
            with self.subTest(ecosystem=ecosystem, version=version):
                self.assertEqual(self._bind(ecosystem, version), binding.Binding(binding.INTRINSIC))

    def test_go_and_pypi_with_no_lock_hash_are_unbound_before_any_lookup(self) -> None:
        for ecosystem in ("go", "pip"):
            with self.subTest(ecosystem=ecosystem), patch.object(upstream, "_fetch") as fetch:
                self.assertEqual(self._bind(ecosystem, "1.2.3"), binding.Binding(binding.UNBOUND, binding.NO_LOCK_HASH))
                fetch.assert_not_called()

    def test_ecosystems_without_a_binding_are_unbound(self) -> None:
        for ecosystem, version, reason in (
            ("docker", "1.0", binding.UNSUPPORTED),
            ("cargo", "1.0.0", binding.UNSUPPORTED),
            ("unknown", "1.0.0", binding.UNSUPPORTED),
        ):
            with self.subTest(ecosystem=ecosystem):
                self.assertEqual(self._bind(ecosystem, version), binding.Binding(binding.UNBOUND, reason))

    def test_locked_reads_the_integrity_of_the_top_entries_for_the_version_in_each_lock_beside_the_change(self) -> None:
        record = {"version": "1.0.1", "resolved": "https://registry.npmjs.org/a/-/a-1.0.1.tgz", "integrity": "sha512-x"}
        nested = {**record, "integrity": "sha512-nested"}
        lock = {"packages": {"node_modules/a": record, "node_modules/b/node_modules/a": nested}}
        yarn = 'a@^1.0.0:\n  version "1.0.1"\n  resolved "https://registry.yarnpkg.com/a/-/a-1.0.1.tgz"\n'
        files = {"web/package-lock.json": json.dumps(lock), "web/yarn.lock": yarn, "package-lock.json": "{}"}
        found = ecosystems.locked("npm", "web", "a", "1.0.1", lambda path: files.get(path, ""), ())
        self.assertEqual(found, ("sha512-x", ""))
        files["web/yarn.lock"] = yarn + "  integrity sha512-y\n"
        self.assertEqual(
            ecosystems.locked("npm", "web", "a", "1.0.1", lambda path: files.get(path, ""), ()),
            ("sha512-x", "sha512-y"),
        )
        self.assertEqual(ecosystems.locked("npm", "web", "a", "1.0.0", lambda path: files.get(path, ""), ()), ())
        self.assertEqual(ecosystems.locked("docker", "web", "a", "1.0.1", lambda path: files.get(path, ""), ()), ())

    def test_locked_reads_the_go_sum_tree_hash_for_the_exact_version(self) -> None:
        go_sum = (
            "github.com/a/b v1.2.3 h1:tree=\ngithub.com/a/b v1.2.3/go.mod h1:mod=\ngithub.com/a/b v1.2.4 h1:next=\n"
        )
        files = {"svc/go.sum": go_sum, "go.sum": "github.com/a/b v1.2.3 h1:root=\n"}

        def read(path: str) -> str:
            return files.get(path, "")

        self.assertEqual(ecosystems.locked("go", "svc", "github.com/a/b", "1.2.3", read, ()), ("h1:tree=",))
        self.assertEqual(ecosystems.locked("go", "svc", "github.com/a/b", "1.2.5", read, ()), ())
        self.assertEqual(ecosystems.locked("go", "svc", "github.com/a/c", "1.2.3", read, ()), ())

    def test_locked_reads_the_file_hashes_of_each_python_lock_beside_the_change(self) -> None:
        files = {"poetry.lock": poetry_lock_text({"requests": "2.32.0"}), "Pipfile.lock": pipfile_lock_text({})}

        def read(path: str) -> str:
            return files.get(path, "")

        (poetry,) = ecosystems.locked("pip", ".", "requests", "2.32.0", read, ())
        self.assertEqual(len(poetry.split()), 2)
        files["Pipfile.lock"] = pipfile_lock_text({"requests": "2.32.0"})
        self.assertEqual(len(ecosystems.locked("pip", ".", "requests", "2.32.0", read, ())), 2)
        self.assertEqual(ecosystems.locked("pip", ".", "requests", "2.31.0", read, ()), ())
        files = {"poetry.lock": poetry_lock_text({"requests": "2.32.0"}, legacy=True)}
        self.assertEqual(ecosystems.locked("pip", ".", "requests", "2.32.0", read, ()), (poetry,))

    def test_locked_reads_the_hashes_of_a_changed_requirements_file_beside_the_change(self) -> None:
        sha_a, sha_b = (f"sha256:{digit * 64}" for digit in "ab")
        files = {
            "app/requirements.txt": f"requests==2.32.0 \\\n    --hash={sha_b} \\\n    --hash={sha_a}\nidna==3.7\n",
            "app/poetry.lock": poetry_lock_text({"requests": "2.32.0"}),
            "requirements.txt": f"requests==2.32.0 --hash={sha_a}\n",
        }

        def read(path: str) -> str:
            return files.get(path, "")

        hashed = ("app/requirements.txt", "requirements.txt", "app/README.md")
        found = ecosystems.locked("pip", "app", "requests", "2.32.0", read, hashed)
        self.assertEqual(len(found), 2)
        self.assertIn(f"{sha_a} {sha_b}", found)
        self.assertEqual(ecosystems.locked("pip", "app", "idna", "3.7", read, hashed), ("",))
        self.assertEqual(ecosystems.locked("pip", "app", "requests", "2.31.0", read, hashed), ())
        self.assertEqual(ecosystems.locked("pip", ".", "requests", "2.32.0", read, ()), ())
        self.assertEqual(ecosystems.locked("pip", ".", "requests", "2.32.0", read, hashed), (sha_a,))

    def test_every_lock_and_checksum_grammar_reads_its_own_hashes(self) -> None:
        """locked() has no per-role case: each row says which entries are installed copies and what they record."""
        rows = [row for row in ecosystems._FILES if row.role in {ecosystems.LOCK, ecosystems.CHECKSUMS} and row.parse]
        self.assertEqual([row for row in rows if row.hashes is None], [])
        (go_sum,) = (row for row in rows if "go.sum" in row.names)
        self.assertEqual(go_sum.hashes(("m", "v1.0.0", False, "m v1.0.0 h1:x=")), "h1:x=")
        (lock,) = (row for row in rows if "yarn.lock" in row.names)
        self.assertIsNone(lock.hashes(("a", "1.0.0", False, 'a@^1:\n  version "1.0.0"\n  integrity sha512-x\n')))
        self.assertEqual(
            lock.hashes(("a", "1.0.0", True, 'a@^1:\n  version "1.0.0"\n  integrity sha512-x\n')), "sha512-x"
        )


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
    def _repo(
        self, ecosystem: str, name: str, version: str, answers: dict[str, object]
    ) -> tuple[upstream.Repo, list[str]]:
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
                self.assertEqual(self._repo(ecosystem, name, "1.0.0", {}), (upstream.Repo(want, upstream.IDENTITY), []))

    def test_npm_repository_spellings(self) -> None:
        url = "https://registry.npmjs.org/@babel%2Fcore/7.24.0"
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
                    (upstream.Repo("babel/babel", upstream.PUBLISHER), [url]),
                )
        for repository in ("https://gitlab.com/a/b", "", {"url": 7}, "https://github.com/../b", None):
            with self.subTest(repository=repository):
                self.assertEqual(
                    self._repo("npm", "@babel/core", "7.24.0", {url: {"repository": repository}})[0], upstream.Repo()
                )

    def test_pypi_prefers_source_labels_over_the_home_page(self) -> None:
        url = "https://pypi.org/pypi/requests/2.32.0/json"
        info = {
            "home_page": "https://github.com/someone/mirror",
            "project_urls": {
                "Documentation": "https://github.com/psf/requests-docs",
                "Source": "https://github.com/psf/requests",
            },
        }
        self.assertEqual(
            self._repo("pip", "requests", "2.32.0", {url: {"info": info}}),
            (upstream.Repo("psf/requests", upstream.PUBLISHER), [url]),
        )
        home_only = {"home_page": "https://github.com/psf/requests", "project_urls": None}
        self.assertEqual(self._repo("pip", "requests", "2.32.0", {url: {"info": home_only}})[0].slug, "psf/requests")
        self.assertEqual(self._repo("pip", "requests", "2.32.0", {url: {"info": "x"}})[0], upstream.Repo())

    def test_other_go_hosts_use_go_import_then_go_source(self) -> None:
        url = "https://golang.org/x/net?go-get=1"
        page = (
            b'<meta name="go-import" content="golang.org/x/net git https://go.googlesource.com/net">\n'
            b'<meta name="go-source" content="golang.org/x/net https://github.com/golang/net/ '
            b'https://github.com/golang/net/tree/master{/dir}">\n'
        )
        with patch.dict(ecosystems.KNOWN_REPO_PREFIXES, clear=True):  # the lookup this allowlist entry replaces
            self.assertEqual(
                self._repo("go", "golang.org/x/net", "v0.21.0", {url: page}),
                (upstream.Repo("golang/net", upstream.PUBLISHER), [url]),
            )
        grpc = b'<meta name="go-import" content="google.golang.org/grpc git https://github.com/grpc/grpc-go">'
        found = self._repo("go", "google.golang.org/grpc", "v1.62.0", {"https://google.golang.org/grpc?go-get=1": grpc})
        self.assertEqual(found[0], upstream.Repo("grpc/grpc-go", upstream.PUBLISHER))
        other = b'<meta name="go-import" content="example.com/other git https://github.com/evil/other">'
        self.assertEqual(
            self._repo("go", "example.com/mod", "v1.0.0", {"https://example.com/mod?go-get=1": other})[0],
            upstream.Repo(),
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
                self.assertEqual(self._repo(ecosystem, name, "1.0.0", {}), (upstream.Repo(), []))

    def test_an_allowlisted_package_is_verified_without_a_lookup(self) -> None:
        with patch.dict(ecosystems.KNOWN_REPOS, {("go", "golang.org/x/net"): "golang/net"}):
            self.assertEqual(
                self._repo("go", "golang.org/x/net", "v0.21.0", {}),
                (upstream.Repo("golang/net", upstream.ALLOWLISTED), []),
            )
        self.assertEqual(ecosystems.KNOWN_REPOS, {}, "exact entries ship empty; each entry is checked by hand")

    def test_the_golang_org_x_prefix_maps_to_the_golang_owner(self) -> None:
        self.assertEqual(ecosystems.KNOWN_REPO_PREFIXES, {("go", "golang.org/x/"): "golang"})
        for name, repo in (
            ("golang.org/x/net", "golang/net"),
            ("golang.org/x/tools/gopls", "golang/tools"),
            ("golang.org/x/exp/typeparams", "golang/exp"),
        ):
            with self.subTest(name):
                self.assertEqual(self._repo("go", name, "v0.60.0", {}), (upstream.Repo(repo, upstream.ALLOWLISTED), []))
        for ecosystem, name in (
            ("go", "golang.org/x/"),
            ("go", "golang.org/x/.."),
            ("go", "golang.org/x//net"),
            ("go", "golang.org/x/n@t"),
            ("go", "golang.org/xnet"),
            ("go", "example.com/golang.org/x/net"),
            ("npm", "golang.org/x/net"),
        ):
            with self.subTest(ecosystem=ecosystem, name=name):
                self.assertEqual(ecosystems.known_repo(ecosystem, name), "")

    def test_an_exact_entry_wins_over_a_prefix(self) -> None:
        with patch.dict(ecosystems.KNOWN_REPOS, {("go", "golang.org/x/net"): "golang/net-mirror"}):
            self.assertEqual(ecosystems.known_repo("go", "golang.org/x/net"), "golang/net-mirror")

    def test_only_identity_attested_and_allowlisted_repositories_are_verified(self) -> None:
        self.assertEqual(upstream.VERIFIED, {upstream.IDENTITY, upstream.ATTESTED, upstream.ALLOWLISTED})
        self.assertNotIn(upstream.PUBLISHER, upstream.VERIFIED)

    def test_fetch_takes_only_https(self) -> None:
        for url in ("http://registry.npmjs.org/a/1.0.0", "file:///etc/passwd", "ftp://example.com/x", "https:///x"):
            with self.subTest(url=url):
                self.assertIsNone(upstream._fetch(url))

    def _follow(self, answers: dict[str, tuple[int, str, bytes]], url: str, follow: frozenset[str]) -> object:
        self.requested: list[str] = []

        def get(url: str, _limit: int, _accept: str, _budget: object = None) -> tuple[int, str, bytes]:
            self.requested.append(url)
            return answers[url]

        with patch.object(upstream, "_get", get):
            return upstream.fetch_archive(url, 100, follow)

    def test_a_redirect_is_followed_only_to_a_listed_https_host_and_path(self) -> None:
        zip_url = "https://proxy.golang.org/m/@v/v1.zip"
        stored = "https://storage.googleapis.com/proxy-golang-org-prod/m/@v/v1.zip"
        follow = binding._GO_REDIRECTS
        for location, allowed, want in (
            (stored, follow, b"zip"),
            ("/other/m.zip", follow, b"zip"),
            (stored, None, None),
            ("https://evil.example/m.zip", follow, None),
            ("https://storage.googleapis.com/other/m.zip", follow, None),
            ("http://storage.googleapis.com/proxy-golang-org-prod/m/@v/v1.zip", follow, None),
            ("", follow, None),
        ):
            target = urllib.parse.urljoin(zip_url, location)
            answers = {target: (200, "", b"zip"), zip_url: (302, location, b"")}
            with self.subTest(location=location, allowed=allowed):
                self.assertEqual(self._follow(answers, zip_url, allowed), want)
                self.assertEqual(self.requested, [zip_url, target] if want else [zip_url])

    def test_a_redirect_path_with_a_dot_segment_is_not_allowed(self) -> None:
        follow = binding._GO_REDIRECTS
        for path in (
            "/proxy-golang-org-prod/m/../x.zip",
            "/proxy-golang-org-prod/m/%2e%2e/x.zip",
            "/proxy-golang-org-prod/m/%2E./x.zip",
            "/proxy-golang-org-prod/./m.zip",
        ):
            with self.subTest(path=path):
                self.assertFalse(upstream._redirect_allowed(f"https://storage.googleapis.com{path}", follow))

    def test_a_redirect_with_a_malformed_host_is_no_answer(self) -> None:
        url = "https://proxy.golang.org/m/@v/v1.zip"

        def get(_url: str, _limit: int, _accept: str, _budget: object = None) -> tuple[int, str, bytes]:
            return 302, "https://[::1/x", b""

        with patch.object(upstream, "_get", get):
            self.assertIsNone(upstream.fetch_archive(url, 100, binding._GO_REDIRECTS))

    def test_a_redirect_loop_is_no_answer(self) -> None:
        url = "https://proxy.golang.org/m/@v/v1.zip"
        self.assertIsNone(self._follow({url: (302, url, b"")}, url, binding._GO_REDIRECTS))
        self.assertEqual(len(self.requested), upstream._MAX_REDIRECTS + 1)

    def test_fetch_json_tells_an_unreadable_answer_from_a_404(self) -> None:
        url = "https://registry.npmjs.org/a/1.0.0"
        for body, want in (
            (b'{"a": 1}', {"a": 1}),
            (b"", {}),
            (None, None),
            (b"not json", None),
            (b"[1]", None),
            (b"null", None),
            (b"\xff", None),
        ):
            with self.subTest(body=body), patch.object(upstream, "_fetch", lambda _url, body=body: body):
                self.assertEqual(upstream.fetch_json(url), want)

    def test_an_unavailable_registry_names_no_repository(self) -> None:
        for ecosystem, name in (("npm", "a"), ("pip", "a"), ("go", "example.com/mod")):
            with self.subTest(ecosystem=ecosystem), patch.object(upstream, "_fetch", lambda _url: None):
                self.assertEqual(ecosystems.upstream_repo(ecosystem, name, "1.0.0"), upstream.Repo())


if __name__ == "__main__":
    unittest.main()


_CHIA = "https://pypi.chia.net/simple/"
_HOST = "pypi.chia.net"
_WHEEL = b"wheel bytes"
_SDIST = b"sdist bytes"
_WHEEL_URL = "https://pypi.chia.net/files/chiapos-2.0.4-cp312-cp312-manylinux_2_28_x86_64.whl"
_SDIST_URL = "https://pypi.chia.net/files/chiapos-2.0.4.tar.gz"
_PAGE = (
    b'<a href="../../files/chiapos-2.0.4-cp312-cp312-manylinux_2_28_x86_64.whl#sha256=AAAA">w</a>\n'
    b'<a href="../../files/chiapos-2.0.4.tar.gz#sha256=bbbb">s</a>\n'
    b'<a href="../../files/chiapos-2.0.3.tar.gz#sha256=cccc">old</a>\n'
)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class TrustedPythonIndexTest(unittest.TestCase):
    def trusted(
        self,
        version: str,
        hashes: tuple[str, ...] = (),
        pages: dict[str, bytes] | None = None,
        downloads: dict[str, bytes | None] | None = None,
        name: str = "ChiaPos",
    ) -> str:
        urls: list[str] = []
        fetched = {f"{_CHIA}chiapos/": _PAGE} if pages is None else pages
        served = {_WHEEL_URL: _WHEEL, _SDIST_URL: _SDIST} if downloads is None else downloads
        downloaded: list[str] = []

        def fetch(url: str, **_kwargs: object) -> bytes | None:
            urls.append(url)
            return fetched.get(url)

        def download(url: str, _hosts: frozenset[str], **_kwargs: object) -> str | None:
            downloaded.append(url)
            body = served.get(url)
            return _sha(body) if isinstance(body, bytes) else None

        with patch.object(upstream, "_fetch", fetch), patch.object(upstream, "_sha256_download", download):
            found = upstream.trusted_python_index(name, version, hashes)
        self.urls = urls
        self.downloaded = downloaded
        return found

    def test_a_hashed_pin_is_trusted_only_when_a_downloaded_file_matches(self) -> None:
        self.assertEqual(self.trusted("2.0.4", (f"sha256:{_sha(_WHEEL)}",)), _HOST)
        self.assertEqual(self.downloaded, [_WHEEL_URL])
        self.assertEqual(self.trusted("2.0.4", (f"sha256:{_sha(_WHEEL)} sha256:{_sha(_SDIST)}",)), _HOST)
        self.assertEqual(self.downloaded, [_WHEEL_URL, _SDIST_URL])
        self.assertEqual(self.trusted("2.0.4", (f"sha256:{_sha(b'other')}",)), "")

    def test_every_locked_hash_must_match_a_downloaded_file(self) -> None:
        locked = f"sha256:{_sha(_WHEEL)} sha256:{_sha(b'other')}"
        self.assertEqual(self.trusted("2.0.4", (locked,)), "")

    def test_page_fragments_do_not_stand_in_for_downloaded_bytes(self) -> None:
        for fragment in ("aaaa", "bbbb", "cccc"):
            with self.subTest(fragment=fragment):
                self.assertEqual(self.trusted("2.0.4", (f"sha256:{fragment}",)), "")

    def test_a_failed_download_is_not_trusted(self) -> None:
        hashed = (f"sha256:{_sha(_WHEEL)}",)
        self.assertEqual(self.trusted("2.0.4", hashed, downloads={_WHEEL_URL: None, _SDIST_URL: _SDIST}), "")

    def test_a_download_budget_limit_is_not_trusted(self) -> None:
        body = b"body"
        page = b'<a href="../../files/chiapos-2.0.4.tar.gz">s</a>\n'

        def get_response(url: str, _accept: str, _budget: object = None) -> tuple[_Connection, _Reply]:
            return _Connection(), _Reply([page if url == f"{_CHIA}chiapos/" else body])

        real_budget = upstream._DownloadBudget
        with (
            patch.object(upstream, "_get_response", get_response),
            patch.object(upstream, "_DownloadBudget", lambda **_kwargs: real_budget(size=1, clock=lambda: 0.0)),
        ):
            found = upstream.trusted_python_index("ChiaPos", "2.0.4", (f"sha256:{_sha(body)}",))
        self.assertEqual(found, "")

    def test_the_index_page_read_uses_the_check_budget(self) -> None:
        now = [0.0]
        page = _Reply([bytes([byte]) for byte in _PAGE], clock=now, step=1.0)
        connection = _Connection()

        def get_response(_url: str, _accept: str, _budget: object = None) -> tuple[_Connection, _Reply]:
            return connection, page

        real_budget = upstream._DownloadBudget
        with (
            patch.object(upstream, "_get_response", get_response),
            patch.object(upstream, "_DownloadBudget", lambda **_kwargs: real_budget(seconds=3, clock=lambda: now[0])),
        ):
            found = upstream.trusted_python_index("ChiaPos", "2.0.4", (f"sha256:{_sha(_SDIST)}",))
        self.assertEqual(found, "")
        self.assertLessEqual(now[0], 3.0)

    def test_an_off_host_file_link_is_not_downloaded(self) -> None:
        page = b'<a href="https://example.com/chiapos-2.0.4.tar.gz">x</a>\n'
        self.assertEqual(self.trusted("2.0.4", (f"sha256:{_sha(_SDIST)}",), pages={f"{_CHIA}chiapos/": page}), "")
        self.assertEqual(self.downloaded, [])

    def test_a_malformed_file_link_is_not_trusted(self) -> None:
        page = b'<a href="https://[::1/chiapos-2.0.4.tar.gz">x</a>\n'
        self.assertEqual(self.trusted("2.0.4", (f"sha256:{_sha(_SDIST)}",), pages={f"{_CHIA}chiapos/": page}), "")
        self.assertEqual(self.downloaded, [])

    def test_a_file_link_on_the_indexes_allowed_file_host_is_downloaded(self) -> None:
        file_url = "https://download.chia.net/files/chiapos-2.0.4.tar.gz"
        page = f'<a href="{file_url}">s</a>\n'.encode()
        self.assertEqual(
            self.trusted(
                "2.0.4",
                (f"sha256:{_sha(_SDIST)}",),
                pages={f"{_CHIA}chiapos/": page},
                downloads={file_url: _SDIST},
            ),
            _HOST,
        )
        self.assertEqual(self.downloaded, [file_url])

    def test_an_unhashed_occurrence_is_never_trusted(self) -> None:
        self.assertEqual(self.trusted("2.0.4"), "")
        self.assertEqual(self.trusted("2.0.4", ("",)), "")
        self.assertEqual(self.trusted("2.0.4", (f"sha256:{_sha(_WHEEL)}", "")), "")
        self.assertEqual(self.downloaded, [])

    def test_a_version_the_index_does_not_serve_is_not_trusted(self) -> None:
        hashed = (f"sha256:{_sha(_WHEEL)}",)
        self.assertEqual(self.trusted("2.0.5", hashed), "")
        self.assertEqual(self.trusted("2.0.4", hashed, pages={}), "")

    def test_only_a_listed_index_is_ever_read(self) -> None:
        evil = "https://pypi.chia.net.evil/simple/"
        self.assertEqual(
            self.trusted("2.0.4", (f"sha256:{_sha(_WHEEL)}",), pages={f"{evil}chiapos/": _PAGE}),
            "",
        )
        self.assertTrue(self.urls)
        self.assertTrue(all("/pypi.chia.net.evil/" not in url for url in self.urls))

    def test_versions_compare_in_canonical_pep440_form(self) -> None:
        for filename_name, page_version, name, version in (
            ("chiapos", "2.0.4", "ChiaPos", "2.0.4"),
            ("Chia_Pos", "2.0.4", "chia.pos", "v2.0.4"),
            ("chiapos", "2.0.4", "chiapos", "2.0.4.0"),
        ):
            file_url = f"https://{_HOST}/files/{filename_name}-{page_version}.tar.gz"
            page = f'<a href="../../files/{filename_name}-{page_version}.tar.gz">s</a>\n'.encode()
            page_url = f"{_CHIA}{upstream._canonical(name)}/"
            with self.subTest(name=name, version=version):
                found = self.trusted(
                    version,
                    (f"sha256:{_sha(_SDIST)}",),
                    pages={page_url: page},
                    downloads={file_url: _SDIST},
                    name=name,
                )
                self.assertEqual(found, _HOST)

    def test_a_post_release_does_not_match_the_plain_version(self) -> None:
        page = b'<a href="../../files/chiapos-2.0.4.post0.tar.gz">s</a>\n'
        page_url = f"{_CHIA}chiapos/"
        hashed = (f"sha256:{_sha(_SDIST)}",)
        file_url = f"https://{_HOST}/files/chiapos-2.0.4.post0.tar.gz"
        self.assertEqual(self.trusted("2.0.4", hashed, pages={page_url: page}), "")
        self.assertEqual(
            self.trusted("2.0.4.post0", hashed, pages={page_url: page}, downloads={file_url: _SDIST}), _HOST
        )

    def _redirect_result(self, answers: dict[str, tuple[int, str, bytes]], version: str) -> str:
        requested: list[str] = []

        def get(url: str, _limit: int, _accept: str, _budget: object = None) -> tuple[int, str, bytes]:
            requested.append(url)
            return answers.get(url, (404, "", b""))

        with (
            patch.object(upstream, "_get", get),
            patch.object(upstream, "_sha256_download", lambda _url, _hosts, **_kwargs: _sha(_SDIST)),
        ):
            found = upstream.trusted_python_index("ChiaPos", version, (f"sha256:{_sha(_SDIST)}",))
        self.requested = requested
        return found

    def test_the_index_page_follows_a_same_host_redirect(self) -> None:
        page_url = f"{_CHIA}chiapos/"
        moved = f"{_CHIA}files/chiapos/"
        answers = {page_url: (302, moved, b""), moved: (200, "", _PAGE)}
        self.assertEqual(self._redirect_result(answers, "2.0.4"), _HOST)
        self.assertEqual(self.requested, [page_url, moved])

    def test_the_index_page_does_not_follow_a_redirect_to_another_host(self) -> None:
        page_url = f"{_CHIA}chiapos/"
        moved = "https://example.com/chiapos/"
        self.assertEqual(self._redirect_result({page_url: (302, moved, b"")}, "2.0.4"), "")
        self.assertEqual(self.requested[:1], [page_url])
        self.assertNotIn(moved, self.requested)

    def test_release_reads_wheel_and_sdist_names(self) -> None:
        self.assertEqual(upstream._release("Chia_Pos-2.0.4-cp312-cp312-linux_x86_64.whl"), ("chia-pos", "2.0.4"))
        self.assertEqual(upstream._release("chia.pos-2.0.4.tar.gz"), ("chia-pos", "2.0.4"))
        self.assertEqual(upstream._release("chiapos-2.0.4.whl"), ("", ""))
        self.assertEqual(upstream._release("chiapos-2.0.4.exe"), ("", ""))


class _Reply:
    def __init__(
        self,
        chunks: list[bytes],
        status: int = 200,
        location: str = "",
        clock: list[float] | None = None,
        step: float = 0.0,
    ) -> None:
        self.status = status
        self.chunks = chunks
        self.location = location
        self._clock = clock
        self._step = step

    def getheader(self, name: str) -> str | None:
        return self.location if name == "Location" else None

    def _advance(self, count: int) -> None:
        if self._clock is not None:
            self._clock[0] += self._step * count

    def read(self, size: int) -> bytes:
        if not self.chunks:
            return b""
        body = b"".join(self.chunks)
        self.chunks = [body[size:]] if body[size:] else []
        self._advance(len(body[:size]))
        return body[:size]

    def read1(self, _size: int) -> bytes:
        if not self.chunks:
            return b""
        self._advance(1)
        return self.chunks.pop(0)


class _Socket:
    def __init__(self) -> None:
        self.timeouts: list[float] = []

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)


class _Connection:
    def __init__(self) -> None:
        self.sock = _Socket()

    def close(self) -> None:
        return None


class InvalidPortTest(unittest.TestCase):
    def test_a_url_with_an_invalid_port_is_unavailable(self) -> None:
        for port in ("99999", "abc"):
            with self.subTest(port=port):
                self.assertIsNone(upstream._get(f"https://example.com:{port}/x", 100))

    def test_a_url_with_a_malformed_host_is_unavailable(self) -> None:
        self.assertIsNone(upstream._get("https://[::1/x", 100))


class Sha256DownloadTest(unittest.TestCase):
    def download(
        self,
        chunks: list[bytes],
        limit: int = 8,
        budget: upstream._DownloadBudget | None = None,
    ) -> str | None:
        reply = _Reply(chunks)
        with patch.object(upstream, "_get_response", lambda _url, _accept, _budget=None: (_Connection(), reply)):
            return upstream._sha256_download(f"https://{_HOST}/x", frozenset({_HOST}), limit, budget)

    def test_a_body_over_the_limit_has_no_digest(self) -> None:
        self.assertIsNone(self.download([b"1234", b"5678", b"9"]))
        self.assertEqual(self.download([b"1234", b"5678"]), _sha(b"12345678"))

    def test_the_byte_budget_is_shared_across_downloads(self) -> None:
        budget = upstream._DownloadBudget(size=8, clock=lambda: 0.0)
        self.assertEqual(self.download([b"1234"], budget=budget), _sha(b"1234"))
        self.assertIsNone(self.download([b"56789"], budget=budget))

    def test_an_expired_deadline_has_no_digest(self) -> None:
        now = [0.0]
        budget = upstream._DownloadBudget(clock=lambda: now[0])
        now[0] = upstream._INDEX_DOWNLOAD_SECONDS + 1
        self.assertIsNone(self.download([b"abc"], budget=budget))

    def test_a_drip_body_stops_at_the_deadline(self) -> None:
        now = [0.0]
        budget = upstream._DownloadBudget(seconds=3, clock=lambda: now[0])
        reply = _Reply([b"x"] * 10, clock=now, step=1.0)
        with patch.object(upstream, "_get_response", lambda _url, _accept, _budget=None: (_Connection(), reply)):
            self.assertIsNone(upstream._sha256_download(f"https://{_HOST}/x", frozenset({_HOST}), 100, budget))
        self.assertLessEqual(now[0], 3.0)

    def test_each_read_uses_the_remaining_budget_as_its_timeout(self) -> None:
        now = [0.0]
        budget = upstream._DownloadBudget(seconds=30, clock=lambda: now[0])
        now[0] = 25.0
        connection = _Connection()
        reply = _Reply([b"x"])
        with patch.object(upstream, "_get_response", lambda _url, _accept, _budget=None: (connection, reply)):
            self.assertEqual(
                upstream._sha256_download(f"https://{_HOST}/x", frozenset({_HOST}), 100, budget),
                _sha(b"x"),
            )
        self.assertEqual(connection.sock.timeouts, [5.0, 5.0])

    def test_a_download_from_another_host_is_not_read(self) -> None:
        self.assertIsNone(upstream._sha256_download("https://example.com/x", frozenset({_HOST})))

    def test_a_redirect_with_an_invalid_port_has_no_digest(self) -> None:
        start = f"https://{_HOST}/x"
        real_get_response = upstream._get_response
        for location in (f"https://{_HOST}:99999/y", f"https://{_HOST}:abc/y", "https://[::1/x"):

            def get_response(
                url: str,
                accept: str,
                budget: upstream._DownloadBudget | None = None,
                location: str = location,
            ) -> tuple[_Connection, _Reply] | None:
                if url == start:
                    return _Connection(), _Reply([], status=302, location=location)
                return real_get_response(url, accept, budget)

            with self.subTest(location=location), patch.object(upstream, "_get_response", get_response):
                self.assertIsNone(upstream._sha256_download(start, frozenset({_HOST})))

    def test_a_download_redirect_may_reach_an_allowed_file_host_only(self) -> None:
        target = "https://download.chia.net/x"
        hosts = frozenset({_HOST, "download.chia.net"})

        def get_response(url: str, _accept: str, _budget: object = None) -> tuple[_Connection, _Reply]:
            if url == f"https://{_HOST}/x":
                return _Connection(), _Reply([], status=302, location=target)
            return _Connection(), _Reply([b"abc"])

        with patch.object(upstream, "_get_response", get_response):
            self.assertEqual(upstream._sha256_download(f"https://{_HOST}/x", hosts), _sha(b"abc"))
            self.assertIsNone(upstream._sha256_download(f"https://{_HOST}/x", frozenset({_HOST})))


class FetchBudgetTest(unittest.TestCase):
    def test_the_default_budget_is_the_non_index_fetch_limit(self) -> None:
        with patch.object(upstream, "_FETCH_SECONDS", 7.0), patch.object(upstream, "_FETCH_BYTES", 11):
            budget = upstream._DownloadBudget(clock=lambda: 0.0)
        self.assertEqual((budget.remaining_seconds(), budget.remaining), (7.0, 11))

    def test_an_index_check_uses_the_index_budget(self) -> None:
        seen: list[int] = []

        def index_files(_index: str, _name: str, _version: str, budget: upstream._DownloadBudget) -> tuple[str, ...]:
            seen.append(budget.remaining)
            return ()

        with (
            patch.object(upstream, "_FETCH_SECONDS", 1.0),
            patch.object(upstream, "_FETCH_BYTES", 1),
            patch.object(upstream, "_INDEX_DOWNLOAD_SECONDS", 120.0),
            patch.object(upstream, "_MAX_INDEX_DOWNLOAD_BYTES", 11),
            patch.object(upstream, "_index_files", index_files),
        ):
            upstream.trusted_python_index("chiapos", "2.0.4", (f"sha256:{_sha(_SDIST)}",))
        self.assertEqual(set(seen), {11})

    def test_a_redirect_body_and_the_next_hop_share_one_deadline(self) -> None:
        now = [0.0]
        budget = upstream._DownloadBudget(seconds=2, clock=lambda: now[0])
        url = f"https://{_HOST}/a"
        moved = f"https://{_HOST}/b"
        requested: list[str] = []

        def get_response(target: str, _accept: str, _budget: object = None) -> tuple[_Connection, _Reply]:
            requested.append(target)
            if target == url:
                return _Connection(), _Reply([b"x"], status=302, location=moved, clock=now, step=1.0)
            return _Connection(), _Reply([b"a", b"b"], clock=now, step=1.0)

        with patch.object(upstream, "_get_response", get_response):
            self.assertIsNone(upstream._fetch(url, follow={_HOST: ""}, budget=budget))
        self.assertEqual(requested, [url, moved])
        self.assertLessEqual(now[0], 2.0)


class _Timer:
    instances: ClassVar[list[_Timer]] = []

    def __init__(self, interval: float, function: Callable[[], None]) -> None:
        self.interval = interval
        self.function = function
        self.started = False
        self.cancelled = False
        _Timer.instances.append(self)

    def start(self) -> None:
        self.started = True

    def cancel(self) -> None:
        self.cancelled = True


def _serve(respond: Callable[[socket.socket], None]) -> int:
    """Start a loopback server that answers one request with `respond` and return its port."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def accept() -> None:
        try:
            connection, _ = server.accept()
        except OSError:
            return
        finally:
            server.close()
        try:
            connection.recv(4096)
            respond(connection)
        except OSError:
            pass
        finally:
            connection.close()

    threading.Thread(target=accept, daemon=True).start()
    return port


def _get_from(port: int, budget: upstream._DownloadBudget) -> tuple[int, str, bytes] | None:
    def connect(parts: urllib.parse.SplitResult, timeout: float) -> http.client.HTTPConnection:
        return http.client.HTTPConnection(parts.hostname, parts.port, timeout=timeout)

    with patch.object(upstream, "_connect", connect):
        return upstream._get(f"https://127.0.0.1:{port}/x", 100, budget=budget)


def _drip_headers(connection: socket.socket) -> None:
    connection.sendall(b"HTTP/1.1 200 OK\r\n")
    for _ in range(60):
        connection.sendall(b"X")
        time.sleep(0.05)
    connection.sendall(b": x\r\n\r\n")


def _drip_chunk_size(connection: socket.socket) -> None:
    connection.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
    for _ in range(60):
        connection.sendall(b"f")
        time.sleep(0.05)
    connection.sendall(b"\r\n")


def _complete_response(connection: socket.socket) -> None:
    connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc")


class ConnectionDeadlineTest(unittest.TestCase):
    def test_headers_that_drip_stop_at_the_deadline(self) -> None:
        port = _serve(_drip_headers)
        started = time.monotonic()
        self.assertIsNone(_get_from(port, upstream._DownloadBudget(seconds=0.5)))
        self.assertLess(time.monotonic() - started, 2.0)

    def test_chunk_size_lines_that_drip_stop_at_the_deadline(self) -> None:
        port = _serve(_drip_chunk_size)
        started = time.monotonic()
        self.assertIsNone(_get_from(port, upstream._DownloadBudget(seconds=0.5)))
        self.assertLess(time.monotonic() - started, 2.0)

    def test_a_normal_response_is_read_and_its_timer_cancelled(self) -> None:
        _Timer.instances.clear()
        port = _serve(_complete_response)
        with patch.object(upstream.threading, "Timer", _Timer):
            self.assertEqual(_get_from(port, upstream._DownloadBudget(seconds=5)), (200, "", b"abc"))
        self.assertEqual(len(_Timer.instances), 1)
        self.assertTrue(_Timer.instances[0].started)
        self.assertTrue(_Timer.instances[0].cancelled)
