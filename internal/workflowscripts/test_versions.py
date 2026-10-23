"""Release-tag spellings, version jumps, the npm registry grammar and the command line."""

from __future__ import annotations

import re
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import dependency_cursor_review_versions as versions
from dependency_manifest_npm import _FOLD_SPEC_RE, _TARBALL_RE
from upstream_malware_scan_case import _commit_file, _git, _init_repo

_SCRIPT = Path(__file__).resolve().parent / "dependency_cursor_review_versions.py"


def _cli(*args: str, script: Path = _SCRIPT) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, "-I", str(script), *args], capture_output=True, text=True, check=False)


class _TagRepo(unittest.TestCase):
    def setUp(self) -> None:
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.repo = Path(tmp.name) / "upstream"
        _init_repo(self.repo)
        self.commits: list[str] = []
        for content in ("1", "2"):
            _commit_file(self.repo, "index.js", content, content)
            self.commits.append(_git(self.repo, "rev-parse", "HEAD"))

    def _tag(self, name: str, commit: int = 0) -> None:
        _git(self.repo, "tag", name, self.commits[commit])


class ReleaseTagTest(_TagRepo):
    def test_accepted_spellings(self) -> None:
        cases = (
            # (tags, requested version, expected tag name)
            (("1.0.0",), "1.0.0", "1.0.0"),
            (("v1.0.0",), "1.0.0", "v1.0.0"),
            (("v1.0.0",), "v1.0.0", "v1.0.0"),
            (("1.0.0", "v1.0.0"), "v1.0.0", "1.0.0"),
            (("1.0.0", "v1.0.0", "V1.0.0"), "1.0.0", "1.0.0"),
            (("V1.0.0",), "V1.0.0", "V1.0.0"),
            (("1.0.0", "V1.0.0"), "V1.0.0", "V1.0.0"),
        )
        for tags, version, name in cases:
            with self.subTest(tags=tags, version=version):
                for tag in tags:
                    self._tag(tag)
                self.assertEqual(
                    versions.release_tag(str(self.repo), version),
                    versions.ReleaseTag(versions.TagStatus.FOUND, self.commits[0], name),
                )
                _git(self.repo, "tag", "-d", *tags)

    def test_annotated_tag_peels_to_its_commit(self) -> None:
        _git(self.repo, "tag", "-a", "-m", "release", "1.0.0", self.commits[1])
        found = versions.release_tag(str(self.repo), "1.0.0")
        self.assertEqual((found.status, found.commit), (versions.TagStatus.FOUND, self.commits[1]))

    def test_spellings_must_agree(self) -> None:
        cases = (
            # Two spellings on different commits disagree whichever is requested.
            ((("1.0.0", 0), ("v1.0.0", 1)), "1.0.0"),
            ((("1.0.0", 0), ("V1.0.0", 1)), "v1.0.0"),
            ((("v1.0.0", 0), ("V1.0.0", 1)), "1.0.0"),
            # A prefixed version is never satisfied by only the other case.
            ((("V1.0.0", 0),), "v1.0.0"),
            ((("v1.0.0", 0),), "V1.0.0"),
            ((("1.0.0", 0),), "V1.0.0"),
        )
        for tags, version in cases:
            with self.subTest(tags=tags, version=version):
                for tag, commit in tags:
                    self._tag(tag, commit)
                self.assertEqual(
                    versions.release_tag(str(self.repo), version), versions.ReleaseTag(versions.TagStatus.DISAGREE)
                )
                _git(self.repo, "tag", "-d", *(tag for tag, _ in tags))

    def test_absent(self) -> None:
        absent = versions.ReleaseTag(versions.TagStatus.ABSENT)
        self._tag("V1.0.0")
        _git(self.repo, "branch", "2.0.0")
        # A bare request does not take only V<bare>, and a branch or raw revision is not a tag.
        for version in ("1.0.0", "9.9.9", "2.0.0", self.commits[0], "HEAD", "main"):
            with self.subTest(version=version):
                self.assertEqual(versions.release_tag(str(self.repo), version), absent)

    def test_invalid_ref_names_are_absent(self) -> None:
        self._tag("1.0.0")
        absent = versions.ReleaseTag(versions.TagStatus.ABSENT)
        for version in ("", "v", "V", "1.0..0", "1.0.0^{tree}", "1.0.0~1", "1.0.0:x", "1 0", "1.0.0.lock", "-1.0.0"):
            with self.subTest(version=version):
                self.assertEqual(versions.release_tag(str(self.repo), version), absent)


class VersionJumpTest(unittest.TestCase):
    def test_jumps(self) -> None:
        for frm, to in (
            ("1.2.3", "2.0.0"),
            ("v1.2.3", "V2.0.0"),
            ("1.2.3.4", "2.0.0"),
            ("1.2.3", "2.0.0.1"),
            ("1.0.0", "1.6.0"),
            ("1.2.3.4", "1.8.0.0"),
            ("2024.2.1", "2025.1.0"),
            ("2024.2.1", "2024.8.0"),
            ("1.0.0rc1", "1.6.0"),
            ("1.0.0-beta.1", "2.0.0+build.5"),
            ("1.0", "1.6"),
        ):
            with self.subTest(frm=frm, to=to):
                self.assertTrue(versions.version_jump(frm, to))

    def test_ordinary_bumps(self) -> None:
        for frm, to in (
            ("1.2.3", "1.2.4"),
            ("1.0.0", "1.5.0"),
            ("1.2.3.4", "1.2.3.5"),
            ("1.2.3.4", "1.7.0.0"),
            ("2024.2.1", "2024.7.0"),
            ("2.0.0", "1.0.0"),
            ("1.9.0", "1.0.0"),
            ("1.0.0.post1", "1.1.0.dev2"),
        ):
            with self.subTest(frm=frm, to=to):
                self.assertFalse(versions.version_jump(frm, to))

    def test_versions_the_scan_does_not_read_are_never_a_jump(self) -> None:
        # The coverage gate scans only exact Dependabot versions, and an empty from version has no from tag.
        for frm, to in (
            ("", "2.0.0"),
            ("1", "2.0.0"),
            ("v1", "v2"),
            ("1.x", "2.0.0"),
            ("^1.0.0", "2.0.0"),
            ("1.0.0", ""),
        ):
            with self.subTest(frm=frm, to=to):
                self.assertFalse(versions.version_jump(frm, to))


class NpmSemverTest(unittest.TestCase):
    def test_only_ascii_digits(self) -> None:
        for digits in ("١.٢.٣", "１.２.３", "1.2.٣", "१.0.0"):
            with self.subTest(version=digits):
                self.assertIsNone(re.fullmatch(versions.NPM_SEMVER, digits))
                self.assertIsNone(_FOLD_SPEC_RE.fullmatch(f"^{digits}"))
                self.assertIsNone(_TARBALL_RE.fullmatch(f"https://registry.npmjs.org/a/-/a-{digits}.tgz"))
                for mode in ("pin", "spec", "dependabot"):
                    self.assertEqual(versions._exact_body(digits, mode=mode), "", mode)

    def test_registry_versions(self) -> None:
        for version in ("1.2.3", "0.0.0-rc.1", "1.2.3+build.5", "10.20.30-alpha-1"):
            with self.subTest(version=version):
                self.assertIsNotNone(re.fullmatch(versions.NPM_SEMVER, version))
        for version in ("1.2", "1.2.3.4", "v1.2.3", "1.2.3-"):
            with self.subTest(version=version):
                self.assertIsNone(re.fullmatch(versions.NPM_SEMVER, version))


class CommandLineTest(_TagRepo):
    def test_release_tag_exit_codes(self) -> None:
        self._tag("1.0.0", 0)
        self._tag("v1.0.0", 0)
        self._tag("2.0.0", 0)
        self._tag("v2.0.0", 1)
        found = _cli("release-tag", str(self.repo), "1.0.0")
        self.assertEqual((found.returncode, found.stdout), (0, f"{self.commits[0]}\t1.0.0\n"), found.stderr)
        absent = _cli("release-tag", str(self.repo), "9.9.9")
        self.assertEqual((absent.returncode, absent.stdout), (3, ""), absent.stderr)
        disagree = _cli("release-tag", str(self.repo), "2.0.0")
        self.assertEqual((disagree.returncode, disagree.stdout), (4, ""), disagree.stderr)

    def test_jump_exit_codes(self) -> None:
        self.assertEqual(_cli("jump", "1.0.0", "2.0.0").returncode, 0)
        self.assertEqual(_cli("jump", "1.0.0", "1.1.0").returncode, 3)
        self.assertEqual(_cli("jump", "", "2.0.0").returncode, 3)

    def test_usage(self) -> None:
        for args in (
            (),
            ("jump", "1.0.0"),
            ("release-tag", str(self.repo)),
            ("peel", "a", "b"),
            ("jump", "1", "2", "3"),
        ):
            with self.subTest(args=args):
                proc = _cli(*args)
                self.assertEqual((proc.returncode, proc.stdout), (64, ""))
                self.assertIn("usage:", proc.stderr)

    def test_python_failures_are_not_answers(self) -> None:
        # Python exits 2 for a missing script and 1 for a traceback; neither is an answer code.
        missing = _cli("jump", "1.0.0", "2.0.0", script=self.repo / "missing.py")
        self.assertEqual(missing.returncode, 2)
        answers = {0, versions.NO_JUMP, *(status.value for status in versions.TagStatus)}
        self.assertNotIn(missing.returncode, answers)
        self.assertNotIn(1, answers)


if __name__ == "__main__":
    unittest.main()
