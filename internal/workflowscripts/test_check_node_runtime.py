"""check_node_runtime.sh rejects unsupported Node runtimes and fails closed."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parent / "check_node_runtime.sh"

_FAKE_GH = """#!/usr/bin/env python3
import json
import os
import sys

fixtures = json.loads(os.environ.get("FAKE_GH_FIXTURES", "{}"))
for arg in sys.argv[1:]:
    if arg.startswith("repos/"):
        body = fixtures.get(arg.split("?", 1)[0])
        if body is not None:
            sys.stdout.write(body)
            sys.exit(0)
sys.exit(1)
"""


def _manifest(using: str) -> str:
    return f"name: fixture\nruns:\n  using: {using}\n  main: index.js\n"


def _workflow(*uses: str) -> str:
    if uses:
        steps = "\n".join(f"      - uses: {use}" for use in uses)
    else:
        steps = "      - run: echo ok"
    return f"name: fixture\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n{steps}\n"


@unittest.skipUnless(shutil.which("yq"), "yq not on PATH")
class CheckNodeRuntimeTest(unittest.TestCase):
    def _run(
        self,
        files: dict[str, str] | None = None,
        fixtures: dict[str, str] | None = None,
        find_fails: bool = False,
        repository: str = "acme/project",
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel, text in (files or {}).items():
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
            bindir = root / "bin"
            bindir.mkdir()
            fake_gh = bindir / "gh"
            fake_gh.write_text(_FAKE_GH, encoding="utf-8")
            fake_gh.chmod(0o755)
            if find_fails:
                fake_find = bindir / "find"
                fake_find.write_text("#!/usr/bin/env bash\nexit 1\n", encoding="utf-8")
                fake_find.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = f"{bindir}{os.pathsep}{env.get('PATH', '')}"
            env["GITHUB_REPOSITORY"] = repository
            env["FAKE_GH_FIXTURES"] = json.dumps(fixtures or {})
            return subprocess.run(
                ["bash", str(_SCRIPT)],
                cwd=root,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

    def test_node20_remote_action_fails(self) -> None:
        proc = self._run(
            files={".github/workflows/x.yml": _workflow("acme/action@v1")},
            fixtures={"repos/acme/action/contents/action.yml": _manifest("node20")},
        )
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertIn(
            "::error file=.github/workflows/x.yml::Action acme/action@v1 uses unsupported Node runtime node20",
            proc.stdout,
        )

    def test_node24_remote_action_passes(self) -> None:
        proc = self._run(
            files={".github/workflows/x.yml": _workflow("acme/action@v1")},
            fixtures={"repos/acme/action/contents/action.yml": _manifest("node24")},
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("::error", proc.stdout)
        self.assertNotIn("::warning", proc.stdout)

    def test_unparseable_remote_manifest_fails(self) -> None:
        proc = self._run(
            files={".github/workflows/x.yml": _workflow("acme/action@v1")},
            fixtures={"repos/acme/action/contents/action.yml": "runs: [unclosed\n"},
        )
        self.assertNotEqual(proc.returncode, 0, proc.stdout)

    def test_node16_local_action_fails(self) -> None:
        proc = self._run(
            files={".github/actions/foo/action.yml": _manifest("node16")},
        )
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertIn(
            "::error file=.github/actions/foo/action.yml::"
            "Action .github/actions/foo/action.yml uses unsupported Node runtime node16",
            proc.stdout,
        )

    def test_chia_network_actions_repository_is_skipped(self) -> None:
        files = {".github/workflows/x.yml": _workflow("acme/action@v1")}
        fixtures = {"repos/acme/action/contents/action.yml": _manifest("node20")}
        for repository in ("Chia-Network/actions", "chia-network/actions"):
            with self.subTest(repository=repository):
                proc = self._run(files=files, fixtures=fixtures, repository=repository)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertNotIn("::error", proc.stdout)
                self.assertIn("::notice::Node runtime check skipped", proc.stdout)
        for repository in ("Chia-Network/actions-fork", "octocat/actions"):
            with self.subTest(repository=repository):
                proc = self._run(files=files, fixtures=fixtures, repository=repository)
                self.assertEqual(proc.returncode, 1, proc.stderr)

    def test_reusable_local_and_docker_refs_are_ignored(self) -> None:
        proc = self._run(
            files={
                ".github/workflows/x.yml": _workflow(
                    "acme/repo/.github/workflows/reusable.yml@v1",
                    "./.github/actions/foo",
                    "docker://alpine:3",
                )
            },
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("::warning", proc.stdout)
        self.assertNotIn("::error", proc.stdout)

    def test_unresolvable_ref_warns_and_passes(self) -> None:
        proc = self._run(
            files={".github/workflows/x.yml": _workflow("acme/missing@v1")},
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(
            "::warning::Unable to resolve acme/missing@v1 used in .github/workflows/x.yml",
            proc.stdout,
        )

    def test_invalid_yaml_workflow_fails(self) -> None:
        proc = self._run(
            files={".github/workflows/bad.yml": "name: bad\njobs: [\n"},
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertTrue(proc.stderr)

    def test_missing_actions_directory_passes(self) -> None:
        proc = self._run(files={".github/workflows/x.yml": _workflow()})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("::error", proc.stdout)
        self.assertNotIn("::warning", proc.stdout)

    def test_find_failure_fails_the_job(self) -> None:
        proc = self._run(
            files={".github/actions/foo/action.yml": _manifest("node24")},
            find_fails=True,
        )
        self.assertNotEqual(proc.returncode, 0)

    def test_workflow_path_with_space_reports_full_path(self) -> None:
        proc = self._run(
            files={".github/workflows/my flow.yml": _workflow("acme/action@v1")},
            fixtures={"repos/acme/action/contents/action.yml": _manifest("node20")},
        )
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertIn(
            "::error file=.github/workflows/my flow.yml::Action acme/action@v1 uses unsupported Node runtime node20",
            proc.stdout,
        )

    def test_non_step_uses_keys_are_ignored(self) -> None:
        workflow = (
            "name: fixture\n"
            "on: push\n"
            "jobs:\n"
            "  test:\n"
            "    runs-on: ubuntu-latest\n"
            "    env:\n"
            "      uses: acme/env@v1\n"
            "    steps:\n"
            "      - run: echo ok\n"
            "        env:\n"
            "          uses: acme/stepenv@v1\n"
            "        with:\n"
            "          uses: acme/with@v1\n"
        )
        proc = self._run(
            files={".github/workflows/x.yml": workflow},
            fixtures={
                "repos/acme/env/contents/action.yml": _manifest("node20"),
                "repos/acme/stepenv/contents/action.yml": _manifest("node20"),
                "repos/acme/with/contents/action.yml": _manifest("node20"),
            },
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("::warning", proc.stdout)
        self.assertNotIn("::error", proc.stdout)


if __name__ == "__main__":
    unittest.main()


class InstallYqStepTest(unittest.TestCase):
    """The workflow installs a pinned yq and refuses a download whose checksum differs."""

    _WORKFLOW = Path(__file__).resolve().parents[2] / "templates" / "check-node-runtime.yml"

    def _step(self) -> str:
        workflow = self._WORKFLOW.read_text(encoding="utf-8")
        self.assertLess(workflow.index("- name: Install yq\n"), workflow.index("- name: Check action Node runtime\n"))
        block = workflow.split("- name: Install yq\n", 1)[1].split("\n      - name: ", 1)[0]
        return textwrap.dedent(block.split("        run: |\n", 1)[1])

    def _run(self, arch: str, payload: str, fake_sum: bool = False) -> tuple[int, str, Path]:
        tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        bin_dir = tmp / "fake-bin"
        bin_dir.mkdir()
        (bin_dir / "curl").write_text(
            f'#!/bin/bash\nwhile [ "$1" != -o ]; do shift; done\nprintf %s {payload!r} >"$2"\n', encoding="utf-8"
        )
        if fake_sum:
            (bin_dir / "sha256sum").write_text("#!/bin/bash\ncat >/dev/null\n", encoding="utf-8")
        for tool in bin_dir.iterdir():
            tool.chmod(0o755)
        github_path = tmp / "github_path"
        github_path.write_text("", encoding="utf-8")
        env = {
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "RUNNER_ARCH": arch,
            "RUNNER_TEMP": str(tmp),
            "GITHUB_PATH": str(github_path),
        }
        proc = subprocess.run(["bash", "-c", self._step()], env=env, capture_output=True, text=True, check=False)
        return proc.returncode, github_path.read_text(encoding="utf-8"), tmp

    def test_a_download_with_another_checksum_is_refused(self) -> None:
        for arch in ("X64", "ARM64"):
            with self.subTest(arch=arch):
                status, github_path, _tmp = self._run(arch, "tampered")
                self.assertNotEqual(status, 0)
                self.assertEqual(github_path, "")

    def test_an_architecture_with_no_pinned_build_is_refused(self) -> None:
        status, github_path, _tmp = self._run("X86", "", fake_sum=True)
        self.assertNotEqual(status, 0)
        self.assertEqual(github_path, "")

    def test_a_verified_download_is_put_on_the_path(self) -> None:
        status, github_path, tmp = self._run("X64", "yq", fake_sum=True)
        self.assertEqual((status, github_path), (0, f"{tmp / 'yq-bin'}\n"))
        self.assertTrue(os.access(tmp / "yq-bin" / "yq", os.X_OK))
