"""check_node_runtime.sh rejects unsupported Node runtimes and fails closed."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
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
    return (
        "name: fixture\n"
        "on: push\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"{steps}\n"
    )


@unittest.skipUnless(shutil.which("yq"), "yq not on PATH")
class CheckNodeRuntimeTest(unittest.TestCase):
    def _run(
        self,
        files: dict[str, str] | None = None,
        fixtures: dict[str, str] | None = None,
        unreadable: tuple[str, ...] = (),
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
            for rel in unreadable:
                (root / rel).chmod(0o000)
            env = os.environ.copy()
            env["PATH"] = f"{bindir}{os.pathsep}{env.get('PATH', '')}"
            env["FAKE_GH_FIXTURES"] = json.dumps(fixtures or {})
            try:
                return subprocess.run(
                    ["bash", str(_SCRIPT)],
                    cwd=root,
                    env=env,
                    check=False,
                    capture_output=True,
                    text=True,
                )
            finally:
                for rel in unreadable:
                    path = root / rel
                    if path.exists():
                        path.chmod(0o700)

    def test_node20_remote_action_fails(self) -> None:
        proc = self._run(
            files={".github/workflows/x.yml": _workflow("acme/action@v1")},
            fixtures={"repos/acme/action/contents/action.yml": _manifest("node20")},
        )
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertIn(
            "::error file=.github/workflows/x.yml::"
            "Action acme/action@v1 uses unsupported Node runtime node20",
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

    @unittest.skipIf(os.geteuid() == 0, "root can read chmod 000 directories")
    def test_find_failure_fails_the_job(self) -> None:
        proc = self._run(
            files={
                ".github/actions/foo/action.yml": _manifest("node24"),
                ".github/actions/sub/keep.txt": "fixture\n",
            },
            unreadable=(".github/actions/sub",),
        )
        self.assertNotEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
