"""Lint synced dependency-cursor-review scripts as a consumer repository would.

Builds `.github/scripts` from the canonical modules (the bytes
`sync_malware_formatter_templates.py` emits) and runs chia-blockchain's ruff
config, shfmt 3.12 (`-i 2`), and ShellCheck. ShellCheck is run twice: once with
chia-blockchain's rcfile (`disable=SC2002` only, so sources are not followed)
and once with super-linter's external-sources defaults.

Python companions are linted at mode 0644. Callers run them with `python3 -I`,
and releases that predate FileModeForContent write every file 0644, so a
shebang is ruff EXE001. Shell shebangs stay 0755.

Skips the tool-backed lint when ruff, shfmt, or shellcheck are absent unless
REQUIRE_DCR_LINT=1. The shebang check does not need those tools.
"""

from __future__ import annotations

import ast
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from formatter_bundle_inventory import (
    consumer_sync_canonical_to_template,
    managed_file_index,
    parse_dcr_companion_files,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCRIPTS = Path(__file__).resolve().parent
_CONFIG = _REPO_ROOT / "config.yaml"
_RUFF_CONFIG = _SCRIPTS / "testdata" / "chia-blockchain-ruff.toml"
_TOOLS = ("ruff", "shfmt", "shellcheck")


def _require_tools() -> None:
    missing = [name for name in _TOOLS if shutil.which(name) is None]
    if not missing:
        return
    message = f"missing lint tools: {', '.join(missing)}"
    if os.environ.get("REQUIRE_DCR_LINT") == "1":
        raise AssertionError(message)
    raise unittest.SkipTest(message)


def _shellcheck_binaries() -> list[str]:
    binaries: list[str] = []
    primary = shutil.which("shellcheck")
    if primary:
        binaries.append(primary)
    extra = shutil.which("shellcheck-0.11")
    if extra and extra not in binaries:
        binaries.append(extra)
    return binaries


def _consumer_script_payloads() -> list[tuple[str, bytes]]:
    """Repo-relative `.github/scripts` paths and the canonical bytes synced there."""
    config_text = _CONFIG.read_text(encoding="utf-8")
    index = managed_file_index(config_text)
    canonical_by_template = {
        template: canonical
        for canonical, template in consumer_sync_canonical_to_template(config_text)
    }
    payloads: list[tuple[str, bytes]] = []
    for name in parse_dcr_companion_files(config_text):
        entry = index.get(name)
        if entry is None:
            continue
        template_name, repo_path = entry
        if not repo_path.startswith(".github/scripts/"):
            continue
        canonical = canonical_by_template.get(template_name)
        if canonical is None:
            continue
        payloads.append((repo_path, (_SCRIPTS / canonical).read_bytes()))
    return payloads


def _checkout_mode(repo_path: str, data: bytes) -> int:
    """Mode used when linting a consumer checkout of this companion.

    Python files stay 0644. A shebang on that mode is ruff EXE001, which is
    what chia-blockchain hits while managed-files still installs a release
    that writes every file 0644. Shell shebangs stay 0755, matching
    FileModeForContent.
    """
    if repo_path.endswith(".py"):
        return 0o644
    if data.startswith(b"#!"):
        return 0o755
    return 0o644


def _assemble(root: Path) -> list[Path]:
    written: list[Path] = []
    for repo_path, data in _consumer_script_payloads():
        dest = root / repo_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        dest.chmod(_checkout_mode(repo_path, data))
        written.append(dest)
    return written


class ConsumerLintTest(unittest.TestCase):
    def test_shebang_python_templates_stay_nonexecutable(self) -> None:
        """A shebang on a 0644 Python companion is ruff EXE001.

        Does not require ruff. Every Python file synced into `.github/scripts/`
        is checked, not only the two review entry points. Shell shebangs stay.
        """
        payloads = _consumer_script_payloads()
        python_payloads = [
            (repo_path, data) for repo_path, data in payloads if repo_path.endswith(".py")
        ]
        shell_payloads = [
            (repo_path, data) for repo_path, data in payloads if repo_path.endswith(".sh")
        ]
        self.assertGreater(len(python_payloads), 0)
        self.assertGreater(len(shell_payloads), 0)
        for repo_path, data in python_payloads:
            mode = _checkout_mode(repo_path, data)
            self.assertEqual(mode & 0o111, 0, repo_path)
            self.assertFalse(
                data.startswith(b"#!"),
                f"{repo_path} is a shebang Python template checked out "
                "non-executable; ruff EXE001 (shebang-not-executable) fails. "
                "Callers use python3; remove the shebang.",
            )
        for repo_path, data in shell_payloads:
            self.assertTrue(data.startswith(b"#!"), f"{repo_path} shell shebang regressed")
            self.assertEqual(_checkout_mode(repo_path, data) & 0o111, 0o111, repo_path)

    def test_vendored_ruff_flags_nonexecutable_python_shebang(self) -> None:
        """chia-blockchain's ruff config must report EXE001 for this case."""
        _require_tools()
        self.assertTrue(_RUFF_CONFIG.is_file(), "vendored chia-blockchain ruff.toml missing")
        with tempfile.TemporaryDirectory() as tmp:
            scripts = Path(tmp) / ".github" / "scripts"
            scripts.mkdir(parents=True)
            init = scripts / "__init__.py"
            init.write_text("from __future__ import annotations\n", encoding="utf-8")
            init.chmod(0o644)
            script = scripts / "shebang_not_executable.py"
            script.write_text(
                "#!/usr/bin/env python3\n"
                '"""Synthetic shebang script."""\n'
                "\n"
                "from __future__ import annotations\n",
                encoding="utf-8",
            )
            script.chmod(0o644)
            self.assertFalse(script.stat().st_mode & stat.S_IXUSR)
            checked = subprocess.run(
                [
                    "ruff",
                    "--config",
                    str(_RUFF_CONFIG),
                    "check",
                    "--output-format",
                    "json",
                    str(script),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            output = checked.stdout + checked.stderr
            self.assertNotEqual(checked.returncode, 0, output)
            codes = {item["code"] for item in json.loads(checked.stdout)}
            self.assertIn("EXE001", codes)

    def test_synced_scripts_pass_chia_ruff_shfmt_and_shellcheck(self) -> None:
        _require_tools()
        self.assertTrue(_RUFF_CONFIG.is_file(), "vendored chia-blockchain ruff.toml missing")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            written = _assemble(root)
            scripts = root / ".github" / "scripts"
            self.assertTrue((scripts / "__init__.py").is_file())
            py_files = [path for path in written if path.suffix == ".py"]
            sh_files = [path for path in written if path.suffix == ".sh"]
            self.assertGreater(len(py_files), 0)
            self.assertEqual(
                {path.name for path in sh_files},
                {
                    "upstream_malware_scan.sh",
                    "upstream_malware_scan_lib.sh",
                    "upstream_malware_scan_findings.sh",
                    "upstream_release_checkout.sh",
                },
            )
            for path in written:
                data = path.read_bytes()
                executable = bool(path.stat().st_mode & stat.S_IXUSR)
                if path.suffix == ".py":
                    self.assertFalse(
                        data.startswith(b"#!"),
                        f"{path.name} is a shebang Python template checked out "
                        "non-executable; ruff EXE001 (shebang-not-executable) fails",
                    )
                    self.assertFalse(
                        executable,
                        f"{path.name} must stay non-executable",
                    )
                elif data.startswith(b"#!"):
                    self.assertTrue(
                        executable,
                        f"{path.name} shebang must be executable",
                    )
                else:
                    self.assertFalse(
                        executable,
                        f"{path.name} must stay non-executable",
                    )
                self.assertTrue(data.endswith(b"\n"), f"{path.name} must end with a newline")
                self.assertNotIn(b"\r", data, path.name)
                for line in data.splitlines():
                    self.assertFalse(
                        line.endswith((b" ", b"\t")),
                        f"trailing whitespace in {path.name}",
                    )
                    self.assertNotIn(b"<<<<<<<", line)
                    self.assertNotIn(b">>>>>>>", line)
                if path.suffix == ".py":
                    ast.parse(data.decode("utf-8"))

            ruff = ["ruff", "--config", str(_RUFF_CONFIG)]
            formatted = subprocess.run(
                [*ruff, "format", "--check", str(scripts)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                formatted.returncode,
                0,
                formatted.stdout + formatted.stderr,
            )
            checked = subprocess.run(
                [*ruff, "check", str(scripts)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)

            shaped = subprocess.run(
                ["shfmt", "-i", "2", "--diff", *[str(path) for path in sh_files]],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(shaped.returncode, 0, shaped.stdout + shaped.stderr)

            plain_rc = root / ".shellcheckrc"
            plain_rc.write_text("disable=SC2002\n", encoding="utf-8")
            follow_rc = root / "shellcheck-follow.rc"
            follow_rc.write_text(
                "disable=SC2002\nexternal-sources=true\nsource-path=SCRIPTDIR\n",
                encoding="utf-8",
            )
            for binary in _shellcheck_binaries():
                for rcfile in (plain_rc, follow_rc):
                    for script in sh_files:
                        proc = subprocess.run(
                            [binary, "--rcfile", str(rcfile), str(script)],
                            check=False,
                            capture_output=True,
                            text=True,
                        )
                        self.assertEqual(
                            proc.returncode,
                            0,
                            f"{binary} {rcfile.name} {script.name}\n{proc.stdout}{proc.stderr}",
                        )


if __name__ == "__main__":
    unittest.main()
