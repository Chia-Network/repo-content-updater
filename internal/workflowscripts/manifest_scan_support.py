"""Shared helpers for the manifest diff coverage tests."""

from __future__ import annotations

import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import dependency_update_coverage as coverage
from test_dependency_update_coverage import _clean, _commit, _git

_PASS_REVIEW = "MALWARE_REVIEW_VERDICT: benign\n\nLockfile change is the listed bump.\n"
_BLOCK_REVIEW = "MALWARE_REVIEW_VERDICT: malicious\n\nDo not merge.\n"


def _run_listed_scan(base: dict[str, str], head: dict[str, str], updates: list[dict]) -> dict:
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        _git(root, "init", "-b", "main")
        _git(root, "config", "user.email", "coverage-test@example.com")
        _git(root, "config", "user.name", "coverage-test")
        for name, content in base.items():
            _commit(root, name, content, f"base {name}")
        _git(root, "checkout", "-b", "pr")
        for name, content in head.items():
            _commit(root, name, content, f"head {name}")
        (root / "dependency_updates.json").write_text(json.dumps(updates), encoding="utf-8")
        previous = os.getcwd()
        saved = {key: os.environ.get(key) for key in ("PR_BASE_SHA", "GITHUB_BASE_REF", "GITHUB_OUTPUT", "DCR_OUT")}
        os.chdir(root)
        os.environ["PR_BASE_SHA"] = _git(root, "rev-parse", "main")
        os.environ.pop("GITHUB_BASE_REF", None)
        os.environ["GITHUB_OUTPUT"] = str(root / "github_output.txt")
        os.environ["DCR_OUT"] = str(root)

        def fake_scan(update: dict, *_args: object, **_kwargs: object) -> dict:
            return _clean(str(update.get("packageName") or ""), str(update.get("upstreamRepo") or ""))

        try:
            with patch.object(coverage, "_scan_one", fake_scan):
                coverage.main()
        finally:
            os.chdir(previous)
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        return json.loads((root / "malware_scan_report.json").read_text(encoding="utf-8"))


def _bump(name: str, frm: str, to: str, repo: str) -> dict[str, str]:
    return {"packageName": name, "fromVersion": frm, "toVersion": to, "upstreamRepo": repo}


def _unresolved(report: dict) -> set[str]:
    return {item["package_name"] for item in report["dependencies"] if item.get("not_scanned_reason") == "unresolved"}
