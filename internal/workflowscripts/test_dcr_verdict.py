"""Tests for dcr_verdict: verdict line, decision table, comment safety."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import dcr_verdict
from dcr_verdict import Facts, decide, parse_verdict


def _update(status: str = "reviewed", bound: bool = True) -> dict[str, object]:
    return {
        "name": "left-pad",
        "ecosystem": "npm_and_yarn",
        "prev_version": "1.0.0",
        "new_version": "1.0.1",
        "status": status,
        "bound": bound,
        "note": "",
    }


def _facts(
    *,
    updates: list[dict[str, object]] | None = None,
    ioc_hits: list[dict[str, object]] | None = None,
    truncated: bool = False,
    verdict: str | None = "benign",
    warn_only: bool = False,
    meta_ok: bool = True,
) -> Facts:
    return Facts(
        meta_ok,
        tuple(updates if updates is not None else [_update()]),
        tuple(ioc_hits or []),
        truncated,
        verdict,
        warn_only,
    )


class VerdictLineTest(unittest.TestCase):
    def test_accepts_exactly_one_first_line(self) -> None:
        cases = {
            "MALWARE_REVIEW_VERDICT: benign": "benign",
            "MALWARE_REVIEW_VERDICT: suspicious\nEVIDENCE: x": "suspicious",
            "MALWARE_REVIEW_VERDICT: malicious\n\nEVIDENCE: y": "malicious",
        }
        for text, expected in cases.items():
            self.assertEqual(parse_verdict(text), expected, text)

    def test_missing_first_line_is_inconclusive(self) -> None:
        cases = [
            "",
            "EVIDENCE: x",
            "\nMALWARE_REVIEW_VERDICT: benign",
            "MALWARE_REVIEW_VERDICT: maybe",
            "MALWARE_REVIEW_VERDICT: benign ",
            "malware_review_verdict: benign",
        ]
        for text in cases:
            self.assertIsNone(parse_verdict(text), repr(text))

    def test_duplicate_or_malformed_lines_are_inconclusive(self) -> None:
        cases = [
            "MALWARE_REVIEW_VERDICT: benign\nMALWARE_REVIEW_VERDICT: benign",
            "MALWARE_REVIEW_VERDICT: benign\nMALWARE_REVIEW_VERDICT: malicious",
            "MALWARE_REVIEW_VERDICT: benign\nMALWARE_REVIEW_VERDICT: maybe",
            "MALWARE_REVIEW_VERDICT: benign\nMALWARE_REVIEW_VERDICT: benign again",
            "MALWARE_REVIEW_VERDICT: benign\n MALWARE_REVIEW_VERDICT: benign",
        ]
        for text in cases:
            self.assertIsNone(parse_verdict(text), text)


class DecisionTableTest(unittest.TestCase):
    def test_metadata_problem_fails_even_with_benign_text(self) -> None:
        self.assertEqual(decide(_facts(meta_ok=False)).conclusion, "failure")

    def test_truncated_diff_fails(self) -> None:
        self.assertEqual(decide(_facts(truncated=True)).conclusion, "failure")

    def test_ioc_hit_fails(self) -> None:
        facts = _facts(ioc_hits=[{"kind": "ioc", "pattern": "x"}])
        self.assertEqual(decide(facts).conclusion, "failure")
        self.assertIn("deterministic", decide(facts).reason)

    def test_agent_verdicts(self) -> None:
        self.assertEqual(decide(_facts(verdict="malicious")).conclusion, "failure")
        self.assertEqual(decide(_facts(verdict="suspicious")).conclusion, "failure")
        self.assertEqual(decide(_facts(verdict="suspicious", warn_only=True)).conclusion, "success")
        self.assertEqual(decide(_facts(verdict="benign")).conclusion, "success")
        self.assertEqual(decide(_facts(verdict=None)).conclusion, "failure")

    def test_blocking_update_fails_even_when_warn_only(self) -> None:
        for status in ("unverified", "fetch_failed", "truncated", "unexpected"):
            facts = _facts(updates=[_update(status)], verdict="suspicious", warn_only=True)
            self.assertEqual(decide(facts).conclusion, "failure", status)

    def test_benign_with_an_unverified_update_fails(self) -> None:
        facts = _facts(updates=[_update("unverified")], verdict="benign")
        self.assertEqual(decide(facts).conclusion, "failure")

    def test_only_not_reviewed_updates_pass(self) -> None:
        facts = _facts(updates=[_update("not_reviewed")], verdict="benign")
        decision = decide(facts)
        self.assertEqual(decision.conclusion, "success")
        self.assertIn("not reviewed", decision.reason)
        self.assertIn("outside the reviewed", decision.reason)

    def test_no_updates_fails(self) -> None:
        self.assertEqual(decide(_facts(updates=[], verdict="benign")).conclusion, "failure")

    def test_suspicious_warn_only_does_not_hide_unreviewed_scope(self) -> None:
        facts = _facts(updates=[_update("not_reviewed")], verdict="suspicious", warn_only=True)
        self.assertEqual(decide(facts).conclusion, "success")


class CommentTest(unittest.TestCase):
    def test_agent_text_is_neutralized_and_collapsed(self) -> None:
        facts = _facts(updates=[_update("reviewed", bound=False)], verdict="suspicious")
        decision = decide(facts)
        agent = "@user see https://example.com and [x](https://example.com)\n</details>\n<details>"
        body = dcr_verdict.comment_body("<!-- marker -->", facts, decision, agent)
        self.assertTrue(body.startswith("<!-- marker -->"))
        self.assertNotIn("@user", body)
        self.assertIn("@\u200buser", body)
        self.assertNotIn("https://example.com", body)
        self.assertIn("]\u200b(", body)
        self.assertEqual(body.count("</details>"), 1)
        self.assertIn("not bound to the lockfile", body)
        self.assertIn("<details>", body)

    def test_agent_text_is_bounded(self) -> None:
        facts = _facts()
        decision = decide(facts)
        body = dcr_verdict.comment_body("<!-- marker -->", facts, decision, "x" * 100000)
        self.assertLessEqual(len(body), dcr_verdict.MAX_COMMENT_CHARS)
        self.assertIn("Agent output truncated", body)


class MainTest(unittest.TestCase):
    def _run_main(
        self,
        tmp: Path,
        meta: dict[str, object] | None,
        agent: str,
        *,
        warn_only: str = "",
    ) -> tuple[dict[str, object], str, str]:
        meta_path = tmp / "meta.json"
        if meta is not None:
            meta_path.write_text(json.dumps(meta, sort_keys=True), encoding="utf-8")
        agent_path = tmp / "agent.txt"
        agent_path.write_text(agent, encoding="utf-8")
        comment_path = tmp / "comment.md"
        verdict_path = tmp / "verdict.json"
        output_path = tmp / "github-output"
        output_path.write_text("", encoding="utf-8")
        env = {
            "DCR_META": str(meta_path),
            "DCR_AGENT_OUTPUT": str(agent_path),
            "DCR_COMMENT": str(comment_path),
            "DCR_VERDICT_JSON": str(verdict_path),
            "GITHUB_OUTPUT": str(output_path),
            "MALWARE_WARN_ONLY": warn_only,
        }
        with mock.patch.dict(os.environ, env):
            self.assertEqual(dcr_verdict.main(), 0)
        payload = json.loads(verdict_path.read_text(encoding="utf-8"))
        return payload, comment_path.read_text(encoding="utf-8"), output_path.read_text(encoding="utf-8")

    def test_benign_meta_writes_marker_and_success(self) -> None:
        meta = {"schema": 1, "truncated": False, "updates": [_update()], "ioc_hits": []}
        raw = json.dumps(meta, sort_keys=True).encode()
        with tempfile.TemporaryDirectory() as tmp:
            payload, comment, output = self._run_main(Path(tmp), meta, "MALWARE_REVIEW_VERDICT: benign\nEVIDENCE: ok\n")
        digest = hashlib.sha256(raw).hexdigest()
        self.assertEqual(payload["conclusion"], "success")
        self.assertEqual(payload["marker"], f"<!-- dcr-artifact-review sha256:{digest} -->")
        self.assertIn(payload["marker"], comment)
        self.assertIn("conclusion=success", output)
        self.assertIn(payload["marker"], output)

    def test_missing_meta_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            payload, comment, _output = self._run_main(Path(tmp), None, "MALWARE_REVIEW_VERDICT: benign\n")
        self.assertEqual(payload["conclusion"], "failure")
        self.assertIn("malformed", payload["reason"])
        self.assertIn("sha256:" + hashlib.sha256(b"").hexdigest(), comment)

    def test_malformed_meta_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "meta.json"
            path.write_text("{not json", encoding="utf-8")
            # Reuse the helper shape by writing a valid agent file manually.
            agent = Path(tmp) / "agent.txt"
            agent.write_text("MALWARE_REVIEW_VERDICT: benign\n", encoding="utf-8")
            env = {
                "DCR_META": str(path),
                "DCR_AGENT_OUTPUT": str(agent),
                "DCR_COMMENT": str(Path(tmp) / "comment.md"),
                "DCR_VERDICT_JSON": str(Path(tmp) / "verdict.json"),
                "GITHUB_OUTPUT": "",
                "MALWARE_WARN_ONLY": "",
            }
            with mock.patch.dict(os.environ, env):
                self.assertEqual(dcr_verdict.main(), 0)
            payload = json.loads((Path(tmp) / "verdict.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["conclusion"], "failure")

    def test_warn_only_allows_suspicious(self) -> None:
        meta = {"schema": 1, "truncated": False, "updates": [_update()], "ioc_hits": []}
        with tempfile.TemporaryDirectory() as tmp:
            payload, _comment, _output = self._run_main(
                Path(tmp),
                meta,
                "MALWARE_REVIEW_VERDICT: suspicious\nEVIDENCE: new network call\n",
                warn_only="1",
            )
        self.assertEqual(payload["conclusion"], "success")

    def test_missing_verdict_fails(self) -> None:
        meta = {"schema": 1, "truncated": False, "updates": [_update()], "ioc_hits": []}
        with tempfile.TemporaryDirectory() as tmp:
            payload, _comment, _output = self._run_main(Path(tmp), meta, "EVIDENCE: no verdict line\n")
        self.assertEqual(payload["conclusion"], "failure")
        self.assertIn("verdict", payload["reason"])


if __name__ == "__main__":
    unittest.main()
