"""Tests for dcr_verdict: verdict line, decision table and comment."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import dcr_verdict
from dcr_verdict import comment_body, decide, parse_verdict


def _update(status: str = "reviewed", note: str = "") -> dict[str, object]:
    return {
        "name": "left-pad",
        "prev_version": "1.0.0",
        "new_version": "1.0.1",
        "status": status,
        "note": note,
    }


def _decide(
    *,
    updates: list[dict[str, object]] | None = None,
    verdict: str | None = "benign",
    warn_only: bool = False,
    meta_ok: bool = True,
) -> tuple[str, str]:
    return decide(meta_ok, tuple(updates if updates is not None else [_update()]), verdict, warn_only)


class VerdictLineTest(unittest.TestCase):
    def test_accepts_an_exact_first_line(self) -> None:
        cases = {
            "MALWARE_REVIEW_VERDICT: benign": "benign",
            "MALWARE_REVIEW_VERDICT: suspicious\nEVIDENCE: x": "suspicious",
            "MALWARE_REVIEW_VERDICT: malicious\n\nEVIDENCE: y": "malicious",
        }
        for text, expected in cases.items():
            self.assertEqual(parse_verdict(text), expected)

    def test_rejects_an_indented_or_wrong_word_line(self) -> None:
        cases = [
            " MALWARE_REVIEW_VERDICT: benign",
            "MALWARE_REVIEW_VERDICT: maybe",
            "",
            "\nMALWARE_REVIEW_VERDICT: benign",
            "MALWARE_REVIEW_VERDICT: benign ",
        ]
        for text in cases:
            self.assertIsNone(parse_verdict(text), repr(text))


class DecisionTableTest(unittest.TestCase):
    def test_missing_or_bad_meta_fails_even_when_updates_pass(self) -> None:
        self.assertEqual(_decide(updates=[_update("not_reviewed")], verdict=None, meta_ok=False)[0], "failure")

    def test_unreviewed_update_fails(self) -> None:
        for status in ("unverified", "fetch_failed", "truncated", "unexpected"):
            self.assertEqual(_decide(updates=[_update(status)])[0], "failure", status)

    def test_no_updates_fails(self) -> None:
        self.assertEqual(_decide(updates=[])[0], "failure")

    def test_all_not_reviewed_passes(self) -> None:
        decision = _decide(updates=[_update("not_reviewed")], verdict=None)
        self.assertEqual(decision[0], "success")
        self.assertIn("outside the reviewed", decision[1])

    def test_missing_verdict_fails(self) -> None:
        self.assertEqual(_decide(verdict=None)[0], "failure")

    def test_malicious_fails(self) -> None:
        self.assertEqual(_decide(verdict="malicious")[0], "failure")

    def test_suspicious_fails_unless_warn_only(self) -> None:
        self.assertEqual(_decide(verdict="suspicious")[0], "failure")
        self.assertEqual(_decide(verdict="suspicious", warn_only=True)[0], "success")

    def test_benign_passes(self) -> None:
        self.assertEqual(_decide(verdict="benign")[0], "success")


class CommentTest(unittest.TestCase):
    def test_contains_the_fixed_marker_and_plain_update_lines(self) -> None:
        updates = (_update(note="new network call"),)
        body = comment_body(updates, _decide(updates=list(updates)), "")
        self.assertTrue(body.startswith("<!-- dcr-artifact-review -->"))
        self.assertIn("- `left-pad` 1.0.0 -> 1.0.1: reviewed - new network call", body)
        self.assertIn(dcr_verdict.TRANSITIVE_NOTE, body)

    def test_agent_output_is_collapsed(self) -> None:
        updates = (_update(),)
        body = comment_body(updates, _decide(updates=list(updates)), "EVIDENCE: ok")
        self.assertIn("<details>", body)
        self.assertIn("EVIDENCE: ok", body)

    def test_comment_is_capped(self) -> None:
        updates = (_update(),)
        body = comment_body(updates, _decide(updates=list(updates)), "x" * 100000)
        self.assertLessEqual(len(body), dcr_verdict.MAX_COMMENT_CHARS)


if __name__ == "__main__":
    unittest.main()
