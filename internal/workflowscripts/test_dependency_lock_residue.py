"""Lockfile residue and locators around a listed Dependabot bump."""

from __future__ import annotations

import json
import unittest

import dependency_manifest_diff as manifest
import dependency_manifest_npm as npm_manifest
import malware_verdict_formatter as formatter
from manifest_scan_support import (
    _BLOCK_REVIEW,
    _PASS_REVIEW,
    _bump,
    _run_listed_scan,
    _unresolved,
)


class DependencyLockResidueTest(unittest.TestCase):
    def test_poetry_lock_is_a_gap_and_npm_residue_passes_when_the_verdict_is_pass(self) -> None:
        listed = [_bump("lodash", "4.17.20", "4.17.21", "lodash/lodash")]
        poetry = _run_listed_scan(
            {"poetry.lock": '[[package]]\nname = "lodash"\nversion = "4.17.20"\n'},
            {"poetry.lock": '[[package]]\nname = "lodash"\nversion = "4.17.21"\n'},
            listed,
        )
        self.assertIs(poetry["scan_conclusive"], False)
        self.assertIn("poetry.lock", " ".join(poetry.get("errors") or []))

        def lock(lodash: str, minimist: str) -> str:
            return (
                json.dumps(
                    {
                        "lockfileVersion": 3,
                        "packages": {
                            "node_modules/lodash": {"version": lodash, "resolved": f"https://registry.npmjs.org/lodash/-/lodash-{lodash}.tgz", "integrity": "sha-" + lodash},
                            "node_modules/minimist": {"version": minimist, "resolved": f"https://registry.npmjs.org/minimist/-/minimist-{minimist}.tgz", "integrity": "sha-" + minimist},
                        },
                    }
                )
                + "\n"
            )

        residue = _run_listed_scan(
            {"package-lock.json": lock("4.17.20", "1.2.0")},
            {"package-lock.json": lock("4.17.21", "1.2.8")},
            listed,
        )
        self.assertIs(residue["scan_conclusive"], True)
        self.assertEqual(residue["status"], "clean")
        self.assertNotIn("minimist", " ".join(residue.get("errors") or []))
        published = formatter.compose_published_review(residue, _PASS_REVIEW, "COMPATIBILITY_RECOMMENDATION: Merge\n")
        self.assertEqual(published["check"], "pass")
        self.assertIs(published["may_complete"], True)
        blocked_review = formatter.compose_published_review(
            residue, _BLOCK_REVIEW, "COMPATIBILITY_RECOMMENDATION: Don't merge\n"
        )
        self.assertEqual(blocked_review["verdict"], "malicious")
        self.assertEqual(blocked_review["check"], "fail")
        self.assertIs(blocked_review["may_complete"], False)
        failed = {
            "status": "not_scanned",
            "scan_conclusive": False,
            "not_scanned_reason": "scanner_tools_missing",
            "verdict_token_in_tree": False,
            "findings": {"unicode": [], "confusable": [], "ioc": [], "heuristic": []},
        }
        scan_failed = formatter.compose_published_review(failed, _PASS_REVIEW, "COMPATIBILITY_RECOMMENDATION: Merge\n")
        self.assertEqual(scan_failed["verdict"], "scan_failed")
        self.assertEqual(scan_failed["check"], "fail")

        blocked = json.loads(json.dumps(residue))
        blocked["warn_only"] = False
        blocked["findings"]["unicode"] = [{"kind": "unicode", "file": "pkg/index.js", "line": 1, "match": "bidi"}]
        blocked_finding = formatter.compose_published_review(
            blocked, _PASS_REVIEW, "COMPATIBILITY_RECOMMENDATION: Merge\n"
        )
        self.assertEqual(blocked_finding["check"], "fail")
        self.assertIs(blocked_finding["may_complete"], False)
        advisory = json.loads(json.dumps(blocked))
        advisory["warn_only"] = True
        advisory_finding = formatter.compose_published_review(
            advisory, _PASS_REVIEW, "COMPATIBILITY_RECOMMENDATION: Merge\n"
        )
        self.assertEqual(advisory_finding["check"], "pass")
        self.assertIs(advisory_finding["may_complete"], True)

    def test_unlisted_resolved_change_stays_unresolved(self) -> None:
        def lock(lodash: str, minimist: str, resolved: str, integrity: str) -> str:
            return (
                json.dumps(
                    {
                        "lockfileVersion": 3,
                        "packages": {
                            "node_modules/lodash": {"version": lodash},
                            "node_modules/minimist": {
                                "version": minimist,
                                "resolved": resolved,
                                "integrity": integrity,
                            },
                        },
                    }
                )
                + "\n"
            )

        listed = [_bump("lodash", "4.17.20", "4.17.21", "lodash/lodash")]
        report = _run_listed_scan(
            {
                "package-lock.json": lock(
                    "4.17.20",
                    "1.2.0",
                    "https://registry.npmjs.org/minimist/-/minimist-1.2.0.tgz",
                    "sha512-old",
                )
            },
            {
                "package-lock.json": lock(
                    "4.17.21",
                    "1.2.8",
                    "https://github.com/evil/minimist/tarball/deadbeef",
                    "sha512-new",
                )
            },
            listed,
        )
        self.assertFalse(report["scan_conclusive"])
        self.assertIn("minimist", _unresolved(report))
        self.assertNotEqual(report["status"], "clean")
        published = formatter.compose_published_review(report, _PASS_REVIEW, "COMPATIBILITY_RECOMMENDATION: Merge\n")
        self.assertEqual(published["check"], "fail")
        self.assertIs(published["may_complete"], False)

    def test_real_dependabot_npm_and_yarn_lock_bumps(self) -> None:
        """Changed records from chia-docs#1138, chia-blockchain-gui#3141, and appsmith#9504."""
        prettier_old = {
            "version": "3.9.8",
            "resolved": "https://registry.npmjs.org/prettier/-/prettier-3.9.8.tgz",
            "integrity": "sha512-WRFq3Wn3WId7LLROfMLdH7xaFr2jR62wU8nLO6rQUOLOxNZUviyJQs1M0iIhLexSFy+L+w0ch66wtoO2jRjG0A==",
            "license": "MIT",
            "bin": {"prettier": "bin/prettier.cjs"},
            "engines": {"node": ">=14"},
            "funding": {"url": "https://github.com/prettier/prettier?sponsor=1"},
        }
        prettier_new = {
            **prettier_old,
            "version": "3.9.9",
            "resolved": "https://registry.npmjs.org/prettier/-/prettier-3.9.9.tgz",
            "integrity": "sha512-Z/CJHIkdujO/OtN7nXUii0Rf3VT5SRuhjBA82Xvu2XhBUgX3nhP67T0LHceBdQLex7OOFGTox+Q5Yg8Jk2Qivg==",
        }
        stylis = {
            "version": "4.4.0",
            "resolved": "https://registry.npmjs.org/stylis/-/stylis-4.4.0.tgz",
            "integrity": "sha512-5Z9ZpRzfuH6l/UAvCPAPUo3665Nk2wLaZU3x+TLHKVzIz33+sbJqbtrYoC3KD4/uVOr2Zp+L0LySezP9OHV9yA==",
            "license": "MIT",
        }
        nested = "node_modules/nano-css/node_modules/stylis"

        def npm(prettier: dict, spec: str, rollup: str, nested_meta: dict) -> str:
            return (
                json.dumps(
                    {
                        "name": "chia-docs",
                        "lockfileVersion": 3,
                        "packages": {
                            "": {"dependencies": {"prettier": spec}},
                            "node_modules/prettier": prettier,
                            "packages/api": {"devDependencies": {"@rollup/plugin-node-resolve": rollup}},
                            nested: nested_meta,
                        },
                    }
                )
                + "\n"
            )

        listed = [_bump("prettier", "3.9.8", "3.9.9", "prettier/prettier")]
        base_npm = npm(prettier_old, "^3.9.8", "^16.0.3", stylis)
        head_npm = npm(prettier_new, "^3.9.9", "16.0.3", stylis)
        entries, residue = npm_manifest._json_parts(base_npm)
        self.assertIn("stylis", entries)
        self.assertNotIn(nested, residue)
        report = _run_listed_scan(
            {"package-lock.json": base_npm},
            {"package-lock.json": head_npm},
            listed,
        )
        self.assertIs(report["scan_conclusive"], True)
        self.assertEqual(report["status"], "clean")
        self.assertNotIn("dependencies", report)
        published = formatter.compose_published_review(report, _PASS_REVIEW, "COMPATIBILITY_RECOMMENDATION: Merge\n")
        self.assertEqual(published["check"], "pass")

        swapped = dict(stylis, integrity="sha512-not-the-published-hash")
        tainted = _run_listed_scan(
            {"package-lock.json": base_npm},
            {"package-lock.json": npm(prettier_new, "^3.9.9", "16.0.3", swapped)},
            listed,
        )
        self.assertFalse(tainted["scan_conclusive"])
        self.assertIn("package-lock.json", _unresolved(tainted))

        yarn_old = (
            'ua-parser-js@^0.7.18:\n'
            '  version "0.7.22"\n'
            '  resolved "https://registry.npmjs.org/ua-parser-js/-/ua-parser-js-0.7.22.tgz"\n'
        )
        yarn_new = (
            'ua-parser-js@^0.7.18:\n'
            '  version "0.7.31"\n'
            '  resolved "https://registry.yarnpkg.com/ua-parser-js/-/ua-parser-js-0.7.31.tgz#649a656b191dffab4f21d5e053e27ca17cbff5c6"\n'
            '  integrity sha512-qLK/Xe9E2uzmYI3qLeOmI0tEOt+TBBQyUIAh4aAgU05FVYzeZrKUdkAZfBNVGRaHVgV0TDkdEngJSw/SyQchkQ==\n'
        )
        yarn_updates = [_bump("ua-parser-js", "0.7.22", "0.7.31", "faisalman/ua-parser-js")]
        yarn_report = _run_listed_scan({"yarn.lock": yarn_old}, {"yarn.lock": yarn_new}, yarn_updates)
        self.assertIs(yarn_report["scan_conclusive"], True)
        self.assertEqual(yarn_report["status"], "clean")
        added = yarn_new + (
            '\ncy-verify-downloads@^0.0.5:\n'
            '  version "0.0.5"\n'
            '  resolved "https://registry.yarnpkg.com/cy-verify-downloads/-/cy-verify-downloads-0.0.5.tgz#2f9c7da0f5fda125ecef2f19ca2b83b1890d3037"\n'
            '  integrity sha512-aRK7VvKG5rmDJK4hjZ27KM2oOOz0cMO7z/j4zX8qCc4ffXZS1XRJkofUY0w5u6MCB/wUsNMs03VuvkeR2tNPoQ==\n'
        )
        self.assertFalse(manifest._entries_explain("yarn", yarn_old, added, yarn_updates))
        added_report = _run_listed_scan({"yarn.lock": yarn_old}, {"yarn.lock": added}, yarn_updates)
        self.assertIs(added_report["scan_conclusive"], True)

    def test_locator_bytes_fail_closed(self) -> None:
        """Non-canonical locators stay byte-for-byte. Residue folds only bare, `^`, and `=` specs."""
        updates = [_bump("left-pad", "1.2.3", "1.2.4", "left-pad/left-pad")]
        canonical = "https://registry.npmjs.org/left-pad/-/left-pad-{}.tgz"
        evil = "https://evil.example/left-pad.tgz"
        mini = "https://registry.npmjs.org/minimist/-/minimist-1.2.5.tgz"

        def npm(version: str, resolved: str, integrity: str | None = None, **extra: object) -> str:
            entry: dict[str, object] = {"version": version, "resolved": resolved, **extra}
            if integrity is not None:
                entry["integrity"] = integrity
            return json.dumps({"lockfileVersion": 3, "packages": {"node_modules/left-pad": entry}})

        def explains(before: str, after: str, listed: list[dict] | None = None) -> bool:
            return manifest._entries_explain("json", before, after, updates if listed is None else listed)

        old = npm("1.2.3", canonical.format("1.2.3"), "sha-old", bin="bin/left-pad.js")
        self.assertTrue(explains(old, npm("1.2.4", canonical.format("1.2.4"), "sha-new", bin="bin/left-pad.js")))
        self.assertFalse(explains(npm("1.2.3", evil, "sha-old"), npm("1.2.4", evil, "sha-new")))
        self.assertFalse(explains(npm("1.2.3", "file:../pwned"), npm("1.2.4", "file:../pwned")))
        self.assertFalse(
            explains(
                npm("1.2.3", evil, "sha-old", resolution="left-pad@npm:1.2.3"),
                npm("1.2.4", "file:../pwned", "sha-new", resolution="left-pad@npm:1.2.4"),
            )
        )
        self.assertFalse(explains(npm("1.2.3", canonical.format("1.2.3")), npm("1.2.4", canonical.format("1.2.4"), "sha-new", resolution="left-pad@npm:1.2.4")))
        self.assertFalse(explains(old, npm("1.2.4", canonical.format("1.2.4"), "sha-new", bin="bin/cli.js")))
        self.assertFalse(explains(old, npm("1.2.4", canonical.format("1.2.4"), "sha-new", bin="../evil.js")))

        def residue(spec: str) -> str:
            return json.dumps({"packages": {"packages/api": {"dependencies": {"moment": spec}}}})

        self.assertTrue(manifest._residues_match("json", residue("^2.31.0"), residue("2.31.0")))
        self.assertTrue(manifest._residues_match("json", residue("=2.31.0"), residue("2.31.0")))
        self.assertFalse(manifest._residues_match("json", residue("~2.31.0"), residue("^2.31.0")))
        self.assertFalse(manifest._residues_match("json", residue("v2.31.0"), residue("2.31.0")))
        self.assertFalse(manifest._residues_match("json", residue("V2.31.0"), residue("2.31.0")))

        def v1(version: str, resolved: str, integrity: str, **extra: object) -> str:
            spec = {"version": version, "resolved": resolved, "integrity": integrity, **extra}
            return json.dumps({"lockfileVersion": 1, "dependencies": {"left-pad": spec}})

        self.assertTrue(explains(v1("1.2.3", canonical.format("1.2.3"), "sha-old"), v1("1.2.4", canonical.format("1.2.4"), "sha-new")))
        self.assertFalse(explains(v1("1.2.3", evil, "sha-old"), v1("1.2.4", evil, "sha-new")))
        self.assertFalse(explains(v1("1.2.3", canonical.format("1.2.3"), "sha-old"), v1("1.2.4", canonical.format("1.2.4"), "sha-new", scripts={"preinstall": "echo pwned"})))

        def nested(integrity: str) -> str:
            pad = {"version": "1.2.3", "resolved": canonical.format("1.2.3"), "integrity": "sha-old", "dependencies": {"minimist": {"version": "1.2.5", "resolved": mini, "integrity": integrity}}}
            return json.dumps({"lockfileVersion": 1, "dependencies": {"left-pad": pad}})

        self.assertFalse(manifest._residues_match("json", nested("sha-a"), nested("sha-b")))
        self.assertFalse(explains(nested("sha-a"), nested("sha-b")))
        yarn_old = 'left-pad@^1.2.3:\n  version "1.2.3"\n  resolved "file:../pwned"\n'
        yarn_new = 'left-pad@^1.2.3:\n  version "1.2.4"\n  resolved "file:../pwned"\n'
        self.assertFalse(manifest._entries_explain("yarn", yarn_old, yarn_new, updates))

if __name__ == "__main__":
    unittest.main()
