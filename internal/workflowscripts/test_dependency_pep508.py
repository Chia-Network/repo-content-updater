"""The strict requirement parser: limits that keep upstream text from stalling or crashing the review."""

import time
import unittest

from dependency_pep508 import parse


class MarkerLimitsTest(unittest.TestCase):
    def test_marker_groups_nest_to_a_limit_then_fail_as_an_invalid_requirement(self) -> None:
        nested = "sigstore==3.6.1 ; {}os_name == 'nt'{}"
        parse(nested.format("(" * 32, ")" * 32))
        for depth in (33, 600, 5000):
            with self.subTest(depth=depth), self.assertRaises(ValueError):
                parse(nested.format("(" * depth, ")" * depth))

    def test_a_long_marker_parses_in_linear_time(self) -> None:
        """A 1.5 MB marker took tens of seconds when each token re-sliced the rest of the line."""
        marker = " or ".join(["os_name == 'nt'"] * 100_000)
        started = time.monotonic()
        parse(f"sigstore==3.6.1 ; {marker}")
        self.assertLess(time.monotonic() - started, 5)


class ArbitraryEqualityTest(unittest.TestCase):
    def test_a_comma_ends_the_arbitrary_equality_value(self) -> None:
        self.assertEqual(len(parse("sigstore===3.6.1,==3.6.1").specs), 2)
        for text in ("sigstore===3.6.1,foo", "sigstore===3.6.1,"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse(text)


if __name__ == "__main__":
    unittest.main()
