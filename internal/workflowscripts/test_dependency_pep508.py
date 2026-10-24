"""The strict requirement parser: limits that keep upstream text from stalling or crashing the review."""

import timeit
import unittest

from dependency_pep508 import parse


class MarkerLimitsTest(unittest.TestCase):
    def test_marker_groups_nest_to_a_limit_then_fail_as_an_invalid_requirement(self) -> None:
        nested = "sigstore==3.6.1 ; {}os_name == 'nt'{}"
        parse(nested.format("(" * 32, ")" * 32))
        for depth in (33, 600, 5000):
            with self.subTest(depth=depth), self.assertRaises(ValueError):
                parse(nested.format("(" * depth, ")" * depth))

    def test_marker_parse_time_grows_linearly_with_its_length(self) -> None:
        """Ten times the marker takes about ten times as long; re-slicing the line per token took a hundred."""

        def seconds(clauses: int) -> float:
            text = "sigstore==3.6.1 ; " + " or ".join(["os_name == 'nt'"] * clauses)
            return min(timeit.repeat(lambda: parse(text), number=1, repeat=3))

        self.assertLess(seconds(100_000) / seconds(10_000), 30)


class SpecifierTest(unittest.TestCase):
    def test_each_operator_takes_the_versions_pip_takes(self) -> None:
        """Checked against pip 26.2.2: `~=` needs two release parts, and only `==`/`!=` take a wildcard or local."""
        for spec in ("~=1.0", "~=1.0.0rc1", "==1.*", "!=1.*", "==1.0+loc", "!=1.0+loc", ">=1", "<1", "===1"):
            with self.subTest(spec=spec):
                parse(f"sigstore{spec}")
        for spec in ("~=1", "~=1.*", "~=1.0+loc", ">=1.*", "<1.*", "<1.0+loc", ">1.0+loc", "<=1.0+loc", ">=1.0+loc"):
            with self.subTest(spec=spec), self.assertRaises(ValueError):
                parse(f"sigstore{spec}")


class ArbitraryEqualityTest(unittest.TestCase):
    def test_a_comma_ends_the_arbitrary_equality_value(self) -> None:
        self.assertEqual(len(parse("sigstore===3.6.1,==3.6.1").specs), 2)
        for text in ("sigstore===3.6.1,foo", "sigstore===3.6.1,"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse(text)


if __name__ == "__main__":
    unittest.main()
