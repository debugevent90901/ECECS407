import unittest
from typing import Optional

from electionguard.utils import (
    get_optional,
    match_optional,
    get_or_else_optional,
    flatmap_optional,
)


class TestOptionalFunctions(unittest.TestCase):
    def test_unwrap(self):
        good: Optional[int] = 3
        bad: Optional[int] = None

        self.assertEqual(get_optional(good), 3)
        self.assertRaises(Exception, get_optional, bad)

    def test_match(self):
        good: Optional[int] = 3
        bad: Optional[int] = None

        self.assertEqual(5, match_optional(good, lambda: 1, lambda x: x + 2))
        self.assertEqual(1, match_optional(bad, lambda: 1, lambda x: x + 2))

    def test_get_or_else(self):
        good: Optional[int] = 3
        bad: Optional[int] = None

        self.assertEqual(3, get_or_else_optional(good, 5))
        self.assertEqual(5, get_or_else_optional(bad, 5))

    def test_flatmap(self):
        good: Optional[int] = 3
        bad: Optional[int] = None

        self.assertEqual(5, get_optional(flatmap_optional(good, lambda x: x + 2)))
        self.assertIsNone(flatmap_optional(bad, lambda x: x + 2))
