#!/usr/bin/env python3
import os
import subprocess
import unittest

from paths import topbuilddir

BUILDDIR = topbuilddir


def testutil_duo_split_at(args):
    return (
        subprocess.check_output(
            [os.path.join(BUILDDIR, "lib", "testutil_duo_split_at")] + args
        )
        .decode("utf-8")
        .strip()
    )


class TestDuoSplitAt(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(testutil_duo_split_at(["foo/bar/baz", "/", "1", "bar"]), "OK")

    def test_first(self):
        self.assertEqual(testutil_duo_split_at(["foo/bar/baz", "/", "0", "foo"]), "OK")

    def test_last(self):
        self.assertEqual(testutil_duo_split_at(["foo/bar/baz", "/", "2", "baz"]), "OK")

    def test_too_many(self):
        self.assertEqual(
            testutil_duo_split_at(["foo/bar/baz", "/", "100", "NULL"]), "OK"
        )

    def test_no_delimiter(self):
        self.assertEqual(testutil_duo_split_at(["foo", "/", "1", "NULL"]), "OK")

    def test_starts_with_delimiter(self):
        self.assertEqual(testutil_duo_split_at(["/foo/bar/baz", "/", "0", ""]), "OK")

    def test_ends_with_delimiter(self):
        self.assertEqual(testutil_duo_split_at(["foo/bar/baz/", "/", "3", ""]), "OK")

    def test_empty(self):
        self.assertEqual(testutil_duo_split_at(["", "/", "0", ""]), "OK")


if __name__ == "__main__":
    unittest.main()
