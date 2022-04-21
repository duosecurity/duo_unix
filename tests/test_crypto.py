#!/usr/bin/env python3
import os
import subprocess
import unittest

from paths import topbuilddir

TESTDIR = os.path.realpath(os.path.dirname(__file__))


class TestCrypto(unittest.TestCase):
    def test_crypto(self):
        process = subprocess.Popen(
            [os.path.join(TESTDIR, "fips_scanner.sh")], stdout=subprocess.PIPE
        )
        (stdout, stderr) = process.communicate()
        self.assertEqual(
            process.returncode,
            0,
            "ERROR: Found potential non-FIPS compliant calls:\n{stdout}".format(
                stdout=stdout
            ),
        )


if __name__ == "__main__":
    unittest.main()
