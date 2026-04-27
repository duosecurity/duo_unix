#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-with-classpath-exception
#
# Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
# All rights reserved.
#
# test_crypto.py
#

import os
import subprocess
import unittest

from paths import topbuilddir

TESTDIR = os.path.realpath(os.path.dirname(__file__))


class TestCrypto(unittest.TestCase):
    def test_fips_scanner(self):
        # Known finding: RAND_load_file in lib/https.c (DRBG bypass).
        # Change expected returncode to 0 once that is resolved.
        process = subprocess.Popen(
            [os.path.join(TESTDIR, "fips_scanner.sh"), os.path.join(TESTDIR, "..")],
            stdout=subprocess.PIPE,
        )
        (stdout, stderr) = process.communicate()
        self.assertEqual(
            process.returncode,
            1,
            "Expected fips_scanner to find RAND_load_file (known issue), "
            "but it returned {rc}:\n{stdout}".format(
                rc=process.returncode, stdout=stdout
            ),
        )

    def test_openssl3_deprecated_apis(self):
        process = subprocess.Popen(
            [os.path.join(TESTDIR, "openssl3_scanner.sh"), os.path.join(TESTDIR, "..")],
            stdout=subprocess.PIPE,
        )
        (stdout, stderr) = process.communicate()
        self.assertEqual(
            process.returncode,
            0,
            "ERROR: Found deprecated low-level OpenSSL API calls:\n{stdout}".format(
                stdout=stdout
            ),
        )


if __name__ == "__main__":
    unittest.main()
