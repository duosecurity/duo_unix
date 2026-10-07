#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-with-classpath-exception
#
# Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
# All rights reserved.
#
# test_check_pie.py
#

import os
import shutil
import subprocess
import unittest

from paths import topbuilddir


def _find_login_duo():
    """Find the real login_duo ELF binary (not the libtool wrapper)."""
    candidates = [
        os.path.join(topbuilddir, "login_duo", ".libs", "login_duo"),
        os.path.join(topbuilddir, "login_duo", "login_duo"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            with open(path, "rb") as f:
                if f.read(4) == b"\x7fELF":
                    return path
    return None


class TestPIE(unittest.TestCase):
    def test_login_duo_is_pie(self):
        """Verify that login_duo is a PIE executable (ELF type ET_DYN)."""
        if not shutil.which("readelf"):
            self.skipTest("readelf not available")

        binary = _find_login_duo()
        if not binary:
            self.skipTest("login_duo ELF binary not found")

        result = subprocess.run(
            ["readelf", "-h", binary],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, f"readelf failed: {result.stderr}")

        for line in result.stdout.splitlines():
            if "Type:" in line:
                self.assertIn(
                    "DYN",
                    line,
                    f"login_duo is not PIE: {line.strip()}",
                )
                return

        self.fail("Could not find Type: line in readelf output")


if __name__ == "__main__":
    unittest.main()
