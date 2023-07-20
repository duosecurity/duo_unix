#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-with-classpath-exception
#
# Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
# All rights reserved.
#
# mocklogin_duo.py
#

import os
import sys

import paths
import pexpect

PROMPT = ".* or option \(1-4\): $"

if sys.platform == "sunos5":
    EOF = pexpect.TIMEOUT
else:
    EOF = pexpect.EOF


def _login_duo(confs):
    p = pexpect.spawn(paths.login_duo + " -d -c" + confs + " -f foobar echo SUCCESS")
    p.expect(PROMPT, timeout=10)
    print "===> %r" % p.match.group(0)
    return p


def main():
    confs = sys.argv[1]
    p = _login_duo(confs)

    # 3 failures in a row
    p.sendline("123456")
    p.expect(PROMPT)
    print "===> %r" % p.match.group(0)

    p.sendline("wefawefgoiagj3rj")
    p.expect(PROMPT)
    print "===> %r" % p.match.group(0)

    p.sendline("A" * 500)
    p.expect(EOF)
    print "===> %r" % p.before

    # menu options
    p = _login_duo(confs)

    p.sendline("3")
    p.expect(PROMPT)
    print "===> %r" % p.match.group(0)

    p.sendline("4")
    p.expect(PROMPT)
    print "===> %r" % p.match.group(0)

    p.sendline("1")
    p.expect(EOF)
    print "===> %r" % p.before

    p = _login_duo(confs)

    p.sendline("2")
    p.expect(EOF)
    print "===> %r" % p.before


if __name__ == "__main__":
    main()
