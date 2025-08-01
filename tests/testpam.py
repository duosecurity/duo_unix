#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-with-classpath-exception
#
# Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
# All rights reserved.
#
# testpam.py
#

import argparse
import getopt
import getpass
import os
import platform
import subprocess
import sys
import tempfile

import paths

# login_duo-compatible wrapper to pam_duo

PAM_SERVICE = "test_duo_unix_service"
PAM_SERVICE_PATH = os.path.join("/etc", "pam.d", "test_duo_unix_service")


def usage():
    print(
        "Usage: {0} [-d] [-c config] [-f user] [-h host]".format(sys.argv[0]),
        file=sys.stderr,
    )
    sys.exit(1)


class TempPamConfig(object):
    def __init__(self, config):
        self.config = config
        try:
            self.file = open(PAM_SERVICE_PATH, "wb")
        except PermissionError as e:
            raise Exception(
                "Permission denied opening pam.d make sure you run tests with elevated permissions"
            ) from e

    def __enter__(self):
        self.file.write(self.config.encode("utf-8"))
        self.file.flush()
        return self.file

    def __exit__(self, type, value, traceback):
        self.file.close()
        os.remove(PAM_SERVICE_PATH)


def testpam(args, config_file_name, env_overrides=None):
    env = os.environ.copy()
    env["PAM_CONF"] = config_file_name
    env["PAM_SERVICE"] = PAM_SERVICE

    if env_overrides:
        env.update(env_overrides)

    if sys.platform == "darwin":
        env["DYLD_LIBRARY_PATH"] = paths.topbuilddir + "/lib/.libs"
        env["DYLD_INSERT_LIBRARIES"] = paths.build + "/.libs/libtestpam_preload.dylib"
        env["DYLD_FORCE_FLAT_NAMESPACE"] = "1"
    elif sys.platform == "sunos5":
        architecture = {"32bit": "32", "64bit": "64"}[platform.architecture()[0]]
        env["LD_PRELOAD_" + architecture] = paths.build + "/.libs/libtestpam_preload.so"
    else:
        env["LD_PRELOAD"] = paths.build + "/.libs/libtestpam_preload.so"

    testpam_path = [os.path.join(paths.build, "testpam")]
    p = subprocess.Popen(testpam_path + args, env=env)
    p.wait()
    return p


def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "dqc:f:h:")
    except getopt.GetoptError:
        usage()

    opt_conf = "/etc/duo/pam_duo.conf"
    opt_user = getpass.getuser()
    opt_host = None
    opt_quiet = False

    for o, a in opts:
        if o == "-c":
            opt_conf = a
        elif o == "-f":
            opt_user = a
        elif o == "-h":
            opt_host = a
        elif o == "-q":
            opt_quiet = True

    args = [opt_user]
    if opt_host:
        args.append(opt_host)

    config = "auth  required  {libpath}/pam_duo.so conf={duo_config_path} debug".format(
        libpath=paths.topbuilddir + "/pam_duo/.libs", duo_config_path=opt_conf
    )
    if opt_quiet:
        config = config + " quiet"
    with TempPamConfig(config) as config_file:
        process = testpam(args, config_file.name)

    sys.exit(process.returncode)


if __name__ == "__main__":
    main()
