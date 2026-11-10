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


def _rlimit_preexec(spec):
    """Build a preexec_fn applying resource limits to the testpam child.

    spec is "NAME:value[,NAME:value...]" using resource.RLIMIT_<NAME>, e.g.
    "AS:33554432,NOFILE:16". FILLFDS:<n> then fills the descriptor
    table, leaving n free below the limit and occupying numbers above it
    (32 of them, or FILLABOVE:<m>). Both the soft and hard limit are set,
    so only a privileged process can raise them again. Limits are applied to the
    testpam binary only, not to this Python wrapper.
    """
    if not spec:
        return None
    import resource

    limits = []
    fill = None
    above = 32
    for item in spec.split(","):
        name, value = item.split(":")
        if name == "FILLFDS":
            fill = int(value)
            continue
        if name == "FILLABOVE":
            above = int(value)
            continue
        limits.append((getattr(resource, "RLIMIT_" + name), int(value)))

    def fill_fds(leave_free, above):
        # Occupy descriptor numbers just above the soft limit, then all free
        # numbers below it except leave_free. Needs privilege for the
        # temporary raise.
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        base = os.open(os.devnull, os.O_RDONLY)
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft + above, max(hard, soft + above)))
        for fd in range(soft, soft + above):
            os.dup2(base, fd, inheritable=True)
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
        held = []
        while True:
            try:
                fd = os.dup(base)
            except OSError:
                break
            os.set_inheritable(fd, True)
            held.append(fd)
        for fd in held[:leave_free]:
            os.close(fd)

    def apply():
        for res, value in limits:
            resource.setrlimit(res, (value, value))
        if fill is not None:
            fill_fds(fill, above)

    return apply


def testpam(args, config_file_name, env_overrides=None, capture_output=False):
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
    p = subprocess.Popen(
        testpam_path + args,
        stdout=subprocess.PIPE if capture_output else None,
        stderr=subprocess.PIPE if capture_output else None,
        stdin=subprocess.PIPE if capture_output else None,
        close_fds=capture_output,
        env=env,
        preexec_fn=_rlimit_preexec(env.pop("TESTPAM_RLIMITS", None)),
    )
    p.wait()

    # Close stdin immediately if we captured it (we don't need it for reading)
    if capture_output and p.stdin:
        p.stdin.close()

    return p


def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "dc:f:h:")
    except getopt.GetoptError:
        usage()

    opt_conf = "/etc/duo/pam_duo.conf"
    opt_user = getpass.getuser()
    opt_host = None

    for o, a in opts:
        if o == "-c":
            opt_conf = a
        elif o == "-f":
            opt_user = a
        elif o == "-h":
            opt_host = a

    args = [opt_user]
    if opt_host:
        args.append(opt_host)

    config = "auth  required  {libpath}/pam_duo.so conf={duo_config_path} debug".format(
        libpath=paths.topbuilddir + "/pam_duo/.libs", duo_config_path=opt_conf
    )
    with TempPamConfig(config) as config_file:
        process = testpam(args, config_file.name)

    sys.exit(process.returncode)


if __name__ == "__main__":
    main()
