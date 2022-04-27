#!/usr/bin/env python3
import os
import subprocess
import sys
import time
import unittest
from tempfile import NamedTemporaryFile

import pexpect
from common_suites import NORMAL_CERT, CommonSuites, fips_available
from config import (
    MOCKDUO_ADMINS_NO_USERS,
    MOCKDUO_AUTOPUSH,
    MOCKDUO_CONF,
    MOCKDUO_FIPS,
    MOCKDUO_GECOS_DEFAULT_DELIM_6_POS,
    MOCKDUO_GECOS_DEPRECATED_PARSE_FLAG,
    MOCKDUO_GECOS_INVALID_DELIM_COLON,
    MOCKDUO_GECOS_INVALID_DELIM_PUNC,
    MOCKDUO_GECOS_INVALID_DELIM_WHITESPACE,
    MOCKDUO_GECOS_INVALID_POS,
    MOCKDUO_GECOS_LONG_DELIM,
    MOCKDUO_GECOS_SEND_UNPARSED,
    MOCKDUO_GECOS_SLASH_DELIM_3_POS,
    MOCKDUO_USERS,
    MOCKDUO_USERS_ADMINS,
    MOTD_CONF,
    DuoUnixConfig,
    TempConfig,
)
from mockduo_context import MockDuo
from paths import topbuilddir

BUILDDIR = topbuilddir
TESTDIR = os.path.realpath(os.path.dirname(__file__))


class LoginDuoTimeoutException(Exception):
    def __init__(self, message="", stdout=None, stderr=None):
        self.message = message
        self.stdout = stdout
        self.stderr = stderr

    def __str__(self):
        if self.stderr:
            stderr_output = "STDERR:\n{stderr}".format(stderr=self.stderr)
        else:
            stderr_output = ""

        if self.stdout:
            stdout_output = "STDOUT:\n{stdout}".format(stdout=self.stdout)
        else:
            stdout_output = ""

        return "Timeout waiting for 'login_duo' to execute\n{message}\n{stdout}\n{stderr}".format(
            mesage=self.message,
            stderr=stderr_output,
            stdout=stdout_output,
        )


def login_duo_interactive(args, env=None, preload_script=""):
    if env is None:
        env = {}

    excluded_keys = ["SSH_CONNECTION", "FALLBACK", "UID", "http_proxy", "TIMEOUT"]
    env_passthrough = {
        key: os.environ[key] for key in os.environ if key not in excluded_keys
    }
    env_passthrough.update(env)

    if preload_script != "":
        login_duo_path = "python3"
        args = [preload_script] + args
    else:
        login_duo_path = os.path.join(BUILDDIR, "login_duo", "login_duo")

    process = pexpect.spawn(login_duo_path, args, cwd=TESTDIR, env=env_passthrough)
    return process


def login_duo(args, env=None, timeout=10, preload_script=""):
    """Runs the login_duo binary in various ways
    args: the list of arguments to pass through to either login_duo or login_duo.py

    env: list of environment variables to pass to login_duo

    timeout: how long to allow login_duo or login_duo.py to run before raising an exception

    preload_script: whether or not to use a wrapping script to allow the caller to load
    a custom preload library for mocking out certain parts of login_duo
    """
    if env is None:
        env = {}

    if preload_script != "":
        login_duo_path = ["python3", preload_script]
    else:
        login_duo_path = [os.path.join(BUILDDIR, "login_duo", "login_duo")]

    excluded_keys = ["SSH_CONNECTION", "FALLBACK", "UID", "http_proxy", "TIMEOUT"]
    env_passthrough = {
        key: os.environ[key] for key in os.environ if key not in excluded_keys
    }
    env_passthrough.update(env)

    process = subprocess.Popen(
        login_duo_path + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        cwd=TESTDIR,
        close_fds=True,
        env=env_passthrough,
    )

    # Try to gracefully handle the case where we get a prompt
    for i in range(0, int(timeout // 0.05)):
        process.poll()
        if process.returncode is not None:
            break
        time.sleep(0.05)
    else:
        (stdout, stderr) = process.communicate(input=b"1\r\n")
        raise LoginDuoTimeoutException(
            "login_duo unexpectedly blocked for user input", stdout, stderr
        )

    stdout = process.stdout.read().decode("utf-8").split("\n")
    stderr = process.stderr.read().decode("utf-8").split("\n")
    process.stdout.close()
    process.stderr.close()
    process.stdin.close()
    return {
        "returncode": process.returncode,
        "stdout": stdout,
        "stderr": stderr,
    }


class TestLoginDuoConfigs(CommonSuites.Configuration):
    def call_binary(self, *args):
        return login_duo(*args)


class TestLoginDuoDown(CommonSuites.DuoDown):
    def call_binary(self, *args):
        return login_duo(*args)


class TestLoginDuoSelfSignedCert(CommonSuites.DuoSelfSignedCert):
    def call_binary(self, *args):
        return login_duo(*args)


class TestLoginDuoBadCN(CommonSuites.DuoBadCN):
    def call_binary(self, *args):
        return login_duo(*args)


class TestMockDuoWithValidCert(CommonSuites.WithValidCert):
    def call_binary(self, *args):
        return login_duo(*args)


class TestLoginDuoPreauthStates(CommonSuites.PreauthStates):
    def call_binary(self, *args):
        return login_duo(*args)


class TestLoginDuoHosts(CommonSuites.Hosts):
    def call_binary(self, *args):
        return login_duo(*args)


class TestLoginDuoHTTPProxy(CommonSuites.HTTPProxy):
    def call_binary(self, *args, **kwargs):
        return login_duo(*args)


class TestLoginDuoGetHostname(CommonSuites.GetHostname):
    def call_binary(self, *args):
        return login_duo(*args)


class TestLoginDuoFIPS(CommonSuites.FIPS):
    def call_binary(self, *args, **kwargs):
        return login_duo(*args, **kwargs)


class TestLoginDuoPreauthFailures(CommonSuites.PreauthFailures):
    def call_binary(self, *args):
        return login_duo(*args)


class TestLoginBSON(CommonSuites.InvalidBSON):
    def call_binary(self, *args, **kwargs):
        return login_duo(*args, **kwargs)


class TestLoginDuoConfig(unittest.TestCase):
    def test_empty_args(self):
        """Test to see how login_duo handles an empty string argument (we do need a valid argument also)"""
        result = login_duo(["", "-h"])
        self.assertRegex(
            result["stderr"][0], ".*login_duo: option requires an argument.*"
        )
        self.assertEqual(
            result["stderr"][1],
            "Usage: login_duo [-v] [-c config] [-d] [-f duouser] [-h host] [prog [args...]]",
        )
        self.assertEqual(result["returncode"], 1)

    def test_help_output(self):
        """Basic help output"""
        result = login_duo(["-h"])
        self.assertRegex(
            result["stderr"][0], ".*login_duo: option requires an argument.*"
        )
        self.assertEqual(
            result["stderr"][1],
            "Usage: login_duo [-v] [-c config] [-d] [-f duouser] [-h host] [prog [args...]]",
        )
        self.assertEqual(result["returncode"], 1)

    def test_version_output(self):
        """Check version output"""
        result = login_duo(["-v"])
        self.assertRegex(result["stderr"][0], "login_duo \d+\.\d+.\d+")


class TestLoginDuoEnv(CommonSuites.Env):
    def call_binary(self, *args, **kwargs):
        return login_duo(*args)


class TestLoginDuoSpecificEnv(unittest.TestCase):
    def run(self, result=None):
        with MockDuo(NORMAL_CERT):
            return super(TestLoginDuoSpecificEnv, self).run(result)

    def test_missing_uid(self):
        with TempConfig(MOCKDUO_CONF) as temp:
            result = login_duo(
                ["-d", "-c", temp.name, "-f", "timeout", "true"],
                env={
                    "TIMEOUT": "1",
                },
                preload_script=os.path.join(TESTDIR, "login_duo.py"),
            )
            self.assertRegex(
                result["stderr"][0],
                r"Who are you?",
            )

    def test_command_from_env(self):
        with TempConfig(MOCKDUO_CONF) as temp:
            result = login_duo(
                ["-d", "-c", temp.name, "-f", "preauth-allow"],
                env={
                    "UID": "1001",
                    "SSH_ORIGINAL_COMMAND": "echo 'hello'",
                },
                preload_script=os.path.join(TESTDIR, "login_duo.py"),
            )
            self.assertRegex(
                result["stdout"][0],
                r"hello",
            )

    def test_env_factor(self):
        config = DuoUnixConfig(
            ikey="DIXYZV6YM8IFYVWBINCA",
            skey="yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo",
            host="localhost:4443",
            cafile="certs/mockduo-ca.pem",
            accept_env_factor="yes",
        )

        with TempConfig(config) as temp:
            process = login_duo_interactive(
                ["-d", "-c", temp.name, "-f", "whatever", "echo", "SUCCESS"],
                env={
                    "UID": "1001",
                    "DUO_PASSCODE": "push1",
                },
            )
            self.assertEqual(process.expect("SUCCESS", timeout=10), 0)


class TestLoginDuoUIDMismatch(unittest.TestCase):
    def run(self, result=None):
        with MockDuo(NORMAL_CERT):
            return super(TestLoginDuoUIDMismatch, self).run(result)

    def test_nonroot(self):
        with TempConfig(MOCKDUO_CONF) as temp:
            result = login_duo(
                ["-d", "-c", temp.name, "-f", "preauth-allow"],
                env={
                    "EUID": "1002",
                    "UID": "1001",
                },
                preload_script=os.path.join(TESTDIR, "login_duo.py"),
            )
            self.assertRegex(
                result["stderr"][0],
                r"Only root may specify -c or -f",
            )

    def test_sync(self):
        with TempConfig(MOCKDUO_CONF) as temp:
            result = login_duo(
                ["-d", "-c", temp.name, "-f", "whatever", "true"],
            )
            self.assertRegex(
                result["stderr"][0],
                r"Successful Duo login for 'whatever'",
            )

    def test_unprivileged(self):
        with TempConfig(MOCKDUO_CONF) as temp:
            result = login_duo(
                ["-d"],
                env={
                    "EUID": "1000",
                    "UID": "1001",
                },
                preload_script=os.path.join(TESTDIR, "login_duo.py"),
                timeout=10,
            )
            self.assertRegex(
                result["stderr"][0],
                r"couldn't drop privileges:",
            )

    def test_privsep_user_not_found(self):
        with TempConfig(MOCKDUO_CONF) as temp:
            result = login_duo(
                ["-d"],
                env={
                    "EUID": "0",
                    "UID": "1001",
                    "NO_PRIVSEP_USER": "1",
                },
                preload_script=os.path.join(TESTDIR, "login_duo.py"),
                timeout=10,
            )
            self.assertRegex(
                result["stderr"][0],
                r"User .* not found",
            )


class TestLoginDuoTimeout(unittest.TestCase):
    def run(self, result=None):
        with MockDuo(NORMAL_CERT):
            return super(TestLoginDuoTimeout, self).run(result)

    def test_connection_timeout(self):
        with TempConfig(MOCKDUO_CONF) as temp:
            result = login_duo(
                ["-d", "-c", temp.name, "-f", "timeout", "true"],
                env={
                    "UID": "1001",
                    "TIMEOUT": "1",
                },
                preload_script=os.path.join(TESTDIR, "login_duo.py"),
                timeout=10,
            )
            for line in result["stderr"][:3]:
                self.assertEqual(line, "Attempting connection")
            self.assertRegex(
                result["stderr"][3],
                r"Failsafe Duo login for 'timeout': Couldn't connect to localhost:4443: Failed to connect",
            )


class TestLoginDuoShell(unittest.TestCase):
    def run(self, result=None):
        with MockDuo(NORMAL_CERT):
            return super(TestLoginDuoShell, self).run(result)

    def test_default_shell(self):
        """Test that we fallback to /bin/sh if there is no shell specified for the user"""
        with TempConfig(MOCKDUO_AUTOPUSH) as temp:
            process = login_duo_interactive(
                ["-d", "-c", temp.name],
                env={"PS1": "$ ", "UID": "1015"},
                preload_script=os.path.join(TESTDIR, "login_duo.py"),
            )
            # this double escaping is needed to check for a literal "$"
            self.assertEqual(process.expect("\\$", timeout=10), 0)

    def test_shell_as_command(self):
        with TempConfig(MOCKDUO_AUTOPUSH) as temp:
            process = login_duo_interactive(
                ["-d", "-c", temp.name, "echo", "SUCCESS"],
                env={"PS1": "> ", "UID": "1017"},
                preload_script=os.path.join(TESTDIR, "login_duo.py"),
            )
            self.assertEqual(process.expect("-c echo SUCCESS", timeout=10), 0)


class TestLoginDuoGroups(unittest.TestCase):
    def run(self, result=None):
        with MockDuo(NORMAL_CERT):
            return super(TestLoginDuoGroups, self).run(result)

    def test_users_only_match_users(self):
        for uid in range(1000, 1003):
            with TempConfig(MOCKDUO_USERS) as temp:
                result = login_duo(
                    ["-d", "-c", temp.name, "-f", "preauth-allow", "true"],
                    env={
                        "UID": str(uid),
                    },
                    preload_script=os.path.join(TESTDIR, "groups.py"),
                )
                self.assertRegex(
                    result["stderr"][0],
                    r"Skipped Duo login for 'preauth-allow': preauth-allowed",
                )

    def test_users_or_admins_match_users(self):
        for uid in range(1000, 1004):
            with TempConfig(MOCKDUO_USERS_ADMINS) as temp:
                result = login_duo(
                    ["-d", "-c", temp.name, "-f", "preauth-allow", "true"],
                    env={
                        "UID": str(uid),
                    },
                    preload_script=os.path.join(TESTDIR, "groups.py"),
                )
                self.assertRegex(
                    result["stderr"][0],
                    r"Skipped Duo login for 'preauth-allow': preauth-allowed",
                )

    def test_admins_and_not_users_match_admins(self):
        with TempConfig(MOCKDUO_ADMINS_NO_USERS) as temp:
            result = login_duo(
                ["-d", "-c", temp.name, "-f", "preauth-allow", "true"],
                env={
                    "UID": "1003",
                },
                preload_script=os.path.join(TESTDIR, "groups.py"),
            )
            self.assertRegex(
                result["stderr"][0],
                r"Skipped Duo login for 'preauth-allow': preauth-allowed",
            )

    def test_users_bypass(self):
        with TempConfig(MOCKDUO_USERS) as temp:
            result = login_duo(
                ["-d", "-c", temp.name, "-f", "preauth-allow", "true"],
                env={"UID": "1004"},
                preload_script=os.path.join(TESTDIR, "groups.py"),
            )
            self.assertRegex(
                result["stderr"][0],
                r"User preauth-allow bypassed Duo 2FA due to user's UNIX group",
            )


class TestLoginDuoInteractive(CommonSuites.Interactive):
    def call_binary(self, *args, **kwargs):
        return login_duo_interactive(*args, **kwargs)


class TestLoginDuoGECOS(unittest.TestCase):
    def run(self, result=None):
        with MockDuo(NORMAL_CERT):
            return super(TestLoginDuoGECOS, self).run(result)

    def test_gecos_field_unparsed(self):
        with TempConfig(MOCKDUO_GECOS_SEND_UNPARSED) as temp:
            result = login_duo(
                ["-d", "-c", temp.name, "true"],
                env={"UID": "1010"},
                preload_script=os.path.join(TESTDIR, "login_duo.py"),
            )
            self.assertRegex(
                result["stderr"][0],
                r"Successful Duo login for '1/2/3/4/5/gecos_user_gecos_field6'",
            )

    def test_deprecated_gecos_parsed_flag(self):
        with TempConfig(MOCKDUO_GECOS_DEPRECATED_PARSE_FLAG) as temp:
            result = login_duo(
                ["-d", "-c", temp.name, "true"],
                env={"UID": "1010"},
                preload_script=os.path.join(TESTDIR, "login_duo.py"),
            )
            self.assertRegex(
                result["stderr"][0],
                r"The gecos_parsed configuration item for Duo Unix is deprecated and no longer has any effect. Use gecos_delim and gecos_username_pos instead",
            )
            self.assertRegex(
                result["stderr"][1],
                "Skipped Duo login for 'gecos/6': gecos/6",
            )

    def test_gecos_delimiter_default_position_6(self):
        with TempConfig(MOCKDUO_GECOS_DEFAULT_DELIM_6_POS) as temp:
            result = login_duo(
                ["-d", "-c", temp.name, "true"],
                env={"UID": "1012"},
                preload_script=os.path.join(TESTDIR, "login_duo.py"),
            )
            self.assertRegex(
                result["stderr"][0],
                "Skipped Duo login for 'gecos_user_gecos_field6': gecos-user-gecos-field6-allowed",
            )

    def test_gecos_delimiter_slash_position_3(self):
        with TempConfig(MOCKDUO_GECOS_SLASH_DELIM_3_POS) as temp:
            result = login_duo(
                ["-d", "-c", temp.name, "true"],
                env={"UID": "1011"},
                preload_script=os.path.join(TESTDIR, "login_duo.py"),
            )
            self.assertRegex(
                result["stderr"][0],
                r"Skipped Duo login for 'gecos_user_gecos_field3': gecos-user-gecos-field3-allowed",
            )

    def test_gecos_parsing_error(self):
        with TempConfig(MOCKDUO_GECOS_SLASH_DELIM_3_POS) as temp:
            result = login_duo(
                ["-d", "-c", temp.name, "true"],
                env={"UID": "1012"},
                preload_script=os.path.join(TESTDIR, "login_duo.py"),
            )
            self.assertRegex(
                result["stderr"][0],
                r"Could not parse GECOS field",
            )

    def test_gecos_empty(self):
        with TempConfig(MOCKDUO_GECOS_SEND_UNPARSED) as temp:
            result = login_duo(
                ["-d", "-c", temp.name, "true"],
                env={"UID": "1016"},
                preload_script=os.path.join(TESTDIR, "login_duo.py"),
            )
            self.assertRegex(
                result["stderr"][0],
                r"Empty GECOS field",
            )

    def test_gecos_invalid_delimiter_length(self):
        with TempConfig(MOCKDUO_GECOS_LONG_DELIM) as temp:
            result = login_duo(
                ["-d", "-c", temp.name, "true"],
            )
            self.assertRegex(
                result["stderr"][0],
                r"Invalid character option length. Character fields must be 1 character long: ',,'",
            )
            self.assertRegex(
                result["stderr"][1],
                r"Invalid login_duo option: 'gecos_delim'",
            )
            self.assertRegex(
                result["stderr"][2],
                r"Parse error in {config}, line \d+".format(config=temp.name),
            )

    def test_invalid_delimiter_value(self):
        for config in [
            MOCKDUO_GECOS_INVALID_DELIM_COLON,
            MOCKDUO_GECOS_INVALID_DELIM_PUNC,
        ]:
            with TempConfig(config) as temp:
                result = login_duo(
                    ["-d", "-c", temp.name, "true"],
                )
                self.assertEqual(
                    result["stderr"][0],
                    "Invalid gecos_delim '{delim}' (delimiter must be punctuation other than ':')".format(
                        delim=config["gecos_delim"]
                    ),
                )
                self.assertRegex(
                    result["stderr"][1],
                    r"Invalid login_duo option: 'gecos_delim'",
                )
                self.assertRegex(
                    result["stderr"][2],
                    r"Parse error in {config}, line \d+".format(config=temp.name),
                )

    def test_invalid_delimiter_value_whitespace(self):
        with TempConfig(MOCKDUO_GECOS_INVALID_DELIM_WHITESPACE) as temp:
            result = login_duo(
                ["-d", "-c", temp.name, "true"],
            )
            self.assertEqual(
                result["stderr"][0],
                "Invalid character option length. Character fields must be 1 character long: ''",
            )
            self.assertRegex(
                result["stderr"][1],
                r"Invalid login_duo option: 'gecos_delim'",
            )
            self.assertRegex(
                result["stderr"][2],
                r"Parse error in {config}, line \d+".format(config=temp.name),
            )

    def test_invalid_pos_value(self):
        with TempConfig(MOCKDUO_GECOS_INVALID_POS) as temp:
            result = login_duo(
                ["-d", "-c", temp.name, "true"],
            )
            self.assertEqual(
                result["stderr"][0],
                "Gecos position starts at 1",
            )
            self.assertRegex(
                result["stderr"][1],
                r"Invalid login_duo option: 'gecos_username_pos'",
            )
            self.assertRegex(
                result["stderr"][2],
                r"Parse error in {config}, line \d+".format(config=temp.name),
            )


@unittest.skipIf(
    sys.platform == "darwin" or sys.platform == "sunos5",
    reason="MOTD testing not available on Mac and Solaris",
)
class TestMOTD(unittest.TestCase):
    def run(self, result=None):
        with MockDuo(NORMAL_CERT):
            return super(TestMOTD, self).run(result)

    def test_motd(self):
        test_motd = "test_motd"
        with TempConfig(MOTD_CONF) as temp:
            try:
                # I don't know why this test doesn't play nice with normal temp files
                # either a race condition or a permissions issue but we have to do this instead
                with open("/tmp/duo_unix_test_motd", "w") as fh:
                    fh.write(test_motd + "\n")
                process = login_duo_interactive(
                    ["-d", "-c", temp.name, "-f", "whatever", "echo", "SUCCESS"],
                    env={
                        "UID": "1001",
                        "MOTD_FILE": "/tmp/duo_unix_test_motd",
                    },
                    preload_script=os.path.join(TESTDIR, "login_duo.py"),
                )
                process.sendline(b"1")
                self.assertEqual(process.expect(test_motd, timeout=10), 0)
            finally:
                try:
                    os.remove("/tmp/duo_unix_test_motd")
                except Exception:
                    pass

    def test_motd_with_ssh_command(self):
        test_motd = "test_motd"
        with TempConfig(MOTD_CONF) as temp:
            with TempConfig(test_motd + "\n") as motd_file:
                process = login_duo_interactive(
                    ["-d", "-c", temp.name, "-f", "whatever", "echo", "SUCCESS"],
                    env={
                        "UID": "1001",
                        "SSH_ORIGINAL_COMMAND": "ls",
                        "MOTD_FILE": motd_file.name,
                    },
                    preload_script=os.path.join(TESTDIR, "login_duo.py"),
                )
                process.sendline(b"1")
            self.assertEqual(process.expect([test_motd, pexpect.EOF], timeout=5), 1)

    def test_motd_users_bypass(self):
        bypass_config = DuoUnixConfig(
            ikey="DIXYZV6YM8IFYVWBINCA",
            skey="yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo",
            host="localhost:4443",
            cafile="certs/mockduo-ca.pem",
            groups="users",
            motd="yes",
        )
        test_motd = "test_motd"
        with TempConfig(bypass_config) as temp:
            with TempConfig(test_motd + "\n") as motd_file:
                process = login_duo_interactive(
                    ["-d", "-c", temp.name, "-f", "preauth-allow", "echo", "SUCCESS"],
                    env={
                        "UID": "1004",
                        "MOTD_FILE": motd_file.name,
                    },
                    preload_script=os.path.join(TESTDIR, "groups.py"),
                )
                process.sendline(b"1")
                self.assertEqual(process.expect(test_motd, timeout=10), 0)
                self.assertEqual(process.expect("SUCCESS", timeout=10), 0)


if __name__ == "__main__":
    unittest.main()
