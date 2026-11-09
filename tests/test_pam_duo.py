#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-with-classpath-exception
#
# Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
# All rights reserved.
#
# test_pam_duo.py
#

import errno
import getpass
import os
import subprocess
import time
import unittest
import sys

import pexpect
from common_suites import NORMAL_CERT, CommonSuites, EOF, CommonTestCase
from config import (
    DuoUnixConfig,
    MOCKDUO_CONF,
    MOCKDUO_FALLBACK,
    MOCKDUO_GECOS_DEFAULT_DELIM_6_POS,
    MOCKDUO_GECOS_DEPRECATED_PARSE_FLAG,
    MOCKDUO_GECOS_INVALID_DELIM_COLON,
    MOCKDUO_GECOS_INVALID_DELIM_PUNC,
    MOCKDUO_GECOS_INVALID_DELIM_WHITESPACE,
    MOCKDUO_GECOS_INVALID_POS,
    MOCKDUO_GECOS_LONG_DELIM,
    MOCKDUO_GECOS_SEND_UNPARSED,
    MOCKDUO_GECOS_SLASH_DELIM_3_POS,
    MOCKDUO_PROMPTS_1,
    MOCKDUO_PROMPTS_DEFAULT,
    MOCKDUO_VERIFIED_PUSH,
    TempConfig,
)
from mockduo import (
    VERIFIED_PUSH_CODE,
    VP_BAD_CODE_USER,
    VP_EXPIRED_USER,
    VP_IGNORED_USER,
    VP_REJECTED_EMPTY_USER,
    VP_REJECTED_USER,
    VP_USER,
)
from mockduo_context import MockDuo
from paths import topbuilddir
from testpam import TempPamConfig, testpam

TESTDIR = os.path.realpath(os.path.dirname(__file__))
SOLARIS_ISSUE = """
    Right now these tests require superuser to run and modify LD_PRELOAD with an insecure
    path. Solaris doesn't like this and prevents the preload from occur which breaks the
    test. So for now we're skipping them.
"""


class PamDuoTimeoutException(Exception):
    def __init__(self, stdout=None, stderr=None):
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

        return "Timeout waiting for 'pam_duo' to execute\n{stdout}\n{stderr}".format(
            stderr=stderr_output,
            stdout=stdout_output,
        )


def pam_duo_interactive(args, env={}, timeout=2):
    pam_duo_path = os.path.join(TESTDIR, "testpam.py")
    # we don't want to accidentally grab these from the calling environment
    excluded_keys = ["SSH_CONNECTION", "FALLBACK", "UID", "http_proxy", "TIMEOUT"]
    env_passthrough = {
        key: os.environ[key] for key in os.environ if key not in excluded_keys
    }
    env_passthrough.update(env)

    process = pexpect.spawn(
        pam_duo_path,
        args,
        cwd=TESTDIR,
        env=env_passthrough,
    )
    return process


def pam_duo(args, env={}, timeout=10):
    pam_duo_path = [os.path.join(TESTDIR, "testpam.py")]
    # we don't want to accidentally grab these from the calling environment
    excluded_keys = ["SSH_CONNECTION", "FALLBACK", "UID", "http_proxy", "TIMEOUT"]
    env_passthrough = {
        key: os.environ[key] for key in os.environ if key not in excluded_keys
    }
    env_passthrough.update(env)

    process = subprocess.Popen(
        pam_duo_path + args,
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
        raise PamDuoTimeoutException(stdout, stderr)

    stdout_lines = process.stdout.read().decode("utf-8").split("\n")
    stderr_lines = process.stderr.read().decode("utf-8").split("\n")

    process.stdout.close()
    process.stderr.close()
    process.stdin.close()

    try:
        process.terminate()
    except:
        pass

    return {
        "returncode": process.returncode,
        "stdout": stdout_lines,
        "stderr": stderr_lines,
    }


@unittest.skipIf(sys.platform == "sunos5", SOLARIS_ISSUE)
class TestPamDuoHelp(CommonTestCase):
    def test_help(self):
        result = pam_duo(["-h"])
        self.assertRegexSomeline(
            result["stderr"],
            r"Usage: .*/tests/testpam.py \[-d\] \[-c config\] \[-f user\] \[-h host\]",
        )


@unittest.skipIf(sys.platform == "sunos5", SOLARIS_ISSUE)
class TestPamDuoConfigs(CommonSuites.Configuration):
    def call_binary(self, *args):
        return pam_duo(*args)


@unittest.skipIf(sys.platform == "sunos5", SOLARIS_ISSUE)
class TestPamDuoDown(CommonSuites.DuoDown):
    def call_binary(self, *args):
        return pam_duo(*args)


@unittest.skipIf(sys.platform == "sunos5", SOLARIS_ISSUE)
class TestPamSelfSignedCerts(CommonSuites.DuoSelfSignedCert):
    def call_binary(self, *args):
        return pam_duo(*args)


@unittest.skipIf(sys.platform == "sunos5", SOLARIS_ISSUE)
class TestPamDuoBadCN(CommonSuites.DuoBadCN):
    def call_binary(self, *args):
        return pam_duo(*args)


@unittest.skipIf(sys.platform == "sunos5", SOLARIS_ISSUE)
class TestPamValidCerts(CommonSuites.WithValidCert):
    def call_binary(self, *args):
        return pam_duo(*args)


@unittest.skipIf(sys.platform == "sunos5", SOLARIS_ISSUE)
class TestPamPreauthStates(CommonSuites.PreauthStates):
    def call_binary(self, *args, **kwargs):
        return pam_duo(*args, **kwargs)


class TestPamEscapeInjection(CommonSuites.EscapeInjection):
    def call_binary(self, *args):
        return pam_duo(*args)


@unittest.skipIf(sys.platform == "sunos5", SOLARIS_ISSUE)
class TestPamHosts(CommonSuites.Hosts):
    def call_binary(self, *args, **kwargs):
        return pam_duo(timeout=15, *args, **kwargs)

    HOSTNAME_WARNING = r"Client address is not a valid IP address"

    def test_hostname_client_warns(self):
        """A non-IP PAM_RHOST is still sent, but logs the policy warning."""
        with TempConfig(MOCKDUO_CONF) as temp:
            result = self.call_binary(
                ["-d", "-c", temp.name, "-f", "preauth-allow", "-h", "nowhere", "true"]
            )
            self.assertRegexSomeline(result["stderr"], self.HOSTNAME_WARNING)
            # The hostname is still reported as the client address (no
            # behavior change; only a warning is added).
            self.assertRegexSomeline(
                result["stderr"],
                r"Skipped Duo login for 'preauth-allow' from nowhere: preauth-allowed",
            )

    def test_ip_client_does_not_warn(self):
        """A valid IPv4 literal must not trigger the hostname warning."""
        with TempConfig(MOCKDUO_CONF) as temp:
            result = self.call_binary(
                ["-d", "-c", temp.name, "-f", "preauth-allow", "-h", "1.2.3.4", "true"]
            )
            self.assertNotRegexAnyline(result["stderr"], self.HOSTNAME_WARNING)

    def test_ipv6_client_does_not_warn(self):
        """A valid IPv6 literal must not trigger the hostname warning.

        Guards the inet_pton(AF_INET6, ...) half of the condition, which is
        the only thing preventing a spurious warning on every IPv6 client.
        """
        with TempConfig(MOCKDUO_CONF) as temp:
            result = self.call_binary(
                ["-d", "-c", temp.name, "-f", "preauth-allow", "-h", "::1", "true"]
            )
            self.assertNotRegexAnyline(result["stderr"], self.HOSTNAME_WARNING)

    def test_local_session_does_not_warn(self):
        """A local session (empty PAM_RHOST, no -h) must stay silent.

        Guards the `ip[0] != '\\0'` check: without it, every local su/sudo
        session (empty PAM_RHOST -> ip = "") would fail both literal checks
        and emit a spurious warning.
        """
        with TempConfig(MOCKDUO_CONF) as temp:
            result = self.call_binary(
                ["-d", "-c", temp.name, "-f", "preauth-allow", "true"]
            )
            self.assertNotRegexAnyline(result["stderr"], self.HOSTNAME_WARNING)

    def test_hostname_with_fallback_warns_once(self):
        """With fallback_local_ip on, only the fallback warning fires.

        Guards the `else if`: downgrading it to a plain `if` would emit both
        the fallback-substitution warning and the hostname warning for the
        same login.
        """
        with TempConfig(MOCKDUO_FALLBACK) as temp:
            result = self.call_binary(
                ["-d", "-c", temp.name, "-f", "preauth-allow", "-h", "nowhere", "true"],
                env={"FALLBACK": "1"},
            )
            self.assertRegexSomeline(
                result["stderr"],
                r"fallback_local_ip is replacing the remote client address",
            )
            self.assertNotRegexAnyline(result["stderr"], self.HOSTNAME_WARNING)


@unittest.skipIf(sys.platform == "sunos5", SOLARIS_ISSUE)
class TestPamHTTPProxy(CommonSuites.HTTPProxy):
    def call_binary(self, *args, **kwargs):
        return pam_duo(*args, **kwargs)


class TestPamHTTPProxyAuth(CommonSuites.HTTPProxyAuth):
    def call_binary(self, *args, **kwargs):
        return pam_duo(*args, **kwargs)


@unittest.skipIf(sys.platform == "sunos5", SOLARIS_ISSUE)
class TestPamGetHostname(CommonSuites.GetHostname):
    def call_binary(self, *args, **kwargs):
        return pam_duo(*args, **kwargs)


@unittest.skipIf(sys.platform == "sunos5", SOLARIS_ISSUE)
class TestPamBSON(CommonSuites.InvalidBSON):
    def call_binary(self, *args, **kwargs):
        return pam_duo(*args, **kwargs)


@unittest.skipIf(sys.platform == "sunos5", SOLARIS_ISSUE)
class TestPamPrompts(CommonTestCase):
    def run(self, result=None):
        with MockDuo(NORMAL_CERT):
            return super(TestPamPrompts, self).run(result)

    def test_max_prompts_equals_one(self):
        with TempConfig(MOCKDUO_PROMPTS_1) as temp:
            result = pam_duo(["-d", "-f", "pam_prompt", "-c", temp.name, "true"])
            self.assertRegexSomeline(
                result["stderr"], "Failed Duo login for 'pam_prompt'"
            )
            self.assertRegexSomeline(
                result["stdout"], "Autopushing login request to phone..."
            )
            self.assertRegexSomeline(
                result["stdout"], "Invalid passcode, please try again."
            )

    def test_max_prompts_equals_maximum(self):
        with TempConfig(MOCKDUO_PROMPTS_DEFAULT) as temp:
            result = pam_duo(["-d", "-f", "pam_prompt", "-c", temp.name, "true"])
            for i in range(1, 4):
                self.assertRegex(
                    result["stderr"][i], "Failed Duo login for 'pam_prompt'"
                )

            for i in range(0, 6, 2):
                self.assertRegex(
                    result["stdout"][i], "Autopushing login request to phone..."
                )
                self.assertRegex(
                    result["stdout"][i + 1], "Invalid passcode, please try again."
                )


@unittest.skipIf(sys.platform == "sunos5", SOLARIS_ISSUE)
class TestPamEnv(CommonSuites.Env):
    def call_binary(self, *args, **kwargs):
        return pam_duo(*args, **kwargs)


@unittest.skipIf(sys.platform == "sunos5", SOLARIS_ISSUE)
class TestPamSpecificEnv(unittest.TestCase):
    def run(self, result=None):
        with MockDuo(NORMAL_CERT):
            return super(TestPamSpecificEnv, self).run(result)

    def test_no_user(self):
        with TempConfig(MOCKDUO_CONF) as temp:
            result = pam_duo(["-d", "-c", temp.name], env={"NO_USER": "1"})
            self.assertEqual(result["returncode"], 1)

    def test_su_service_bad_user(self):
        """Test that we return user unknown if we can't find the calling user"""
        with TempConfig(MOCKDUO_CONF) as temp:
            result = pam_duo(
                ["-d", "-c", temp.name],
                env={"SIMULATE_SERVICE": "su", "NO_USER": "1"},
            )
            self.assertEqual(result["returncode"], 1)


@unittest.skipIf(sys.platform == "sunos5", SOLARIS_ISSUE)
class TestPamPreauthFailures(CommonSuites.PreauthFailures):
    def call_binary(self, *args):
        return pam_duo(*args)


@unittest.skipIf(sys.platform == "sunos5", SOLARIS_ISSUE)
class TestPamDuoInteractive(CommonSuites.Interactive):
    INITIAL_TEXT = [".*CA bundle version.*"]

    def call_binary(self, *args, **kwargs):
        return pam_duo_interactive(*args, **kwargs)

    def test_su_service(self):
        """Test that the -f option is ignored if the service is Su"""
        with TempConfig(MOCKDUO_CONF) as temp:
            process = self.call_binary(
                ["-d", "-c", temp.name, "-f", "foobar", "true"],
                env={"SIMULATE_SERVICE": "su"},
            )
            # This is here to prevent race conditions with character entry
            process.expect(CommonSuites.Interactive.PROMPT_REGEX, timeout=10)
            process.sendline(b"2")
            self.assertEqual(process.expect(EOF), 0)
            user = getpass.getuser()
            self.assertOutputEqual(
                process.before,
                [
                    "2",
                    "Dialing XXX-XXX-1234...",
                    "Answered. Press '#' on your phone to log in.",
                    "Success. Logging you in...",
                    "[6] Successful Duo login for '{user}'".format(user=user),
                ],
            )


@unittest.skipIf(sys.platform == "sunos5", SOLARIS_ISSUE)
class TestPamdConf(unittest.TestCase):
    def test_invalid_argument(self):
        with TempConfig(MOCKDUO_CONF) as duo_config:
            pamd_conf = "auth  required  {libpath}/pam_duo.so conf={duo_config_path} notanarg".format(
                libpath=os.path.join(topbuilddir, "pam_duo", ".libs"),
                duo_config_path=duo_config.name,
            )
            with TempPamConfig(pamd_conf) as pam_config:
                process = testpam(
                    ["-d", "-c", duo_config.name, "-f", "whatever"], pam_config.name
                )
                self.assertEqual(process.returncode, 1)

    def test_multiple_invalid_argument(self):
        with TempConfig(MOCKDUO_CONF) as duo_config:
            pamd_conf = "auth  required  {libpath}/pam_duo.so debug conf={duo_config_path} notanarg1 notanarg2".format(
                libpath=os.path.join(topbuilddir, "pam_duo", ".libs"),
                duo_config_path=duo_config.name,
            )
            with TempPamConfig(pamd_conf) as pam_config:
                process = testpam(
                    ["-d", "-c", duo_config.name, "-f", "whatever"], pam_config.name, capture_output=True
                )
                self.assertEqual(process.returncode, 1)

                stderr = process.stderr.read().decode("utf-8").split("\n")
                stderr_text = "\n".join(stderr)
                process.stderr.close()
                if process.stdout:
                    process.stdout.close()
                self.assertRegex(stderr_text, r"Invalid pam_duo option: 'notanarg1'")
                self.assertRegex(stderr_text, r"Invalid pam_duo option: 'notanarg2'")


@unittest.skipIf(sys.platform == "sunos5", SOLARIS_ISSUE)
class TestPamGECOS(CommonTestCase):
    def run(self, result=None):
        with MockDuo(NORMAL_CERT):
            return super(TestPamGECOS, self).run(result)

    def test_gecos_field_unparsed(self):
        with TempConfig(MOCKDUO_GECOS_SEND_UNPARSED) as temp:
            result = pam_duo(
                ["-d", "-c", temp.name, "-f", "fullgecos", "true"],
            )
            self.assertRegexSomeline(
                result["stderr"],
                r"Skipped Duo login for 'full_gecos_field': full-gecos-field",
            )

    def test_deprecated_gecos_parsed_flag(self):
        with TempConfig(MOCKDUO_GECOS_DEPRECATED_PARSE_FLAG) as temp:
            result = pam_duo(
                ["-d", "-c", temp.name, "-f", "gecos/6", "true"],
            )
            self.assertRegexSomeline(
                result["stderr"],
                r"The gecos_parsed configuration item for Duo Unix is deprecated and no longer has any effect. Use gecos_delim and gecos_username_pos instead",
            )
            self.assertRegexSomeline(
                result["stderr"],
                "Skipped Duo login for 'gecos/6': gecos/6",
            )

    def test_gecos_delimiter_default_position_6(self):
        with TempConfig(MOCKDUO_GECOS_DEFAULT_DELIM_6_POS) as temp:
            result = pam_duo(
                ["-d", "-c", temp.name, "-f", "gecos,6", "true"],
            )
            self.assertRegexSomeline(
                result["stderr"],
                "Skipped Duo login for 'gecos_user_gecos_field6': gecos-user-gecos-field6-allowed",
            )

    def test_gecos_delimiter_slash_position_3(self):
        with TempConfig(MOCKDUO_GECOS_SLASH_DELIM_3_POS) as temp:
            result = pam_duo(
                ["-d", "-c", temp.name, "-f", "gecos/3", "true"],
            )
            self.assertRegexSomeline(
                result["stderr"],
                r"Skipped Duo login for 'gecos_user_gecos_field3': gecos-user-gecos-field3-allowed",
            )

    def test_gecos_invalid_delimiter_length(self):
        with TempConfig(MOCKDUO_GECOS_LONG_DELIM) as temp:
            result = pam_duo(
                ["-d", "-c", temp.name, "true"],
            )
            self.assertRegex(
                result["stderr"][0],
                r"Invalid character option length. Character fields must be 1 character long: ',,'",
            )
            self.assertRegex(
                result["stderr"][1],
                r"Invalid pam_duo option: 'gecos_delim'",
            )
            self.assertRegex(
                result["stderr"][2],
                r"Parse error in {config}, line \d+".format(config=temp.name),
            )

    def test_invalid_delimiter_value_colon(self):
        for config in [
            MOCKDUO_GECOS_INVALID_DELIM_COLON,
            MOCKDUO_GECOS_INVALID_DELIM_PUNC,
        ]:
            with TempConfig(config) as temp:
                result = pam_duo(
                    ["-d", "-c", temp.name, "true"],
                )
                self.assertIn(
                    "Invalid gecos_delim '{delim}' (delimiter must be punctuation other than ':')".format(
                        delim=config["gecos_delim"]
                    ),
                    result["stderr"],
                )
                self.assertRegexSomeline(
                    result["stderr"],
                    r"Invalid pam_duo option: 'gecos_delim'",
                )
                self.assertRegexSomeline(
                    result["stderr"],
                    r"Parse error in {config}, line \d+".format(config=temp.name),
                )

    def test_invalid_delimiter_value_whitespace(self):
        with TempConfig(MOCKDUO_GECOS_INVALID_DELIM_WHITESPACE) as temp:
            result = pam_duo(
                ["-d", "-c", temp.name, "true"],
            )
            self.assertEqual(
                result["stderr"][0],
                "Invalid character option length. Character fields must be 1 character long: ''",
            )
            self.assertRegex(
                result["stderr"][1],
                r"Invalid pam_duo option: 'gecos_delim'",
            )
            self.assertRegex(
                result["stderr"][2],
                r"Parse error in {config}, line \d+".format(config=temp.name),
            )

    def test_invalid_pos_value(self):
        with TempConfig(MOCKDUO_GECOS_INVALID_POS) as temp:
            result = pam_duo(
                ["-d", "-c", temp.name, "true"],
            )
            self.assertEqual(
                result["stderr"][0],
                "Gecos position starts at 1",
            )
            self.assertRegex(
                result["stderr"][1],
                r"Invalid pam_duo option: 'gecos_username_pos'",
            )
            self.assertRegex(
                result["stderr"][2],
                r"Parse error in {config}, line \d+".format(config=temp.name),
            )

    def test_gecos_parsing_error(self):
        with TempConfig(MOCKDUO_GECOS_SLASH_DELIM_3_POS) as temp:
            process = pam_duo_interactive(
                ["-d", "-c", temp.name, "-f", "gecos,3"],
            )
            self.assertEqual(process.expect("Could not parse GECOS field"), 0)

    def test_gecos_only_delim(self):
        with TempConfig(MOCKDUO_GECOS_DEFAULT_DELIM_6_POS) as temp:
            process = pam_duo_interactive(
                ["-d", "-c", temp.name, "-f", "onlydelim"],
            )
            self.assertEqual(process.expect("Could not parse GECOS field"), 0)

    def test_gecos_empty(self):
        with TempConfig(MOCKDUO_GECOS_SEND_UNPARSED) as temp:
            process = pam_duo_interactive(
                ["-d", "-c", temp.name, "-f", "emptygecos"],
            )
            self.assertEqual(process.expect("Empty GECOS field"), 0)


@unittest.skipIf(sys.platform == "sunos5", SOLARIS_ISSUE)
class TestPamDuoIPv6(CommonTestCase):
    def run(self, result=None):
        with MockDuo(NORMAL_CERT):
            return super(TestPamDuoIPv6, self).run(result)

    def test_ipv6_rhost_not_replaced_by_fallback(self):
        """IPv6 PAM_RHOST must be sent as-is, not replaced by duo_local_ip()"""
        with TempConfig(MOCKDUO_FALLBACK) as temp:
            result = pam_duo(
                ["-d", "-c", temp.name, "-f", "preauth-allow", "-h", "::1"],
                env={
                    "FALLBACK": "1",
                },
            )
            self.assertRegexSomeline(
                result["stderr"],
                r"Skipped Duo login for 'preauth-allow' from ::1",
            )

    def test_hostname_rhost_still_triggers_fallback(self):
        """Non-IP PAM_RHOST should still trigger duo_local_ip() fallback"""
        with TempConfig(MOCKDUO_FALLBACK) as temp:
            result = pam_duo(
                ["-d", "-c", temp.name, "-f", "preauth-allow", "-h", "badhost.example.com"],
                env={
                    "FALLBACK": "1",
                },
            )
            self.assertRegexSomeline(
                result["stderr"],
                r"Skipped Duo login for 'preauth-allow' from 1\.2\.3\.4",
            )


@unittest.skipIf(sys.platform == "sunos5", SOLARIS_ISSUE)
class TestPamDuoVerifiedPush(CommonTestCase):
    """Verified Push code display for sshd (sync) and other services (async)"""

    PROMPT_REGEX = CommonSuites.Interactive.PROMPT_REGEX
    CODE_LINE = "If Duo Mobile asks for a code, enter " + VERIFIED_PUSH_CODE
    SSHD = {"SIMULATE_SERVICE": "sshd"}

    def run(self, result=None):
        with MockDuo(NORMAL_CERT):
            return super(TestPamDuoVerifiedPush, self).run(result)

    def start(self, temp, user, env=None):
        process = pam_duo_interactive(
            ["-d", "-c", temp.name, "-f", user, "true"], env=env or {}
        )
        process.expect(self.PROMPT_REGEX, timeout=10)
        return process, (process.before + process.after).decode()

    def finish(self, process, choice=b"1"):
        process.sendline(choice)
        self.assertEqual(process.expect(EOF, timeout=10), 0)
        return process.before.decode()

    def test_sshd_prompt_shows_code(self):
        with TempConfig(MOCKDUO_VERIFIED_PUSH) as temp:
            process, prompt = self.start(temp, VP_USER, self.SSHD)
            # On its own line, between the factor list and the input line
            self.assertIn(
                "  4. Phone 2 (deny)\r\n\r\n"
                + self.CODE_LINE
                + "\r\n\r\nPasscode or option (1-4): ",
                prompt,
            )
            output = self.finish(process)
            self.assertIn("Success. Logging you in...", output)
            self.assertIn("Successful Duo login for '{0}'".format(VP_USER), output)
            self.assertNotIn(VERIFIED_PUSH_CODE, output)

    def test_async_service_shows_code_once(self):
        with TempConfig(MOCKDUO_VERIFIED_PUSH) as temp:
            process, prompt = self.start(temp, VP_USER)
            self.assertNotIn(VERIFIED_PUSH_CODE, prompt)
            output = self.finish(process)
            self.assertEqual(output.count(VERIFIED_PUSH_CODE), 1)
            self.assertIn(
                "Please enter verification code {0} into Duo Mobile...".format(
                    VERIFIED_PUSH_CODE
                ),
                output,
            )
            self.assertIn("Successful Duo login for '{0}'".format(VP_USER), output)

    def assert_retry(self, user, message, log_error):
        with TempConfig(MOCKDUO_VERIFIED_PUSH) as temp:
            process, prompt = self.start(temp, user, self.SSHD)
            self.assertIn(self.CODE_LINE, prompt)
            process.sendline(b"1")
            # The attempt fails and a fresh preauth prompts again
            self.assertEqual(process.expect(self.PROMPT_REGEX, timeout=10), 0)
            retry = (process.before + process.after).decode()
            self.assertIn(message, retry)
            self.assertIn(
                "Failed Duo login for '{0}': {1}".format(user, log_error), retry
            )
            self.assertNotIn("Aborted Duo login", retry)
            self.assertIn(self.CODE_LINE, retry)
            process.terminate(force=True)

    def test_sshd_expired_before_auth_retries(self):
        """Preauth expiration already passed when the user answers"""
        self.assert_retry(
            VP_EXPIRED_USER,
            "Login request expired, please try again.",
            "Verified Push request expired before /auth",
        )

    def test_sshd_auth_rejected_retries(self):
        """/auth answers HTTP 400: retry, and log the server's error"""
        self.assert_retry(
            VP_REJECTED_USER,
            "Login request could not be completed, please try again.",
            "Verified Push request rejected by /auth: HTTP 400 40002: "
            "Invalid request parameters "
            "(No verification code found for the given txid.)",
        )

    def test_sshd_auth_rejected_without_body_retries(self):
        """/auth answers HTTP 400 with no JSON body"""
        self.assert_retry(
            VP_REJECTED_EMPTY_USER,
            "Login request could not be completed, please try again.",
            "Verified Push request rejected by /auth: HTTP 400 0: (no message)",
        )

    def test_sshd_expired_passcode_left_to_server(self):
        """The local expiry check only applies to push; /auth decides for others"""
        with TempConfig(MOCKDUO_VERIFIED_PUSH) as temp:
            process, _ = self.start(temp, VP_EXPIRED_USER, self.SSHD)
            process.sendline(b"123456")
            self.assertEqual(process.expect(self.PROMPT_REGEX, timeout=10), 0)
            retry = (process.before + process.after).decode()
            # Reached the mock's /auth, which rejects this passcode
            self.assertIn("Invalid passcode, please try again.", retry)
            self.assertNotIn("Login request expired", retry)
            process.terminate(force=True)

    def test_sshd_non_numeric_code_not_shown(self):
        with TempConfig(MOCKDUO_VERIFIED_PUSH) as temp:
            process, prompt = self.start(temp, VP_BAD_CODE_USER, self.SSHD)
            self.assertNotIn("If Duo Mobile asks for a code", prompt)
            self.assertNotIn("12ab", prompt)
            output = self.finish(process)
            self.assertIn(
                "Successful Duo login for '{0}'".format(VP_BAD_CODE_USER), output
            )

    def test_sshd_no_code_from_server(self):
        with TempConfig(MOCKDUO_VERIFIED_PUSH) as temp:
            process, prompt = self.start(temp, VP_IGNORED_USER, self.SSHD)
            self.assertNotIn("If Duo Mobile asks for a code", prompt)
            output = self.finish(process)
            self.assertIn(
                "Successful Duo login for '{0}'".format(VP_IGNORED_USER), output
            )

    def test_sshd_verified_push_disabled(self):
        with TempConfig(MOCKDUO_CONF) as temp:
            process, prompt = self.start(temp, "foobar", self.SSHD)
            self.assertNotIn("If Duo Mobile asks for a code", prompt)
            process.terminate(force=True)


MEM_FLOOR = 1024 * 1024 * 1024
NOFILE_FLOOR = 1024
FD_HEADROOM = 16


def _can_raise_hard_rlimit():
    """True if a child process can raise a hard limit it has lowered.

    Raising a hard limit needs privilege (CAP_SYS_RESOURCE on Linux), which
    root inside a container may not have.
    """
    code = (
        "import resource as r\n"
        "s, h = r.getrlimit(r.RLIMIT_NOFILE)\n"
        "r.setrlimit(r.RLIMIT_NOFILE, (64, 64))\n"
        "r.setrlimit(r.RLIMIT_NOFILE, (2048, 2048))\n"
    )
    return subprocess.call([sys.executable, "-c", code]) == 0


def _parse_rlimit_reports(stderr_lines):
    """Map "before"/"during"/"after" to a list of {name: (cur, max)} dicts."""
    reports = {}
    for line in stderr_lines:
        if not line.startswith("TESTPAM rlimits "):
            continue
        when, _, rest = line[len("TESTPAM rlimits "):].partition(":")
        limits = {}
        for item in rest.split():
            name, _, value = item.partition("=")
            if ":" not in value:
                limits[name] = int(value)
                continue
            cur, _, hard = value.partition(":")
            limits[name] = (
                float("inf") if cur == "inf" else int(cur),
                float("inf") if hard == "inf" else int(hard),
            )
        reports.setdefault(when, []).append(limits)
    return reports


@unittest.skipIf(sys.platform != "linux", "resource limit tests are Linux-only")
@unittest.skipUnless(_can_raise_hard_rlimit(), "needs privilege to raise hard limits")
class TestPamResourceLimits(CommonTestCase):
    def run(self, result=None):
        with MockDuo(NORMAL_CERT):
            return super(TestPamResourceLimits, self).run(result)

    def _run_with_limits(self, spec):
        with TempConfig(MOCKDUO_CONF) as temp:
            result = pam_duo(
                ["-d", "-c", temp.name, "-f", "preauth-deny", "true"],
                env={"TESTPAM_RLIMITS": spec, "TESTPAM_REPORT_RLIMITS": "1"},
            )
        return result, _parse_rlimit_reports(result["stderr"])

    def test_low_limits_raised_during_auth_and_restored(self):
        """Limits below the floor are raised for authentication, then restored"""
        mem = 64 * 1024 * 1024
        result, reports = self._run_with_limits(
            "AS:{0},DATA:{0},NOFILE:64".format(mem)
        )
        self.assertRegexSomeline(
            result["stderr"], r"Aborted Duo login for 'preauth-deny'"
        )
        self.assertNotEqual(result["returncode"], 0)

        self.assertIn("during", reports)
        for during in reports["during"]:
            for name in ("AS", "DATA"):
                self.assertGreaterEqual(during[name][0], MEM_FLOOR)
                self.assertGreaterEqual(during[name][1], MEM_FLOOR)
            self.assertGreaterEqual(during["NOFILE"][0], NOFILE_FLOOR)

        self.assertEqual(reports["before"][0]["AS"], (mem, mem))
        self.assertEqual(reports["after"], reports["before"])

    def test_fd_headroom_with_occupied_descriptors(self):
        """Free descriptors are made available even when the limit is above the floor"""
        result, reports = self._run_with_limits("NOFILE:1024,FILLFDS:2")
        self.assertRegexSomeline(
            result["stderr"], r"Aborted Duo login for 'preauth-deny'"
        )
        self.assertNotEqual(result["returncode"], 0)

        self.assertIn("during", reports)
        for during in reports["during"]:
            self.assertGreaterEqual(during["FREEFD"], FD_HEADROOM)
        self.assertEqual(reports["after"], reports["before"])

    def test_fd_headroom_with_many_descriptors_above_limit(self):
        """Free descriptors are made available however many are open above the limit"""
        result, reports = self._run_with_limits(
            "NOFILE:1024,FILLFDS:0,FILLABOVE:6000"
        )
        self.assertRegexSomeline(
            result["stderr"], r"Aborted Duo login for 'preauth-deny'"
        )
        self.assertNotEqual(result["returncode"], 0)

        self.assertIn("during", reports)
        for during in reports["during"]:
            self.assertGreaterEqual(during["FREEFD"], FD_HEADROOM)
        self.assertEqual(reports["after"], reports["before"])

    def test_limits_above_floor_unchanged(self):
        """Limits already at or above the floor are left alone"""
        mem = 2 * MEM_FLOOR
        result, reports = self._run_with_limits(
            "AS:{0},DATA:{0},NOFILE:4096".format(mem)
        )
        self.assertNotEqual(result["returncode"], 0)
        self.assertIn("during", reports)
        for during in reports["during"]:
            during = {k: v for k, v in during.items() if k != "FREEFD"}
            self.assertEqual(during, reports["before"][0])
        self.assertEqual(reports["after"], reports["before"])


@unittest.skipIf(sys.platform != "linux", "open() error injection is Linux-only")
class TestPamConfigOpenErrors(CommonTestCase):
    """How a failed open() of the config file affects the result, with failmode=safe"""

    def _auth_with_open_error(self, err):
        config = DuoUnixConfig(MOCKDUO_CONF, failmode="safe")
        with TempConfig(config) as temp:
            return pam_duo(
                ["-d", "-c", temp.name, "-f", "preauth-allow", "true"],
                env={
                    "TESTPAM_OPEN_FAIL_PATH": temp.name,
                    "TESTPAM_OPEN_FAIL_ERRNO": str(err),
                },
            )

    def test_resource_errors_deny(self):
        """Running out of descriptors or memory denies authentication"""
        for err in (errno.EMFILE, errno.ENFILE, errno.ENOMEM):
            with self.subTest(errno=errno.errorcode[err]):
                result = self._auth_with_open_error(err)
                self.assertRegexSomeline(
                    result["stderr"], r"Couldn't open .*: " + os.strerror(err)
                )
                self.assertNotEqual(result["returncode"], 0)

    def test_other_errors_follow_failmode(self):
        """Other open() errors still follow failmode"""
        for err in (errno.ENOENT, errno.EACCES):
            with self.subTest(errno=errno.errorcode[err]):
                result = self._auth_with_open_error(err)
                self.assertRegexSomeline(
                    result["stderr"], r"Couldn't open .*: " + os.strerror(err)
                )
                self.assertEqual(result["returncode"], 0)


if __name__ == "__main__":
    unittest.main()
