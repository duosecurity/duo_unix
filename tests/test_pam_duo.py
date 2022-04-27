#!/usr/bin/env python3
import getpass
import os
import subprocess
import time
import unittest

import pexpect
from common_suites import NORMAL_CERT, CommonSuites
from config import (
    MOCKDUO_CONF,
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
    TempConfig,
)
from mockduo_context import MockDuo
from paths import topbuilddir
from testpam import TempPamConfig, testpam

TESTDIR = os.path.realpath(os.path.dirname(__file__))


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


def pam_duo(args, env={}, timeout=2):
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


class TestPamDuoHelp(unittest.TestCase):
    def test_help(self):
        result = pam_duo(["-h"])
        self.assertRegex(
            result["stderr"][0],
            r"Usage: .*/tests/testpam.py \[-d\] \[-c config\] \[-f user\] \[-h host\]",
        )


class TestPamDuoConfigs(CommonSuites.Configuration):
    def call_binary(self, *args):
        return pam_duo(*args)


class TestPamDuoDown(CommonSuites.DuoDown):
    def call_binary(self, *args):
        return pam_duo(*args)


class TestPamSelfSignedCerts(CommonSuites.DuoSelfSignedCert):
    def call_binary(self, *args):
        return pam_duo(*args)


class TestPamDuoBadCN(CommonSuites.DuoBadCN):
    def call_binary(self, *args):
        return pam_duo(*args)


class TestPamValidCerts(CommonSuites.WithValidCert):
    def call_binary(self, *args):
        return pam_duo(*args)


class TestPamPreauthStates(CommonSuites.PreauthStates):
    def call_binary(self, *args):
        return pam_duo(*args)


class TestPamHosts(CommonSuites.Hosts):
    def call_binary(self, *args, **kwargs):
        return pam_duo(timeout=15, *args, **kwargs)


class TestPamHTTPProxy(CommonSuites.HTTPProxy):
    def call_binary(self, *args, **kwargs):
        return pam_duo(*args, **kwargs)


class TestPamFIPS(CommonSuites.FIPS):
    def call_binary(self, *args, **kwargs):
        return pam_duo(*args, **kwargs)


class TestPamGetHostname(CommonSuites.GetHostname):
    def call_binary(self, *args, **kwargs):
        return pam_duo(*args, **kwargs)


class TestPamBSON(CommonSuites.InvalidBSON):
    def call_binary(self, *args, **kwargs):
        return pam_duo(*args, **kwargs)


class TestPamPrompts(unittest.TestCase):
    def run(self, result=None):
        with MockDuo(NORMAL_CERT):
            return super(TestPamPrompts, self).run(result)

    def test_max_prompts_equals_one(self):
        with TempConfig(MOCKDUO_PROMPTS_1) as temp:
            result = pam_duo(["-d", "-f", "pam_prompt", "-c", temp.name, "true"])
            self.assertRegex(result["stderr"][0], "Failed Duo login for 'pam_prompt'")
            self.assertRegex(
                result["stdout"][0], "Autopushing login request to phone..."
            )
            self.assertRegex(result["stdout"][1], "Invalid passcode, please try again.")

    def test_max_prompts_equals_maximum(self):
        with TempConfig(MOCKDUO_PROMPTS_DEFAULT) as temp:
            result = pam_duo(["-d", "-f", "pam_prompt", "-c", temp.name, "true"])
            for i in range(0, 3):
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


class TestPamEnv(CommonSuites.Env):
    def call_binary(self, *args, **kwargs):
        return pam_duo(*args, **kwargs)


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


class TestPamPreauthFailures(CommonSuites.PreauthFailures):
    def call_binary(self, *args):
        return pam_duo(*args)


class TestPamDuoInteractive(CommonSuites.Interactive):
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
            self.assertEqual(process.expect(pexpect.EOF), 0)
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


class TestPamGECOS(unittest.TestCase):
    def run(self, result=None):
        with MockDuo(NORMAL_CERT):
            return super(TestPamGECOS, self).run(result)

    def test_gecos_field_unparsed(self):
        with TempConfig(MOCKDUO_GECOS_SEND_UNPARSED) as temp:
            result = pam_duo(
                ["-d", "-c", temp.name, "-f", "fullgecos", "true"],
            )
            self.assertRegex(
                result["stderr"][0],
                r"Skipped Duo login for 'full_gecos_field': full-gecos-field",
            )

    def test_deprecated_gecos_parsed_flag(self):
        with TempConfig(MOCKDUO_GECOS_DEPRECATED_PARSE_FLAG) as temp:
            result = pam_duo(
                ["-d", "-c", temp.name, "-f", "gecos/6", "true"],
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
            result = pam_duo(
                ["-d", "-c", temp.name, "-f", "gecos,6", "true"],
            )
            self.assertRegex(
                result["stderr"][0],
                "Skipped Duo login for 'gecos_user_gecos_field6': gecos-user-gecos-field6-allowed",
            )

    def test_gecos_delimiter_slash_position_3(self):
        with TempConfig(MOCKDUO_GECOS_SLASH_DELIM_3_POS) as temp:
            result = pam_duo(
                ["-d", "-c", temp.name, "-f", "gecos/3", "true"],
            )
            self.assertRegex(
                result["stderr"][0],
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
                self.assertEqual(
                    result["stderr"][0],
                    "Invalid gecos_delim '{delim}' (delimiter must be punctuation other than ':')".format(
                        delim=config["gecos_delim"]
                    ),
                )
                self.assertRegex(
                    result["stderr"][1],
                    r"Invalid pam_duo option: 'gecos_delim'",
                )
                self.assertRegex(
                    result["stderr"][2],
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


if __name__ == "__main__":
    unittest.main()
