import os
import socket
import subprocess
import time

from paths import topbuilddir

TESTDIR = os.path.realpath(os.path.dirname(__file__))

WRONGHOST_CERT = os.path.join(TESTDIR, "certs", "mockduo-wronghost.pem")
NORMAL_CERT = os.path.join(TESTDIR, "certs", "mockduo.pem")
SELFSIGNED_CERT = os.path.join(TESTDIR, "certs", "selfsigned.pem")


def port_open(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((ip, int(port)))
        s.shutdown(2)
        s.close()
        return True
    except:
        s.close()
        return False
    finally:
        s.close()


class MockDuoException(Exception):
    def __init__(self, returncode, cmd, stderr, stdout):
        self.returncode = returncode
        self.cmd = cmd
        self.stderr = stderr
        self.stdout = stdout

    def __str__(self):
        if self.stderr:
            stderr_output = "STDERR:\n{stderr}".format(stderr=self.stderr)
        else:
            stderr_output = ""

        if self.stdout:
            stdout_output = "STDOUT:\n{stdout}".format(stdout=self.stdout)
        else:
            stdout_output = ""

        return "Command: '{cmd}' returned non-zero exit code: {returncode}\n{stdout}{stderr}".format(
            cmd=self.cmd,
            returncode=self.returncode,
            stderr=stderr_output,
            stdout=stdout_output,
        )


class MockDuoTimeoutException(MockDuoException):
    def __str__(self):
        return (
            "Timeout starting MockDuo\n"
            + super(MockDuoTimeoutException, self).__str__()
        )


class MockDuo:
    def __init__(self, cert=NORMAL_CERT):
        self.cert = cert
        self.cmd = ["python3", os.path.join(TESTDIR, "mockduo.py"), self.cert]
        self.process = None

    def __enter__(self):
        self.process = subprocess.Popen(
            self.cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # wait a couple of seconds max for the local server to start
        for i in range(0, 80):
            if port_open("127.0.0.1", 4443):
                break
            time.sleep(0.05)
        else:
            stderr = self.process.stderr.read().decode("utf-8")
            stdout = self.process.stdout.read().decode("utf-8")
            self.process.stderr.close()
            self.process.stdout.close()

            if self.process.stdin:
                self.process.stdin.close()

            self.process.wait()
            raise MockDuoTimeoutException(
                returncode=None,
                cmd=self.cmd,
                stderr=stderr,
                stdout=stdout,
            )

        time.sleep(0.3)
        return self.process

    def __exit__(self, type, value, traceback):
        try:
            returncode = self.process.poll()
            if returncode is None:
                self.process.terminate()
                return

            stderr = self.process.stderr.read().decode("utf-8")
            stdout = self.process.stdout.read().decode("utf-8")
            if returncode != 0:
                raise MockDuoException(
                    returncode=returncode,
                    cmd=self.cmd,
                    stderr=stderr,
                    stdout=stdout,
                )
        finally:
            self.process.stderr.close()
            self.process.stdout.close()
            self.process.terminate()
            self.process.wait()
