#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-with-classpath-exception
#
# Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
# All rights reserved.
#
# mockduo.py
#

import cgi
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import email.utils
import calendar

try:
    from hashlib import sha512
except ImportError:
    import sha as sha512

import base64
import hmac
import os
import socket
import ssl
import sys
import time
import urllib
import urllib.parse

IKEY = "DIXYZV6YM8IFYVWBINCA"
SKEY = b"yWHSMhWucAcp7qvuH3HWTaSaKABs8Gaddiv1NIRo"
# Used to check if the FQDN is set to either the ipv4 or ipv6 address
IPV6_LOOPBACK_ADDR = (
    "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa"
)
IPV4_LOOPBACK_ADDR = "1.0.0.127.in-addr.arpa"
VERIFIED_PUSH_TXID = "verified-push-txid"

tx_msgs = {
    VERIFIED_PUSH_TXID: [
        "0:Please enter verification code 376 into Duo Mobile...",
        "1:Success. Logging you in...",
    ],
    "txPUSH1": [
        "0:Pushed a login request to your phone.",
        "1:Success. Logging you in...",
    ],
    "txVOICE1": [
        "0:Dialing XXX-XXX-1234...",
        "1:Answered. Press '#' on your phone to log in.",
        "1:Success. Logging you in...",
    ],
    "txSMSREFRESH1": ["0:New SMS passcodes sent"],
    "txVOICE2": [
        "0:Dialing XXX-XXX-5678...",
        "1:Answered. Press '#' on your phone to log in.",
        "2:Authentication timed out.",
    ],
}


class MockDuoHandler(BaseHTTPRequestHandler):
    server_version = "MockDuo/1.0"
    protocol_version = "HTTP/1.1"

    # Class variables for skew simulation
    _skew_permanent = 0
    _skew_once = None

    def __init__(self, *args, **kwargs):
        self._rl_req_clock = 0
        self._rl_req_num = 0
        self.path = ""
        self.qs = ""
        self.args = {}
        self.method = ""
        super().__init__(*args, **kwargs)

    def _get_skew(self):
        # Return one-time skew if set, then clear it
        if type(self)._skew_once is not None:
            skew = type(self)._skew_once
            type(self)._skew_once = None
            return skew
        return type(self)._skew_permanent

    def _verify_sig(self):
        authz = base64.b64decode(self.headers["Authorization"].split()[1]).decode(
            "utf-8"
        )
        ikey, sig = authz.split(":")
        if ikey != IKEY:
            return False

        # first look for x-duo-date header
        datestring = self.headers.get("x-duo-date")
        if datestring is None:
            # if it doesn't exist, try looking for Date header
            datestring = self.headers.get("Date")

        if datestring is None:
            return False

        # Parse the date header and check if it's within a reasonable window
        datetuple = email.utils.parsedate_tz(datestring)
        if datetuple is None:
            return False
        try:
            date = calendar.timegm(datetuple[:9])
        except Exception:
            return False
        if datetuple[9] is not None:
            date -= datetuple[9]
        # Use special skew for test usernames
        skew = self._get_skew()
        now = time.time() + skew
        sig_window = 300  # 5 minutes
        if abs(date - now) > sig_window:
            return False

        canon = [datestring, self.method, self.headers["Host"].split(":")[0].lower(), self.path]
        l = []
        for k in sorted(self.args.keys()):
            l.append(
                "{0}={1}".format(
                    urllib.parse.quote(k, "~"), urllib.parse.quote(self.args[k], "~")
                )
            )
        canon.append("&".join(l))
        h = hmac.new(SKEY, ("\n".join(canon)).encode("utf8"), digestmod="sha512")

        return sig == h.hexdigest()

    def _get_args(self):
        if self.method == "POST":
            env = {
                "REQUEST_METHOD": "POST",
                "CONTENT_TYPE": self.headers["Content-Type"],
            }
            fs = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ=env)
            args = {}
            for k in fs.keys():
                args[k] = fs[k].value
        else:
            args = dict(urllib.parse.parse_qsl(self.qs))
        print("got {0} {1} args: {2}".format(self.method, self.path, args))
        return args

    def _get_tx_response(self, txid, is_async):
        last = True
        if txid not in tx_msgs:
            secs, msg = 0, "Invalid passcode, please try again."
        elif is_async:
            secs, msg = tx_msgs[txid].pop(0).split(":", 1)
            last = not tx_msgs[txid]
        else:
            secs, msg = tx_msgs[txid][-1].split(":", 1)

        if msg.startswith("Success"):
            rsp = {"result": "allow", "status_msg": msg}
        elif is_async and not last:
            rsp = {"result": "waiting", "status_msg": msg}
        else:
            rsp = {"result": "deny", "status_msg": msg}
        time.sleep(int(secs))
        return rsp

    def _send(self, code, buf=b"", headers=None):
        self.send_response(code)
        self.send_header("Content-length", str(len(buf)))
        if headers:
            for key, value in headers.items():
                self.send_header(key, value)
        if buf:
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(buf.encode("utf8"))
        else:
            self.end_headers()

    def do_GET(self):
        self.method = "GET"
        if "?" in self.path:
            self.path, self.qs = self.path.split("?", 1)
            self.args = self._get_args()
        else:
            self.qs = ""
            self.args = {}

        # Special endpoint to set skew
        if self.path == "/mockduo/set-skew":
            try:
                skew = int(self.args.get("skew", "0"))
                mode = self.args.get("mode", "permanent")
                if mode == "once":
                    type(self)._skew_once = skew
                else:
                    type(self)._skew_permanent = skew
                self._send(200, json.dumps({"stat": "OK", "skew": skew, "mode": mode}))
            except Exception as e:
                self._send(400, json.dumps({"stat": "FAIL", "error": str(e)}))
            return self._send(200)

        ret = {"stat": "OK"}

        if self.path == "/auth/v2/ping":
            skew = self._get_skew()
            ret["response"] = {"time": int(time.time()) + skew}
            buf = json.dumps(ret)
            return self._send(200, buf)

        if not self._verify_sig():
            return self._send(401)

        if self.path == "/auth/v2/auth_status":
            ret["response"] = self._get_tx_response(self.args["txid"], 1)
            buf = json.dumps(ret)
            return self._send(200, buf)

        self._send(404)

    def hostname_check(self, hostname):
        domain_fqdn = socket.getfqdn().lower()
        if hostname == domain_fqdn.lower() or hostname == socket.gethostname().lower():
            return True
        # Check if socket.getfqdn() is the loopback address for ipv4 or ipv6 then check the hostname of the machine
        if domain_fqdn == IPV6_LOOPBACK_ADDR or domain_fqdn == IPV4_LOOPBACK_ADDR:
            if hostname == socket.gethostbyaddr(socket.gethostname())[0].lower():
                return True
        return False

    def do_POST(self):
        self.method = "POST"
        self.args = self._get_args()
        buf = None

        if not self._verify_sig():
            return self._send(401)

        try:
            return self._send(int(self.args["username"]))
        except:
            ret = {"stat": "OK"}

        if self.path == "/auth/v2/preauth":
            # text_prompt should always be set
            if not bool(self.args.get("text_prompt")):
                ret = {"stat": "FAIL", "code": 1000, "message": "No text prompt was requested"}
            if self.args["username"] == "preauth-ok-missing_response":
                pass
            elif self.args["username"] == "preauth-fail-missing_response":
                ret["stat"] = "FAIL"
            elif self.args["username"] == "preauth-bad-stat":
                ret["stat"] = "BAD_STATUS"
            elif self.args["username"] == "preauth-fail":
                ret = {
                    "stat": "FAIL",
                    "code": 1000,
                    "message": "Pre-authentication failed",
                }
            elif self.args["username"] == "preauth-deny":
                ret["response"] = {"result": "deny", "status_msg": "preauth-denied"}
            elif self.args["username"] == "preauth-allow":
                ret["response"] = {"result": "allow", "status_msg": "preauth-allowed"}
            elif self.args["username"] == "preauth-allow-bad_response":
                ret["response"] = {
                    "result": "allow",
                    "xxx": "preauth-allowed-bad-response",
                }
            elif self.args["username"] == "hostname":
                if self.hostname_check(self.args["hostname"].lower()):
                    ret["response"] = {"result": "deny", "status_msg": "correct hostname"}
                else:
                    response = (
                        "hostname received: "
                        + self.args["hostname"]
                        + " found: "
                        + socket.getfqdn()
                    )
                    ret["response"] = {"result": "deny", "status_msg": response}
            elif self.args["username"] == "failopen":
                if self.args["failmode"] == "open":
                    ret["response"] = {"result": "deny", "status_msg": "correct failmode"}
                else:
                    ret["response"] = {"result": "deny", "status_msg": "incorrect failmode"}
            elif self.args["username"] == "failclosed":
                if self.args["failmode"] == "closed":
                    ret["response"] = {"result": "deny", "status_msg": "correct failmode"}
                else:
                    ret["response"] = {"result": "deny", "status_msg": "incorrect failmode"}
            elif self.args["username"] == "gecos_user_gecos_field6":
                ret["response"] = {
                    "result": "allow",
                    "status_msg": "gecos-user-gecos-field6-allowed",
                }
            elif self.args["username"] == "gecos_user_gecos_field3":
                ret["response"] = {
                    "result": "allow",
                    "status_msg": "gecos-user-gecos-field3-allowed",
                }
            elif self.args["username"] == "full_gecos_field":
                ret["response"] = {"result": "allow", "status_msg": "full-gecos-field"}
            elif self.args["username"] == "gecos/6":
                ret["response"] = {"result": "allow", "status_msg": "gecos/6"}
            elif self.args["username"] == "enroll":
                ret["response"] = {
                    "enroll_portal_url": "https://api-abcd1234.duosecurity.com/portal?code=48bac5d9393fb2c2&akey=DIXXXXXXXXXXXXXXXXXX",
                    "result": "enroll",
                    "status_msg": "Enroll an authentication device to proceed"
                }
                if self.args["text_prompt"]:
                    ret["response"]["prompt"] = {
                        "text": "Please enroll at https://api-abcd1234.duosecurity.com/portal?code=48bac5d9393fb2c2&akey=DIXXXXXXXXXXXXXXXXXX"
                    }
            elif self.args["username"] == "bad-json":
                buf = b""
            elif self.args["username"] == "retry-after-3-preauth-allow":
                if self._rl_req_num == 0:
                    self._rl_req_num = 1
                    return self._send(429, headers={"X-Retry-After": "3"})
                else:
                    self._rl_req_num = 0
                    ret["response"] = {"result": "allow", "status_msg": "preauth-allowed"}
            elif self.args["username"] == "retry-after-date-preauth-allow":
                if self._rl_req_num == 0:
                    self._rl_req_num = 1
                    timestr = time.strftime("%a, %d %b %Y %H:%M:%S %Z", time.gmtime(time.time()+3))
                    return self._send(429, headers={"Retry-After": timestr})
                else:
                    self._rl_req_num = 0
                    ret["response"] = {"result": "allow", "status_msg": "preauth-allowed"}
            elif self.args["username"] == "rate-limited-preauth-allow":
                if self._rl_req_num in [0,1]:
                    self._rl_req_num += 1
                    return self._send(429)
                elif self._rl_req_num == 2:
                    self._rl_req_num = 0
                    ret["response"] = {"result": "allow", "status_msg": "preauth-allowed"}
                else:
                    return self._send(500, "Wrong timeout")
            else:
                ret["response"] = { "result": "auth" }
                client_supports_verified_push = bool(
                    self.args.get("client_supports_verified_push", False)
                ) and self.args["username"] != "client-supports-verified-push-ignored"
                if self.args["text_prompt"]:
                    ret["response"]["prompt"] = {
                        "text": "Duo login for {0}\n\n".format(self.args["username"])
                        + "Choose or lose:\n\n"
                        + "  1. Push 1\n  2. Phone 1\n"
                        + "  3. SMS 1 (deny)\n  4. Phone 2 (deny)\n\n"
                        + "Passcode or option (1-4): ",
                        "factors": {
                            "default": "verified_push1" if client_supports_verified_push else "push1",
                            "1": "verified_push1" if client_supports_verified_push else "push1",
                            "2": "voice1",
                            "3": "smsrefresh1",
                            "4": "voice2",
                        }
                    }
                    if client_supports_verified_push:
                        ret["response"]["txid"] = VERIFIED_PUSH_TXID
        elif self.path == "/auth/v2/auth":
            if self.args["factor"] == "prompt":
                txid = self.args.get("txid", None)
                if txid:
                    if (
                        self.args["username"] == "client-supports-verified-push-ignored"
                        or not self.args["prompt"].startswith("verified_push")
                    ):
                        ret["response"] = {
                            "result": "deny",
                            "status_msg": "txid should not be passed to /auth",
                        }
                    elif self.args["username"] == "client-supports-verified-push" and txid != VERIFIED_PUSH_TXID:
                        ret["response"] = {
                            "result": "deny",
                            "status_msg": "wrong txid passed to /auth",
                        }
                else:
                    if self.args["username"] == "client-supports-verified-push":
                        ret["response"] = {
                            "result": "deny",
                            "status_msg": "txid should be passed to /auth",
                        }
                    else:
                        txid = "tx" + self.args["prompt"].upper()
                if self.args["username"] == "pam_prompt":
                    ret["response"] = {"txid": "wrongFactor1"}
                elif self.args["async"] == "1":
                    ret["response"] = {"txid": txid}
                else:
                    ret["response"] = self._get_tx_response(txid, 0)
            else:
                ret["response"] = {
                    "result": "deny",
                    "status_msg": "no {0}".format(self.args["factor"]),
                }
            if self.args["username"] == "auth_timeout":
                return self._send(500)
        else:
            return self._send(404)

        if buf is None:
            buf = json.dumps(ret)

        return self._send(200, buf)

class HTTPServerV6(HTTPServer):
    address_family = socket.AF_INET6

def main():
    port = 4443
    host = "::"
    if len(sys.argv) == 1:
        cafile = os.path.realpath(
            "{0}/certs/mockduo.pem".format(os.path.dirname(__file__))
        )
    elif len(sys.argv) == 2:
        cafile = sys.argv[1]
    else:
        print("Usage: {0} [certfile]\n".format(sys.argv[0]), file=sys.stderr)
        sys.exit(1)

    httpd = HTTPServerV6((host, port), MockDuoHandler)

    ctx = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cafile)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    httpd.serve_forever()


if __name__ == "__main__":
    main()
