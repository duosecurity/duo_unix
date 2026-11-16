#
# SPDX-License-Identifier: GPL-2.0-with-classpath-exception
#
# mockproxy.py
#
# Copyright (c) 2026 Cisco Systems, Inc. and/or its affiliates
# All rights reserved.
#
# A minimal HTTP CONNECT proxy that requires Basic authentication and
# tunnels authenticated connections to their target, for testing http_proxy.
#

import base64
import select
import socket
import socketserver
import threading


class _ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        server = self.server
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            data += chunk
        head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1")
        lines = head.split("\r\n")
        method, target, _ = lines[0].split(" ", 2)

        credentials = None
        for line in lines[1:]:
            name, _, value = line.partition(":")
            if name.strip().lower() == "proxy-authorization":
                scheme, _, encoded = value.strip().partition(" ")
                if scheme.lower() == "basic":
                    credentials = base64.b64decode(encoded).decode("latin-1")
        server.seen_credentials.append(credentials)

        if method != "CONNECT":
            self.request.sendall(b"HTTP/1.0 405 Method Not Allowed\r\n\r\n")
            return
        if credentials != server.expected_credentials:
            self.request.sendall(
                b"HTTP/1.0 407 Proxy Authentication Required\r\n"
                b'Proxy-Authenticate: Basic realm="mockproxy"\r\n\r\n'
            )
            return

        host, _, port = target.rpartition(":")
        upstream = socket.create_connection((host.strip("[]"), int(port)))
        self.request.sendall(b"HTTP/1.0 200 Connection established\r\n\r\n")
        sockets = [self.request, upstream]
        try:
            while True:
                readable, _, _ = select.select(sockets, [], [], 30)
                if not readable:
                    return
                for sock in readable:
                    chunk = sock.recv(65536)
                    if not chunk:
                        return
                    other = upstream if sock is self.request else self.request
                    other.sendall(chunk)
        finally:
            upstream.close()


class _ProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, family, expected_credentials):
        self.address_family = family
        self.expected_credentials = expected_credentials
        self.seen_credentials = []
        super().__init__(address, _ProxyHandler)


class MockProxy:
    """Context manager running a CONNECT proxy on an ephemeral port.

    expected_credentials is the decoded "user:password" the proxy accepts;
    seen_credentials lists what each request sent (None if no credentials).
    """

    def __init__(self, expected_credentials, ipv6=False):
        if ipv6:
            self.server = _ProxyServer(
                ("::1", 0), socket.AF_INET6, expected_credentials
            )
        else:
            self.server = _ProxyServer(
                ("127.0.0.1", 0), socket.AF_INET, expected_credentials
            )
        self.port = self.server.server_address[1]
        self.seen_credentials = self.server.seen_credentials
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


def ipv6_loopback_available():
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
            sock.bind(("::1", 0))
        return True
    except OSError:
        return False
