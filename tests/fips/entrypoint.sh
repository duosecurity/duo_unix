#!/bin/bash
#
# SPDX-License-Identifier: GPL-2.0-with-classpath-exception
#
# Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
# All rights reserved.
#
# entrypoint.sh — verify FIPS enforcement, build duo_unix, run test suite.
# Runs inside the Rocky 9 FIPS container.
#
set -euo pipefail

echo "=== Verifying OpenSSL FIPS enforcement ==="

# MD5 MUST fail (not FIPS-approved)
if openssl dgst -md5 /dev/null 2>/dev/null; then
    echo "FATAL: MD5 succeeded — FIPS is NOT enforced!"
    exit 1
fi
echo "PASS: MD5 correctly rejected"

# SHA-256 MUST succeed (FIPS-approved)
openssl dgst -sha256 /dev/null >/dev/null
echo "PASS: SHA-256 works under FIPS"

# SHA-512 MUST succeed (used by duo_unix HMAC-SHA512 signing)
openssl dgst -sha512 /dev/null >/dev/null
echo "PASS: SHA-512 works under FIPS"

echo ""
echo "=== Building duo_unix ==="
./bootstrap
./configure --with-pam --prefix=/usr PYTHON=python3.12
make

echo ""
echo "=== Running test suite under FIPS enforcement ==="
make check PYTHON=python3.12

echo ""
echo "=== All tests passed under OpenSSL FIPS mode ==="
