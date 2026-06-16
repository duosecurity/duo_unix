#!/bin/bash
#
# SPDX-License-Identifier: GPL-2.0-with-classpath-exception
#
# Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
# All rights reserved.
#
# run_fips_test.sh — Build and run the duo_unix FIPS test container.
#
# Builds a Rocky 9 Docker image with OpenSSL configured in FIPS mode
# (default_properties = fips=yes), then runs the duo_unix build and test
# suite inside it. Non-FIPS algorithms are rejected at the OpenSSL level.
#
# Usage:
#   ./tests/fips/run_fips_test.sh
#
# Requires: docker
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

IMAGE_NAME="duo_unix_fips_test"

command -v docker >/dev/null || { echo "FATAL: docker not found" >&2; exit 1; }

echo "Building FIPS test image (Rocky Linux 9)..."
docker build -t "$IMAGE_NAME" -f "$SCRIPT_DIR/Dockerfile" "$REPO_ROOT"

echo ""
echo "Running duo_unix test suite under OpenSSL FIPS enforcement..."
docker run --rm "$IMAGE_NAME"
