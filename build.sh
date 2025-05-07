#!/usr/bin/env bash

./bootstrap
./configure --with-pam --prefix=/usr
pip3 install -r test_requirements.txt
/root/.local/bin/reuse spdx --output sbom.spdx
PYTHON=python3 make distcheck
