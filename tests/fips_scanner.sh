#!/bin/bash
#
# SPDX-License-Identifier: GPL-2.0-with-classpath-exception
#
# Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
# All rights reserved.
#
# fips_scanner.sh
#
# This program scans for cryptographic algorithms and patterns that are
# disallowed by the FIPS 140-3 security policy.  It checks four categories:
#
#   1. Non-FIPS algorithms via low-level APIs (MD5, MD4, MDC2, RC4)
#   2. Non-FIPS algorithms via EVP-level APIs (md5, md4, mdc2, rc4, rc2,
#      single-DES, IDEA, Blowfish, CAST5, SEED)
#   3. DRBG bypass patterns (seeding the RNG from external sources)
#   4. Dead FIPS 140-2 APIs (FIPS_mode_set/get, removed in OpenSSL 3.x)
#
# Low-level API usage that bypasses EVP (AES_encrypt, SHA512_Init, etc.)
# is an OpenSSL 3.x deprecation concern and is checked separately by
# openssl3_scanner.sh.
#
#
# Usage:
#   ./fips_scanner.sh <directory to scan>
#
# If no directory is given, it scans the current directory.
#
#
case "$OSTYPE" in
  solaris*) GREP="ggrep" ;;
  *) GREP="grep" ;;
esac

echo "Starting scan ..."

# Set directory to scan
if [ -z "$1" ] ; then
  DIR="."
else
  DIR=$1
fi

echo -e "Scanning directory\n"

EXITCODE=0

#Exclude files that are being used to search for anything not fips compliant
#Unless excluded, these files will also be scanned and trigger false positives
errorFile="fips_scanner.sh.err"
fipsScanner="fips_scanner.sh"
opensslScanner="openssl3_scanner.sh"
testCrypto="test_crypto-0*"
testCryptoPy="test_crypto.py"
GREP_OPTS="-R -I --exclude=$fipsScanner --exclude=$opensslScanner --exclude=$testCrypto --exclude=$testCryptoPy --exclude=$errorFile --exclude-dir=.git --exclude-dir=build --exclude-dir=worktree_tmp --exclude-dir=.libs"

# Category 1: Non-FIPS algorithms (low-level)
NONFIPS_LOWLEVEL=("MD5_Init" "MD5_Update" "MD5_Final"
                  "MD4_Init" "MD4_Update" "MD4_Final"
                  "MDC2_Init" "MDC2_Update" "MDC2_Final"
                  "RC4_set_key")

echo "Checking for non-FIPS algorithms (low-level)"
echo -e "=============================================\n"

for func in ${NONFIPS_LOWLEVEL[@]} ; do
    echo "Scanning for function: ${func}"
    if $GREP $GREP_OPTS ${func} ${DIR} ; then
      echo "Found potential calls for ${func}"
      EXITCODE=1
    fi
done

# Category 2: Non-FIPS algorithms (EVP-level)
NONFIPS_EVP=("EVP_md5" "EVP_md4" "EVP_mdc2"
             "EVP_rc4" "EVP_rc2_cbc" "EVP_rc2_ecb" "EVP_rc2_cfb" "EVP_rc2_ofb"
             "EVP_des_ecb" "EVP_des_cbc" "EVP_des_cfb" "EVP_des_ofb"
             "EVP_idea_ecb" "EVP_idea_cbc" "EVP_idea_cfb" "EVP_idea_ofb"
             "EVP_bf_ecb" "EVP_bf_cbc" "EVP_bf_cfb" "EVP_bf_ofb"
             "EVP_cast5_ecb" "EVP_cast5_cbc" "EVP_cast5_cfb" "EVP_cast5_ofb"
             "EVP_seed_ecb" "EVP_seed_cbc" "EVP_seed_cfb" "EVP_seed_ofb")

echo -e "\nChecking for non-FIPS algorithms (EVP-level)"
echo -e "=============================================\n"

for func in ${NONFIPS_EVP[@]} ; do
    echo "Scanning for function: ${func}"
    if $GREP $GREP_OPTS ${func} ${DIR} ; then
      echo "Found potential calls for ${func}"
      EXITCODE=1
    fi
done

# Category 3: DRBG bypass patterns
DRBG_BYPASS=("RAND_load_file" "RAND_seed" "RAND_add")

echo -e "\nChecking for DRBG bypass patterns"
echo -e "=================================\n"

for func in ${DRBG_BYPASS[@]} ; do
    echo "Scanning for function: ${func}"
    if $GREP $GREP_OPTS ${func} ${DIR} ; then
      echo "Found potential calls for ${func}"
      EXITCODE=1
    fi
done

# Category 4: Dead FIPS 140-2 APIs
DEAD_FIPS_APIS=("FIPS_mode_set" "FIPS_mode_get")

echo -e "\nChecking for dead FIPS 140-2 APIs"
echo -e "=================================\n"

for func in ${DEAD_FIPS_APIS[@]} ; do
    echo "Scanning for function: ${func}"
    if $GREP $GREP_OPTS ${func} ${DIR} ; then
      echo "Found potential calls for ${func}"
      EXITCODE=1
    fi
done

exit $EXITCODE
