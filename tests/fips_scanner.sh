#!/bin/bash

#
# fips_scanner.sh
#
# This program scans for low-level Openssl function calls that are NOT
# allowed when running in FIPS mode. The list of functions was taken
# from searching the Openssl library for calls to "fips_cipher_abort" and
# "fips_md_init_ctx" which are the functions for generating the low-level
# API abort messages.  These abort messages are only generated when running
# in FIPS mode. We then looked at the ".h" for each cipher/digest and manpage to
# get the list of related low-level function calls.
#
# Usage:
#   ./fips_scanner.sh <directory to scan>
#
# If no directory is given, it scans the directory the current directory.
#

echo "Starting scan ..."

# Set directory to scan
if [ -z "$1" ] ; then
  DIR="."
else
  DIR=$1
fi

echo -e "Scanning directory\n"

CIPHER_LIST=("AES_set_encrypt_key"
             "AES_set_decrypt_key"
             "AES_encrypt"
             "AES_decrypt"
             "AES_ctr128_encrypt"
             "AES_ecb_encrypt"
             "AES_cbc_encrypt"
             "AES_cfb128_encrypt"
             "AES_cfb1_encrypt"
             "AES_cfb8_encrypt"
             "AES_ofb128_encrypt"
             "AES_ctr128_encrypt"
             "AES_ige_encrypt"
             "AES_bi_ige_encrypt"
             "AES_wrap_key"
             "AES_unwrap_key"
             "BF_set_key"
             "BF_encrypt"
             "BF_ecb_encrypt"
             "BF_cbc_encrypt"
             "BF_cfb64_encrypt"
             "BF_ofb64_encrypt"
             "Camellia_set_key"
             "Camellia_encrypt"
             "Camellia_decrypt"
             "Camellia_ecb_encrypt"
             "Camellia_cbc_encrypt"
             "Camellia_cfb128_encrypt"
             "Camellia_cfb1_encrypt"
             "Camellia_cfb8_encrypt"
             "Camellia_ofb128_encrypt"
             "Camellia_ctr128_encrypt"
             "CAST_set_key"
             "CAST_ecb_encrypt"
             "CAST_encrypt"
             "CAST_cbc_encrypt"
             "CAST_cfb64_encrypt"
             "CAST_ofb64_encrypt"
             "DES_set_key_unchecked"
             "DES_ecb2_encrypt"
             "DES_ede2_cbc_encrypt"
             "DES_ede2_cfb64_encrypt"
             "DES_ede2_ofb64_encrypt"
             "DES_ecb3_encrypt"
             "DES_cbc_cksum"
             "DES_cbc_encrypt"
             "DES_ncbc_encrypt"
             "DES_xcbc_encrypt"
             "DES_cfb_encrypt"
             "DES_ecb_encrypt"
             "DES_encrypt1"
             "DES_encrypt2"
             "DES_encrypt3"
             "DES_decrypt3"
             "DES_ede3_cbc_encrypt"
             "DES_ede3_cbcm_encrypt"
             "DES_ede3_cfb64_encrypt"
             "DES_ede3_cfb_encrypt"
             "DES_ede3_ofb64_encrypt"
             "DES_enc_read"
             "DES_enc_write"
             "DES_ofb_encrypt"
             "DES_quad_cksum"
             "DES_random_key"
             "DES_check_key_parity"
             "DES_set_key"
             "DES_pcbc_encrypt"
             "DES_set_key_checked"
             "DES_string_to_key"
             "DES_cfb64_encrypt"
             "DES_ofb64_encrypt"
             "DES_read_password"
             "DES_fixup_key_parity"
             "DES_set_odd_parity"
             "idea_set_encrypt_key"
             "idea_ecb_encrypt"
             "idea_set_decrypt_key"
             "idea_cfb64_encrypt"
             "idea_ofb64_encrypt"
             "idea_encrypt"
             "RC2_set_key"
             "RC2_encrypt"
             "RC2_cbc_encrypt"
             "RC2_cfb64_encrypt"
             "RC2_ofb64_encrypt"
             "RC4_set_key"
             "SEED_set_key"
             "SEED_encrypt"
             "SEED_decrypt"
             "SEED_ecb_encrypt"
             "SEED_cbc_encrypt"
             "SEED_cfb128_encrypt"
             "SEED_ofb128_encrypt")

echo -e "Checking for low-level cipher calls"
echo -e "===================================\n"

#Exclude files that are being used to search for anything not fips compliant 
#Unless excluded, these files will also be scanned and trigger false positives
fipsScanner="fips_scanner.sh"
testCrypto="test_crypto-0*"
for cipher in ${CIPHER_LIST[@]} ; do
    echo "Scanning for cipher function: ${cipher}"
    if grep -R ${cipher} ${DIR} --exclude={$fipsScanner,$testCrypto} ; then
      echo -e "\e[92mFound potential calls for ${cipher}\e[0m"
    fi
done

# Scan for unapproved digest calls
DIGEST_LIST=("SHA1_Init"
             "SHA1_Update"
             "SHA1_Final"
             "SHA224_Init"
             "SHA224_Update"
             "SHA224_Final"
             "SHA256_Init"
             "SHA256_Update"
             "SHA256_Final"
             "SHA384_Init"
             "SHA384_Update"
             "SHA384_Final"
             "SHA512_Init"
             "SHA512_Update"
             "SHA512_Final")

echo -e "\nChecking for low-level digest calls"
echo -e "===================================\n"
for digest in ${DIGEST_LIST[@]} ; do
    echo "Scanning for cipher function: ${digest}"
    if grep -R ${digest} ${DIR} --exclude={$fipsScanner,$testCrypto} ; then
      echo -e "\e[92mFound potential calls for ${digest}\e[0m"
    fi    
done
