Testing files to make sure fips compliant
  $ cd ${TESTDIR}
  $ chmod +x ./fips_scanner.sh
  $ ./fips_scanner.sh ../
  Starting scan ...
  Scanning directory
  
  Checking for low-level cipher calls
  ===================================
  
  Scanning for cipher function: AES_set_encrypt_key
  Scanning for cipher function: AES_set_decrypt_key
  Scanning for cipher function: AES_encrypt
  Scanning for cipher function: AES_decrypt
  Scanning for cipher function: AES_ctr128_encrypt
  Scanning for cipher function: AES_ecb_encrypt
  Scanning for cipher function: AES_cbc_encrypt
  Scanning for cipher function: AES_cfb128_encrypt
  Scanning for cipher function: AES_cfb1_encrypt
  Scanning for cipher function: AES_cfb8_encrypt
  Scanning for cipher function: AES_ofb128_encrypt
  Scanning for cipher function: AES_ctr128_encrypt
  Scanning for cipher function: AES_ige_encrypt
  Scanning for cipher function: AES_bi_ige_encrypt
  Scanning for cipher function: AES_wrap_key
  Scanning for cipher function: AES_unwrap_key
  Scanning for cipher function: BF_set_key
  Scanning for cipher function: BF_encrypt
  Scanning for cipher function: BF_ecb_encrypt
  Scanning for cipher function: BF_cbc_encrypt
  Scanning for cipher function: BF_cfb64_encrypt
  Scanning for cipher function: BF_ofb64_encrypt
  Scanning for cipher function: Camellia_set_key
  Scanning for cipher function: Camellia_encrypt
  Scanning for cipher function: Camellia_decrypt
  Scanning for cipher function: Camellia_ecb_encrypt
  Scanning for cipher function: Camellia_cbc_encrypt
  Scanning for cipher function: Camellia_cfb128_encrypt
  Scanning for cipher function: Camellia_cfb1_encrypt
  Scanning for cipher function: Camellia_cfb8_encrypt
  Scanning for cipher function: Camellia_ofb128_encrypt
  Scanning for cipher function: Camellia_ctr128_encrypt
  Scanning for cipher function: CAST_set_key
  Scanning for cipher function: CAST_ecb_encrypt
  Scanning for cipher function: CAST_encrypt
  Scanning for cipher function: CAST_cbc_encrypt
  Scanning for cipher function: CAST_cfb64_encrypt
  Scanning for cipher function: CAST_ofb64_encrypt
  Scanning for cipher function: DES_set_key_unchecked
  Scanning for cipher function: DES_ecb2_encrypt
  Scanning for cipher function: DES_ede2_cbc_encrypt
  Scanning for cipher function: DES_ede2_cfb64_encrypt
  Scanning for cipher function: DES_ede2_ofb64_encrypt
  Scanning for cipher function: DES_ecb3_encrypt
  Scanning for cipher function: DES_cbc_cksum
  Scanning for cipher function: DES_cbc_encrypt
  Scanning for cipher function: DES_ncbc_encrypt
  Scanning for cipher function: DES_xcbc_encrypt
  Scanning for cipher function: DES_cfb_encrypt
  Scanning for cipher function: DES_ecb_encrypt
  Scanning for cipher function: DES_encrypt1
  Scanning for cipher function: DES_encrypt2
  Scanning for cipher function: DES_encrypt3
  Scanning for cipher function: DES_decrypt3
  Scanning for cipher function: DES_ede3_cbc_encrypt
  Scanning for cipher function: DES_ede3_cbcm_encrypt
  Scanning for cipher function: DES_ede3_cfb64_encrypt
  Scanning for cipher function: DES_ede3_cfb_encrypt
  Scanning for cipher function: DES_ede3_ofb64_encrypt
  Scanning for cipher function: DES_enc_read
  Scanning for cipher function: DES_enc_write
  Scanning for cipher function: DES_ofb_encrypt
  Scanning for cipher function: DES_quad_cksum
  Scanning for cipher function: DES_random_key
  Scanning for cipher function: DES_check_key_parity
  Scanning for cipher function: DES_set_key
  Scanning for cipher function: DES_pcbc_encrypt
  Scanning for cipher function: DES_set_key_checked
  Scanning for cipher function: DES_string_to_key
  Scanning for cipher function: DES_cfb64_encrypt
  Scanning for cipher function: DES_ofb64_encrypt
  Scanning for cipher function: DES_read_password
  Scanning for cipher function: DES_fixup_key_parity
  Scanning for cipher function: DES_set_odd_parity
  Scanning for cipher function: idea_set_encrypt_key
  Scanning for cipher function: idea_ecb_encrypt
  Scanning for cipher function: idea_set_decrypt_key
  Scanning for cipher function: idea_cfb64_encrypt
  Scanning for cipher function: idea_ofb64_encrypt
  Scanning for cipher function: idea_encrypt
  Scanning for cipher function: RC2_set_key
  Scanning for cipher function: RC2_encrypt
  Scanning for cipher function: RC2_cbc_encrypt
  Scanning for cipher function: RC2_cfb64_encrypt
  Scanning for cipher function: RC2_ofb64_encrypt
  Scanning for cipher function: RC4_set_key
  Scanning for cipher function: SEED_set_key
  Scanning for cipher function: SEED_encrypt
  Scanning for cipher function: SEED_decrypt
  Scanning for cipher function: SEED_ecb_encrypt
  Scanning for cipher function: SEED_cbc_encrypt
  Scanning for cipher function: SEED_cfb128_encrypt
  Scanning for cipher function: SEED_ofb128_encrypt
  
  Checking for low-level digest calls
  ===================================
  
  Scanning for cipher function: SHA1_Init
  Scanning for cipher function: SHA1_Update
  Scanning for cipher function: SHA1_Final
  Scanning for cipher function: SHA224_Init
  Scanning for cipher function: SHA224_Update
  Scanning for cipher function: SHA224_Final
  Scanning for cipher function: SHA256_Init
  Scanning for cipher function: SHA256_Update
  Scanning for cipher function: SHA256_Final
  Scanning for cipher function: SHA384_Init
  Scanning for cipher function: SHA384_Update
  Scanning for cipher function: SHA384_Final
  Scanning for cipher function: SHA512_Init
  Scanning for cipher function: SHA512_Update
  Scanning for cipher function: SHA512_Final

