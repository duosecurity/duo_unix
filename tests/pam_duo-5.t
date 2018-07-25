mockduo with wrong CN

  $ cd ${TESTDIR}
  $ python mockduo.py certs/mockduo.pem >/dev/null 2>&1 &
  $ MOCKPID=$!
  $ trap 'exec kill $MOCKPID >/dev/null 2>&1' EXIT
  $ sleep 1

Fips Testing Variable Setup
  $ check_fips_found="$(gcc -dM -include "openssl/crypto.h" -E - < /dev/null 2>/dev/null | grep '#define OPENSSL_FIPS')" && echo [1]
  [1]
  $ no_fips_error="[3] FIPS mode flag specified, but OpenSSL not built with FIPS support. Failing the auth.\n[1]\n"

Test Fips Enabled
  $ if [ "$check_fips_found" ]; then
  >    CONFS="mockduo_fips.conf";
  > else
  >    CONFS="mockduo.conf";
  > fi
  $ ./testpam.py -d -c confs/$CONFS -f preauth-allow true
  [4] Skipped Duo login for 'preauth-allow': you rock

Test Fips Writes to Logs / We need to echo the output if the OS (eg. CentOS 7) has OpenSSL with Fips
  $ if [ "$check_fips_found" ]; then
  >    printf "$no_fips_error";
  > else
  >    ./testpam.py -d -c confs/mockduo_fips.conf -f whatever true;
  > fi
  [3] FIPS mode flag specified, but OpenSSL not built with FIPS support. Failing the auth.
  [1]
