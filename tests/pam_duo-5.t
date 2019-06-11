mockduo with wrong CN

  $ cd ${TESTDIR}
  $ python mockduo.py certs/mockduo.pem >/dev/null 2>&1 &
  $ MOCKPID=$!
  $ trap 'exec kill $MOCKPID >/dev/null 2>&1' EXIT
  $ sleep 1

FIPS testing variable setup
  $ fips_available=$(./is_fips_supported.sh) && echo "[1]"
  [1]
  $ no_fips_error="[3] FIPS mode flag specified, but OpenSSL not built with FIPS support. Failing the auth.\n[1]\n"

Test that an auth works with FIPS enabled (if available on this system). Otherwise, test a regular non-FIPS auth as normal.
  $ if [ $fips_available -eq 0 ]; then
  >    CONFS="mockduo_fips.conf";
  > else
  >    CONFS="mockduo.conf";
  > fi
  $ ./testpam.py -d -c confs/$CONFS -f preauth-allow true
  [4] Skipped Duo login for 'preauth-allow': preauth-allowed

Test that a config with FIPS enabled but unavailable on the system logs that an auth failed due to the lack of FIPS. Mock the output otherwise if FIPS does actually exist on the system.
  $ if [ $fips_available -eq 0 ]; then
  >    printf "$no_fips_error";
  > else
  >    ./testpam.py -d -c confs/mockduo_fips.conf -f whatever true;
  > fi
  [3] FIPS mode flag specified, but OpenSSL not built with FIPS support. Failing the auth.
  [1]
