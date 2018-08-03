mockduo with valid cert
  $ cd ${TESTDIR}
  $ python mockduo.py certs/mockduo.pem >/dev/null 2>&1 &
  $ MOCKPID=$!
  $ trap 'exec kill $MOCKPID >/dev/null 2>&1' EXIT
  $ sleep 1

Failsafe preauth fail
  $ ${BUILDDIR}/login_duo/login_duo -d -c confs/mockduo.conf -f auth_timeout true
  [3] Error in Duo login for 'auth_timeout': HTTP 500
  [1]


Failsecure preauth fail
  $ ${BUILDDIR}/login_duo/login_duo -d -c confs/mockduo_failsecure.conf -f auth_timeout true
  [3] Error in Duo login for 'auth_timeout': HTTP 500
  [1]

