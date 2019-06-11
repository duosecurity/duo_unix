mockduo with wrong CN

  $ cd ${TESTDIR}
  $ python mockduo.py certs/mockduo-wronghost.pem >/dev/null 2>&1 &
  $ MOCKPID=$!
  $ trap 'exec kill $MOCKPID >/dev/null 2>&1' EXIT
  $ sleep 1

Wrong hostname
  $ ${BUILDDIR}/login_duo/login_duo -d -c confs/mockduo.conf -f whatever true
  [4] Failsafe Duo login for 'whatever': Couldn't connect to localhost:4443: Certificate name validation failed
  
  $ ${BUILDDIR}/login_duo/login_duo -d -c confs/mockduo_failsecure.conf -f whatever true
  [4] Failsecure Duo login for 'whatever': Couldn't connect to localhost:4443: Certificate name validation failed
  
  [1]

With noverify
  $ ${BUILDDIR}/login_duo/login_duo -d -c confs/mockduo_noverify.conf -f preauth-allow true
  [4] Skipped Duo login for 'preauth-allow': preauth-allowed
