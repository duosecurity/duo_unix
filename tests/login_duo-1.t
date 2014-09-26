mockduo down

  $ ${BUILDDIR}/login_duo/login_duo -d -c ${TESTDIR}/confs/duo.conf -f whatever true
  [4] Failsafe Duo login for 'whatever': Couldn't connect to localhost:4443: Failed to connect
  
down and fail secure
  $ ${BUILDDIR}/login_duo/login_duo -d -c ${TESTDIR}/confs/mockduo_failsecure.conf -f whatever true
  [3] Couldn't open Duo API handle for '*' (glob)
  [1]
