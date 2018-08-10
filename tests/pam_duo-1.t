mockduo down
  $ ${TESTDIR}/testpam.py -d -c ${TESTDIR}/confs/duo.conf -f whatever true
  [4] Failsafe Duo login for 'whatever': Couldn't connect to localhost:4443: Failed to connect
  
down and fail secure
  $ ${TESTDIR}/testpam.py -d -c ${TESTDIR}/confs/mockduo_failsecure.conf -f whatever true
  [3] Couldn't open Duo API handle for 'whatever'
  [1]

