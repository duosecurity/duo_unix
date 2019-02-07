mockduo with valid cert
  $ cd ${TESTDIR}
  $ python mockduo.py certs/mockduo.pem >/dev/null 2>&1 &
  $ MOCKPID=$!
  $ trap 'exec kill $MOCKPID >/dev/null 2>&1' EXIT
  $ sleep 1

Failsafe preauth fail
  $ ./testpam.py -d -c confs/mockduo_autopush.conf -f auth_timeout true
  [3] Error in Duo login for 'auth_timeout': HTTP 500
  Autopushing login request to phone...
  [1]



Failsecure preauth fail
  $ ./testpam.py -d -c confs/mockduo_autopush_secure.conf -f auth_timeout true
  [3] Error in Duo login for 'auth_timeout': HTTP 500
  Autopushing login request to phone...
  [1]

Failmode safe
  $ ./testpam.py -d -c confs/mockduo.conf -f failopen true
  [4] Aborted Duo login for 'failopen': correct failmode
  correct failmode
  [1]
Failmode secure
  $ ./testpam.py -d -c confs/mockduo_failsecure.conf -f failclosed true
  [4] Aborted Duo login for 'failclosed': correct failmode
  correct failmode
  [1]
