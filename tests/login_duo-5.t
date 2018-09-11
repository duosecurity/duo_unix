mockduo with valid cert

  $ cd ${TESTDIR}
  $ python mockduo.py certs/mockduo.pem >/dev/null 2>&1 &
  $ MOCKPID=$!
  $ trap 'exec kill $MOCKPID >/dev/null 2>&1' EXIT
  $ sleep 1

Timeout
  $ env UID=1001 TIMEOUT=1 ./login_duo.py -d -c confs/mockduo.conf -f timeout true
  Attempting connection
  Attempting connection
  Attempting connection
  [4] Failsafe Duo login for 'timeout': Couldn't connect to localhost:4443: Failed to connect
  
