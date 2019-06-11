mockduo with self-signed cert

  $ cd ${TESTDIR}
  $ python mockduo.py certs/selfsigned.pem >/dev/null 2>&1 &
  $ MOCKPID=$!
  $ trap 'exec kill $MOCKPID >/dev/null 2>&1' EXIT
  $ sleep 1

Invalid cert
  $ ./testpam.py -d -c confs/mockduo.conf -f whatever true
  [4] Failsafe Duo login for 'whatever': Couldn't connect to localhost:4443: certificate verify failed
  
  $ ./testpam.py -d -c confs/mockduo_failsecure.conf -f whatever true
  [4] Failsecure Duo login for 'whatever': Couldn't connect to localhost:4443: certificate verify failed
  
  [1]

With noverify
  $ ./testpam.py -d -c confs/mockduo_noverify.conf -f preauth-allow true
  [4] Skipped Duo login for 'preauth-allow': preauth-allowed
