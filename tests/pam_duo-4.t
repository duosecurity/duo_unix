mockduo with valid cert

  $ cd ${TESTDIR}
  $ python mockduo.py certs/mockduo.pem >/dev/null 2>&1 &
  $ MOCKPID=$!
  $ trap 'exec kill $MOCKPID >/dev/null 2>&1' EXIT
  $ sleep 1

HTTP server errors
  $ for http_code in 400 401 402 403 404 500 501 502 503 504; do ./testpam.py -d -c confs/mockduo.conf -f $http_code true; done
  [4] Aborted Duo login for '400': HTTP 400
  [4] Failsafe Duo login for '401': Invalid ikey or skey
  [4] Aborted Duo login for '402': HTTP 402
  [4] Aborted Duo login for '403': HTTP 403
  [4] Aborted Duo login for '404': HTTP 404
  [4] Failsafe Duo login for '500': HTTP 500
  [4] Failsafe Duo login for '501': HTTP 501
  [4] Failsafe Duo login for '502': HTTP 502
  [4] Failsafe Duo login for '503': HTTP 503
  [4] Failsafe Duo login for '504': HTTP 504
  $ for http_code in 400 401 402 403 404 500 501 502 503 504; do ./testpam.py -d -c confs/mockduo_failsecure.conf -f $http_code true; done
  [4] Aborted Duo login for '400': HTTP 400
  [4] Failsecure Duo login for '401': Invalid ikey or skey
  [4] Aborted Duo login for '402': HTTP 402
  [4] Aborted Duo login for '403': HTTP 403
  [4] Aborted Duo login for '404': HTTP 404
  [4] Failsecure Duo login for '500': HTTP 500
  [4] Failsecure Duo login for '501': HTTP 501
  [4] Failsecure Duo login for '502': HTTP 502
  [4] Failsecure Duo login for '503': HTTP 503
  [4] Failsecure Duo login for '504': HTTP 504
  [1]

With bad keys
  $ ./testpam.py -d -c confs/mockduo_badkeys.conf -f whatever true
  [4] Failsafe Duo login for 'whatever': Invalid ikey or skey
  $ ./testpam.py -d -c confs/mockduo_badkeys_failsecure.conf -f whatever true
  [4] Failsecure Duo login for 'whatever': Invalid ikey or skey
  [1]

Preauth states
  $ for user in preauth-ok-missing_response preauth-fail-missing_response preauth-bad-stat preauth-fail preauth-deny preauth-allow preauth-allow-bad_response; do ./testpam.py -d -c confs/mockduo.conf -f $user true; done
  [4] Failsafe Duo login for 'preauth-ok-missing_response': BSON missing valid 'response'
  [4] Failsafe Duo login for 'preauth-fail-missing_response': BSON missing valid 'code'
  [4] Failsafe Duo login for 'preauth-bad-stat'
  [4] Failed Duo login for 'preauth-fail': 1000: Pre-authentication failed
  [4] Failed Duo login for 'preauth-fail': 1000: Pre-authentication failed
  [4] Failed Duo login for 'preauth-fail': 1000: Pre-authentication failed
  [4] Aborted Duo login for 'preauth-deny': preauth-denied
  preauth-denied
  [4] Skipped Duo login for 'preauth-allow': preauth-allowed
  [4] Failsafe Duo login for 'preauth-allow-bad_response': BSON missing valid 'status'
  $ for user in preauth-ok-missing_response preauth-fail-missing_response preauth-bad-stat preauth-fail preauth-deny preauth-allow preauth-allow-bad_response; do ./testpam.py -d -c confs/mockduo_failsecure.conf -f $user true; done
  [4] Failsecure Duo login for 'preauth-ok-missing_response': BSON missing valid 'response'
  [4] Failsecure Duo login for 'preauth-fail-missing_response': BSON missing valid 'code'
  [4] Failsecure Duo login for 'preauth-bad-stat'
  [4] Failed Duo login for 'preauth-fail': 1000: Pre-authentication failed
  [4] Failed Duo login for 'preauth-fail': 1000: Pre-authentication failed
  [4] Failed Duo login for 'preauth-fail': 1000: Pre-authentication failed
  [4] Aborted Duo login for 'preauth-deny': preauth-denied
  preauth-denied
  [4] Skipped Duo login for 'preauth-allow': preauth-allowed
  [4] Failsecure Duo login for 'preauth-allow-bad_response': BSON missing valid 'status'
  [1]

Test manually-set hosts
  $ for host in 1.2.3.4 XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:AAA.BBB.CCC.DDD nowhere "%s" "!@#$%^&*()_+<>{}|;'"; do ./testpam.py -d -c confs/mockduo.conf -f preauth-allow -h $host true; done
  [4] Skipped Duo login for 'preauth-allow' from 1.2.3.4: preauth-allowed
  [4] Skipped Duo login for 'preauth-allow' from XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:AAA.BBB.CCC.DDD: preauth-allowed
  [4] Skipped Duo login for 'preauth-allow' from nowhere: preauth-allowed
  [4] Skipped Duo login for 'preauth-allow' from %s: preauth-allowed
  [4] Skipped Duo login for 'preauth-allow' from !@#$%^&*()_+<>{}|;': preauth-allowed

  $ env FALLBACK=1 ./testpam.py -d -c confs/mockduo_fallback.conf -f preauth-allow -h BADHOST true
  [4] Skipped Duo login for 'preauth-allow' from 1.2.3.4: preauth-allowed



Test using configured http_proxy variable
  $ orig_http_proxy=$http_proxy
  $ unset http_proxy

  $ ./testpam.py -d -c confs/mockduo.conf -f preauth-allow true
  [4] Skipped Duo login for 'preauth-allow': preauth-allowed
  $ export http_proxy=0.0.0.0
  $ ./testpam.py -d -c confs/mockduo.conf -f preauth-allow true
  [4] Skipped Duo login for 'preauth-allow': preauth-allowed
  $ ./testpam.py -d -c confs/mockduo_proxy.conf -f preauth-allow true
  [4] Failsafe Duo login for 'preauth-allow': Couldn't connect to localhost:4443: Failed to connect
  
  $ export http_proxy=$orig_http_proxy

Test getting hostname
  $ ./testpam.py -d -c confs/mockduo.conf -f hostname true
  [4] Aborted Duo login for 'hostname': correct hostname
  correct hostname
  [1]

