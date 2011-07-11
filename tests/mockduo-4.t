mockduo with valid cert

  $ cd ${TESTDIR}
  $ python mockduo.py certs/mockduo.pem >/dev/null 2>&1 &
  $ trap 'kill %1' EXIT
  $ sleep 1

HTTP server errors

  $ for http_code in 400 401 402 403 404 500 501 502 503 504; do ${BUILDDIR}/login_duo/login_duo -d -c confs/mockduo.conf -f $http_code true; done
  [4] Failsafe Duo login for '400': HTTP 400
  [4] Failsafe Duo login for '401': HTTP 401
  [4] Failsafe Duo login for '402': HTTP 402
  [4] Failsafe Duo login for '403': HTTP 403
  [4] Failsafe Duo login for '404': HTTP 404
  [4] Failsafe Duo login for '500': HTTP 500
  [4] Failsafe Duo login for '501': HTTP 501
  [4] Failsafe Duo login for '502': HTTP 502
  [4] Failsafe Duo login for '503': HTTP 503
  [4] Failsafe Duo login for '504': HTTP 504

With bad keys
  $ ${BUILDDIR}/login_duo/login_duo -d -c confs/mockduo_badkeys.conf -f whatever true
  [4] Failsafe Duo login for 'whatever': HTTP 401

Preauth states

  $ for user in preauth-ok-missing_response preauth-fail-missing_response preauth-bad-stat preauth-fail preauth-deny preauth-allow preauth-allow-bad_response; do ${BUILDDIR}/login_duo/login_duo -d -c confs/mockduo.conf -f $user true; done
  [4] Failsafe Duo login for 'preauth-ok-missing_response': BSON missing valid 'response'
  [4] Failsafe Duo login for 'preauth-fail-missing_response': BSON missing valid 'code'
  [4] Failsafe Duo login for 'preauth-bad-stat'
  [4] Failsafe Duo login for 'preauth-fail': BSON missing valid 'response'
  [4] Aborted Duo login for 'preauth-deny': you suck
  [4] Skipped Duo login for 'preauth-allow': you rock
  [4] Failsafe Duo login for 'preauth-allow-bad_response': BSON missing valid 'status'

Test manually-set hosts

  $ for host in 1.2.3.4 XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:AAA.BBB.CCC.DDD nowhere "%s" "!@#$%^&*()_+<>{}|;'"; do ${BUILDDIR}/login_duo/login_duo -d -c confs/mockduo.conf -f preauth-allow -h $host true; done
  [4] Skipped Duo login for 'preauth-allow' from 1.2.3.4: you rock
  [4] Skipped Duo login for 'preauth-allow' from XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:AAA.BBB.CCC.DDD: you rock
  [4] Skipped Duo login for 'preauth-allow' from nowhere: you rock
  [4] Skipped Duo login for 'preauth-allow' from %s: you rock
  [4] Skipped Duo login for 'preauth-allow' from !@#$%^&*()_+<>{}|;': you rock

Test SSH-set host

  $ env SSH_CONNECTION="1.2.3.4 64903 127.0.0.1 22" ${BUILDDIR}/login_duo/login_duo -d -c confs/mockduo.conf -f preauth-allow true
  [4] Skipped Duo login for 'preauth-allow' from 1.2.3.4: you rock
