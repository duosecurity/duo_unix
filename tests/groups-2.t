mockduo with valid cert

  $ cd ${TESTDIR}
  $ python mockduo.py certs/mockduo.pem >/dev/null 2>&1 &
  $ MOCKPID=$!
  $ trap 'exec kill $MOCKPID >/dev/null 2>&1' EXIT
  $ sleep 1

match groups with spaces
  $ env UID=1001 ./groups.py -d -c confs/mockduo_space_users.conf -f preauth-allow true
  [4] Skipped Duo login for 'preauth-allow': preauth-allowed

match groups with backslash
  $ env UID=1004 ./groups.py -d -c confs/mockduo_space_users.conf -f preauth-allow true
  [4] Skipped Duo login for 'preauth-allow': preauth-allowed

match groups without spaces
  $ env UID=1002 ./groups.py -d -c confs/mockduo_space_users.conf -f preauth-allow true
  [4] Skipped Duo login for 'preauth-allow': preauth-allowed
