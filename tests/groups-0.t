mockduo with valid cert

  $ cd ${TESTDIR}
  $ python mockduo.py certs/mockduo.pem >/dev/null 2>&1 &
  $ MOCKPID=$!
  $ trap 'exec kill $MOCKPID >/dev/null 2>&1' EXIT
  $ sleep 1

users only: match users
==> primary group
  $ env UID=1001 ./groups.py -d -c confs/mockduo_users.conf -f preauth-allow true
  [4] Skipped Duo login for 'preauth-allow': preauth-allowed
==> supplemental group
  $ env UID=1000 ./groups.py -d -c confs/mockduo_users.conf -f preauth-allow true
  [4] Skipped Duo login for 'preauth-allow': preauth-allowed
  $ env UID=1002 ./groups.py -d -c confs/mockduo_users.conf -f preauth-allow true
  [4] Skipped Duo login for 'preauth-allow': preauth-allowed

users or admins: match users
==> primary group
  $ env UID=1001 ./groups.py -d -c confs/mockduo_users_admins.conf -f preauth-allow true
  [4] Skipped Duo login for 'preauth-allow': preauth-allowed
  $ env UID=1002 ./groups.py -d -c confs/mockduo_users_admins.conf -f preauth-allow true
  [4] Skipped Duo login for 'preauth-allow': preauth-allowed
==> supplemental group
  $ env UID=1000 ./groups.py -d -c confs/mockduo_users_admins.conf -f preauth-allow true
  [4] Skipped Duo login for 'preauth-allow': preauth-allowed
  $ env UID=1003 ./groups.py -d -c confs/mockduo_users_admins.conf -f preauth-allow true
  [4] Skipped Duo login for 'preauth-allow': preauth-allowed

admins and not users: match admins
  $ env UID=1003 ./groups.py -d -c confs/mockduo_admins_no_users.conf -f preauth-allow true
  [4] Skipped Duo login for 'preauth-allow': preauth-allowed

