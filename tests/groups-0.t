mockduo with valid cert

  $ cd ${TESTDIR}
  $ python mockduo.py certs/mockduo.pem >/dev/null 2>&1 &
  $ MOCKPID=$!
  $ trap 'exec kill $MOCKPID >/dev/null 2>&1' EXIT
  $ sleep 1

users only: match users
==> primary group
  $ env UID=1001 ./groups.py -d -c confs/mockduo_users.conf -f preauth-allow true
  [4] Skipped Duo login for 'preauth-allow': you rock
==> supplemental group
  $ env UID=1000 ./groups.py -d -c confs/mockduo_users.conf -f preauth-allow true
  [4] Skipped Duo login for 'preauth-allow': you rock
  $ env UID=1002 ./groups.py -d -c confs/mockduo_users.conf -f preauth-allow true
  [4] Skipped Duo login for 'preauth-allow': you rock

users only: skip users
  $ env UID=1003 ./groups.py -d -c confs/mockduo_users.conf -f preauth-allow echo SKIP
  SKIP
  $ env UID=1004 ./groups.py -d -c confs/mockduo_users.conf -f preauth-allow echo SKIP
  SKIP

users or admins: match users
==> primary group
  $ env UID=1001 ./groups.py -d -c confs/mockduo_users_admins.conf -f preauth-allow true
  [4] Skipped Duo login for 'preauth-allow': you rock
  $ env UID=1002 ./groups.py -d -c confs/mockduo_users_admins.conf -f preauth-allow true
  [4] Skipped Duo login for 'preauth-allow': you rock
==> supplemental group
  $ env UID=1000 ./groups.py -d -c confs/mockduo_users_admins.conf -f preauth-allow true
  [4] Skipped Duo login for 'preauth-allow': you rock
  $ env UID=1003 ./groups.py -d -c confs/mockduo_users_admins.conf -f preauth-allow true
  [4] Skipped Duo login for 'preauth-allow': you rock

users or admins: skip users
  $ env UID=1004 ./groups.py -d -c confs/mockduo_users_admins.conf -f preauth-allow echo SKIP
  SKIP

admins and not users: match admins
  $ env UID=1003 ./groups.py -d -c confs/mockduo_admins_no_users.conf -f preauth-allow true
  [4] Skipped Duo login for 'preauth-allow': you rock

admins and not users: skip users
  $ env UID=1000 ./groups.py -d -c confs/mockduo_admins_no_users.conf -f preauth-allow echo SKIP
  SKIP
  $ env UID=1001 ./groups.py -d -c confs/mockduo_admins_no_users.conf -f preauth-allow echo SKIP
  SKIP
  $ env UID=1002 ./groups.py -d -c confs/mockduo_admins_no_users.conf -f preauth-allow echo SKIP
  SKIP
  $ env UID=1004 ./groups.py -d -c confs/mockduo_admins_no_users.conf -f preauth-allow echo SKIP
  SKIP

non-existent shell
  $ env UID=1005 ./groups.py -d -c confs/mockduo_users.conf -f noshell echo SKIP
  SKIP
