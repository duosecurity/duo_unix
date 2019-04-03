mockduo with valid cert

  $ cd ${TESTDIR}
  $ python mockduo.py certs/mockduo.pem >/dev/null 2>&1 &
  $ MOCKPID=$!
  $ trap 'exec kill $MOCKPID >/dev/null 2>&1' EXIT
  $ sleep 1

users only: bypass users 
  $ env UID=1003 ./groups.py -d -c confs/mockduo_users.conf -f preauth-allow true
  [6] User preauth-allow bypassed Duo 2FA due to user's UNIX group
  $ env UID=1004 ./groups.py -d -c confs/mockduo_users.conf -f preauth-allow true
  [6] User preauth-allow bypassed Duo 2FA due to user's UNIX group

users or admins: bypass users 
  $ env UID=1004 ./groups.py -d -c confs/mockduo_users_admins.conf -f preauth-allow true
  [6] User preauth-allow bypassed Duo 2FA due to user's UNIX group

admins and not users: bypass users 
  $ env UID=1000 ./groups.py -d -c confs/mockduo_admins_no_users.conf -f preauth-allow true
  [6] User preauth-allow bypassed Duo 2FA due to user's UNIX group
  $ env UID=1001 ./groups.py -d -c confs/mockduo_admins_no_users.conf -f preauth-allow true
  [6] User preauth-allow bypassed Duo 2FA due to user's UNIX group
  $ env UID=1002 ./groups.py -d -c confs/mockduo_admins_no_users.conf -f preauth-allow true
  [6] User preauth-allow bypassed Duo 2FA due to user's UNIX group
  $ env UID=1004 ./groups.py -d -c confs/mockduo_admins_no_users.conf -f preauth-allow true
  [6] User preauth-allow bypassed Duo 2FA due to user's UNIX group

non-existent shell
  $ env UID=1005 ./groups.py -d -c confs/mockduo_users.conf -f noshell true
  [6] User noshell bypassed Duo 2FA due to user's UNIX group
