mockduo with valid cert

  $ cd ${TESTDIR}
  $ python mockduo.py certs/mockduo.pem >/dev/null 2>&1 &
  $ MOCKPID=$!
  $ trap 'exec kill $MOCKPID >/dev/null 2>&1' EXIT
  $ sleep 1

Sync
  $ ${BUILDDIR}/login_duo/login_duo -d -c confs/mockduo.conf -f whatever true < /dev/null
  [6] Successful Duo login for 'whatever'

FIPS testing variable setup
  $ fips_available=$(./is_fips_supported.sh) && echo "[1]"
  [1]

mocklogin_duo
  $ if [ $fips_available -eq 0 ]; then
  >    CONFS="mockduo_fips.conf";
  > else
  >    CONFS="mockduo.conf";
  > fi
  $ python ./mocklogin_duo.py confs/$CONFS
  ===> 'Duo login for foobar\r\n\r\nChoose or lose:\r\n\r\n  1. Push 1\r\n  2. Phone 1\r\n  3. SMS 1 (deny)\r\n  4. Phone 2 (deny)\r\n\r\nPasscode or option (1-4): '
  ===> "123456\r\n\r\nInvalid passcode, please try again.\r\n[4] Failed Duo login for 'foobar'\r\n\r\nDuo login for foobar\r\n\r\nChoose or lose:\r\n\r\n  1. Push 1\r\n  2. Phone 1\r\n  3. SMS 1 (deny)\r\n  4. Phone 2 (deny)\r\n\r\nPasscode or option (1-4): "
  ===> "wefawefgoiagj3rj\r\n\r\nInvalid passcode, please try again.\r\n[4] Failed Duo login for 'foobar'\r\n\r\nDuo login for foobar\r\n\r\nChoose or lose:\r\n\r\n  1. Push 1\r\n  2. Phone 1\r\n  3. SMS 1 (deny)\r\n  4. Phone 2 (deny)\r\n\r\nPasscode or option (1-4): "
  ===> "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n[3] Error in Duo login for 'foobar'\r\n"
  ===> 'Duo login for foobar\r\n\r\nChoose or lose:\r\n\r\n  1. Push 1\r\n  2. Phone 1\r\n  3. SMS 1 (deny)\r\n  4. Phone 2 (deny)\r\n\r\nPasscode or option (1-4): '
  ===> "3\r\n\r\nNew SMS passcodes sent\r\n[4] Failed Duo login for 'foobar'\r\n\r\nDuo login for foobar\r\n\r\nChoose or lose:\r\n\r\n  1. Push 1\r\n  2. Phone 1\r\n  3. SMS 1 (deny)\r\n  4. Phone 2 (deny)\r\n\r\nPasscode or option (1-4): "
  ===> "4\r\n\r\nDialing XXX-XXX-5678...\r\nAnswered. Press '#' on your phone to log in.\r\nAuthentication timed out.\r\n[4] Failed Duo login for 'foobar'\r\n\r\nDuo login for foobar\r\n\r\nChoose or lose:\r\n\r\n  1. Push 1\r\n  2. Phone 1\r\n  3. SMS 1 (deny)\r\n  4. Phone 2 (deny)\r\n\r\nPasscode or option (1-4): "
  ===> "1\r\n\r\nPushed a login request to your phone.\r\nSuccess. Logging you in...\r\n[6] Successful Duo login for 'foobar'\r\nSUCCESS\r\n"
  ===> 'Duo login for foobar\r\n\r\nChoose or lose:\r\n\r\n  1. Push 1\r\n  2. Phone 1\r\n  3. SMS 1 (deny)\r\n  4. Phone 2 (deny)\r\n\r\nPasscode or option (1-4): '
  ===> "2\r\n\r\nDialing XXX-XXX-1234...\r\nAnswered. Press '#' on your phone to log in.\r\nSuccess. Logging you in...\r\n[6] Successful Duo login for 'foobar'\r\nSUCCESS\r\n"
