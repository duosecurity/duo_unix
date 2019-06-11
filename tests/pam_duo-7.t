mockduo with valid cert
  $ cd ${TESTDIR}
  $ python mockduo.py certs/mockduo.pem >/dev/null 2>&1 &
  $ MOCKPID=$!
  $ trap 'exec kill $MOCKPID >/dev/null 2>&1' EXIT
  $ sleep 1

Send gecos field unparsed
  $ ./testpam.py -d -c confs/mockduo_gecos_send_unparsed.conf -f "fullgecos" true
  [4] Skipped Duo login for 'full_gecos_field': full-gecos-field

Deprecated gecos_parsed flag
  $ ./testpam.py -d -c confs/mockduo_gecos_deprecated_parse_flag.conf -f "gecos/6" true
  [3] The gecos_parsed configuration item for Duo Unix is deprecated and no longer has any effect. Use gecos_delim and gecos_username_pos instead
  [4] Skipped Duo login for 'gecos/6': gecos/6

Gecos delimiter = default position = 6
  $ ./testpam.py -d -c confs/mockduo_gecos_default_delim_6_pos.conf -f "gecos,6" true
  [4] Skipped Duo login for 'gecos_user_gecos_field6': gecos-user-gecos-field6-allowed

Gecos delimiter = / position = 3
  $ ./testpam.py -d -c confs/mockduo_gecos_slash_delim_3_pos.conf -f "gecos/3" true
  [4] Skipped Duo login for 'gecos_user_gecos_field3': gecos-user-gecos-field3-allowed

Gecos invalid delimiter length
  $ ./testpam.py -d -c confs/mockduo_gecos_long_delim.conf true
  Invalid character option length. Character fields must be 1 character long: ',,'
  [3] Invalid pam_duo option: 'gecos_delim'
  [3] Parse error in confs/mockduo_gecos_long_delim.conf, line 6

Gecos invalid delimiter value, :
  $ ./testpam.py -d -c confs/mockduo_gecos_invalid_delim_colon.conf true
  Invalid gecos_delim ':' (delimiter must be punctuation other than ':')
  [3] Invalid pam_duo option: 'gecos_delim'
  [3] Parse error in confs/mockduo_gecos_invalid_delim_colon.conf, line 6

Gecos invalid delimiter value, non punctuation
  $ ./testpam.py -d -c confs/mockduo_gecos_invalid_delim_punc.conf true
  Invalid gecos_delim 'a' (delimiter must be punctuation other than ':')
  [3] Invalid pam_duo option: 'gecos_delim'
  [3] Parse error in confs/mockduo_gecos_invalid_delim_punc.conf, line 6

Gecos invalid delimiter value, whitespace
  $ ./testpam.py -d -c confs/mockduo_gecos_invalid_delim_whitespace.conf true
  Invalid character option length. Character fields must be 1 character long: ''
  [3] Invalid pam_duo option: 'gecos_delim'
  [3] Parse error in confs/mockduo_gecos_invalid_delim_whitespace.conf, line 6

Gecos invalid pos value
  $ ./testpam.py -d -c confs/mockduo_gecos_invalid_pos.conf true
  Gecos position starts at 1
  [3] Invalid pam_duo option: 'gecos_username_pos'
  [3] Parse error in confs/mockduo_gecos_invalid_pos.conf, line 6
