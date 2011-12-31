
Basic help output

  $ ${BUILDDIR}/login_duo/login_duo -h
  *login_duo: option requires an argument* (glob)
  Usage: login_duo [-v] [-c config] [-d] [-f duouser] [-h host] [prog [args...]]
  [1]

Missing conf file

  $ ${BUILDDIR}/login_duo/login_duo -d -c /nonexistent true
  Couldn't open /nonexistent: No such file or directory

Bad permissions on conf file

  $ ${TESTDIR}/../autotools/install-sh -c -m 644 ${TESTDIR}/confs/duo.conf ${TMPDIR}
  $ ${BUILDDIR}/login_duo/login_duo -d -c ${TMPDIR}/duo.conf true
  */duo.conf must be readable only by user '*' (glob)

Ensure perms on conf files

  $ chmod 600 ${TESTDIR}/confs/*.conf

Bad configuration files

  $ for config in ${TESTDIR}/confs/bad-*.conf; do echo '==>' `basename $config` && ${BUILDDIR}/login_duo/login_duo -d -c $config true; done
  ==> bad-corrupt.conf
  Parse error in */tests/confs/bad-corrupt.conf, line 5 (glob)
  ==> bad-empty.conf
  Missing host, ikey, or skey in */tests/confs/bad-empty.conf (glob)
  ==> bad-header_only.conf
  Missing host, ikey, or skey in */tests/confs/bad-header_only.conf (glob)
  ==> bad-missing_values.conf
  Missing host, ikey, or skey in */tests/confs/bad-missing_values.conf (glob)

