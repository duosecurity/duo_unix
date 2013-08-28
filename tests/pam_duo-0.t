
Basic help output

  $ ${TESTDIR}/testpam.py -h
  Usage: */tests/testpam.py [-d] [-c config] [-f user] [-h host] (glob)
  [1]

Missing conf file

  $ ${TESTDIR}/testpam.py -d -c /nonexistent true
  [3] Couldn't open /nonexistent: No such file or directory

Bad permissions on conf file

  $ ${TESTDIR}/../autotools/install-sh -c -m 644 ${TESTDIR}/confs/duo.conf ${TMPDIR}
  $ ${TESTDIR}/testpam.py -d -c ${TMPDIR}/duo.conf true
  */duo.conf must be readable only by user '*' (glob)

Ensure perms on conf files

  $ chmod 600 ${TESTDIR}/confs/*.conf

Bad configuration files

  $ for config in ${TESTDIR}/confs/bad-*.conf; do echo '==>' `basename $config` && ${TESTDIR}/testpam.py -d -c $config true; done
  ==> bad-corrupt.conf
  [3] Parse error in */tests/confs/bad-corrupt.conf, line 5 (glob)
  ==> bad-empty.conf
  [3] Missing host, ikey, or skey in */tests/confs/bad-empty.conf (glob)
  ==> bad-header_only.conf
  [3] Missing host, ikey, or skey in */tests/confs/bad-header_only.conf (glob)
  ==> bad-missing_values.conf
  [3] Missing host, ikey, or skey in */tests/confs/bad-missing_values.conf (glob)

