util.{c,h} unit tests

  $ cd ${BUILDDIR}/lib

duo_split_at: basic
  $ ./testutil_duo_split_at foo/bar/baz / 1 bar
  OK

duo_split_at: first
  $ ./testutil_duo_split_at foo/bar/baz / 0 foo
  OK

duo_split_at: last
  $ ./testutil_duo_split_at foo/bar/baz / 2 baz
  OK

duo_split_at: too many
  $ ./testutil_duo_split_at foo/bar/baz / 100 NULL
  OK

duo_split_at: no delimiter
  $ ./testutil_duo_split_at foo / 1 NULL
  OK

duo_split_at: starts with delimiter
  $ ./testutil_duo_split_at /foo/bar/baz / 0 ""
  OK

duo_split_at: ends with delimiter
  $ ./testutil_duo_split_at foo/bar/baz/ / 3 ""
  OK

duo_split_at: empty
  $ ./testutil_duo_split_at "" / 0 ""
  OK
