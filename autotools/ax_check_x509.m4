#
#   Copyright (c) 2014 Duo Security
#   All rights reserved, all wrongs reversed
#
# SYNOPSIS
#
#   AX_CHECK_X509([action-if-found[, action-if-not-found]])
#
# DESCRIPTION
#
#   Checks to see if the function X509_TEA_set_state exists in OPENSSL_LIBS
#
#serial 1

AU_ALIAS([CHECK_X509], [AX_CHECK_X509])
AC_DEFUN([AX_CHECK_X509],[
    AC_MSG_CHECKING([whether X509_TEA_set_state runs])
    save_LIBS="$LIBS"
    save_LDFLAGS="$LDFLAGS"
    save_CPPFLAGS="$CPPFLAGS"
    LDFLAGS="$LDFLAGS $OPENSSL_LDFLAGS"
    LIBS="$OPENSSL_LIBS $LIBS"
    CPPFLAGS="$OPENSSL_INCLUDES $CPPFLAGS"
    AC_RUN_IFELSE(
        AC_LANG_PROGRAM([void X509_TEA_set_state(int change);], [X509_TEA_set_state(0);]),
        [
            AC_MSG_RESULT([yes])
            $1
        ], [
            AC_MSG_RESULT([no])
            $2
    ])
    CPPFLAGS="$save_CPPFLAGS"
    LDFLAGS="$save_LDFLAGS"
    LIBS="$save_LIBS"
])