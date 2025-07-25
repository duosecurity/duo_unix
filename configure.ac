#
# SPDX-License-Identifier: GPL-2.0-with-classpath-exception
#
# Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
# All rights reserved.

# Minimum autoconf version
AC_PREREQ(2.65)

# Package, version, bug report address
AC_INIT([duo_unix],
	[2.1.0],
	[support@duosecurity.com])

# Tells autoconf where to find necessary build scripts and macros.
AC_CONFIG_AUX_DIR([autotools])
AC_CONFIG_MACRO_DIR([autotools])

# Init automake
AM_INIT_AUTOMAKE([1.12.0 foreign subdir-objects serial-tests])
AM_MAINTAINER_MODE
AB_INIT

# Init header
AC_CONFIG_HEADER(config.h)

# Default sysconfdir to /etc/duo
test "$sysconfdir" = '${prefix}/etc' && sysconfdir=/etc/duo
AC_DEFINE_DIR([DUO_CONF_DIR], [sysconfdir], [Configuration directory])

# Determine platform
AC_CANONICAL_HOST
AC_DEFINE_UNQUOTED([CANONICAL_HOST], ["${host}"], [Canonical host])
AC_AIX

# Check for programs
AC_PROG_CC
AM_PROG_CC_C_O
AC_USE_SYSTEM_EXTENSIONS
AC_PROG_INSTALL
AC_PROG_MKDIR_P
LT_INIT

AC_MSG_NOTICE(checking if we can establish a build date)
AC_PATH_TOOL(GIT,[git])
AS_IF([test x"$GIT" != x], [
    AC_MSG_CHECKING(are we configuring inside a git repository)
    $GIT rev-parse 2>/dev/null
    is_git_repo=$?
    AS_IF([test $is_git_repo == 0], [
       AC_MSG_RESULT(yes)
       AC_MSG_CHECKING(is the current working tree clean)
       $GIT update-index --really-refresh
       $GIT diff-index --quiet HEAD
       AS_IF([test $? == 0],
           [
               AC_MSG_RESULT(yes)
               source_date_epoch=`$GIT show -s --format=%ct`
               AC_MSG_NOTICE(setting build-date to $source_date_epoch)
               echo "$source_date_epoch" > build-date
           ],
           [
               AC_MSG_RESULT(no current working tree is dirty)
               AC_MSG_NOTICE(removing build-date)
               rm -f build-date
           ]
       )
    ],
    [
       AC_MSG_RESULT(no)
    ])
])

# Set third party library versions
unity_version=Unity-2.5.2
AC_DEFINE_DIR([UNITY_VERSION], [unity_version], [Unity directory name])


# Compiler options
if test "x$GCC" = "xyes"; then
   if test "x$with_coverage" != "xyes"; then
      CFLAGS="$CFLAGS -Wall -D_FORTIFY_SOURCE=2 -fPIE"
      AC_MSG_NOTICE([Adding gcc options: $CFLAGS])
   fi
fi
GGL_CHECK_STACK_PROTECTOR([has_stack_protector=yes], [has_stack_protector=no])
IS_AIX=no
# XXX - disable -fstack-protector due to missing libssp_nonshared
case "$host_os" in
    linux* | gnu* | k*bsd*-gnu)
        CFLAGS="$CFLAGS -Wl,-z,relro,-z,now,--no-as-needed,-ldl"
        ;;
    *aix*)
        AC_MSG_NOTICE([-fstack-protector disabled on AIX])
        AC_MSG_NOTICE([Compiler optimizations disabled on AIX])
        CFLAGS="$CFLAGS -O0 -Wl,-lm"
        has_stack_protector=no
        IS_AIX=yes
        ;;
    *sunos*)
        AC_MSG_NOTICE([-fstack-protector disabled on SunOS])
        has_stack_protector=no
        ;;
    *solaris*)
        AC_MSG_NOTICE([-fstack-protector disabled on Solaris])
        has_stack_protector=no
        ;;
esac
if test x$has_stack_protector = xyes; then
   CFLAGS="$CFLAGS -fstack-protector"
   AC_MSG_NOTICE([-fstack-protector enabled in CFLAGS])
fi

AC_SUBST(IS_AIX, "$IS_AIX")

# Check for platform features
AC_C_BIGENDIAN
AC_C_CONST
AC_TYPE_INT64_T
AH_BOTTOM([/* XXX - common HP-UX b0rkage */
#ifdef hpux
# include <sys/types.h>
# ifndef _BSIZE_T
# define _BSIZE_T
typedef long  sbsize_t;
typedef unsigned long bsize_t;
# endif
#endif
])

# Check headers
AC_HEADER_STDC
AC_CHECK_HEADERS([inttypes.h limits.h memory.h stdint.h stdlib.h string.h unistd.h])

# Check OpenSSL
AX_CHECK_OPENSSL([], AC_MSG_FAILURE([OpenSSL not found]))
# Define if X509_TEA_set_state exists
AX_CHECK_X509(AC_DEFINE([HAVE_X509_TEA_SET_STATE],[1],[Define if X509_set_state exists]), [])
# Default PAM install dir
case "$host" in
     *darwin*)         PAM_DIR="/usr/lib/pam" ;;
     *freebsd*)        PAM_DIR="/usr/lib" ;;
     *x86_64-*-linux*) PAM_DIR="/lib64/security" ;;
     *linux*)          PAM_DIR="/lib/security" ;;
     *)                PAM_DIR="/usr/lib/security" ;; # NetBSD, Solaris, AIX, HP-UX
esac

AC_ARG_WITH(coverage,
  AS_HELP_STRING([--with-coverage=COV],[build for coverage testing]),
  [],
  [ with_coverage=no ]
)
AM_CONDITIONAL([COVERAGE], [ test "x$with_coverage" != "xno" ])
AS_IF([test "x$with_coverage" != "xno"], [
   CFLAGS="$CFLAGS -O0 --coverage"
   LFLAGS="$LFLAGS -lgcov --coverage"
   AC_MSG_NOTICE([--coverage enabled in CFLAGS])
])

AC_ARG_WITH(debug,
  AS_HELP_STRING([--with-debug=DBG],[build with debug info]),
  [],
  [ with_debug=no ]
)
AM_CONDITIONAL([DEBUG], [ test "x$with_debug" != "xno" ])
AS_IF([test "x$with_debug" != "xno"], [
   CFLAGS="$CFLAGS -g2"
   AC_MSG_NOTICE([debugging enabled in CFLAGS])
])
AS_IF([test "x$with_debug" == "xno"], [
   CFLAGS="$CFLAGS -g0"
])

# Check PAM
AC_ARG_WITH(pam,
  AS_HELP_STRING([--with-pam=DIR],[build PAM module (and optionally override the default install DIR)]),
  [],
  [ with_pam=no ]
)
AM_CONDITIONAL([PAM], [ test "x$with_pam" != "xno" ])

AS_IF([test "x$with_pam" != "xno"], [
  save_LIBS=$LIBS
  AC_CHECK_HEADERS([security/pam_appl.h], [],
    [AC_MSG_ERROR([[PAM header files not found. Install libpam-dev/pam-devel/etc.]])])
  AC_CHECK_HEADERS([security/pam_modules.h security/pam_ext.h], [], [],
    [#include <security/pam_appl.h>])

  AC_CHECK_LIB([pam], [main], [], AC_MSG_FAILURE([libpam not found]))
  AC_SUBST([LIBPAM], ["-lpam"])

  AS_IF([ test "x$with_pam" != "xno" ], [
    case "${withval}" in
    /*|\$*) PAMDIR="${withval}";;
    ./*|../*) AC_MSG_ERROR(Bad value for --with-pam);;
    *)  PAMDIR="${PAM_DIR}";;
    esac
    AC_MSG_NOTICE([PAM installation path $PAMDIR])
  ])
  AC_CHECK_FUNCS([pam_vprompt])
  LIBS=$save_LIBS
])
AC_SUBST(PAMDIR, "$PAMDIR")

# Check for Duo privsep user
case "$host" in
     *darwin*)		DUO_PRIVSEP_USER="_sshd" ;;
     *)			DUO_PRIVSEP_USER="sshd" ;;
esac
AC_ARG_WITH(privsep-user,
  AS_HELP_STRING([--with-privsep-user=USER],[Specify user for privilege separation]),
  [
	if test -n "$withval" && test "x$withval" != "xno" && \
	    test "x${withval}" != "xyes" && test "x${withval}" != "xroot" ; then
	    	DUO_PRIVSEP_USER=$withval
	else
		AC_MSG_ERROR(["Invalid privsep user specified"])
	fi
  ]
)
AC_MSG_NOTICE([Using privilege separation user "$DUO_PRIVSEP_USER"])
AC_DEFINE_UNQUOTED(DUO_PRIVSEP_USER, "$DUO_PRIVSEP_USER",
	[Dedicated user for privilege separation])
AC_SUBST(DUO_PRIVSEP_USER)

# Multilib foo
AC_ARG_ENABLE(lib64,
[ --enable-lib64=[yes/no] Enable lib64 support [default=yes]],,
    enable_lib64=yes)
AC_SUBST(enable_lib64)

# If the user specified a libdir ending in lib64 do not append another
# 64 to the library names.
base_libdir=`basename "$libdir"`
case $base_libdir in
lib64)
  enable_lib64=no
esac

AC_MULTILIB($enable_lib64)
libdir="$libdir$libdirsuffix"
AC_MSG_NOTICE([Using libdir "$libdir"])

# Check for functions
AC_CONFIG_LIBOBJ_DIR([compat])
AC_CHECK_FUNCS([memcpy memset sysconf getaddrinfo open64 fopen64 explicit_bzero memset_s])
AC_REPLACE_FUNCS([asprintf getgrouplist strlcpy vsyslog strnlen timegm])
AC_SEARCH_LIBS(inet_ntoa, nsl)
AC_SEARCH_LIBS(socket, socket)

AC_CONFIG_FILES(Makefile compat/Makefile duo_unix_support/Makefile lib/Makefile lib/libduo.pc login_duo/Makefile pam_duo/Makefile tests/Makefile tests/unity_tests/Makefile tests/unity_tests/Unity-2.5.2/Makefile)

AC_OUTPUT
