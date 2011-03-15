# 
# Copyright 2010 Duo Security
# All rights reserved, all wrongs reversed

# Minimum autoconf version
AC_PREREQ(2.65)

# Package, version, bug report address
AC_INIT([duo_unix],
	[1.2],
	[duo_unix@duosecurity.com])

# Tells autoconf where to find necessary build scripts and macros.
AC_CONFIG_AUX_DIR([autotools])
AC_CONFIG_MACRO_DIR([autotools])

# Init automake
AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_MAINTAINER_MODE

# Init header
AC_CONFIG_HEADER(config.h)

# Default sysconfdir to /etc, if no --prefix is given
case "$prefix" in
     NONE) test "$sysconfdir" = '${prefix}/etc' && sysconfdir=/etc ;;
esac

# Determine platform
AC_CANONICAL_HOST
AC_DEFINE_UNQUOTED([CANONICAL_HOST], ["${host}"], [Canonical host])

# Check for programs
AC_PROG_CC
AM_PROG_CC_C_O
AC_USE_SYSTEM_EXTENSIONS
AC_PROG_INSTALL
LT_INIT

# Compiler options
if test "x$GCC" = "xyes"; then
   CFLAGS="$CFLAGS -Wall -D_FORTIFY_SOURCE=2"
   AC_MSG_NOTICE([Adding gcc options: $CFLAGS])
fi
GGL_CHECK_STACK_PROTECTOR([has_stack_protector=yes], [has_stack_protector=no])
# XXX - disable -fstack-protector due to missing libssp_nonshared
case "$host_os" in
     *aix*)
	AC_MSG_NOTICE([-fstack-protector disabled on AIX])
	has_stack_protector=no
	;;
esac
if test x$has_stack_protector = xyes; then
   CFLAGS="$CFLAGS -fstack-protector"
   AC_MSG_NOTICE([-fstack-protector enabled in CFLAGS])
fi

# Check for platform features
AC_C_BIGENDIAN
AC_TYPE_INT64_T

# Check headers
AC_CHECK_HEADERS([inttypes.h stdint.h unistd.h])

# Check libcurl
LIBCURL_CHECK_CONFIG(["yes"], [7.15.1])
if test "x$libcurl_cv_lib_curl_usable" != "xyes"; then
   AC_MSG_ERROR(["no usable libcurl found"])
fi
if test "x$libcurl_protocol_HTTPS" != "xyes"; then
   AC_MSG_ERROR(["We need libcurl with support for HTTPS!"])
fi

# Default PAM install dir
case "$host" in
     *darwin*)         PAM_DIR="/usr/lib/pam" ;;
     *freebsd*)        PAM_DIR="/usr/lib" ;;
     *x86_64-*-linux*) PAM_DIR="/lib64/security" ;;
     *linux*)          PAM_DIR="/lib/security" ;;
     *)                PAM_DIR="/usr/lib/security" ;; # NetBSD, Solaris, AIX, HP-UX
esac
AC_SUBST(PAMDIR, "$PAM_DIR")

# Check PAM
AC_ARG_WITH(pam,
  AS_HELP_STRING([--with-pam=DIR],[build PAM module (and optionally override the default install DIR)]),
  [],
  [ with_pam=no ]
)
AM_CONDITIONAL([PAM], [ test "x$with_pam" != "xno" ])

if test "x$with_pam" != "xno" ; then
  AC_CHECK_HEADERS([security/pam_appl.h], [],
    [AC_MSG_ERROR([[PAM header files not found, install libpam-dev/pam-devel/etc.]])])
  AC_CHECK_HEADERS([security/pam_modules.h security/pam_ext.h], [], [],
    [#include <security/pam_appl.h>])
  AC_CHECK_LIB([pam], [main], [AC_SUBST([LIBPAM], ["-lpam"])], AC_MSG_FAILURE([libpam not found]))
  AS_IF([ test "x$with_pam" != "xno" ], [
    case "${withval}" in
    /*) PAMDIR="${withval}";;
    ./*|../*) AC_MSG_ERROR(Bad value for --with-pam);;
    *)  PAMDIR="${PAM_DIR}";;
    esac
    AC_MSG_NOTICE([PAM installation path $PAMDIR])
  ])
  AC_SEARCH_LIBS(pam_vprompt, pam, [AC_DEFINE([HAVE_PAM_VPROMPT], [1], [Define if pam_vprompt exists])])
fi

# Check for Duo privsep user
case "$host" in
     *darwin*)		DUO_PRIVSEP_USER="_sshd" ;;
     *)			DUO_PRIVSEP_USER="sshd" ;;
esac
AC_ARG_WITH(privsep-user,
  AS_HELP_STRING([--with-privsep-user=USER],[Specify user for privilege separation (default sshd)]),
  [
	if test -n "$withval"  &&  test "x$withval" != "xno"  &&  \
	    test "x${withval}" != "xyes"; then
	    	DUO_PRIVSEP_USER=$withval
	fi
  ]
)
AC_DEFINE_UNQUOTED(DUO_PRIVSEP_USER, "$DUO_PRIVSEP_USER",
	[Dedicated user for privilege separation])
AC_SUBST(DUO_PRIVSEP_USER)

# Check for functions
AC_CONFIG_LIBOBJ_DIR([compat])
AC_REPLACE_FUNCS([asprintf getgrouplist strlcpy])
AC_SEARCH_LIBS(inet_ntoa, nsl)
AC_SEARCH_LIBS(gethostbyname, resolv nsl)

AC_CONFIG_FILES(Makefile compat/Makefile lib/Makefile lib/libduo.pc login_duo/Makefile pam_duo/Makefile)

AC_OUTPUT
