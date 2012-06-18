
ACLOCAL_AMFLAGS = -I autotools

noinst_LTLIBRARIES = libcommon.la

libcommon_la_SOURCES = \
	lib/groupaccess.c lib/groupaccess.h \
	lib/match.c lib/match.h
libcommon_la_LIBADD = @LTLIBOBJS@

SUBDIRS = . lib login_duo

if PAM
SUBDIRS += pam_duo
endif

SUBDIRS += tests

dist_doc_DATA = README AUTHORS CHANGES LICENSE

# XXX - get around our default non-prefix-preserving paths for distcheck
DISTCHECK_CONFIGURE_FLAGS = --sysconfdir='$${prefix}/etc/duo'
if PAM
DISTCHECK_CONFIGURE_FLAGS += --with-pam='$${prefix}/lib/security'
endif

