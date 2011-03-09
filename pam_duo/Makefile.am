
AM_CPPFLAGS = -I$(top_srcdir)/compat -I$(top_srcdir)/lib @LIBCURL_CPPFLAGS@

pam_libdir = $(DESTDIR)@PAMDIR@
pam_lib_LTLIBRARIES = pam_duo.la

pam_duo_la_DEFS = -DDEBUG_PAM -DPAM_DEBUG @DEFS@
pam_duo_la_SOURCES = pam_duo.c pam_extra.h pam_extra.c
pam_duo_la_LIBADD = $(top_builddir)/lib/libcommon.la @LIBCURL@ -lssl -lcrypto -lpam
pam_duo_la_LDFLAGS = -module -no-undefined -avoid-version

notrans_dist_man8_MANS = pam_duo.8

noinst_PROGRAMS = testpam
testpam_LDADD = -lpam
