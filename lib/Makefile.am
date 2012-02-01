
AM_CPPFLAGS = -I$(top_srcdir)/compat $(OPENSSL_CFLAGS)

lib_LTLIBRARIES = libduo.la

libduo_la_SOURCES = bson.h bson.c cacert.h duo.c \
		    http_parser.h http_parser.c https.h https.c ini.h ini.c \
		    urlenc.h urlenc.c
libduo_la_LIBADD = ../libcommon.la $(OPENSSL_LIBS)
# http://sourceware.org/autobook/autobook/autobook_91.html
libduo_la_LDFLAGS = -no-undefined -version-info 3:0:0

libduo_la_includedir = $(includedir)
libduo_la_include_HEADERS = duo.h

notrans_dist_man3_MANS = duo.3

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libduo.pc

noinst_PROGRAMS = testduo

testduo_LDADD = libduo.la

install-exec-hook:
	-@if [ ! -f $(DESTDIR)$(sysconfdir)/duo.crt ]; then \
	  mkdir -p -m 755 $(DESTDIR)$(sysconfdir); \
	  cp duo.crt $(DESTDIR)$(sysconfdir)/duo.crt; \
	  echo "Created ${DESTDIR}$(sysconfdir)/duo.crt"; \
	else \
	  echo "Found existing ${DESTDIR}$(sysconfdir)/login_duo.conf - skipping"; \
	fi

