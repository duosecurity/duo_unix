AM_CPPFLAGS = -I$(top_srcdir)/compat @OPENSSL_INCLUDES@

noinst_LTLIBRARIES = libduo.la

libduo_la_SOURCES = bson.h bson.c cacert.h duo.c \
		    http_parser.h http_parser.c https.h https.c ini.h ini.c \
		    urlenc.h urlenc.c util.c
libduo_la_LIBADD = @OPENSSL_LDFLAGS@ @OPENSSL_LIBS@
# http://sourceware.org/autobook/autobook/autobook_91.html
libduo_la_LDFLAGS = -no-undefined -version-info 3:0:0 -export-symbols-regex '^duo_'

libduo_la_includedir = $(includedir)
libduo_la_include_HEADERS = duo.h duo_private.h util.h shell.h

notrans_dist_man3_MANS = duo.3

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libduo.pc

noinst_PROGRAMS = testduo testutil_duo_split_at

testduo_LDADD = libduo.la $(top_builddir)/compat/libcompat.la

testutil_duo_split_at_LDADD = libduo.la $(top_builddir)/compat/libcompat.la

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)
	-@if [ ! -f $(DESTDIR)$(sysconfdir)/duo.crt ]; then \
	  cp duo.crt $(DESTDIR)$(sysconfdir)/duo.crt; \
	  echo "Created ${DESTDIR}$(sysconfdir)/duo.crt"; \
	else \
	  echo "Found existing ${DESTDIR}$(sysconfdir)/duo.crt - skipping"; \
	fi

