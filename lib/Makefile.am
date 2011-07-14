
AM_CPPFLAGS = -I$(top_srcdir)/compat @LIBCURL_CPPFLAGS@

lib_LTLIBRARIES = libduo.la

libduo_la_SOURCES = bson.h bson.c cacert.h duo.c \
		    groupaccess.h groupaccess.c ini.h ini.c \
		    match.h match.c urlenc.h urlenc.c
libduo_la_LIBADD = $(top_builddir)/compat/libcompat.la @LIBCURL@ -lssl -lcrypto
# http://sourceware.org/autobook/autobook/autobook_91.html
libduo_la_LDFLAGS = -no-undefined -version-info 2:0:0

libduo_la_includedir = $(includedir)
libduo_la_include_HEADERS = duo.h

notrans_dist_man3_MANS = duo.3

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libduo.pc

noinst_PROGRAMS = testduo

testduo_LDADD = libduo.la

