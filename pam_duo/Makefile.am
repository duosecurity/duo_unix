
AM_CPPFLAGS = -I$(top_srcdir)/compat -I$(top_srcdir)/lib @OPENSSL_INCLUDES@

pam_libdir = @PAMDIR@
pam_lib_LTLIBRARIES = pam_duo.la

pam_duo_la_DEFS = -DDEBUG_PAM -DPAM_DEBUG @DEFS@
pam_duo_la_SOURCES = pam_duo.c pam_extra.h pam_extra.c
pam_duo_la_LIBADD = $(top_builddir)/lib/libduo.la $(top_builddir)/compat/libcompat.la @OPENSSL_LDFLAGS@ @OPENSSL_LIBS@ -lpam
pam_duo_la_LDFLAGS = -module -no-undefined -avoid-version -shared -export-symbols-regex '^pam_sm_'

notrans_dist_man8_MANS = pam_duo.8

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)
	-@if [ ! -f $(DESTDIR)$(sysconfdir)/pam_duo.conf ]; then \
		cp pam_duo.conf $(DESTDIR)$(sysconfdir)/pam_duo.conf; \
		echo "Created ${DESTDIR}$(sysconfdir)/pam_duo.conf"; \
		echo "Please edit it to add your Duo integration and secret keys"; \
	else \
		echo "Found existing ${DESTDIR}$(sysconfdir)/pam_duo.conf - updating permissions"; \
	fi
	-chmod 600 $(DESTDIR)$(sysconfdir)/pam_duo.conf
	-@if test "x$(IS_AIX)" = "xyes"; then \
		rm -f $(PAMDIR)/pam_duo.so; \
		ar x $(top_builddir)/pam_duo/.libs/pam_duo.a $(PAMDIR)/pam_duo.so; \
		echo "Extracting shared object ${PAMDIR}/pam_duo.so from $(top_builddir)/pam_duo/.libs/pam_duo.a"; \
	fi

uninstall-local:
	-@if test "x$(IS_AIX)" = "xyes"; then \
		rm -f $(PAMDIR)/pam_duo.so; \
		echo "Removing shared object ${PAMDIR}/pam_duo.so"; \
	fi

EXTRA_DIST = pam_duo.conf
