
AM_CPPFLAGS = -I$(top_srcdir)/compat -I$(top_srcdir)/lib @OPENSSL_INCLUDES@
SOURCES = pam_duo.c pam_extra.h pam_extra.c pam_duo_private.c pam_duo_private.h
LIBADD = $(top_builddir)/lib/libduo.la $(top_builddir)/compat/libcompat.la @OPENSSL_LDFLAGS@ @OPENSSL_LIBS@ -lpam
LDFLAGS = -module -no-undefined -avoid-version -shared -export-symbols-regex '^pam_sm_'

#Because pam_duo.la is shared, linking it with the unit tests will not compile
#Instead use unit_testing_pam_duo.la to link with them
check_LTLIBRARIES = unit_testing_pam_duo.la
unit_testing_pam_duo_la_SOURCES = $(SOURCES)
unit_testing_pam_duo_la_LIBADD = $(LIBADD)

pam_libdir = @PAMDIR@
pam_lib_LTLIBRARIES = pam_duo.la

pam_duo_la_DEFS = -DDEBUG_PAM -DPAM_DEBUG @DEFS@
pam_duo_la_SOURCES = $(SOURCES)
pam_duo_la_LIBADD = $(LIBADD)

notrans_dist_man8_MANS = pam_duo.8
semodule_name = authlogin_duo
semodule:
	-make -f /usr/share/selinux/devel/Makefile

semodule-install:
	-bzip2 -9 $(semodule_name).pp
	-install -d $(DESTDIR)/usr/share/selinux/packages/
	-install -m 0644 $(semodule_name).pp.bz2 $(DESTDIR)/usr/share/selinux/packages/
	-semodule -i $(DESTDIR)/usr/share/selinux/packages/$(semodule_name).pp.bz2

semodule-remove:
	-semodule -r $(semodule_name)
	-rm -f $(DESTDIR)/usr/share/selinux/packages/$(semodule_name).pp.bz2

clean-local: clean-local-semodule

clean-local-semodule:
	-rm -f $(semodule_name).{mod,pp,pp.bz2}

.PHONY: semodule semodule-enable semodule-install semodule-remove clean-local-semodule


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

EXTRA_DIST = pam_duo.conf $(semodule_name).te
