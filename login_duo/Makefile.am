AM_CPPFLAGS = -I$(top_srcdir)/compat -I$(top_srcdir)/lib @OPENSSL_INCLUDES@ 

sbin_PROGRAMS = login_duo

login_duo_SOURCES = login_duo.c
login_duo_LDADD = $(top_builddir)/lib/libduo.la $(top_builddir)/compat/libcompat.la @OPENSSL_LDFLAGS@ @OPENSSL_LIBS@

notrans_dist_man8_MANS = login_duo.8

install-exec-hook:
	-chown root $(DESTDIR)$(sbindir)/login_duo && \
	 chmod 4755 $(DESTDIR)$(sbindir)/login_duo

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)
	-@if [ ! -f $(DESTDIR)$(sysconfdir)/login_duo.conf ]; then \
	  cp login_duo.conf $(DESTDIR)$(sysconfdir)/login_duo.conf; \
	  echo "Created ${DESTDIR}$(sysconfdir)/login_duo.conf"; \
	  echo "Please edit it to add your Duo integration and secret keys"; \
	else \
	  echo "Found existing ${DESTDIR}$(sysconfdir)/login_duo.conf - updating permissions"; \
	fi
	-chown $(DUO_PRIVSEP_USER) $(DESTDIR)$(sysconfdir)/login_duo.conf
	-chmod 600 $(DESTDIR)$(sysconfdir)/login_duo.conf

EXTRA_DIST = login_duo.conf
