#
# SPDX-License-Identifier: GPL-2.0-with-classpath-exception
#
# Makefile.am
#
# Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
# All rights reserved.
#

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
	@conf=$(DESTDIR)$(sysconfdir)/login_duo.conf; \
	privsep_group=`id -gn $(DUO_PRIVSEP_USER) 2>/dev/null`; \
	if [ -n "$$privsep_group" ]; then \
	  echo "chown root:$$privsep_group $$conf"; \
	  chown root:$$privsep_group $$conf 2>/dev/null && chmod 640 $$conf && ok=1; \
	fi; \
	if [ -z "$$ok" ]; then \
	  echo "Privsep user '$(DUO_PRIVSEP_USER)' not found; installing $$conf root-owned mode 0600"; \
	  chown root $$conf 2>/dev/null; chmod 600 $$conf; \
	fi

EXTRA_DIST = login_duo.conf
