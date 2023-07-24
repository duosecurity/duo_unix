#
# SPDX-License-Identifier: GPL-2.0-with-classpath-exception
#
# Makefile.am
#
# Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
# All rights reserved.
#

ACLOCAL_AMFLAGS = -I autotools

SUBDIRS = compat lib login_duo duo_unix_support

if PAM
SUBDIRS += pam_duo
endif

SUBDIRS += tests
SUBDIRS += tests/unity_tests

dist_doc_DATA = README.md CONTRIBUTING.md AUTHORS CHANGES $(wildcard sbom.spdx)

LICENSES = $(wildcard LICENSES/*.txt)

licensedir = $(datadir)/LICENSES
dist_license_DATA = $(LICENSES)

# XXX - get around our default non-prefix-preserving paths for distcheck
DISTCHECK_CONFIGURE_FLAGS = --sysconfdir='$${prefix}/etc/duo'
if PAM
DISTCHECK_CONFIGURE_FLAGS += --with-pam='$${prefix}/lib/security'
endif
