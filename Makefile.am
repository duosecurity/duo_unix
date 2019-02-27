
ACLOCAL_AMFLAGS = -I autotools

SUBDIRS = compat lib login_duo

if PAM
SUBDIRS += pam_duo
endif

SUBDIRS += tests
SUBDIRS += tests/unity_tests

dist_doc_DATA = README.md CONTRIBUTING.md AUTHORS CHANGES LICENSE

# XXX - get around our default non-prefix-preserving paths for distcheck
DISTCHECK_CONFIGURE_FLAGS = --sysconfdir='$${prefix}/etc/duo'
if PAM
DISTCHECK_CONFIGURE_FLAGS += --with-pam='$${prefix}/lib/security'
endif

