
ACLOCAL_AMFLAGS = -I autotools

SUBDIRS = compat lib login_duo

if PAM
SUBDIRS += pam_duo
endif

SUBDIRS += tests

EXTRA_DIST = AUTHORS CHANGES LICENSE

# XXX - get around our default non-prefix-preserving paths for distcheck
DISTCHECK_CONFIGURE_FLAGS = --sysconfdir='$${prefix}/etc/duo'
if PAM
DISTCHECK_CONFIGURE_FLAGS += --with-pam='$${prefix}/lib/security'
endif

