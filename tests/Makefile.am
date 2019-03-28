TESTS_ENVIRONMENT = env BUILDDIR=$(abs_top_builddir) $(PYTHON) $(top_srcdir)/tests/cram.py

# Preserve ordering; login_duo-0.t does some setup
TESTS = login_duo-0.t login_duo-1.t login_duo-2.t login_duo-3.t login_duo-4.t login_duo-5.t login_duo-6.t login_duo-7.t
TESTS += groups-0.t groups-1.t groups-2.t mocklogin_duo-0.t mocklogin_duo-1.t util-0.t test_crypto-0.t
PAM_TESTS = pam_duo-0.t pam_duo-1.t pam_duo-2.t pam_duo-3.t pam_duo-4.t pam_duo-5.t pam_duo-6.t pam_duo-7.t

check_LTLIBRARIES = libgroups_preload.la
libgroups_preload_la_SOURCES = groups_preload.c
libgroups_preload_la_LDFLAGS = -no-undefined -avoid-version -rpath /foo -shared

check_LTLIBRARIES += liblogin_duo_preload.la
liblogin_duo_preload_la_SOURCES = login_duo_preload.c
liblogin_duo_preload_la_LDFLAGS = -no-undefined -avoid-version -rpath /baz -shared

if PAM
TESTS += $(PAM_TESTS)

check_LTLIBRARIES += libtestpam_preload.la
libtestpam_preload_la_SOURCES = testpam_preload.c
libtestpam_preload_la_LDFLAGS = -no-undefined -avoid-version -rpath /bar -shared

check_PROGRAMS = testpam
testpam_LDADD = -lpam
endif

EXTRA_DIST = bson/codec.py bson/__init__.py certs confs cram.py fips_scanner.sh is_fips_supported.sh groups.py login_duo.py mockduo.py mocklogin_duo.py paths.py pexpect.py testpam.py $(TESTS) $(PAM_TESTS)
