TESTS_ENVIRONMENT = env BUILDDIR=$(abs_top_builddir) $(PYTHON)

TESTS = test_login_duo.py test_crypto.py test_duo_split_at.py
PAM_TESTS = test_pam_duo.py

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

EXTRA_DIST = certs confs cram.py fips_scanner.sh is_fips_supported.sh groups.py login_duo.py mockduo.py mocklogin_duo.py paths.py pexpect.py testpam.py $(TESTS) $(PAM_TESTS) common_suites.py mockduo_context.py config.py
