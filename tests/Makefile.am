
TESTS_ENVIRONMENT = env BUILDDIR=$(abs_top_builddir) $(PYTHON) $(top_srcdir)/tests/cram.py 

TESTS = groups-0.t
TESTS += login_duo-0.t login_duo-1.t login_duo-2.t login_duo-3.t login_duo-4.t 
PAM_TESTS = pam_duo-0.t pam_duo-1.t pam_duo-2.t pam_duo-3.t pam_duo-4.t

check_LTLIBRARIES = libgroups_preload.la
libgroups_preload_la_SOURCES = groups_preload.c
libgroups_preload_la_LDFLAGS = -no-undefined -avoid-version -rpath /foo

if PAM
TESTS += $(PAM_TESTS)

check_LTLIBRARIES += libtestpam_preload.la
libtestpam_preload_la_SOURCES = testpam_preload.c
libtestpam_preload_la_LDFLAGS = -no-undefined -avoid-version -rpath /bar

check_PROGRAMS = testpam
testpam_LDADD = -lpam
endif

EXTRA_DIST = bson/codec.py bson/__init__.py certs confs cram.py mockduo.py testpam.py $(TESTS) $(PAM_TESTS)
