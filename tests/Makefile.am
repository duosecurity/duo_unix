
TESTS_ENVIRONMENT = env BUILDDIR=$(abs_top_builddir) $(PYTHON) $(top_srcdir)/tests/cram.py 

TESTS = login_duo-0.t login_duo-1.t login_duo-2.t login_duo-3.t login_duo-4.t 
PAM_TESTS = pam_duo-0.t pam_duo-1.t pam_duo-2.t pam_duo-3.t pam_duo-4.t

EXTRA_DIST = bson/codec.py bson/__init__.py certs confs cram.py mockduo.py testpam.py $(TESTS) $(PAM_TESTS)

if PAM
check_LTLIBRARIES = libtestpam_preload.la
libtestpam_preload_la_SOURCES = testpam_preload.c
libtestpam_preload_la_LDFLAGS = -module -no-undefined -avoid-version -rpath /foo

check_PROGRAMS = testpam
testpam_LDADD = -lpam

TESTS += $(PAM_TESTS)
endif
