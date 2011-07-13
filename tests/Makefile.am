
noinst_LTLIBRARIES = libtestpam_preload.la
libtestpam_preload_la_SOURCES = testpam_preload.c
libtestpam_preload_la_LDFLAGS = -module -no-undefined -avoid-version -rpath /foo

noinst_PROGRAMS = testpam
testpam_LDADD = -lpam

TESTS_ENVIRONMENT = env BUILDDIR=$(abs_top_builddir) $(PYTHON) $(top_srcdir)/tests/cram.py 

TESTS = login_duo.t mockduo-1.t mockduo-2.t mockduo-3.t mockduo-4.t

EXTRA_DIST = bson/codec.py bson/__init__.py certs confs cram.py mockduo.py $(TESTS)
