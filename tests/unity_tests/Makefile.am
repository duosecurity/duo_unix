AM_CPPFLAGS = -I$(top_srcdir)/compat -I$(top_srcdir)/lib -I$(top_srcdir)/tests/unity_tests/$(UNITY_VERSION) @OPENSSL_INCLUDES@
TESTS_ENVIRONMENT = env BUILDDIR=$(abs_top_builddir)/unityrunner 

SUBDIRS = $(UNITY_VERSION)

# Create the unity runner executable
check_PROGRAMS = unityrunner
unityrunner_LDADD = $(top_builddir)/lib/libduo.la $(top_builddir)/compat/libcompat.la $(top_builddir)/tests/unity_tests/$(UNITY_VERSION)/libunity.la
TESTS = unityrunner
