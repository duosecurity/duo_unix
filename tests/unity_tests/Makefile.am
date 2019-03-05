AM_CPPFLAGS = -I$(top_srcdir)/compat -I$(top_srcdir)/lib -I$(top_srcdir)/tests/unity_tests/$(UNITY_VERSION) @OPENSSL_INCLUDES@
TESTS_ENVIRONMENT = env BUILDDIR=$(abs_top_builddir)/unityrunner 

SUBDIRS = $(UNITY_VERSION)

# Create the unity runner executable
check_PROGRAMS = unityrunner add_groupname add_param_test
unityrunner_LDADD = $(top_builddir)/lib/libduo.la $(top_builddir)/compat/libcompat.la $(top_builddir)/tests/unity_tests/$(UNITY_VERSION)/libunity.la

add_groupname_LDADD = $(top_builddir)/lib/libduo.la $(top_builddir)/compat/libcompat.la $(top_builddir)/tests/unity_tests/$(UNITY_VERSION)/libunity.la
add_groupname_CFLAGS = -Werror -Wunused-function

add_param_test_LDADD = $(top_builddir)/lib/libduo.la $(top_builddir)/compat/libcompat.la $(top_builddir)/tests/unity_tests/$(UNITY_VERSION)/libunity.la
add_param_test_CFLAGS = -Werror -Wunused-function

TESTS = unityrunner add_groupname add_param_test
