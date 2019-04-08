AM_CPPFLAGS = -I$(top_srcdir)/compat -I$(top_srcdir)/lib -I$(top_srcdir)/tests/unity_tests/$(UNITY_VERSION) @OPENSSL_INCLUDES@
TESTS_ENVIRONMENT = env BUILDDIR=$(abs_top_builddir)/unityrunner 

SUBDIRS = $(UNITY_VERSION)

UNITY_TESTS = unityrunner add_param_test common_ini_wrong_flag_test common_ini_failmode_test common_ini_prompts_test common_ini_https_timeout common_ini_string_options common_ini_bool_options_test add_groupname_test gecos_ini_test

# Create the unity runner executable
check_PROGRAMS = $(UNITY_TESTS)
include_HEADERS = common_ini_test.h

LDADD = $(top_builddir)/lib/libduo.la $(top_builddir)/compat/libcompat.la $(top_builddir)/tests/unity_tests/$(UNITY_VERSION)/libunity.la 
CFLAGS = -Werror -Wunused-function

TESTS = $(UNITY_TESTS)
