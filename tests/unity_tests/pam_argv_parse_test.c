#include <stdio.h>
#include <string.h>
#include "pam_duo_private.h"
#include "util.h"
#include "src/unity.h"

static void test_pam_config_NULL() {
    const char *config = NULL;
    const char *argv[] = {"conf=hi"};
    int argc = 1;

    TEST_ASSERT_FALSE(parse_argv(&config, argc, argv));
}

static void test_pam_argc_zero() {
    const char *config = "";
    const char *argv[] = {NULL};
    int argc = 0;

    TEST_ASSERT_TRUE(parse_argv(&config, argc, argv));
}

static void test_pam_argv_error() {
    const char *config = "";
    const char *argv[] = {"Error"};
    int argc = 1;

    TEST_ASSERT_FALSE(parse_argv(&config, argc, argv));
}

static void test_pam_argv_debug() {
    const char *config = "";
    const char *argv[] = {"debug"};
    int argc = 1;
    int expected_debug = 1;
    duo_debug = 0;

    parse_argv(&config, argc, argv);
    
    TEST_ASSERT_EQUAL(expected_debug, duo_debug);
    duo_debug = 0;
}

static void test_pam_argv_conf() {
    const char *config = "";
    const char *argv[] = {"conf=hi"};
    char *expected_config = "hi";
    int argc = 1;

    parse_argv(&config, argc, argv);
    
    TEST_ASSERT_EQUAL_STRING(expected_config, config);
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_pam_config_NULL);
    RUN_TEST(test_pam_argc_zero);
    RUN_TEST(test_pam_argv_error);
    RUN_TEST(test_pam_argv_debug);
    RUN_TEST(test_pam_argv_conf);
    return UNITY_END();
}
