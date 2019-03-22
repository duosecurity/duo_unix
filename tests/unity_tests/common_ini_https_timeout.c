#include "common_ini_test.h"

/* Test setting https_timeout for duo_config */ 
static void test_https_timeout_negitive_one() {
    struct duo_config cfg = {0};
    char *name = "https_timeout";
    char *value = "-1";
    int expected_timeout = -1;

    duo_common_ini_handler(&cfg, SECTION, name, value);
    TEST_ASSERT_EQUAL(expected_timeout, cfg.https_timeout);
}

static void test_https_timeout_zero() {
    struct duo_config cfg = {0};
    char *name = "https_timeout";
    char *value = "0";
    int expected_timeout = -1;

    duo_common_ini_handler(&cfg, SECTION, name, value);
    TEST_ASSERT_EQUAL(expected_timeout, cfg.https_timeout);
}

static void test_https_timeout_one() {
    struct duo_config cfg = {0};
    char *name = "https_timeout";
    char *value = "1";
    int expected_timeout = 1000;

    duo_common_ini_handler(&cfg, SECTION, name, value);
    TEST_ASSERT_EQUAL(expected_timeout, cfg.https_timeout);
}

static void test_https_timeout_four() { 
    struct duo_config cfg = {0};
    char *name = "https_timeout";
    char *value = "4";
    int expected_timeout = 4000;

    duo_common_ini_handler(&cfg, SECTION, name, value);
    TEST_ASSERT_EQUAL(expected_timeout, cfg.https_timeout);
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_https_timeout_negitive_one);
    RUN_TEST(test_https_timeout_zero);
    RUN_TEST(test_https_timeout_one);
    RUN_TEST(test_https_timeout_four);
    return UNITY_END();
}
