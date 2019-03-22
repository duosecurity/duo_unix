#include "common_ini_test.h"

/* Testing adding failmode to duo_config */
static void test_failmode_safe() {
    struct duo_config cfg = {0};
    char *name = "failmode";
    char *failmode = "safe";
    int expected_failmode = DUO_FAIL_SAFE;

    duo_common_ini_handler(&cfg, SECTION, name, failmode);
    TEST_ASSERT_EQUAL(expected_failmode, cfg.failmode);
}

static void test_failmode_secure() {
    struct duo_config cfg = {0};
    char *name = "failmode";
    char *failmode = "secure";
    int expected_failmode = DUO_FAIL_SECURE;

    duo_common_ini_handler(&cfg, SECTION, name, failmode);
    TEST_ASSERT_EQUAL(expected_failmode, cfg.failmode);
}

/* duo_common_ini_handler returns 0 for invalid input */
static void test_failmode_neither() {
    struct duo_config cfg = {0};
    char *name = "failmode";
    char *failmode = "neither";

    TEST_ASSERT_FALSE(duo_common_ini_handler(&cfg, SECTION, name, failmode));
}

static void test_failmode_empty() {
    struct duo_config cfg = {0};
    char *name = "failmode";

    TEST_ASSERT_FALSE(duo_common_ini_handler(&cfg, SECTION, name, EMPTY_STR));
}

static void test_failmode_null() {
    struct duo_config cfg = {0};
    char *name = "failmode";

    TEST_ASSERT_FALSE(duo_common_ini_handler(&cfg, SECTION, name, NULL_STR));
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_failmode_safe);
    RUN_TEST(test_failmode_secure);
    RUN_TEST(test_failmode_neither);
    RUN_TEST(test_failmode_empty);
    RUN_TEST(test_failmode_null);
    return UNITY_END();
}
