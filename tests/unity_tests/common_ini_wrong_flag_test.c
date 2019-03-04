#include "common_ini_test.h"

/* Testing duo_common_ini_handler with a wrong flag */
static void test_wrong_flag() {
    struct duo_config cfg = {0};
    char *name = "wrong_flag";
    char *value = "asdf";

    TEST_ASSERT_FALSE(duo_common_ini_handler(&cfg, SECTION, name, value));
}

static void test_wrong_flag_empty() {
    struct duo_config cfg = {0};
    char *value = "asdf";

    TEST_ASSERT_FALSE(duo_common_ini_handler(&cfg, SECTION, EMPTY_STR, value));
}

static void test_wrong_flag_null() {
    struct duo_config cfg = {0};
    char *value = "asdf";

    TEST_ASSERT_FALSE(duo_common_ini_handler(&cfg, SECTION, NULL_STR, value));
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_wrong_flag);
    RUN_TEST(test_wrong_flag_empty);
    RUN_TEST(test_wrong_flag_null);
    return UNITY_END();
}
