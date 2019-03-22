#include "common_ini_test.h"

static void test_send_gecos_true() {
    struct duo_config cfg = {0};
    char *name = "send_gecos";
    char *value = "true";
    int expected_output = 1;

    duo_common_ini_handler(&cfg, SECTION, name, value);
    TEST_ASSERT_EQUAL(expected_output, cfg.send_gecos);
}

static void test_send_gecos_false() {
    struct duo_config cfg = {0};
    char *name = "send_gecos";
    char *value = "false";
    int expected_output = 0;
    
    duo_common_ini_handler(&cfg, SECTION, name, value);
    TEST_ASSERT_EQUAL(expected_output, cfg.send_gecos);
}

/* Testing gecos_parsed flag in duo_common_ini_handler */
static void test_gecos_parsed() {
    struct duo_config cfg = {0};
    char *name = "gecos_parsed";
    
    TEST_ASSERT_TRUE(duo_common_ini_handler(&cfg, SECTION, name, EMPTY_STR));
}

/* Testing gecos_delim flag in duo_common_ini_handler */
static void test_gecos_delim_success() {
    struct duo_config cfg = {0};
    char *name = "gecos_delim";
    char *value = ".";
    char expected_cfg_val = '.';

    duo_common_ini_handler(&cfg, SECTION, name, value);
    TEST_ASSERT_EQUAL(expected_cfg_val, cfg.gecos_delim);
}

static void test_gecos_delim_colon() {
    struct duo_config cfg = {0};
    char *name = "gecos_delim";
    char *value = ":";

    TEST_ASSERT_FALSE(duo_common_ini_handler(&cfg, SECTION, name, value));
}

static void test_gecos_delim_letter() {
    struct duo_config cfg = {0};
    char *name = "gecos_delim";
    char *value = "a";

    TEST_ASSERT_FALSE(duo_common_ini_handler(&cfg, SECTION, name, value));
}

static void test_gecos_delim_two_char() {
    struct duo_config cfg = {0};
    char *name = "gecos_delim";
    char *value = ".,";

    TEST_ASSERT_FALSE(duo_common_ini_handler(&cfg, SECTION, name, value));
}

static void test_gecos_delim_empty() {
    struct duo_config cfg = {0};
    char *name = "gecos_delim";

    TEST_ASSERT_FALSE(duo_common_ini_handler(&cfg, SECTION, name, EMPTY_STR));
}

static void test_gecos_delim_null() {
    struct duo_config cfg = {0};
    char *name = "gecos_delim";

    TEST_ASSERT_FALSE(duo_common_ini_handler(&cfg, SECTION, name, NULL_STR));
}

/* Testing gecos_username_pos flag in duo_common_ini_handler */
static void test_gecos_username_pos_negative_one() {
    struct duo_config cfg = {0};
    char *name = "gecos_username_pos";
    char *position = "-1";

    TEST_ASSERT_FALSE(duo_common_ini_handler(&cfg, SECTION, name, position));
} 

static void test_gecos_username_pos_one() {
    struct duo_config cfg = {0};
    char *name = "gecos_username_pos";
    char *position = "1";
    int expected_pos = 0;

    duo_common_ini_handler(&cfg, SECTION, name, position);
    TEST_ASSERT_EQUAL(expected_pos, cfg.gecos_username_pos); 
}

static void test_gecos_username_pos_two() {
    struct duo_config cfg = {0};
    char *name = "gecos_username_pos";
    char *position = "2";
    int expected_pos = 1;
    
    duo_common_ini_handler(&cfg, SECTION, name, position);
    TEST_ASSERT_EQUAL(expected_pos, cfg.gecos_username_pos); 
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_send_gecos_true);
    RUN_TEST(test_send_gecos_false);
    RUN_TEST(test_gecos_parsed);
    RUN_TEST(test_gecos_delim_success);
    RUN_TEST(test_gecos_delim_colon);
    RUN_TEST(test_gecos_delim_letter);
    RUN_TEST(test_gecos_delim_two_char);
    RUN_TEST(test_gecos_delim_empty);
    RUN_TEST(test_gecos_delim_null);
    RUN_TEST(test_gecos_username_pos_negative_one);
    RUN_TEST(test_gecos_username_pos_one);
    RUN_TEST(test_gecos_username_pos_two);
    return UNITY_END();
}
