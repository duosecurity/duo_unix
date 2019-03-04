#include "common_ini_test.h"

/* Testing  duo_set_boolean_option(val) */
static void test_set_boolean_option_yes() {
    char *value = "yes";
    
    TEST_ASSERT_TRUE(duo_set_boolean_option(value));
}   

static void test_set_boolean_option_one() {
    char *value = "1";

    TEST_ASSERT_TRUE(duo_set_boolean_option(value));
}

static void test_set_boolean_option_true() {
    char *value = "true";

    TEST_ASSERT_TRUE(duo_set_boolean_option(value));
}

static void test_set_boolean_option_on() {
    char *value = "on";

    TEST_ASSERT_TRUE(duo_set_boolean_option(value));
}

static void test_set_boolean_option_off() {
    char *value = "off";

    TEST_ASSERT_FALSE(duo_set_boolean_option(value));
}

static void test_set_boolean_option_random() {
    char *value = "random";

    TEST_ASSERT_FALSE(duo_set_boolean_option(value)); 
}

static void test_set_boolean_option_empty() {
    TEST_ASSERT_FALSE(duo_set_boolean_option(EMPTY_STR));
}

static void test_set_boolean_option_null() {
    TEST_ASSERT_FALSE(duo_set_boolean_option(NULL_STR));
}

/* Test duo_common_ini_handler pushinfo flag */
static void test_pushinfo_true() {
    struct duo_config cfg = {0}; 
    char *name = "pushinfo";
    char *value = "true"; 
    int expected_cfg_value = 1;
    
    duo_common_ini_handler(&cfg, SECTION, name, value);
    TEST_ASSERT_EQUAL(expected_cfg_value, cfg.pushinfo);    
}

static void test_pushinfo_false() {
    struct duo_config cfg = {0}; 
    char *name = "pushinfo";
    char *value = "false";
    int expected_cfg_value = 0;

    duo_common_ini_handler(&cfg, SECTION, name, value);
    TEST_ASSERT_EQUAL(expected_cfg_value, cfg.pushinfo);    
}

/* Test duo_common_ini_handler noverify flag */
static void test_noverify_true() {
    struct duo_config cfg = {0};
    char *name = "noverify";
    char *value = "true";
    int expected_cfg_value = 1;

    duo_common_ini_handler(&cfg, SECTION, name, value);
    TEST_ASSERT_EQUAL(expected_cfg_value, cfg.noverify);    
}

static void test_noverify_false() {
    struct duo_config cfg = {0};
    char *name = "noverify";
    char *value = "false";
    int expected_cfg_value = 0;

    duo_common_ini_handler(&cfg, SECTION, name, value);
    TEST_ASSERT_EQUAL(expected_cfg_value, cfg.noverify);    
}

/* Test duo_common_ini_handler autopush flag */ 
static void test_autopush_true() {
    struct duo_config cfg = {0};
    char *name = "autopush";
    char *value = "true";
    int expected_cfg_value = 1;

    duo_common_ini_handler(&cfg, SECTION, name, value);
    TEST_ASSERT_EQUAL(expected_cfg_value, cfg.autopush);    
}

static void test_autopush_false() {
    struct duo_config cfg = {0};
    char *name = "autopush";
    char *value = "false";
    int expected_cfg_value = 0;

    duo_common_ini_handler(&cfg, SECTION, name, value);
    TEST_ASSERT_EQUAL(expected_cfg_value, cfg.autopush);    
} 

/* Test duo_common_ini_handler accept_env_factor flag */
static void test_accept_env_true() {
    struct duo_config cfg = {0};
    char *name = "accept_env_factor";
    char *value = "true";
    int expected_cfg_value = 1;

    duo_common_ini_handler(&cfg, SECTION, name, value);
    TEST_ASSERT_EQUAL(expected_cfg_value, cfg.accept_env);    
}

static void test_accept_env_false() {
    struct duo_config cfg = {0};
    char *name = "accept_env_factor";
    char *value = "false";
    int expected_cfg_value = 0;

    duo_common_ini_handler(&cfg, SECTION, name, value);
    TEST_ASSERT_EQUAL(expected_cfg_value, cfg.accept_env);    
}

/* Test duo_common_ini_handler fallback_local_ip flag */
static void test_fallback_local_ip_true() {
    struct duo_config cfg = {0};
    char *name = "fallback_local_ip";
    char *value = "true";
    int expected_cfg_value = 1;

    duo_common_ini_handler(&cfg, SECTION, name, value);
    TEST_ASSERT_EQUAL(expected_cfg_value, cfg.local_ip_fallback);    
}

static void test_fallback_local_ip_false() {
    struct duo_config cfg = {0};
    char *name = "fallback_local_ip";
    char *value = "false";
    int expected_cfg_value = 0;
    
    duo_common_ini_handler(&cfg, SECTION, name, value);
    TEST_ASSERT_EQUAL(expected_cfg_value, cfg.local_ip_fallback);    
}

/* Test dev_fips_mode flag */
static void test_dev_fips_mode_true() {
    struct duo_config cfg = {0};
    char *name = "dev_fips_mode";
    char *value = "true";
    int expected_cfg_value = 1;

    duo_common_ini_handler(&cfg, SECTION, name, value);
    TEST_ASSERT_EQUAL(expected_cfg_value, cfg.fips_mode);    
}

static void test_dev_fips_mode_false() {
    struct duo_config cfg = {0};
    char *name = "dev_fips_mode";
    char *value = "false";
    int expected_cfg_value = 0;

    duo_common_ini_handler(&cfg, SECTION, name, value);
    TEST_ASSERT_EQUAL(expected_cfg_value, cfg.fips_mode);    
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_set_boolean_option_yes);
    RUN_TEST(test_set_boolean_option_one);
    RUN_TEST(test_set_boolean_option_true);
    RUN_TEST(test_set_boolean_option_on);
    RUN_TEST(test_set_boolean_option_off);
    RUN_TEST(test_set_boolean_option_random);
    RUN_TEST(test_set_boolean_option_empty);
    RUN_TEST(test_set_boolean_option_null);
    RUN_TEST(test_pushinfo_true);
    RUN_TEST(test_pushinfo_false);
    RUN_TEST(test_noverify_true);
    RUN_TEST(test_noverify_false);
    RUN_TEST(test_autopush_true);
    RUN_TEST(test_autopush_false);
    RUN_TEST(test_noverify_false);
    RUN_TEST(test_accept_env_true);
    RUN_TEST(test_accept_env_false);
    RUN_TEST(test_fallback_local_ip_true);
    RUN_TEST(test_fallback_local_ip_false);
    RUN_TEST(test_dev_fips_mode_true);
    RUN_TEST(test_dev_fips_mode_false);
    return UNITY_END();
}
