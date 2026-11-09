/*
 * SPDX-License-Identifier: GPL-2.0-with-classpath-exception
 *
 * common_ini_bool_options_test.c
 *
 * Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved.
 */

#include <unistd.h>

#include "common_ini_test.h"

extern void setUp(void) {};
extern void tearDown(void) {};

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

/* Test duo_common_ini_handler disable_ca_pinning flag */
static void test_disable_ca_pinning_true() {
    struct duo_config cfg = {0};
    char *name = "disable_ca_pinning";
    char *value = "true";
    int expected_cfg_value = 1;

    duo_common_ini_handler(&cfg, SECTION, name, value);
    TEST_ASSERT_EQUAL(expected_cfg_value, cfg.disable_ca_pinning);
}

static void test_disable_ca_pinning_false() {
    struct duo_config cfg = {0};
    char *name = "disable_ca_pinning";
    char *value = "false";
    int expected_cfg_value = 0;

    duo_common_ini_handler(&cfg, SECTION, name, value);
    TEST_ASSERT_EQUAL(expected_cfg_value, cfg.disable_ca_pinning);
}

/* Accepted values match in any case */
static void test_set_boolean_option_any_case() {
    TEST_ASSERT_TRUE(duo_set_boolean_option("YES"));
    TEST_ASSERT_TRUE(duo_set_boolean_option("True"));
    TEST_ASSERT_TRUE(duo_set_boolean_option("oN"));
    TEST_ASSERT_FALSE(duo_set_boolean_option("No"));
    TEST_ASSERT_FALSE(duo_set_boolean_option("FALSE"));
    TEST_ASSERT_FALSE(duo_set_boolean_option(NULL));
}

/*
 * Call duo_parse_boolean_option() with stderr captured, returning its result
 * and what it logged (empty if nothing).
 */
static int parse_and_capture(const char *name, const char *val,
                             char *logged, size_t logged_size)
{
    FILE *capture;
    size_t bytes_read;
    int saved_stderr, result;

    capture = tmpfile();
    TEST_ASSERT_NOT_NULL(capture);
    fflush(stderr);
    saved_stderr = dup(STDERR_FILENO);
    TEST_ASSERT_TRUE(saved_stderr >= 0);
    TEST_ASSERT_EQUAL(STDERR_FILENO, dup2(fileno(capture), STDERR_FILENO));

    duo_debug = 1;
    result = duo_parse_boolean_option(name, val);

    fflush(stderr);
    TEST_ASSERT_EQUAL(STDERR_FILENO, dup2(saved_stderr, STDERR_FILENO));
    close(saved_stderr);
    rewind(capture);
    bytes_read = fread(logged, 1, logged_size - 1, capture);
    logged[bytes_read] = '\0';
    fclose(capture);
    return (result);
}

static void test_parse_boolean_option_recognized_values_do_not_log() {
    const char *true_values[] = { "yes", "Yes", "TRUE", "On", "1" };
    const char *false_values[] = { "no", "No", "FALSE", "Off", "0" };
    char logged[512];
    size_t i;

    for (i = 0; i < sizeof(true_values) / sizeof(true_values[0]); i++) {
        TEST_ASSERT_TRUE(parse_and_capture("verified_push", true_values[i],
            logged, sizeof(logged)));
        TEST_ASSERT_EQUAL_STRING("", logged);
    }
    for (i = 0; i < sizeof(false_values) / sizeof(false_values[0]); i++) {
        TEST_ASSERT_FALSE(parse_and_capture("verified_push", false_values[i],
            logged, sizeof(logged)));
        TEST_ASSERT_EQUAL_STRING("", logged);
    }
}

static void test_parse_boolean_option_unrecognized_values_log() {
    const char *values[] = { "enabled", "y", "2", "", " yes" };
    char logged[512];
    size_t i;

    for (i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        TEST_ASSERT_FALSE(parse_and_capture("verified_push", values[i],
            logged, sizeof(logged)));
        TEST_ASSERT_EQUAL_STRING("[4] Unrecognized value for verified_push, "
            "which is treated as \"no\"; use \"yes\" or \"no\"\n", logged);
    }
}

/* Every boolean option is case-insensitive, and an unrecognized value is
   handled (treated as "no") rather than rejected, so parsing continues */
static void test_handler_boolean_options_any_case() {
    const char *names[] = { "pushinfo", "noverify", "autopush",
        "accept_env_factor", "fallback_local_ip", "send_gecos",
        "verified_push", "disable_ca_pinning" };
    size_t i;

    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        struct duo_config on, off, other;

        /* memset, not {0}, so padding compares equal too */
        memset(&on, 0, sizeof(on));
        memset(&off, 0, sizeof(off));
        memset(&other, 0, sizeof(other));
        TEST_ASSERT_TRUE(duo_common_ini_handler(&on, SECTION, names[i], "True"));
        TEST_ASSERT_TRUE(duo_common_ini_handler(&off, SECTION, names[i], "NO"));
        TEST_ASSERT_TRUE(duo_common_ini_handler(&other, SECTION, names[i], "enabled"));
        TEST_ASSERT_TRUE_MESSAGE(memcmp(&on, &off, sizeof(on)) != 0, names[i]);
        TEST_ASSERT_TRUE_MESSAGE(memcmp(&off, &other, sizeof(off)) == 0, names[i]);
    }
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
    RUN_TEST(test_set_boolean_option_any_case);
    RUN_TEST(test_parse_boolean_option_recognized_values_do_not_log);
    RUN_TEST(test_parse_boolean_option_unrecognized_values_log);
    RUN_TEST(test_handler_boolean_options_any_case);
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
    RUN_TEST(test_disable_ca_pinning_true);
    RUN_TEST(test_disable_ca_pinning_false);
    return UNITY_END();
}
