/*
 * SPDX-License-Identifier: GPL-2.0-with-classpath-exception
 *
 * common_ini_wrong_flag_test.c
 *
 * Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved.
 */

#include "common_ini_test.h"

extern void setUp(void) {};
extern void tearDown(void) {};

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

/* The removed dev_fips_mode option must be accepted as a no-op (return
   true) rather than rejected, so a stale key left in a config after
   upgrade does not abort parsing and silently disable 2FA. */
static void test_dev_fips_mode_accepted_as_noop() {
    struct duo_config cfg = {0};
    char *name = "dev_fips_mode";
    char *value = "no";

    TEST_ASSERT_TRUE(duo_common_ini_handler(&cfg, SECTION, name, value));
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_wrong_flag);
    RUN_TEST(test_wrong_flag_empty);
    RUN_TEST(test_wrong_flag_null);
    RUN_TEST(test_dev_fips_mode_accepted_as_noop);
    return UNITY_END();
}
