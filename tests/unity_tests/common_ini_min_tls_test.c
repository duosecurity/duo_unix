/*
 * SPDX-License-Identifier: GPL-2.0-with-classpath-exception
 *
 * common_ini_min_tls_test.c
 *
 * Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved.
 */

#include "common_ini_test.h"

extern void setUp(void) {};
extern void tearDown(void) {};

/* Each accepted value maps to the matching DUO_MIN_TLS_* constant. */
static void test_min_tls_1_0() {
    struct duo_config cfg = {0};

    TEST_ASSERT_TRUE(duo_common_ini_handler(&cfg, SECTION, "min_tls", "1.0"));
    TEST_ASSERT_EQUAL(DUO_MIN_TLS_1_0, cfg.min_tls);
}

static void test_min_tls_1_1() {
    struct duo_config cfg = {0};

    TEST_ASSERT_TRUE(duo_common_ini_handler(&cfg, SECTION, "min_tls", "1.1"));
    TEST_ASSERT_EQUAL(DUO_MIN_TLS_1_1, cfg.min_tls);
}

static void test_min_tls_1_2() {
    struct duo_config cfg = {0};

    TEST_ASSERT_TRUE(duo_common_ini_handler(&cfg, SECTION, "min_tls", "1.2"));
    TEST_ASSERT_EQUAL(DUO_MIN_TLS_1_2, cfg.min_tls);
}

static void test_min_tls_1_3() {
    struct duo_config cfg = {0};

    TEST_ASSERT_TRUE(duo_common_ini_handler(&cfg, SECTION, "min_tls", "1.3"));
    TEST_ASSERT_EQUAL(DUO_MIN_TLS_1_3, cfg.min_tls);
}

/* The default (unset) value leaves the floor at DUO_MIN_TLS_UNSET. */
static void test_min_tls_default_unset() {
    struct duo_config cfg = {0};

    duo_config_default(&cfg);
    TEST_ASSERT_EQUAL(DUO_MIN_TLS_UNSET, cfg.min_tls);
}

/* Invalid values are rejected and must not select any floor. */
static void test_min_tls_invalid_junk() {
    struct duo_config cfg = {0};

    TEST_ASSERT_FALSE(duo_common_ini_handler(&cfg, SECTION, "min_tls", "junk"));
    TEST_ASSERT_EQUAL(DUO_MIN_TLS_UNSET, cfg.min_tls);
}

static void test_min_tls_invalid_version() {
    struct duo_config cfg = {0};

    TEST_ASSERT_FALSE(duo_common_ini_handler(&cfg, SECTION, "min_tls", "9.9"));
    TEST_ASSERT_EQUAL(DUO_MIN_TLS_UNSET, cfg.min_tls);
}

/* An empty value must not silently pick the least-safe floor. */
static void test_min_tls_empty() {
    struct duo_config cfg = {0};

    TEST_ASSERT_FALSE(duo_common_ini_handler(&cfg, SECTION, "min_tls", EMPTY_STR));
    TEST_ASSERT_EQUAL(DUO_MIN_TLS_UNSET, cfg.min_tls);
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_min_tls_1_0);
    RUN_TEST(test_min_tls_1_1);
    RUN_TEST(test_min_tls_1_2);
    RUN_TEST(test_min_tls_1_3);
    RUN_TEST(test_min_tls_default_unset);
    RUN_TEST(test_min_tls_invalid_junk);
    RUN_TEST(test_min_tls_invalid_version);
    RUN_TEST(test_min_tls_empty);
    return UNITY_END();
}
