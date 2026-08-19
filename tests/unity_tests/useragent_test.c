/*
 * SPDX-License-Identifier: GPL-2.0-with-classpath-exception
 *
 * useragent_test.c
 *
 * Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved.
 */

#include "config.h"
#undef UNITY_VERSION

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "src/unity.h"
#include "util.h"
#include "duo.h"
#include "duo_private.h"

extern void setUp(void) {};
extern void tearDown(void) {};

#define TEST_HOST "localhost"
#define TEST_IKEY "DIXXXXXXXXXXXXXXXXXX"
#define TEST_SKEY "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
#define TEST_PROGNAME "test_duo/1.0"
#define TEST_CAFILE TOP_SRCDIR "/tests/certs/mockduo-ca.pem"

/* Test ca_pinning=enabled with real CA file */
static void test_useragent_ca_pinning_enabled_real_cafile() {
    duo_t *duo = duo_open(TEST_HOST, TEST_IKEY, TEST_SKEY,
        TEST_PROGNAME, TEST_CAFILE, -1, NULL, 0);
    TEST_ASSERT_NOT_NULL(duo);
    TEST_ASSERT_NOT_NULL(strstr(duo->useragent, "ca_bundle/" DUO_CA_BUNDLE_VERSION));
    TEST_ASSERT_NOT_NULL(strstr(duo->useragent, "(ca_pinning=enabled)"));
    duo_close(duo);
}

/* Test ca_pinning=disabled with DUO_USE_SYSTEM_CERTS */
static void test_useragent_ca_pinning_disabled_system_certs() {
    duo_t *duo = duo_open(TEST_HOST, TEST_IKEY, TEST_SKEY,
        TEST_PROGNAME, DUO_USE_SYSTEM_CERTS, -1, NULL, 0);
    TEST_ASSERT_NOT_NULL(duo);
    TEST_ASSERT_NOT_NULL(strstr(duo->useragent, "ca_bundle/" DUO_CA_BUNDLE_VERSION));
    TEST_ASSERT_NOT_NULL(strstr(duo->useragent, "(ca_pinning=disabled)"));
    TEST_ASSERT_NULL(strstr(duo->useragent, "(ca_pinning=enabled)"));
    duo_close(duo);
}

/* Test ca_pinning=disabled with noverify (empty cafile) */
static void test_useragent_ca_pinning_disabled_noverify() {
    duo_t *duo = duo_open(TEST_HOST, TEST_IKEY, TEST_SKEY,
        TEST_PROGNAME, "", -1, NULL, 0);
    TEST_ASSERT_NOT_NULL(duo);
    TEST_ASSERT_NOT_NULL(strstr(duo->useragent, "ca_bundle/" DUO_CA_BUNDLE_VERSION));
    TEST_ASSERT_NOT_NULL(strstr(duo->useragent, "(ca_pinning=disabled)"));
    duo_close(duo);
}

/* Test that toggling cafile changes pinning status in user agent */
static void test_useragent_ca_pinning_toggles() {
    duo_t *enabled = duo_open(TEST_HOST, TEST_IKEY, TEST_SKEY,
        TEST_PROGNAME, TEST_CAFILE, -1, NULL, 0);
    duo_t *disabled = duo_open(TEST_HOST, TEST_IKEY, TEST_SKEY,
        TEST_PROGNAME, DUO_USE_SYSTEM_CERTS, -1, NULL, 0);

    TEST_ASSERT_NOT_NULL(enabled);
    TEST_ASSERT_NOT_NULL(disabled);

    TEST_ASSERT_NOT_NULL(strstr(enabled->useragent, "(ca_pinning=enabled)"));
    TEST_ASSERT_NOT_NULL(strstr(disabled->useragent, "(ca_pinning=disabled)"));

    duo_close(enabled);
    duo_close(disabled);
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_useragent_ca_pinning_enabled_real_cafile);
    RUN_TEST(test_useragent_ca_pinning_disabled_system_certs);
    RUN_TEST(test_useragent_ca_pinning_disabled_noverify);
    RUN_TEST(test_useragent_ca_pinning_toggles);
    return UNITY_END();
}
