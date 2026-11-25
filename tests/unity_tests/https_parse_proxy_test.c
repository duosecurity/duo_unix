/*
 * SPDX-License-Identifier: GPL-2.0-with-classpath-exception
 *
 * https_parse_proxy_test.c
 *
 * Copyright (c) 2026 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved.
 */

#include <stdlib.h>

#include "src/unity.h"
#include "https.h"

extern int _https_parse_proxy(const char *spec, char **buf, char **host,
    char **port, char **auth);

extern void setUp(void) {};
extern void tearDown(void) {};

/* Parse spec and check each part; a NULL expected auth means none */
static void
check_proxy(const char *spec, const char *host, const char *port,
    const char *auth)
{
    char *buf, *h, *p, *a;

    TEST_ASSERT_EQUAL_INT(0, _https_parse_proxy(spec, &buf, &h, &p, &a));
    TEST_ASSERT_EQUAL_STRING(host, h);
    TEST_ASSERT_EQUAL_STRING(port, p);
    if (auth == NULL) {
        TEST_ASSERT_NULL(a);
    } else {
        TEST_ASSERT_EQUAL_STRING(auth, a);
    }
    free(buf);
}

static void test_host_only(void)
{
    check_proxy("proxy", "proxy", "80", NULL);
}

static void test_host_and_port(void)
{
    check_proxy("proxy.example.com:3128", "proxy.example.com", "3128", NULL);
}

static void test_path_is_ignored(void)
{
    check_proxy("proxy:3128/", "proxy", "3128", NULL);
    check_proxy("proxy:3128/some/path", "proxy", "3128", NULL);
}

static void test_user_and_password(void)
{
    check_proxy("user:secret@proxy:3128", "proxy", "3128", "user:secret");
}

static void test_user_only(void)
{
    check_proxy("user@proxy:3128", "proxy", "3128", "user");
}

/* The user name and password end at the last '@' */
static void test_raw_at_in_password(void)
{
    check_proxy("pxuser:p@ssw0rd@proxy:3128", "proxy", "3128",
        "pxuser:p@ssw0rd");
}

static void test_raw_at_in_user_name(void)
{
    check_proxy("user@example.com:secret@proxy:3128", "proxy", "3128",
        "user@example.com:secret");
}

static void test_encoded_at_in_password(void)
{
    check_proxy("pxuser:p%40ssw0rd@proxy:3128", "proxy", "3128",
        "pxuser:p@ssw0rd");
}

static void test_encoded_characters_in_user_name(void)
{
    check_proxy("us%65r%2Fx:secret@proxy", "proxy", "80", "user/x:secret");
}

/* An encoded ':' in the password stays in the password */
static void test_encoded_colon_in_password(void)
{
    check_proxy("user:a%3Ab@proxy", "proxy", "80", "user:a:b");
}

/* A raw '/' in the password still works, as it did before */
static void test_raw_slash_in_password(void)
{
    check_proxy("user:a/b@proxy:3128/", "proxy", "3128", "user:a/b");
}

static void test_lowercase_and_uppercase_escapes(void)
{
    check_proxy("user:%2f%2F@proxy", "proxy", "80", "user://");
}

/* Malformed escapes and %00 are passed through undecoded */
static void test_malformed_escapes_kept(void)
{
    check_proxy("user:100%@proxy", "proxy", "80", "user:100%");
    check_proxy("user:%zz%4@proxy", "proxy", "80", "user:%zz%4");
    check_proxy("user:a%00b@proxy", "proxy", "80", "user:a%00b");
}

static void test_bracketed_ipv6(void)
{
    check_proxy("[2001:db8::1]:3128", "2001:db8::1", "3128", NULL);
    check_proxy("[::1]", "::1", "80", NULL);
    check_proxy("user:p@ss@[::1]:3128/", "::1", "3128", "user:p@ss");
}

/* Malformed values are logged but still returned, to fail on connect */
static void test_malformed_values_passed_through(void)
{
    check_proxy("[::1", "[", ":1", NULL);
    check_proxy("::1:3128", "", ":1:3128", NULL);
    check_proxy("proxy:", "proxy", "", NULL);
    check_proxy("proxy:http", "proxy", "http", NULL);
    check_proxy("proxy:99999", "proxy", "99999", NULL);
    check_proxy("user:secret@", "", "80", "user:secret");
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_host_only);
    RUN_TEST(test_host_and_port);
    RUN_TEST(test_path_is_ignored);
    RUN_TEST(test_user_and_password);
    RUN_TEST(test_user_only);
    RUN_TEST(test_raw_at_in_password);
    RUN_TEST(test_raw_at_in_user_name);
    RUN_TEST(test_encoded_at_in_password);
    RUN_TEST(test_encoded_characters_in_user_name);
    RUN_TEST(test_encoded_colon_in_password);
    RUN_TEST(test_raw_slash_in_password);
    RUN_TEST(test_lowercase_and_uppercase_escapes);
    RUN_TEST(test_malformed_escapes_kept);
    RUN_TEST(test_bracketed_ipv6);
    RUN_TEST(test_malformed_values_passed_through);
    return UNITY_END();
}
