/*
 * SPDX-License-Identifier: GPL-2.0-with-classpath-exception
 *
 * https_ipaddr_test.c
 *
 * Copyright (c) 2026 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved.
 */

#include <arpa/inet.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "src/unity.h"

extern int _https_ipaddr_matches(const void *addr, size_t addrsize, const void *altptr, size_t altsize);

extern void setUp(void) {};
extern void tearDown(void) {};

static void test_ipv4_san_matches_hostname(void)
{
    struct in_addr san;

    TEST_ASSERT_EQUAL(1, inet_pton(AF_INET, "192.0.2.10", &san));
    TEST_ASSERT_TRUE(_https_ipaddr_matches(&san, sizeof(san), &san, sizeof(san)));
}

static void test_ipv4_san_rejects_different_hostname(void)
{
    struct in_addr san;
    struct in_addr hostname;

    TEST_ASSERT_EQUAL(1, inet_pton(AF_INET, "192.0.2.10", &san));
    TEST_ASSERT_EQUAL(1, inet_pton(AF_INET, "192.0.2.11", &hostname));
    TEST_ASSERT_FALSE(_https_ipaddr_matches(&hostname, sizeof(hostname), &san, sizeof(san)));
}

static void test_ipv6_san_matches_hostname(void)
{
    struct in6_addr san;

    TEST_ASSERT_EQUAL(1, inet_pton(AF_INET6, "2001:db8::10", &san));
    TEST_ASSERT_TRUE(_https_ipaddr_matches(&san, sizeof(san), &san, sizeof(san)));
}

static void test_ip_san_rejects_wrong_length(void)
{
    struct in_addr san;

    TEST_ASSERT_EQUAL(1, inet_pton(AF_INET, "192.0.2.10", &san));
    TEST_ASSERT_FALSE(_https_ipaddr_matches(&san, sizeof(san), &san, sizeof(san) - 1));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_ipv4_san_matches_hostname);
    RUN_TEST(test_ipv4_san_rejects_different_hostname);
    RUN_TEST(test_ipv6_san_matches_hostname);
    RUN_TEST(test_ip_san_rejects_wrong_length);
    return UNITY_END();
}
