/*
 * SPDX-License-Identifier: GPL-2.0-with-classpath-exception
 *
 * parse_retry_after_test.c
 *
 * Copyright (c) 2026 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved.
 */

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "src/unity.h"

extern time_t _parse_retry_after(const char *header_value);
extern time_t _retry_after_deadline(long delay_seconds, int parse_errno, time_t now);

static const time_t TIME_T_MAX =
    (time_t)(((uintmax_t)1 << (sizeof(time_t) * CHAR_BIT - 1)) - 1);

extern void setUp(void) {};
extern void tearDown(void) {};

/* A valid small delay returns an absolute time roughly now + delay. */
static void test_valid_delay_seconds(void)
{
    time_t before = time(NULL);
    time_t result = _parse_retry_after("3");
    time_t after = time(NULL);

    TEST_ASSERT_TRUE(result >= before + 3);
    TEST_ASSERT_TRUE(result <= after + 3);
}

/* NULL header yields the not-present sentinel. */
static void test_null_header(void)
{
    TEST_ASSERT_EQUAL(-1, (long)_parse_retry_after(NULL));
}

/* Non-numeric, non-date garbage yields the sentinel. */
static void test_garbage(void)
{
    TEST_ASSERT_EQUAL(-1, (long)_parse_retry_after("not-a-number"));
}

/* A negative delay is rejected (sentinel), not turned into a past timestamp. */
static void test_negative_delay(void)
{
    TEST_ASSERT_EQUAL(-1, (long)_parse_retry_after("-100"));
}

/* LONG_MAX would overflow the time_t addition; must be rejected, not computed. */
static void test_overflow_value(void)
{
    TEST_ASSERT_EQUAL(-1, (long)_parse_retry_after("9223372036854775807"));
}

/* A value past the plausibility ceiling (one day) is rejected. */
static void test_implausibly_large_delay(void)
{
    TEST_ASSERT_EQUAL(-1, (long)_parse_retry_after("100000"));
}

/* Trailing junk after digits is not a valid delta-seconds value. */
static void test_trailing_junk(void)
{
    TEST_ASSERT_EQUAL(-1, (long)_parse_retry_after("30x"));
}

/* _retry_after_deadline: a normal delay well below time_t_max adds cleanly. */
static void test_deadline_normal(void)
{
    time_t now = 1000;
    TEST_ASSERT_EQUAL(1030, (long)_retry_after_deadline(30, 0, now));
}

/* _retry_after_deadline: ERANGE from strtol is rejected. */
static void test_deadline_erange(void)
{
    TEST_ASSERT_EQUAL(-1, (long)_retry_after_deadline(LONG_MAX, ERANGE, 1000));
}

/* _retry_after_deadline: a clock within the delay of time_t_max must be
   rejected rather than allowed to overflow (the 32-bit-2038 case). */
static void test_deadline_near_time_t_max_overflows(void)
{
    time_t now = TIME_T_MAX - 10;   /* only 10s of headroom */
    TEST_ASSERT_EQUAL(-1, (long)_retry_after_deadline(30, 0, now));
}

/* _retry_after_deadline: exactly enough headroom still succeeds. */
static void test_deadline_exact_headroom(void)
{
    time_t now = TIME_T_MAX - 30;
    TEST_ASSERT_EQUAL((long)TIME_T_MAX, (long)_retry_after_deadline(30, 0, now));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_valid_delay_seconds);
    RUN_TEST(test_null_header);
    RUN_TEST(test_garbage);
    RUN_TEST(test_negative_delay);
    RUN_TEST(test_overflow_value);
    RUN_TEST(test_implausibly_large_delay);
    RUN_TEST(test_trailing_junk);
    RUN_TEST(test_deadline_normal);
    RUN_TEST(test_deadline_erange);
    RUN_TEST(test_deadline_near_time_t_max_overflows);
    RUN_TEST(test_deadline_exact_headroom);
    return UNITY_END();
}
