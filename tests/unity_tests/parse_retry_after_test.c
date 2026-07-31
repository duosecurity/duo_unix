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
#include "https.h"

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

/* An absent header (NULL) yields the "none" sentinel so the caller falls back
   to its own bounded backoff. This is distinct from a present-but-invalid
   header, which must be terminal. */
static void test_null_header(void)
{
    TEST_ASSERT_TRUE(_parse_retry_after(NULL) == DUO_RETRY_AFTER_NONE);
}

/* An empty header string is present-but-unusable, not absent, so it must be
   the invalid sentinel -- not a deadline of "now" (the pre-guard behavior
   returned time(NULL)+0). */
static void test_empty_header(void)
{
    TEST_ASSERT_TRUE(_parse_retry_after("") == DUO_RETRY_AFTER_INVALID);
}

/* Non-numeric, non-date garbage is present-but-unusable: invalid, not none. */
static void test_garbage(void)
{
    TEST_ASSERT_TRUE(_parse_retry_after("not-a-number") == DUO_RETRY_AFTER_INVALID);
}

/* A negative delay is rejected (invalid), not turned into a past timestamp. */
static void test_negative_delay(void)
{
    TEST_ASSERT_TRUE(_parse_retry_after("-100") == DUO_RETRY_AFTER_INVALID);
}

/* LONG_MAX would overflow the time_t addition; must be rejected, not computed. */
static void test_overflow_value(void)
{
    TEST_ASSERT_TRUE(
        _parse_retry_after("9223372036854775807") == DUO_RETRY_AFTER_INVALID);
}

/* A value past the plausibility ceiling (one day) is rejected as invalid --
   which the caller treats as terminal, not as a cue to back off. */
static void test_implausibly_large_delay(void)
{
    TEST_ASSERT_TRUE(_parse_retry_after("100000") == DUO_RETRY_AFTER_INVALID);
}

/* Trailing junk after digits is not a valid delta-seconds value. */
static void test_trailing_junk(void)
{
    TEST_ASSERT_TRUE(_parse_retry_after("30x") == DUO_RETRY_AFTER_INVALID);
}

/* --- HTTP-date branch --- */

/* A valid future GMT date parses to an absolute deadline near that date. */
static void test_date_valid_future(void)
{
    time_t now = time(NULL);
    struct tm tm;
    /* now + 100 seconds, formatted as an HTTP-date in GMT. */
    time_t target = now + 100;
    gmtime_r(&target, &tm);
    char header[64];
    strftime(header, sizeof(header), "%a, %d %b %Y %H:%M:%S GMT", &tm);

    time_t result = _parse_retry_after(header);
    /* Allow a second of slack for the clock advancing across the calls. */
    TEST_ASSERT_TRUE(result >= now + 99);
    TEST_ASSERT_TRUE(result <= now + 101);
}

/* A past-dated GMT date is rejected: it yields a non-positive delta. */
static void test_date_past(void)
{
    TEST_ASSERT_TRUE(
        _parse_retry_after("Thu, 01 Jan 1970 00:00:00 GMT")
        == DUO_RETRY_AFTER_INVALID);
}

/* A non-GMT zone must be rejected: the parser requires a literal GMT, so a
   permissive %Z accepting "PST" as GMT would be a regression. */
static void test_date_non_gmt_zone(void)
{
    TEST_ASSERT_TRUE(
        _parse_retry_after("Mon, 01 Jan 2035 00:00:00 PST")
        == DUO_RETRY_AFTER_INVALID);
}

/* An absent timezone must be rejected -- the literal-GMT requirement fails to
   match, unlike a permissive %Z which would treat it as GMT. */
static void test_date_absent_zone(void)
{
    TEST_ASSERT_TRUE(
        _parse_retry_after("Mon, 01 Jan 2035 00:00:00")
        == DUO_RETRY_AFTER_INVALID);
}

/* Trailing junk glued to the zone ("GMTjunk") is caught by the
   full-consumption check even though the literal GMT matched. */
static void test_date_trailing_glued(void)
{
    TEST_ASSERT_TRUE(
        _parse_retry_after("Mon, 01 Jan 2035 00:00:00 GMTjunk")
        == DUO_RETRY_AFTER_INVALID);
}

/* Trailing junk separated by whitespace is likewise rejected by the
   full-consumption check. */
static void test_date_trailing_separated(void)
{
    TEST_ASSERT_TRUE(
        _parse_retry_after("Mon, 01 Jan 2035 00:00:00 GMT TRAILING")
        == DUO_RETRY_AFTER_INVALID);
}

/* A far-future date must not slip past the ceiling via int narrowing: it is
   rejected as invalid (over the one-day plausibility ceiling), which the
   caller treats as terminal. */
static void test_date_far_future(void)
{
    TEST_ASSERT_TRUE(
        _parse_retry_after("Fri, 31 Dec 9999 23:59:59 GMT")
        == DUO_RETRY_AFTER_INVALID);
}

/* --- _retry_after_deadline --- */

/* A normal delay well below time_t_max adds cleanly. */
static void test_deadline_normal(void)
{
    time_t now = 1000;
    TEST_ASSERT_TRUE(_retry_after_deadline(30, 0, now) == (time_t)1030);
}

/* ERANGE from strtol is rejected. */
static void test_deadline_erange(void)
{
    TEST_ASSERT_TRUE(
        _retry_after_deadline(LONG_MAX, ERANGE, 1000) == DUO_RETRY_AFTER_INVALID);
}

/* A clock within the delay of time_t_max must be rejected rather than allowed
   to overflow (the 32-bit-2038 case). Compared as time_t directly: a (long)
   cast here would truncate TIME_T_MAX to -1 on 32-bit long / 64-bit time_t and
   make the assertion pass vacuously. */
static void test_deadline_near_time_t_max_overflows(void)
{
    time_t now = TIME_T_MAX - 10;   /* only 10s of headroom */
    TEST_ASSERT_TRUE(
        _retry_after_deadline(30, 0, now) == DUO_RETRY_AFTER_INVALID);
}

/* Exactly enough headroom still succeeds. Compared as time_t directly for the
   same reason as above -- narrowing through (long) would void the test on a
   64-bit time_t target with 32-bit long. */
static void test_deadline_exact_headroom(void)
{
    time_t now = TIME_T_MAX - 30;
    TEST_ASSERT_TRUE(_retry_after_deadline(30, 0, now) == TIME_T_MAX);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_valid_delay_seconds);
    RUN_TEST(test_null_header);
    RUN_TEST(test_empty_header);
    RUN_TEST(test_garbage);
    RUN_TEST(test_negative_delay);
    RUN_TEST(test_overflow_value);
    RUN_TEST(test_implausibly_large_delay);
    RUN_TEST(test_trailing_junk);
    RUN_TEST(test_date_valid_future);
    RUN_TEST(test_date_past);
    RUN_TEST(test_date_non_gmt_zone);
    RUN_TEST(test_date_absent_zone);
    RUN_TEST(test_date_trailing_glued);
    RUN_TEST(test_date_trailing_separated);
    RUN_TEST(test_date_far_future);
    RUN_TEST(test_deadline_normal);
    RUN_TEST(test_deadline_erange);
    RUN_TEST(test_deadline_near_time_t_max_overflows);
    RUN_TEST(test_deadline_exact_headroom);
    return UNITY_END();
}
