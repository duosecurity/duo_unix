/*
 * SPDX-License-Identifier: GPL-2.0-with-classpath-exception
 *
 * sanitize_str_test.c
 *
 * Copyright (c) 2026 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved.
 */

#include <stdio.h>
#include <string.h>

#include "src/unity.h"
#include "util.h"

extern void setUp(void) {};
extern void tearDown(void) {};

static void test_printable_unchanged(void) {
    char s[] = "Hello, World! 123 ~`@#$%^&*()";
    duo_sanitize_str(s);
    TEST_ASSERT_EQUAL_STRING("Hello, World! 123 ~`@#$%^&*()", s);
}

static void test_empty_string(void) {
    char s[] = "";
    duo_sanitize_str(s);
    TEST_ASSERT_EQUAL_STRING("", s);
}

static void test_tab_preserved(void) {
    char s[] = "col1\tcol2\tcol3";
    duo_sanitize_str(s);
    TEST_ASSERT_EQUAL_STRING("col1\tcol2\tcol3", s);
}

static void test_newline_preserved(void) {
    char s[] = "line1\nline2\n";
    duo_sanitize_str(s);
    TEST_ASSERT_EQUAL_STRING("line1\nline2\n", s);
}

static void test_escape_replaced(void) {
    /* ESC = 0x1b */
    char s[] = "before\x1b[31mred\x1b[0mafter";
    duo_sanitize_str(s);
    TEST_ASSERT_EQUAL_STRING("before?[31mred?[0mafter", s);
}

static void test_bel_replaced(void) {
    /* BEL = 0x07 */
    char s[] = "\x1b]52;c;dGVzdA==\x07";
    duo_sanitize_str(s);
    TEST_ASSERT_EQUAL_STRING("?]52;c;dGVzdA==?", s);
}

static void test_osc_title_replaced(void) {
    /* OSC 0 set title: ESC ] 0 ; PWNED BEL */
    char s[] = "\x1b]0;PWNED\x07rest";
    duo_sanitize_str(s);
    TEST_ASSERT_EQUAL_STRING("?]0;PWNED?rest", s);
}

static void test_null_byte_terminates(void) {
    /* Ensure we stop at NUL and don't overrun */
    char s[] = "abc\x1b\x00xyz";
    duo_sanitize_str(s);
    /* Only first 4 chars matter (abc + replaced ESC), NUL terminates */
    TEST_ASSERT_EQUAL_STRING("abc?", s);
}

static void test_del_replaced(void) {
    char s[] = "test\x7fmore";
    duo_sanitize_str(s);
    TEST_ASSERT_EQUAL_STRING("test?more", s);
}

static void test_high_bytes_preserved(void) {
    /* Bytes >= 0x80 pass through (valid UTF-8 multi-byte sequences) */
    char s[] = "a\x80\xff" "b";
    duo_sanitize_str(s);
    TEST_ASSERT_EQUAL_STRING("a\x80\xff" "b", s);
}

static void test_utf8_preserved(void) {
    /* Valid multi-byte UTF-8: é (U+00E9), ñ (U+00F1), 日 (U+65E5) */
    char s[] = "caf\xc3\xa9 espa\xc3\xb1ol \xe6\x97\xa5\xe6\x9c\xac";
    char expected[] = "caf\xc3\xa9 espa\xc3\xb1ol \xe6\x97\xa5\xe6\x9c\xac";
    duo_sanitize_str(s);
    TEST_ASSERT_EQUAL_STRING(expected, s);
}

static void test_utf8_4byte_preserved(void) {
    /* 4-byte UTF-8: U+1F600 (emoji grinning face) */
    char s[] = "hi \xf0\x9f\x98\x80 there";
    char expected[] = "hi \xf0\x9f\x98\x80 there";
    duo_sanitize_str(s);
    TEST_ASSERT_EQUAL_STRING(expected, s);
}

static void test_mixed_controls(void) {
    /* Mix of printable, tab, newline, and various control chars */
    char s[] = "ok\t\x01\x02\nfine\x1b\x07";
    duo_sanitize_str(s);
    TEST_ASSERT_EQUAL_STRING("ok\t??\nfine??", s);
}

static void test_all_low_controls_except_tab_newline(void) {
    /* 0x01 through 0x1f, excluding 0x09 (tab) and 0x0a (newline) */
    char input[32];
    char expected[32];
    int i, j = 0, k = 0;

    for (i = 1; i <= 0x1f; i++) {
        input[j++] = (char)i;
        if (i == '\t' || i == '\n') {
            expected[k++] = (char)i;
        } else {
            expected[k++] = '?';
        }
    }
    input[j] = '\0';
    expected[k] = '\0';

    duo_sanitize_str(input);
    TEST_ASSERT_EQUAL_STRING(expected, input);
}

static void test_realistic_fail_message(void) {
    /* Simulates what a stat=FAIL message with escape injection looks like */
    char s[] = "40001: \x1b]0;PWNED\x07\x1b]52;c;ZWNobyBwd25lZA==\x07\x1b[1;31m! Access denied\x1b[0m";
    duo_sanitize_str(s);
    /* All ESC and BEL replaced with '?' */
    TEST_ASSERT_EQUAL_STRING("40001: ?]0;PWNED??]52;c;ZWNobyBwd25lZA==??[1;31m! Access denied?[0m", s);
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_printable_unchanged);
    RUN_TEST(test_empty_string);
    RUN_TEST(test_tab_preserved);
    RUN_TEST(test_newline_preserved);
    RUN_TEST(test_escape_replaced);
    RUN_TEST(test_bel_replaced);
    RUN_TEST(test_osc_title_replaced);
    RUN_TEST(test_null_byte_terminates);
    RUN_TEST(test_del_replaced);
    RUN_TEST(test_high_bytes_preserved);
    RUN_TEST(test_utf8_preserved);
    RUN_TEST(test_utf8_4byte_preserved);
    RUN_TEST(test_mixed_controls);
    RUN_TEST(test_all_low_controls_except_tab_newline);
    RUN_TEST(test_realistic_fail_message);
    return UNITY_END();
}
