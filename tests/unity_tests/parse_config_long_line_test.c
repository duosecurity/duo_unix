/*
 * SPDX-License-Identifier: GPL-2.0-with-classpath-exception
 *
 * parse_config_long_line_test.c
 *
 * Copyright (c) 2026 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "src/unity.h"
#include "duo.h"

/* The parser's initial line buffer size (INITIAL_LINE in lib/ini.c). Lines
 * around and well past this length exercise the buffer-growth path. */
#define INITIAL_LINE 200

static char template[] = "/tmp/duo_long_line_test_XXXXXX";
static char *conf_path = NULL;

/* What the handler saw: how many times skey was set and its last value, the
 * last groups value, and whether failmode was seen. */
static int skey_calls;
static char last_skey[4096];
static char last_groups[4096];
static char last_failmode[64];

extern void setUp(void) {
    skey_calls = 0;
    last_skey[0] = '\0';
    last_groups[0] = '\0';
    last_failmode[0] = '\0';
    conf_path = NULL;
}

extern void tearDown(void) {
    if (conf_path != NULL) {
        unlink(conf_path);
        conf_path = NULL;
    }
}

/* Write the given contents to a fresh 0600 temp file. */
static void
_write_conf(const char *contents)
{
    int fd;
    size_t len = strlen(contents);

    if (conf_path != NULL) {
        unlink(conf_path);
    }
    strcpy(template, "/tmp/duo_long_line_test_XXXXXX");
    fd = mkstemp(template);
    TEST_ASSERT_TRUE_MESSAGE(fd >= 0, "could not create temp config");
    TEST_ASSERT_EQUAL((ssize_t)len, write(fd, contents, len));
    close(fd);
    conf_path = template;
}

/* Fill buf with a "; " comment line of exactly len characters (no newline),
 * with a space every few characters like real prose, so any split of the line
 * would very likely leave a whitespace-led remainder. */
static void
_comment_line(char *buf, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        buf[i] = (i % 6 == 5) ? ' ' : 'x';
    }
    buf[0] = ';';
    buf[1] = ' ';
    buf[len] = '\0';
}

static void
_copy(char *dst, size_t size, const char *src)
{
    strncpy(dst, src, size - 1);
    dst[size - 1] = '\0';
}

static int
_record(void *arg, const char *section, const char *name, const char *val)
{
    (void)arg; (void)section;
    if (strcmp(name, "skey") == 0) {
        skey_calls++;
        _copy(last_skey, sizeof(last_skey), val);
    } else if (strcmp(name, "groups") == 0) {
        _copy(last_groups, sizeof(last_groups), val);
    } else if (strcmp(name, "failmode") == 0) {
        _copy(last_failmode, sizeof(last_failmode), val);
    }
    return (1);
}

/*
 * The case from the bug report: a long comment after skey, with a space at
 * the point where the old 200-byte reader split the line. The remainder used
 * to be parsed as a continuation of skey and silently replaced its value. Now
 * the whole line is read as one comment and skey is untouched.
 */
static void test_long_comment_after_skey_is_ignored() {
    const char *conf =
        "[duo]\n"
        "skey = realsecret\n"
        "; failmode = safe: in the event of errors with this configuration "
        "file or with the connection to the Duo service this mode will allow "
        "login without 2FA. failmode = secure will deny access in cases as "
        "above and may result in you being locked out of this system if the "
        "Duo service is misconfigured.\n";

    _write_conf(conf);
    TEST_ASSERT_EQUAL(0, duo_parse_config(conf_path, _record, NULL));
    TEST_ASSERT_EQUAL(1, skey_calls);
    TEST_ASSERT_EQUAL_STRING("realsecret", last_skey);
}

/*
 * A long comment must not stop the parse: options after it, such as
 * failmode = secure, must still be read. (Treating long lines as a parse
 * error would leave failmode at its fail-open default.)
 */
static void test_options_after_long_comment_still_read() {
    char conf[2048];
    char comment[1024];

    _comment_line(comment, 1000);
    snprintf(conf, sizeof(conf),
        "[duo]\nautopush = yes\n%s\nfailmode = secure\nskey = realsecret\n",
        comment);

    _write_conf(conf);
    TEST_ASSERT_EQUAL(0, duo_parse_config(conf_path, _record, NULL));
    TEST_ASSERT_EQUAL_STRING("secure", last_failmode);
    TEST_ASSERT_EQUAL(1, skey_calls);
    TEST_ASSERT_EQUAL_STRING("realsecret", last_skey);
}

/* A long groups list (one of the triggers in ZTCSI-3213) is read in full,
 * not cut off partway through. */
static void test_long_groups_line_read_in_full() {
    char groups[1024] = "";
    char conf[2048];
    int i;

    for (i = 0; i < 60; i++) {
        char name[16];
        snprintf(name, sizeof(name), "%sgrp%03d", i ? " " : "", i);
        strcat(groups, name);
    }
    TEST_ASSERT_TRUE(strlen(groups) > 2 * INITIAL_LINE);
    snprintf(conf, sizeof(conf), "[duo]\ngroups = %s\n", groups);

    _write_conf(conf);
    TEST_ASSERT_EQUAL(0, duo_parse_config(conf_path, _record, NULL));
    TEST_ASSERT_EQUAL_STRING(groups, last_groups);
}

/* A long value is passed to the handler intact, across several buffer
 * growths. */
static void test_long_value_read_in_full() {
    char value[3001];
    char conf[4096];

    memset(value, 'a', sizeof(value) - 1);
    value[sizeof(value) - 1] = '\0';
    snprintf(conf, sizeof(conf), "[duo]\nskey = %s\n", value);

    _write_conf(conf);
    TEST_ASSERT_EQUAL(0, duo_parse_config(conf_path, _record, NULL));
    TEST_ASSERT_EQUAL(1, skey_calls);
    TEST_ASSERT_EQUAL_STRING(value, last_skey);
}

/* Lines right at the initial buffer size, where the reader first has to grow
 * the buffer, parse the same as short ones. */
static void test_lines_at_buffer_boundary() {
    size_t lens[] = { INITIAL_LINE - 2, INITIAL_LINE - 1, INITIAL_LINE,
        INITIAL_LINE + 1, 2 * INITIAL_LINE - 1, 2 * INITIAL_LINE };
    size_t i;

    for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        char conf[1024];
        char comment[2 * INITIAL_LINE + 1];

        setUp();
        _comment_line(comment, lens[i]);
        snprintf(conf, sizeof(conf),
            "[duo]\nskey = realsecret\n%s\nfailmode = secure\n", comment);

        _write_conf(conf);
        TEST_ASSERT_EQUAL(0, duo_parse_config(conf_path, _record, NULL));
        TEST_ASSERT_EQUAL(1, skey_calls);
        TEST_ASSERT_EQUAL_STRING("realsecret", last_skey);
        TEST_ASSERT_EQUAL_STRING("secure", last_failmode);
    }
}

/* A last line with no trailing newline is read, including a long one. */
static void test_final_line_without_newline() {
    char conf[2048];
    char value[1001];

    _write_conf("[duo]\nskey = realsecret");
    TEST_ASSERT_EQUAL(0, duo_parse_config(conf_path, _record, NULL));
    TEST_ASSERT_EQUAL_STRING("realsecret", last_skey);

    memset(value, 'b', sizeof(value) - 1);
    value[sizeof(value) - 1] = '\0';
    snprintf(conf, sizeof(conf), "[duo]\nskey = %s", value);
    _write_conf(conf);
    TEST_ASSERT_EQUAL(0, duo_parse_config(conf_path, _record, NULL));
    TEST_ASSERT_EQUAL_STRING(value, last_skey);
}

/* Line numbers in parse errors still count physical lines when long lines
 * come first. */
static void test_parse_error_line_number_after_long_line() {
    char conf[2048];
    char comment[1024];

    _comment_line(comment, 900);
    snprintf(conf, sizeof(conf), "[duo]\n%s\nskey = realsecret\nbogus\n",
        comment);

    _write_conf(conf);
    TEST_ASSERT_EQUAL(4, duo_parse_config(conf_path, _record, NULL));
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_long_comment_after_skey_is_ignored);
    RUN_TEST(test_options_after_long_comment_still_read);
    RUN_TEST(test_long_groups_line_read_in_full);
    RUN_TEST(test_long_value_read_in_full);
    RUN_TEST(test_lines_at_buffer_boundary);
    RUN_TEST(test_final_line_without_newline);
    RUN_TEST(test_parse_error_line_number_after_long_line);
    return UNITY_END();
}
