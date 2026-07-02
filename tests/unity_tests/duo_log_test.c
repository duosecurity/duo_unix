/*
 * SPDX-License-Identifier: GPL-2.0-with-classpath-exception
 *
 * duo_log_test.c
 *
 * Copyright (c) 2026 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved.
 */

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "src/unity.h"
#include "util.h"

extern void setUp(void) {};
extern void tearDown(void) {};

static void assert_logged(int priority, const char *msg, const char *user,
                          const char *ip, const char *err, const char *expected)
{
    char logged[1024];
    FILE *capture;
    size_t bytes_read;
    int saved_stderr;

    capture = tmpfile();
    TEST_ASSERT_NOT_NULL(capture);

    fflush(stderr);
    saved_stderr = dup(STDERR_FILENO);
    TEST_ASSERT_TRUE(saved_stderr >= 0);
    TEST_ASSERT_EQUAL(STDERR_FILENO, dup2(fileno(capture), STDERR_FILENO));

    duo_debug = 1;
    duo_log(priority, msg, user, ip, err);

    fflush(stderr);
    TEST_ASSERT_EQUAL(STDERR_FILENO, dup2(saved_stderr, STDERR_FILENO));
    close(saved_stderr);

    rewind(capture);
    bytes_read = fread(logged, 1, sizeof(logged) - 1, capture);
    if (bytes_read > 0) {
        bytes_read -= 1;        /* Remove trailing newline. */
    }
    logged[bytes_read] = '\0';
    fclose(capture);

    TEST_ASSERT_EQUAL_STRING(expected, logged);
}

static void test_duo_log(void) {
    duo_log(LOG_WARNING, "a log message", "username", "ip.addr", "err-or");
    assert_logged(LOG_WARNING, "a log message", "username", "ip.addr", "err-or",
                  "[4] a log message for 'username' from ip.addr: err-or");
}

static void test_duo_log_long_username(void) {
    char input_username[601];
    char expected[516];
    char expected_username[487];

    memset(expected_username, 'u', sizeof(expected_username) - 1);
    expected_username[sizeof(expected_username) - 1] = '\0';

    memset(input_username, 'u', sizeof(input_username) - 1);
    input_username[sizeof(input_username) - 1] = '\0';

    snprintf(expected, sizeof(expected), "[4] Another log message for '%s",
             expected_username);
    assert_logged(LOG_WARNING, "Another log message", input_username,
                  "ip.addr", NULL, expected);
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_duo_log);
    RUN_TEST(test_duo_log_long_username);
    return UNITY_END();
}
