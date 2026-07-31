/*
 * SPDX-License-Identifier: GPL-2.0-with-classpath-exception
 *
 * parse_config_perms_test.c
 *
 * Copyright (c) 2026 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "src/unity.h"
#include "duo.h"

/* duo_parse_config return codes exercised here:
 *    0  success (permission/ownership gate passed and the body parsed)
 *   -2  rejected because of unsafe read permissions/ownership
 * The permission/ownership check runs before parsing, and the body below is a
 * syntactically valid minimal config, so an accepted file returns exactly 0. */
#define PARSE_OK     (0)
#define REJECT_PERMS (-2)

/* A non-root uid to model "config owned by an unprivileged account". */
#define NOBODY_UID 65534

static char template[] = "/tmp/duo_perms_test_XXXXXX";
static char *conf_path = NULL;

extern void setUp(void) {
    int fd;

    strcpy(template, "/tmp/duo_perms_test_XXXXXX");
    fd = mkstemp(template);
    TEST_ASSERT_TRUE_MESSAGE(fd >= 0, "could not create temp config");
    /* A syntactically valid, minimal config body. */
    TEST_ASSERT_EQUAL(15, write(fd, "[duo]\nikey = x\n", 15));
    close(fd);
    conf_path = template;
}

extern void tearDown(void) {
    if (conf_path != NULL) {
        unlink(conf_path);
        conf_path = NULL;
    }
}

/* Trivial INI callback: accept every line so parsing itself never fails and
 * an accepted file returns exactly 0 rather than a parse-error line number. */
static int
_accept_all(void *arg, const char *section, const char *name, const char *val)
{
    (void)arg; (void)section; (void)name; (void)val;
    return (1);
}

/* Owner-only (0600) is always accepted. Assert exactly 0, not merely "not -2",
 * so an accept-path regression that turned into -1 (open failed) or -3 would
 * be caught rather than passing vacuously. */
static void test_perms_owner_only_accepted() {
    TEST_ASSERT_EQUAL(0, chmod(conf_path, 0600));
    TEST_ASSERT_EQUAL(PARSE_OK,
        duo_parse_config(conf_path, _accept_all, NULL));
}

/* World-readable (0644) is always rejected, regardless of owner. */
static void test_perms_world_readable_rejected() {
    TEST_ASSERT_EQUAL(0, chmod(conf_path, 0644));
    TEST_ASSERT_EQUAL(REJECT_PERMS,
        duo_parse_config(conf_path, _accept_all, NULL));
}

/*
 * The gate checks read exposure only; write bits are intentionally ignored, as
 * on master. These two cases guard against a fail-open regression: adding a
 * write-bit rejection here would turn a valid, readable config into a -2, which
 * -- because the default failmode is DUO_FAIL_SAFE and callers read it after
 * the parse -- silently authenticates every user on upgrade. Assert they stay
 * accepted. (0620/0602 grant no read access to group/other, so neither is a
 * secret-exposure concern.)
 */
static void test_perms_group_writable_not_rejected() {
    TEST_ASSERT_EQUAL(0, chmod(conf_path, 0620));
    TEST_ASSERT_EQUAL(PARSE_OK,
        duo_parse_config(conf_path, _accept_all, NULL));
}

static void test_perms_other_writable_not_rejected() {
    TEST_ASSERT_EQUAL(0, chmod(conf_path, 0602));
    TEST_ASSERT_EQUAL(PARSE_OK,
        duo_parse_config(conf_path, _accept_all, NULL));
}

/*
 * Group-readable (0640): accepted only when the file is owned by root, so a
 * root:<group> 0640 layout works while a non-root-owned group-readable file
 * (the privsep account owning its own config) stays rejected. The accept path
 * is the one behavior this change exists to add; assert it as EQUAL(0), and
 * where we lack the privilege to exercise it, ignore rather than pass silently.
 */
static void test_perms_group_readable_depends_on_root_owner() {
    TEST_ASSERT_EQUAL(0, chmod(conf_path, 0640));

    if (geteuid() == 0) {
        struct stat st;
        TEST_ASSERT_EQUAL(0, stat(conf_path, &st));
        /* mkstemp created it owned by root here; root-owned 0640 is accepted. */
        TEST_ASSERT_EQUAL_MESSAGE(0, (int)st.st_uid,
            "expected temp file to be root-owned when running as root");
        TEST_ASSERT_EQUAL(PARSE_OK,
            duo_parse_config(conf_path, _accept_all, NULL));

        /* Re-own to a non-root account: now group-readable must be rejected. */
        TEST_ASSERT_EQUAL(0, chown(conf_path, NOBODY_UID, -1));
        TEST_ASSERT_EQUAL(REJECT_PERMS,
            duo_parse_config(conf_path, _accept_all, NULL));
    } else {
        /* Non-root: the file is owned by us (non-root), so we can confirm the
         * reject side, but the root-owned accept path -- the whole point of
         * this change -- cannot be reached without privilege. */
        TEST_ASSERT_EQUAL(REJECT_PERMS,
            duo_parse_config(conf_path, _accept_all, NULL));
        TEST_IGNORE_MESSAGE(
            "root-owned 0640 accept path requires running as root");
    }
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_perms_owner_only_accepted);
    RUN_TEST(test_perms_world_readable_rejected);
    RUN_TEST(test_perms_group_writable_not_rejected);
    RUN_TEST(test_perms_other_writable_not_rejected);
    RUN_TEST(test_perms_group_readable_depends_on_root_owner);
    return UNITY_END();
}
