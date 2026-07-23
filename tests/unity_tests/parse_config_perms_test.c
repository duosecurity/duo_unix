/*
 * SPDX-License-Identifier: GPL-2.0-with-classpath-exception
 *
 * parse_config_perms_test.c
 *
 * Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
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

/* duo_parse_config return codes we care about here:
 *    0  success (file readable with acceptable permissions)
 *   -2  rejected because of unsafe permissions/ownership
 * The permission/ownership check runs before parsing, so a minimal valid
 * body is enough; we only assert whether -2 is returned. */
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
 * any non-(-2) return means the permission gate let the file through. */
static int
_accept_all(void *arg, const char *section, const char *name, const char *val)
{
    (void)arg; (void)section; (void)name; (void)val;
    return (1);
}

/* Owner-only (0600) is always accepted. */
static void test_perms_owner_only_accepted() {
    TEST_ASSERT_EQUAL(0, chmod(conf_path, 0600));
    TEST_ASSERT_NOT_EQUAL(REJECT_PERMS,
        duo_parse_config(conf_path, _accept_all, NULL));
}

/* World-readable (0644) is always rejected, regardless of owner. */
static void test_perms_world_readable_rejected() {
    TEST_ASSERT_EQUAL(0, chmod(conf_path, 0644));
    TEST_ASSERT_EQUAL(REJECT_PERMS,
        duo_parse_config(conf_path, _accept_all, NULL));
}

/* Group-writable (0660) is always rejected, even when owned by root: only
 * the owner may modify the configuration. */
static void test_perms_group_writable_rejected() {
    TEST_ASSERT_EQUAL(0, chmod(conf_path, 0660));
    TEST_ASSERT_EQUAL(REJECT_PERMS,
        duo_parse_config(conf_path, _accept_all, NULL));
}

/* Other-writable (0602) is always rejected. */
static void test_perms_other_writable_rejected() {
    TEST_ASSERT_EQUAL(0, chmod(conf_path, 0602));
    TEST_ASSERT_EQUAL(REJECT_PERMS,
        duo_parse_config(conf_path, _accept_all, NULL));
}

/*
 * Group-readable (0640): accepted only when the file is owned by root, so a
 * root:<group> 0640 layout works while a non-root-owned group-readable file
 * (the privsep account owning its own config) stays rejected.
 */
static void test_perms_group_readable_depends_on_root_owner() {
    TEST_ASSERT_EQUAL(0, chmod(conf_path, 0640));

    if (geteuid() == 0) {
        struct stat st;
        TEST_ASSERT_EQUAL(0, stat(conf_path, &st));
        /* mkstemp created it owned by root here; root-owned 0640 is accepted. */
        TEST_ASSERT_EQUAL_MESSAGE(0, (int)st.st_uid,
            "expected temp file to be root-owned when running as root");
        TEST_ASSERT_NOT_EQUAL(REJECT_PERMS,
            duo_parse_config(conf_path, _accept_all, NULL));

        /* Re-own to a non-root account: now group-readable must be rejected. */
        TEST_ASSERT_EQUAL(0, chown(conf_path, NOBODY_UID, -1));
        TEST_ASSERT_EQUAL(REJECT_PERMS,
            duo_parse_config(conf_path, _accept_all, NULL));
    } else {
        /* Non-root: the file is owned by us (non-root), so group-readable is
         * rejected. We cannot exercise the root-owned accept path without
         * privilege. */
        TEST_ASSERT_EQUAL(REJECT_PERMS,
            duo_parse_config(conf_path, _accept_all, NULL));
    }
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_perms_owner_only_accepted);
    RUN_TEST(test_perms_world_readable_rejected);
    RUN_TEST(test_perms_group_writable_rejected);
    RUN_TEST(test_perms_other_writable_rejected);
    RUN_TEST(test_perms_group_readable_depends_on_root_owner);
    return UNITY_END();
}
