/*
 * SPDX-License-Identifier: GPL-2.0-with-classpath-exception
 *
 * common_ini_groups_negation_test.c
 *
 * Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved.
 */

#include "common_ini_test.h"

extern void setUp(void) {};
extern void tearDown(void) {};

/* An empty groups filter is not "all negated". */
static void test_no_groups() {
    struct duo_config cfg = {0};

    TEST_ASSERT_FALSE(duo_groups_all_negated(&cfg));
}

/* A single negated group can never match any user. */
static void test_single_negated() {
    struct duo_config cfg = {0};

    duo_common_ini_handler(&cfg, SECTION, "groups", "!wheel");
    TEST_ASSERT_TRUE(duo_groups_all_negated(&cfg));
}

/* Multiple space-separated negations still match no one. */
static void test_multiple_negated() {
    struct duo_config cfg = {0};

    duo_common_ini_handler(&cfg, SECTION, "groups", "!wheel !admins");
    TEST_ASSERT_TRUE(duo_groups_all_negated(&cfg));
}

/* A single non-negated group is a normal, valid filter. */
static void test_single_positive() {
    struct duo_config cfg = {0};

    duo_common_ini_handler(&cfg, SECTION, "groups", "wheel");
    TEST_ASSERT_FALSE(duo_groups_all_negated(&cfg));
}

/* The idiomatic "everyone except a group" form must stay silent. */
static void test_wildcard_then_negated() {
    struct duo_config cfg = {0};

    duo_common_ini_handler(&cfg, SECTION, "groups", "* !wheel");
    TEST_ASSERT_FALSE(duo_groups_all_negated(&cfg));
}

/* A mix of positive and negated patterns is a valid filter. */
static void test_mixed_positive_and_negated() {
    struct duo_config cfg = {0};

    duo_common_ini_handler(&cfg, SECTION, "groups", "admins !wheel");
    TEST_ASSERT_FALSE(duo_groups_all_negated(&cfg));
}

/*
 * A comma-separated pattern-list is stored as a single token. A positive
 * subpattern after an initial negation ("!wheel,admin") can still match,
 * so it must not be reported as all-negated.
 */
static void test_positive_subpattern_after_negation() {
    struct duo_config cfg = {0};

    duo_common_ini_handler(&cfg, SECTION, "groups", "!wheel,admin");
    TEST_ASSERT_FALSE(duo_groups_all_negated(&cfg));
}

/* Every comma-separated subpattern negated still matches no user. */
static void test_all_subpatterns_negated() {
    struct duo_config cfg = {0};

    duo_common_ini_handler(&cfg, SECTION, "groups", "!wheel,!admin");
    TEST_ASSERT_TRUE(duo_groups_all_negated(&cfg));
}

/* A positive subpattern in a later token also disqualifies the warning. */
static void test_positive_subpattern_in_later_token() {
    struct duo_config cfg = {0};

    duo_common_ini_handler(&cfg, SECTION, "groups", "!wheel admin,!staff");
    TEST_ASSERT_FALSE(duo_groups_all_negated(&cfg));
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_no_groups);
    RUN_TEST(test_single_negated);
    RUN_TEST(test_multiple_negated);
    RUN_TEST(test_single_positive);
    RUN_TEST(test_wildcard_then_negated);
    RUN_TEST(test_mixed_positive_and_negated);
    RUN_TEST(test_positive_subpattern_after_negation);
    RUN_TEST(test_all_subpatterns_negated);
    RUN_TEST(test_positive_subpattern_in_later_token);
    return UNITY_END();
}
