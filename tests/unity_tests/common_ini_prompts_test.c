/*
 * SPDX-License-Identifier: GPL-2.0-with-classpath-exception
 *
 * common_ini_prompts_test.c
 *
 * Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved.
 */

#include "common_ini_test.h"

extern void setUp(void) {};
extern void tearDown(void) {};

/* Testing adding a number of prompts */
static void test_prompt_number_zero() {
    struct duo_config cfg = {0};
    char *name = "prompts";
    char *value = "0";
    int expected_prompts = 1;
    int num_prompts_start = 3;

    cfg.prompts = num_prompts_start;

    duo_common_ini_handler(&cfg, SECTION, name, value);
    TEST_ASSERT_EQUAL(expected_prompts, cfg.prompts);
}

static void test_prompt_number_negitive_one() {
    struct duo_config cfg = {0};
    char *name = "prompts";
    char *value = "-1";
    int expected_prompts = 1;
    int num_prompts_start = 3;

    cfg.prompts = num_prompts_start;

    duo_common_ini_handler(&cfg, SECTION, name, value);
    TEST_ASSERT_EQUAL(expected_prompts, cfg.prompts);
}

static void test_prompt_number_one() {
    struct duo_config cfg = {0};
    char *name = "prompts";
    char *value = "1";
    int expected_prompts = 1;
    int num_prompts_start = 3;

    cfg.prompts = num_prompts_start;

    duo_common_ini_handler(&cfg, SECTION, name, value);
    TEST_ASSERT_EQUAL(expected_prompts, cfg.prompts);
}

static void test_prompt_number_two() {
    struct duo_config cfg = {0};
    char *name = "prompts";
    char *value = "2";
    int expected_prompts = 1;
    int num_prompts_start = 1;

    cfg.prompts = num_prompts_start;

    duo_common_ini_handler(&cfg, SECTION, name, value);
    TEST_ASSERT_EQUAL(expected_prompts, cfg.prompts);
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_prompt_number_negitive_one);
    RUN_TEST(test_prompt_number_zero);
    RUN_TEST(test_prompt_number_one);
    RUN_TEST(test_prompt_number_two);
    return UNITY_END();
}
