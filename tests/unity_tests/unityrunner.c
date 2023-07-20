/*
 * SPDX-License-Identifier: GPL-2.0-with-classpath-exception
 *
 * unityrunner.c
 *
 * Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved.
 */

#include <stdio.h>
#include "src/unity.h"
#include "duo.h"

extern void setUp(void) {};
extern void tearDown(void) {};

void test_placeholder() {
    TEST_ASSERT_EQUAL(1, 1);
}


int main() {
    UNITY_BEGIN();
    RUN_TEST(test_placeholder);
    return UNITY_END();
}
