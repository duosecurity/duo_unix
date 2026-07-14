/*
 * SPDX-License-Identifier: GPL-2.0-with-classpath-exception
 *
 * ga_init_retry_test.c
 *
 * Copyright (c) 2026 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved.
 */

#include <sys/types.h>
#include <grp.h>
#include <stdlib.h>
#include <string.h>

#include "src/unity.h"
#include "groupaccess.h"

extern void setUp(void) {};
extern void tearDown(void) {};

static int getgrouplist_call_count;
static int getgrouplist_fail_on_call;

/*
 * Mock getgrouplist: when getgrouplist_fail_on_call is set, fail on that
 * call number and write back a large ngroups value (simulating user with
 * more groups than buffer can hold).
 */
int
#ifdef __APPLE__
getgrouplist(const char *user, int group, int *groups, int *ngroups)
#else
getgrouplist(const char *user, gid_t group, gid_t *groups, int *ngroups)
#endif
{
	getgrouplist_call_count++;
	if (getgrouplist_fail_on_call == getgrouplist_call_count) {
		*ngroups = *ngroups + 100;
		return (-1);
	}
	groups[0] = group;
	*ngroups = 1;
	return 1;
}

static struct group test_group = { "testgroup", NULL, 1000, NULL };

struct group *
getgrgid(gid_t gid)
{
	test_group.gr_gid = gid;
	return &test_group;
}

/*
 * Verify that when ga_init() fails due to getgrouplist overflow,
 * then a second ga_init() call must not crash (UAF/double-free).
 */
void test_ga_init_retry_after_getgrouplist_failure(void)
{
	int ret;

	getgrouplist_call_count = 0;
	getgrouplist_fail_on_call = 1;

	ret = ga_init("testuser", 1000);
	TEST_ASSERT_EQUAL(-1, ret);

	/* Second call must not crash — this is the bug scenario. */
	getgrouplist_fail_on_call = 0;
	ret = ga_init("testuser", 1000);
	TEST_ASSERT_EQUAL(1, ret);

	ga_free();
}

/*
 * Verify consecutive getgrouplist failures don't accumulate corruption.
 */
void test_ga_init_multiple_failures(void)
{
	int ret;

	getgrouplist_call_count = 0;
	getgrouplist_fail_on_call = 1;

	ret = ga_init("testuser", 1000);
	TEST_ASSERT_EQUAL(-1, ret);

	getgrouplist_call_count = 0;
	ret = ga_init("testuser", 1000);
	TEST_ASSERT_EQUAL(-1, ret);

	getgrouplist_call_count = 0;
	ret = ga_init("testuser", 1000);
	TEST_ASSERT_EQUAL(-1, ret);

	/* Now succeed — must not crash. */
	getgrouplist_fail_on_call = 0;
	ret = ga_init("testuser", 1000);
	TEST_ASSERT_EQUAL(1, ret);

	ga_free();
}

int main(void)
{
	UNITY_BEGIN();
	RUN_TEST(test_ga_init_retry_after_getgrouplist_failure);
	RUN_TEST(test_ga_init_multiple_failures);
	return UNITY_END();
}
