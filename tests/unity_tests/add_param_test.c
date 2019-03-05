#include <stdlib.h>
#include <stdio.h>
#include "src/unity.h"
#include "duo.h"
#include "duo_private.h"

enum {
    DUO_FAIL_SAFE = 0,
    DUO_FAIL_SECURE
};

/* Testing the function duo_add_param(ctx, name, value) */
static void test_add_param() { 
    struct duo_ctx ctx = {0}; 
    const char *name_str = "testing";
    const char *value_str = "value";
    const char *expected_str = "testing=value";

    TEST_ASSERT_EQUAL(DUO_OK, duo_add_param(&ctx, name_str, value_str));
    TEST_ASSERT_EQUAL(1, ctx.argc);
    TEST_ASSERT_EQUAL_STRING(expected_str, ctx.argv[ctx.argc - 1]);
}

static void test_add_param_empty_str() {	
    struct duo_ctx ctx = {0};
    const char *full_str = "value";
    const char *empty_str = "";

    TEST_ASSERT_EQUAL(DUO_CLIENT_ERROR, duo_add_param(&ctx, empty_str, full_str));	
    TEST_ASSERT_EQUAL(DUO_CLIENT_ERROR, duo_add_param(&ctx, full_str, empty_str));
    TEST_ASSERT_EQUAL(DUO_CLIENT_ERROR, duo_add_param(&ctx, empty_str, empty_str));
}

static void test_add_param_null_str() {
    struct duo_ctx ctx = {0};
    const char *full_str = "value";
    const char *null_str  = "\0";

    TEST_ASSERT_EQUAL(DUO_CLIENT_ERROR, duo_add_param(&ctx, full_str, null_str));
    TEST_ASSERT_EQUAL(DUO_CLIENT_ERROR, duo_add_param(&ctx, null_str, full_str));
    TEST_ASSERT_EQUAL(DUO_CLIENT_ERROR, duo_add_param(&ctx, null_str, null_str));
}

static void test_add_param_full_argc() {
    struct duo_ctx ctx = {0};
    const char *name_str = "testing";
    const char *value_str = "value";

    ctx.argc = 17;
    TEST_ASSERT_EQUAL(DUO_LIB_ERROR, duo_add_param(&ctx, name_str, value_str));
}

/* Testing duo_add_optional_param(ctx, name, value) */
static void test_add_opt_param() {
    struct duo_ctx ctx = {0};
    const char *name_str = "testing";
    const char *value_str = "value";
    const char *expected_str = "testing=value";

    TEST_ASSERT_EQUAL(DUO_OK, duo_add_optional_param(&ctx, name_str, value_str));
    TEST_ASSERT_EQUAL_STRING(expected_str, ctx.argv[ctx.argc - 1]);
};

static void test_add_opt_empty() {
    struct duo_ctx ctx = {0};
    const char *full_str = "testing";
    const char *empty_str = "";

    TEST_ASSERT_EQUAL(DUO_CLIENT_ERROR, duo_add_optional_param(&ctx, empty_str, full_str));
    TEST_ASSERT_EQUAL(DUO_OK, duo_add_optional_param(&ctx, full_str, empty_str));
    TEST_ASSERT_EQUAL(DUO_OK, duo_add_optional_param(&ctx, empty_str, empty_str));
    TEST_ASSERT_EQUAL(0, ctx.argc);
}

static void test_add_opt_null() {
    struct duo_ctx ctx = {0};
    const char *full_str = "testing";
    const char *null_str = "\0";

    TEST_ASSERT_EQUAL(DUO_CLIENT_ERROR, duo_add_optional_param(&ctx, null_str, full_str));
    TEST_ASSERT_EQUAL(DUO_OK, duo_add_optional_param(&ctx, full_str, null_str));
    TEST_ASSERT_EQUAL(DUO_OK, duo_add_optional_param(&ctx, null_str, null_str));
    TEST_ASSERT_EQUAL(0, ctx.argc);
}

/* Testing _duo_add_failmode_param(ctx, failmode) */ 
static void test_add_failclosed() {
    struct duo_ctx ctx = {0};
    char *expected_str = "failmode=closed";

    TEST_ASSERT_EQUAL(DUO_OK, _duo_add_failmode_param(&ctx, DUO_FAIL_SECURE));
    TEST_ASSERT_EQUAL_STRING(expected_str, ctx.argv[ctx.argc - 1]);
}

static void test_add_failopen() {
    struct duo_ctx ctx = {0};
    const char *expected_str = "failmode=open";

    TEST_ASSERT_EQUAL(DUO_OK, _duo_add_failmode_param(&ctx, DUO_FAIL_SAFE));
    TEST_ASSERT_EQUAL_STRING(expected_str, ctx.argv[ctx.argc - 1]);
}

int main() {
    UNITY_BEGIN();
    
    RUN_TEST(test_add_param);
    RUN_TEST(test_add_param_empty_str);
    RUN_TEST(test_add_param_null_str);
    RUN_TEST(test_add_param_full_argc);
    RUN_TEST(test_add_opt_param);
    RUN_TEST(test_add_opt_empty);
    RUN_TEST(test_add_opt_null);
    RUN_TEST(test_add_failclosed);
    RUN_TEST(test_add_failopen);

    return UNITY_END();
}
