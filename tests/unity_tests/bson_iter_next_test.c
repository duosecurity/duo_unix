
#include "common_ini_test.h"
#include "bson.h"

/* Set to true if the test has reached the error_test function */
int reached_error_test;

void error_test(int i, const char* msg) {
    /* Mock out bson_fatal_msg */
    reached_error_test = 1;
    printf("Reached function pointer: %d %s\n", i, msg);
}

/* The format of the shorter BSON messages:
 *  size_of_message...bson_type key.size_of_value...value..
 */
static void test_bson_iter_next_basic_success() {
    /* Test if bson_iterator_next successfully skips over the value "Value" and returns the end of the BSON string */
    bson_iterator it;
    /* 20...2Key.6...Value.. */
    char msg[20] = "\x14\x00\x00\x00\x02\x4b\x65\x79\x00\x06\x00\x00\x00\x56\x61\x6c\x75\x65\x00\x00";
    int msg_size = 20;
    int expected_size = msg_size - 1;

    bson_iterator_init(&it, msg, msg_size, error_test);
    /* If it.first is 1, which it is by default, bson_iterator_next will return it.cur */
    it.first = 0;

    bson_iterator_next(&it, error_test);
    TEST_ASSERT_EQUAL(expected_size, it.curSize);
}

/* The format of this BSON message is:
 *  size_of_message...bson_type key.size_of_value...value.bson_type KEY.size_of_VALUE...VALUE..
 */
static void test_bson_iter_next_long_msg_success() {
    /* Test if bson_iterator_next successfully skips over the value "world" and returns the bson_type of the next key value pair */
    bson_iterator it;
    /* 35...2key.6...value.2KEY.6...VALUE.. */
    char msg[35] = "\x23\x00\x00\x00\x02\x6b\x65\x79\x00\x06\x00\x00\x00\x76\x61\x6c\x75\x65\x00\x02\x4b\x45\x59\x00\x06\x00\x00\x00\x56\x41\x4c\x55\x45\x00\x00";
    int msg_size = 35;
    int response;
    int expected_response = 2;

    bson_iterator_init(&it, msg, msg_size, error_test);
    it.first = 0;

    response = bson_iterator_next(&it, error_test);
    TEST_ASSERT_EQUAL(expected_response, response);
}

static void test_bson_iter_next_large_size() {
    /* Test if bson_iterator_next succeeds when the size of the BSON message defined by the BSON is larger than the actual length of the message */
    bson_iterator it;
    /* 21...2Key.6...Value.. */
    char msg[20] = "\x15\x00\x00\x00\x02\x4b\x65\x79\x00\x06\x00\x00\x00\x56\x61\x6c\x75\x65\x00\x00";
    int msg_size = 20;
    reached_error_test = 0;

    bson_iterator_init(&it, msg, msg_size, error_test);
    it.first = 0;

    bson_iterator_next(&it, error_test);
    /* The size of the BSON message defined by the BSON is not taken into account so bson_iterator_next should not reach error_test */
    TEST_ASSERT_FALSE(reached_error_test);
}

static void test_bson_iter_next_smaller_value_size() {
    /* Test if bson_iterator_next succeeds when the size of "Value" according to the BSON is smaller than the actual size of "Value" */
    bson_iterator it;
    /* 20...2Key.4...Value.. */
    char msg[20] = "\x14\x00\x00\x00\x02\x4b\x65\x79\x00\x04\x00\x00\x00\x56\x61\x6c\x75\x65\x00\x00";
    int msg_size = 20;
    reached_error_test = 0;

    bson_iterator_init(&it, msg, msg_size, error_test);
    it.first = 0;

    bson_iterator_next(&it, error_test);
    /* This will skip 4 characters so it.cur will point to the "e" character and not go over the end of the BSON message */
    TEST_ASSERT_FALSE(reached_error_test);
}

static void test_bson_iter_next_smaller_msg_size() {
    /* Test if bson_iterator_next succeeds if the size of the BSON message according to the BSON is smaller than the actual size of the message */
    bson_iterator it;
    /* 18...2Key.6...Value.. */
    char msg[20] = "\x12\x00\x00\x00\x02\x4b\x65\x79\x00\x06\x00\x00\x00\x56\x61\x6c\x75\x65\x00\x00";
    int msg_size = 20;
    reached_error_test = 0;

    bson_iterator_init(&it, msg, msg_size, error_test);
    it.first = 0;

    bson_iterator_next(&it, error_test);
    /* The size of the BSON message defined by the BSON is not taken into account so bson_iterator_next should not reach error_test */
    TEST_ASSERT_FALSE(reached_error_test);
}

static void test_bson_iter_next_eoo() {
    /* Test if bson_iterator_next succeeds when it.cur is at the end of input */
    bson_iterator it;
    /* 20...2Key.6...Value.. */
    char msg[20] = "\x14\x00\x00\x00\x02\x4b\x65\x79\x00\x06\x00\x00\x00\x56\x61\x6c\x75\x65\x00\x00";
    int msg_size = 20;
    reached_error_test = 0;

    bson_iterator_init(&it, msg, msg_size, error_test);
    it.first = 0;

    bson_iterator_next(&it, error_test);
    bson_iterator_next(&it, error_test);
    TEST_ASSERT_FALSE(reached_error_test);
}

static void test_bson_iter_next_large_value() {
    /* Test if bson_iterator_next fails when the size of "Value" according to the BSON is larger than the actual size of "Value" */
    bson_iterator it;
    /* 20...2Key.7...Value..*/
    char msg[20] = "\x14\x00\x00\x00\x02\x4b\x65\x79\x00\x07\x00\x00\x00\x56\x61\x6c\x75\x65\x00\x00";
    int msg_size = 20;
    reached_error_test = 0;

    bson_iterator_init(&it, msg, msg_size, error_test);
    it.first = 0;

    bson_iterator_next(&it, error_test);
    TEST_ASSERT_TRUE(reached_error_test);
}

static void test_bson_iter_next_no_null() {
    /* Test that bson_iterator_next will fail when the BSON message does not end with a null byte */
    bson_iterator it;
    /* 18...2Key.6...Value */
    char msg[18] = "\x12\x00\x00\x00\x02\x4b\x65\x79\x00\x06\x00\x00\x00\x56\x61\x6c\x75\x65";
    int msg_size = 18;
    reached_error_test = 0;

    bson_iterator_init(&it, msg, msg_size, error_test);
    it.first = 0;

    bson_iterator_next(&it, error_test);
    TEST_ASSERT_TRUE(reached_error_test);
}

static void test_bson_iter_next_missing_null() {
    /* Test if bson_iterator_next fails when there is no null between the value and the size of the key */
    bson_iterator it;
    /* 19...2Key6...Value.. */
    char msg[19] = "\x13\x00\x00\x00\x02\x4b\x65\x79\x06\x00\x00\x00\x56\x61\x6c\x75\x65\x00\x00";
    int msg_size = 19;
    reached_error_test = 0;

    bson_iterator_init(&it, msg, msg_size, error_test);
    it.first = 0;

    bson_iterator_next(&it, error_test);
    TEST_ASSERT_TRUE(reached_error_test);
}

static void test_bson_iter_next_no_value() {
    /* Test if bson_iterator_next fails when the bson message does not have a value for the key "Key" */
    bson_iterator it;
    /* 9...2Key. */
    char msg[9] = "\x09\x00\x00\x00\x02\x4b\x65\x79\x00";
    int msg_size = 9;
    reached_error_test = 0;

    bson_iterator_init(&it, msg, msg_size, error_test);
    it.first = 0;

    bson_iterator_next(&it, error_test);
    TEST_ASSERT_TRUE(reached_error_test);
}

static void test_bson_iter_small_msg() {
    /* Test if bson_iterator_next fails when i->cur + 1 is out of bounds in bson_iterator_next */
    bson_iterator it;
    /* 5...2 */
    char msg[5] = "\x05\x00\x00\x00\x02";
    int msg_size = 5;
    reached_error_test = 0;

    bson_iterator_init(&it, msg, msg_size, error_test);
    it.first = 0;

    bson_iterator_next(&it, error_test);
    TEST_ASSERT_TRUE(reached_error_test);
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_bson_iter_next_basic_success);
    RUN_TEST(test_bson_iter_next_long_msg_success);
    RUN_TEST(test_bson_iter_next_large_size);
    RUN_TEST(test_bson_iter_next_smaller_value_size);
    RUN_TEST(test_bson_iter_next_smaller_msg_size);
    RUN_TEST(test_bson_iter_next_eoo);
    RUN_TEST(test_bson_iter_next_large_value);
    RUN_TEST(test_bson_iter_next_no_null);
    RUN_TEST(test_bson_iter_next_missing_null);
    RUN_TEST(test_bson_iter_next_no_value);
    RUN_TEST(test_bson_iter_small_msg);
    return UNITY_END();
}
