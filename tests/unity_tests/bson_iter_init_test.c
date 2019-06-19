#include "common_ini_test.h"
#include "bson.h"

/* Set to true if the test has reached the error_test function */
int reached_error_test;

void error_test(int i, const char* msg) {
    /* Mock out bson_fatal_msg */
    reached_error_test = 1;
    printf("Reached function pointer: %d %s\n", i, msg);
}

/* The format of this BSON message is:
 *  size_of_message...bson_type key.size_of_value...value.bson_type KEY.size_of_VALUE...VALUE..
 */
static void test_bson_iter_init_success() {
    /* Test if bson_iterator_init properly sets the curSize and maxBufferSize */
    bson_iterator it;
    /* 35...2key.6...value.2KEY.6...VALUE.. */
    char msg[35] = "\x23\x00\x00\x00\x02\x6b\x65\x79\x00\x06\x00\x00\x00\x76\x61\x6c\x75\x65\x00\x02\x4b\x45\x59\x00\x06\x00\x00\x00\x56\x41\x4c\x55\x45\x00\x00";
    int msg_size = 35;
    int expected_cur_size = 4;
    int expected_max_buff_size = msg_size;
    void (*func_ptr)(int, const char*);
    func_ptr = &error_test;

    bson_iterator_init(&it, msg, msg_size, func_ptr);
    TEST_ASSERT_EQUAL(expected_cur_size, it.curSize);
    TEST_ASSERT_EQUAL(expected_max_buff_size, it.maxBufferSize);
}

static void test_bson_iter_init_four_size() {
    /* Test that bson_iterator_init fails if the BSON message has exactly 4 bytes */
    bson_iterator it;
    /* 4..1 */
    char msg[4] = "\x04\x00\x00\x01";
    char *expected_error_msg = "Invalid BSON response";
    int msg_size = 4;
    reached_error_test = 0;

    bson_iterator_init(&it, msg, msg_size, error_test);
    TEST_ASSERT_TRUE(reached_error_test);
}

static void test_bson_iter_init_five_size() {
    /* Test that bson_iterator_init succeeds if the BSON message has exactly 5 bytes */
    bson_iterator it;
    /* 5...1 */
    char msg[5] = "\x05\x00\x00\x00\x01";
    int msg_size = 5;
    reached_error_test = 0;

    bson_iterator_init(&it, msg, msg_size, error_test);
    TEST_ASSERT_FALSE(reached_error_test);
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_bson_iter_init_success);
    RUN_TEST(test_bson_iter_init_four_size);
    RUN_TEST(test_bson_iter_init_five_size);
    return UNITY_END();
}
