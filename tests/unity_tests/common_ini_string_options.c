#include "common_ini_test.h"

/* Test adding ikey to duo_config */
static void test_ikey() {
    struct duo_config cfg = {0};
    char *name = "ikey";
    char *value = "1234123412341234";
    char *expected_value = "1234123412341234"; 
    
    duo_common_ini_handler(&cfg, SECTION, name, value);
    TEST_ASSERT_EQUAL_STRING(expected_value, cfg.ikey);
}

static void test_ikey_empty() {
    struct duo_config cfg = {0};
    char *name = "ikey";
    const char *expected_value = EMPTY_STR;

    duo_common_ini_handler(&cfg, SECTION, name, EMPTY_STR);
    TEST_ASSERT_EQUAL_STRING(expected_value, cfg.ikey); 
}

static void test_ikey_null() {
    struct duo_config cfg = {0};
    char *name = "ikey";
    const char *expected_value = NULL_STR;

    duo_common_ini_handler(&cfg, SECTION, name, NULL_STR);
    TEST_ASSERT_EQUAL_STRING(expected_value, cfg.ikey); 
}

/* Test adding skey to duo_config */
static void test_skey() {
    struct duo_config cfg = {0};
    char *name = "skey";
    char *value = "1234123412341234";
    char *expected_value = "1234123412341234";

    duo_common_ini_handler(&cfg, SECTION, name, value);
    TEST_ASSERT_EQUAL_STRING(expected_value, cfg.skey); 
}

static void test_skey_empty() {
    struct duo_config cfg = {0};
    char *name = "skey";
    const char *expected_value = EMPTY_STR;
    
    duo_common_ini_handler(&cfg, SECTION, name, EMPTY_STR);
    TEST_ASSERT_EQUAL_STRING(expected_value, cfg.skey); 
}

static void test_skey_null() {
    struct duo_config cfg = {0};
    char *name = "skey";
    const char *expected_value = NULL_STR;

    duo_common_ini_handler(&cfg, SECTION, name, NULL_STR);
    TEST_ASSERT_EQUAL_STRING(expected_value, cfg.skey); 
}

/* Test adding apihost to duo_config */
static void test_host() {
    struct duo_config cfg = {0};
    char *name = "host";
    char *value = "123412341234";
    char *expected_value = "123412341234";

    duo_common_ini_handler(&cfg, SECTION, name, value);
    TEST_ASSERT_EQUAL_STRING(expected_value, cfg.apihost); 
}

static void test_host_empty() {
    struct duo_config cfg = {0};
    char *name = "host";
    const char *expected_value = EMPTY_STR; 
    
    duo_common_ini_handler(&cfg, SECTION, name, EMPTY_STR);
    TEST_ASSERT_EQUAL_STRING(expected_value, cfg.apihost); 
}

static void test_host_null() {
    struct duo_config cfg = {0};
    char *name = "host";
    const char *expected_value = NULL_STR;

    duo_common_ini_handler(&cfg, SECTION, name, NULL_STR);
    TEST_ASSERT_EQUAL_STRING(expected_value, cfg.apihost); 
}

/* Test adding cafile to duo_config */
static void test_cafile() {
    struct duo_config cfg = {0};
    char *name = "cafile";
    char *value = "cafilevalue";
    char *expected_value = "cafilevalue";

    duo_common_ini_handler(&cfg, SECTION, name, value);
    TEST_ASSERT_EQUAL_STRING(expected_value, cfg.cafile); 
}

static void test_cafile_empty() {
    struct duo_config cfg = {0};
    char *name = "cafile";
    const char *expected_value = EMPTY_STR;    

    duo_common_ini_handler(&cfg, SECTION, name, EMPTY_STR);
    TEST_ASSERT_EQUAL_STRING(EMPTY_STR, cfg.cafile); 
}

static void test_cafile_null() {
    struct duo_config cfg = {0};
    char *name = "cafile";
    const char *expected_value = NULL_STR;

    duo_common_ini_handler(&cfg, SECTION, name, NULL_STR);
    TEST_ASSERT_EQUAL_STRING(expected_value, cfg.cafile);
}

/* Test adding http_proxy to duo_config */
static void test_http_proxy() {
    struct duo_config cfg = {0};
    char *name = "http_proxy";
    char *value = "http://username:password@proxy.example.org:8080";
    char *expected_value = "http://username:password@proxy.example.org:8080";

    duo_common_ini_handler(&cfg, SECTION, name, value);
    TEST_ASSERT_EQUAL_STRING(expected_value, cfg.http_proxy); 
}

static void test_http_proxy_empty() {
    struct duo_config cfg = {0};
    char *name = "http_proxy";
    const char *expected_value = EMPTY_STR;

    duo_common_ini_handler(&cfg, SECTION, name, EMPTY_STR);
    TEST_ASSERT_EQUAL_STRING(expected_value, cfg.http_proxy); 
}

static void test_http_proxy_null() {
    struct duo_config cfg = {0};
    char *name = "http_proxy";
    const char *expected_value = NULL_STR;

    duo_common_ini_handler(&cfg, SECTION, name, NULL_STR);
    TEST_ASSERT_EQUAL_STRING(expected_value, cfg.http_proxy); 
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_ikey);
    RUN_TEST(test_ikey_empty);
    RUN_TEST(test_ikey_null);
    RUN_TEST(test_skey);
    RUN_TEST(test_skey_empty);
    RUN_TEST(test_skey_null);
    RUN_TEST(test_host);
    RUN_TEST(test_host_empty);
    RUN_TEST(test_host_null);
    RUN_TEST(test_cafile);
    RUN_TEST(test_cafile_empty);
    RUN_TEST(test_cafile_null);
    RUN_TEST(test_http_proxy);
    RUN_TEST(test_http_proxy_empty);
    RUN_TEST(test_http_proxy_null);
    
    return UNITY_END();
}
