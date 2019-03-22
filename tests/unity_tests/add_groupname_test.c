#include <stdio.h>
#include "src/unity.h"
#include "util.h"

/* Testing adding a groupname with duo_common_ini_handler(cfg, section, name, var) */
void test_groupname() {
    struct duo_config cfg = {0};
    const char *name = "groups";
    char *value = "groupsname";
    const char *section = "\0";

    TEST_ASSERT_EQUAL(1, duo_common_ini_handler(&cfg, section, name, value));
    TEST_ASSERT_EQUAL_STRING(value, cfg.groups[cfg.groups_cnt - 1]);
}

void test_groupname_comma() {
    struct duo_config cfg = {0};
    const char *name = "group";
    const char *value = "group,name";
    const char *section = "\0";

    TEST_ASSERT_EQUAL(1, duo_common_ini_handler(&cfg, section, name, value));
    TEST_ASSERT_EQUAL_STRING("group,name", cfg.groups[cfg.groups_cnt - 1]);
}

void test_groupname_space() {
    struct duo_config cfg = {0};
    const char *name = "group";
    const char *value = "groups name";
    const char *section = "\0";

    TEST_ASSERT_EQUAL(1, duo_common_ini_handler(&cfg, section, name, value));
    TEST_ASSERT_EQUAL_STRING("groups", cfg.groups[cfg.groups_cnt - 2]);
    TEST_ASSERT_EQUAL_STRING("name", cfg.groups[cfg.groups_cnt - 1]);
}

void test_groupname_escaped_one() {
    struct duo_config cfg = {0};
    const char *name = "group";
    const char *value = "testing\\ name";
    const char *section = "\0";

    TEST_ASSERT_EQUAL(1, duo_common_ini_handler(&cfg, section, name, value));
    TEST_ASSERT_EQUAL_STRING("testing name", cfg.groups[cfg.groups_cnt - 1]);
}

void test_groupname_escaped_and_space() {
    struct duo_config cfg = {0};
    const char *name = "group";
    const char *value = "test group\\ name";
    const char *section = "\0";

    TEST_ASSERT_EQUAL(1, duo_common_ini_handler(&cfg, section, name, value));
    TEST_ASSERT_EQUAL_STRING("test", cfg.groups[cfg.groups_cnt - 2]);
    TEST_ASSERT_EQUAL_STRING("group name", cfg.groups[cfg.groups_cnt - 1]);
}

void test_groupname_excaped_comma_and_spaces() {
    struct duo_config cfg = {0};
    const char *name = "group";
    const char *value = "test group\\ name,groups";
    const char *section = "\0";

    TEST_ASSERT_EQUAL(1, duo_common_ini_handler(&cfg, section, name, value));
    TEST_ASSERT_EQUAL_STRING("test", cfg.groups[cfg.groups_cnt - 2]);
    TEST_ASSERT_EQUAL_STRING("group name,groups", cfg.groups[cfg.groups_cnt - 1]);
}

void test_groupname_escaped_two() {
    struct duo_config cfg = {0};
    const char *name = "groups";
    const char *value = "test group\\ name\\ here";
    const char *section = "\0";

    TEST_ASSERT_EQUAL(1, duo_common_ini_handler(&cfg, section, name, value));
    TEST_ASSERT_EQUAL_STRING("test", cfg.groups[cfg.groups_cnt - 2]);
    TEST_ASSERT_EQUAL_STRING("group name here", cfg.groups[cfg.groups_cnt - 1]);
}


int main() {
    UNITY_BEGIN();
    RUN_TEST(test_groupname);
    RUN_TEST(test_groupname_comma);
    RUN_TEST(test_groupname_space);
    RUN_TEST(test_groupname_escaped_one);
    RUN_TEST(test_groupname_escaped_and_space);
    RUN_TEST(test_groupname_excaped_comma_and_spaces);
    RUN_TEST(test_groupname_escaped_two);
    return UNITY_END();
}
