/*
 * SPDX-License-Identifier: GPL-2.0-with-classpath-exception
 *
 * https_cert_host_test.c
 *
 * Copyright (c) 2026 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved.
 */

#include <stddef.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "src/unity.h"

extern int _https_cert_matches_host(X509 *cert, const char *hostname);

extern void setUp(void) {};
extern void tearDown(void) {};

/* Append a dNSName of len bytes, stored as is. */
static void
add_dns_name(GENERAL_NAMES *names, const char *name, int len)
{
    GENERAL_NAME *gen = GENERAL_NAME_new();
    ASN1_IA5STRING *ia5 = ASN1_IA5STRING_new();

    TEST_ASSERT_NOT_NULL(gen);
    TEST_ASSERT_NOT_NULL(ia5);
    TEST_ASSERT_EQUAL(1, ASN1_STRING_set(ia5, name, len));
    GENERAL_NAME_set0_value(gen, GEN_DNS, ia5);
    TEST_ASSERT_TRUE(sk_GENERAL_NAME_push(names, gen) > 0);
}

/* Append an iPAddress parsed from text. */
static void
add_ip_name(GENERAL_NAMES *names, const char *addr)
{
    GENERAL_NAME *gen = GENERAL_NAME_new();
    ASN1_OCTET_STRING *ip = a2i_IPADDRESS(addr);

    TEST_ASSERT_NOT_NULL(gen);
    TEST_ASSERT_NOT_NULL(ip);
    GENERAL_NAME_set0_value(gen, GEN_IPADD, ip);
    TEST_ASSERT_TRUE(sk_GENERAL_NAME_push(names, gen) > 0);
}

static void
add_san(X509 *cert, GENERAL_NAMES *names)
{
    TEST_ASSERT_EQUAL(1, X509_add1_ext_i2d(cert, NID_subject_alt_name, names, 0,
        X509V3_ADD_DEFAULT));
    GENERAL_NAMES_free(names);
}

/*
 * Build an unsigned certificate with an optional CN and an optional
 * comma-separated subjectAltName list ("DNS:a.example,IP:192.0.2.1").
 * Name matching doesn't look at the signature, so no key is needed.
 * The names are built by hand rather than from OpenSSL config syntax,
 * because some libraries refuse to build malformed DNS names, and those
 * are the ones the matcher has to reject.
 */
static X509 *
make_cert(const char *cn, const char *san)
{
    X509 *cert = X509_new();
    TEST_ASSERT_NOT_NULL(cert);

    if (cn != NULL) {
        TEST_ASSERT_EQUAL(1, X509_NAME_add_entry_by_txt(
            X509_get_subject_name(cert), "CN", MBSTRING_UTF8,
            (const unsigned char *)cn, -1, -1, 0));
    }
    if (san != NULL) {
        GENERAL_NAMES *names = sk_GENERAL_NAME_new_null();
        char buf[256];
        char *entry, *next;

        TEST_ASSERT_NOT_NULL(names);
        TEST_ASSERT_TRUE(strlen(san) < sizeof(buf));
        strcpy(buf, san);
        for (entry = buf; entry != NULL; entry = next) {
            if ((next = strchr(entry, ',')) != NULL) {
                *next++ = '\0';
            }
            if (strncmp(entry, "DNS:", 4) == 0) {
                add_dns_name(names, entry + 4, (int)strlen(entry + 4));
            } else if (strncmp(entry, "IP:", 3) == 0) {
                add_ip_name(names, entry + 3);
            } else {
                TEST_FAIL_MESSAGE("bad subjectAltName in test");
            }
        }
        add_san(cert, names);
    }
    return (cert);
}

/* Build a certificate whose only subjectAltName is a raw dNSName of len bytes. */
static X509 *
make_cert_raw_dns(const char *name, int len)
{
    X509 *cert = X509_new();
    GENERAL_NAMES *names = sk_GENERAL_NAME_new_null();

    TEST_ASSERT_NOT_NULL(cert);
    TEST_ASSERT_NOT_NULL(names);
    add_dns_name(names, name, len);
    add_san(cert, names);
    return (cert);
}

static int
matches(const char *cn, const char *san, const char *hostname)
{
    X509 *cert = make_cert(cn, san);
    int result = _https_cert_matches_host(cert, hostname);

    X509_free(cert);
    return (result);
}

/* DNS subjectAltName */

static void test_san_wildcard_matches_one_label(void)
{
    /* The shape of Duo's API certificates */
    TEST_ASSERT_TRUE(matches(NULL, "DNS:*.duosecurity.com,DNS:duosecurity.com",
        "api-12345678.duosecurity.com"));
}

static void test_san_exact_match_ignores_case(void)
{
    TEST_ASSERT_TRUE(matches(NULL, "DNS:api-12345678.duosecurity.com",
        "API-12345678.DuoSecurity.com"));
}

static void test_san_later_entry_matches(void)
{
    TEST_ASSERT_TRUE(matches(NULL, "DNS:other.example.com,DNS:duo.example.com",
        "duo.example.com"));
}

static void test_san_different_name_rejected(void)
{
    TEST_ASSERT_FALSE(matches(NULL, "DNS:other.example.com", "duo.example.com"));
}

static void test_san_wildcard_does_not_span_labels(void)
{
    TEST_ASSERT_FALSE(matches(NULL, "DNS:*.corp.example",
        "duo-gw.internal.corp.example"));
}

static void test_san_wildcard_needs_a_label(void)
{
    TEST_ASSERT_FALSE(matches(NULL, "DNS:*.corp.example", "corp.example"));
}

static void test_san_partial_label_wildcard_rejected(void)
{
    TEST_ASSERT_FALSE(matches(NULL, "DNS:api-*.duosecurity.com",
        "api-12345678.duosecurity.com"));
    TEST_ASSERT_FALSE(matches(NULL, "DNS:*api.example.com", "duoapi.example.com"));
    TEST_ASSERT_FALSE(matches(NULL, "DNS:d*o.example.com", "duo.example.com"));
}

static void test_san_question_mark_is_not_a_wildcard(void)
{
    TEST_ASSERT_FALSE(matches(NULL, "DNS:a?i.duosecurity.com", "api.duosecurity.com"));
}

static void test_san_bare_wildcard_rejected(void)
{
    TEST_ASSERT_FALSE(matches(NULL, "DNS:*", "duo.example.com"));
    TEST_ASSERT_FALSE(matches(NULL, "DNS:*", "localhost"));
}

static void test_san_wildcard_on_top_level_domain_rejected(void)
{
    TEST_ASSERT_FALSE(matches(NULL, "DNS:*.com", "duosecurity.com"));
}

static void test_san_multiple_wildcards_rejected(void)
{
    TEST_ASSERT_FALSE(matches(NULL, "DNS:*.*.example.com", "a.b.example.com"));
    TEST_ASSERT_FALSE(matches(NULL, "DNS:*.example.*", "duo.example.com"));
}

static void test_san_wildcard_not_in_left_most_label_rejected(void)
{
    TEST_ASSERT_FALSE(matches(NULL, "DNS:duo.*.example.com", "duo.corp.example.com"));
}

static void test_san_embedded_nul_rejected(void)
{
    static const char name[] = "duo.example.com\0.attacker.example";
    X509 *cert = make_cert_raw_dns(name, (int)sizeof(name) - 1);

    TEST_ASSERT_FALSE(_https_cert_matches_host(cert, "duo.example.com"));
    X509_free(cert);
}

/* CN fallback */

static void test_cn_used_without_san(void)
{
    TEST_ASSERT_TRUE(matches("duo.example.com", NULL, "duo.example.com"));
}

static void test_cn_wildcard_matches_one_label(void)
{
    TEST_ASSERT_TRUE(matches("*.example.com", NULL, "duo.example.com"));
}

static void test_cn_wildcard_does_not_span_labels(void)
{
    TEST_ASSERT_FALSE(matches("*.corp.example", NULL, "duo-gw.internal.corp.example"));
}

static void test_cn_ignored_when_dns_san_present(void)
{
    TEST_ASSERT_FALSE(matches("duo.example.com", "DNS:other.example.com",
        "duo.example.com"));
}

static void test_cn_used_when_san_has_no_dns_names(void)
{
    TEST_ASSERT_TRUE(matches("duo.example.com", "IP:192.0.2.10", "duo.example.com"));
}

static void test_no_names_rejected(void)
{
    TEST_ASSERT_FALSE(matches(NULL, NULL, "duo.example.com"));
}

/* IP address hostnames */

static void test_ip_san_matches(void)
{
    TEST_ASSERT_TRUE(matches(NULL, "IP:192.0.2.10", "192.0.2.10"));
    TEST_ASSERT_TRUE(matches(NULL, "IP:2001:db8::10", "2001:db8::10"));
}

static void test_ip_san_different_address_rejected(void)
{
    TEST_ASSERT_FALSE(matches(NULL, "IP:192.0.2.11", "192.0.2.10"));
}

static void test_ip_hostname_not_matched_by_dns_wildcard(void)
{
    TEST_ASSERT_FALSE(matches(NULL, "DNS:*.0.2.10", "192.0.2.10"));
    TEST_ASSERT_FALSE(matches("*.0.2.10", NULL, "192.0.2.10"));
    TEST_ASSERT_FALSE(matches("*", NULL, "192.0.2.10"));
}

static void test_ip_hostname_cn_exact_match(void)
{
    TEST_ASSERT_TRUE(matches("192.0.2.10", NULL, "192.0.2.10"));
    TEST_ASSERT_TRUE(matches("192.0.2.10", "DNS:duo.example.com", "192.0.2.10"));
}

static void test_ip_hostname_cn_ignored_when_ip_san_present(void)
{
    TEST_ASSERT_FALSE(matches("192.0.2.10", "IP:192.0.2.11", "192.0.2.10"));
}

/* Arguments */

static void test_bad_arguments_rejected(void)
{
    X509 *cert = make_cert("duo.example.com", "DNS:duo.example.com");

    TEST_ASSERT_FALSE(_https_cert_matches_host(NULL, "duo.example.com"));
    TEST_ASSERT_FALSE(_https_cert_matches_host(cert, NULL));
    TEST_ASSERT_FALSE(_https_cert_matches_host(cert, ""));
    X509_free(cert);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_san_wildcard_matches_one_label);
    RUN_TEST(test_san_exact_match_ignores_case);
    RUN_TEST(test_san_later_entry_matches);
    RUN_TEST(test_san_different_name_rejected);
    RUN_TEST(test_san_wildcard_does_not_span_labels);
    RUN_TEST(test_san_wildcard_needs_a_label);
    RUN_TEST(test_san_partial_label_wildcard_rejected);
    RUN_TEST(test_san_question_mark_is_not_a_wildcard);
    RUN_TEST(test_san_bare_wildcard_rejected);
    RUN_TEST(test_san_wildcard_on_top_level_domain_rejected);
    RUN_TEST(test_san_multiple_wildcards_rejected);
    RUN_TEST(test_san_wildcard_not_in_left_most_label_rejected);
    RUN_TEST(test_san_embedded_nul_rejected);
    RUN_TEST(test_cn_used_without_san);
    RUN_TEST(test_cn_wildcard_matches_one_label);
    RUN_TEST(test_cn_wildcard_does_not_span_labels);
    RUN_TEST(test_cn_ignored_when_dns_san_present);
    RUN_TEST(test_cn_used_when_san_has_no_dns_names);
    RUN_TEST(test_no_names_rejected);
    RUN_TEST(test_ip_san_matches);
    RUN_TEST(test_ip_san_different_address_rejected);
    RUN_TEST(test_ip_hostname_not_matched_by_dns_wildcard);
    RUN_TEST(test_ip_hostname_cn_exact_match);
    RUN_TEST(test_ip_hostname_cn_ignored_when_ip_san_present);
    RUN_TEST(test_bad_arguments_rejected);
    return UNITY_END();
}
