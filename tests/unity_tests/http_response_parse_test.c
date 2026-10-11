/*
 * SPDX-License-Identifier: GPL-2.0-with-classpath-exception
 *
 * http_response_parse_test.c
 *
 * Copyright (c) 2026 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved.
 */

#include <stddef.h>
#include <string.h>
#include <time.h>

#include "src/unity.h"
#include "https.h"

extern HTTPScode _https_request_new(https_t **reqp, const char *host);
extern HTTPScode _https_recv_begin(https_t *req);
extern HTTPScode _https_parse(https_t *req, const char *buf, size_t len);
extern HTTPScode _https_recv_end(https_t *req, int *code, const char **body,
    int *len, time_t *retry_after);

#define PREAUTH_BODY \
    "{\"stat\": \"OK\", \"response\": {\"result\": \"auth\", " \
    "\"status_msg\": \"Account is active\"}}"

static https_t *req;

extern void setUp(void)
{
    TEST_ASSERT_EQUAL(HTTPS_OK, _https_request_new(&req, "api-test.duosecurity.com"));
}

extern void tearDown(void)
{
    https_close(&req);
}

struct response {
    HTTPScode rc;
    int code;
    const char *body;
    int len;
    time_t retry_after;
};

/* Parse one response, handing it to the parser chunk bytes at a time (or all
   at once if chunk is 0), the way https_recv() hands over each socket read. */
static struct response
parse(const char *raw, size_t chunk)
{
    struct response r;
    size_t total = strlen(raw);
    size_t off, n;

    memset(&r, 0, sizeof(r));
    TEST_ASSERT_EQUAL(HTTPS_OK, _https_recv_begin(req));
    if (chunk == 0) {
        chunk = total;
    }
    for (off = 0; off < total; off += n) {
        n = total - off < chunk ? total - off : chunk;
        if ((r.rc = _https_parse(req, raw + off, n)) != HTTPS_OK) {
            return (r);
        }
    }
    r.rc = _https_recv_end(req, &r.code, &r.body, &r.len, &r.retry_after);
    return (r);
}

static void
assert_preauth_ok(struct response r)
{
    TEST_ASSERT_EQUAL(HTTPS_OK, r.rc);
    TEST_ASSERT_EQUAL(200, r.code);
    TEST_ASSERT_EQUAL((int)strlen(PREAUTH_BODY), r.len);
    TEST_ASSERT_EQUAL_STRING(PREAUTH_BODY, r.body);
    TEST_ASSERT_TRUE(r.retry_after == DUO_RETRY_AFTER_NONE);
}

static const char content_length_response[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: 81\r\n"
    "\r\n"
    PREAUTH_BODY;

static const char chunked_response[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: application/json\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "13\r\n"
    "{\"stat\": \"OK\", \"res\r\n"
    "3e\r\n"
    "ponse\": {\"result\": \"auth\", \"status_msg\": \"Account is active\"}}\r\n"
    "0\r\n"
    "\r\n";

static void test_content_length_body(void)
{
    TEST_ASSERT_EQUAL(81, strlen(PREAUTH_BODY));
    assert_preauth_ok(parse(content_length_response, 0));
}

static void test_chunked_body(void)
{
    assert_preauth_ok(parse(chunked_response, 0));
}

/* Network reads can split anywhere: inside the status line, a header name or
   value, a chunk-size line, or the body. Byte-at-a-time is the worst case. */
static void test_byte_at_a_time(void)
{
    assert_preauth_ok(parse(content_length_response, 1));
    assert_preauth_ok(parse(chunked_response, 1));
}

/* Several responses on one keep-alive connection reuse the same parser. */
static void test_keep_alive_reuses_parser(void)
{
    struct response r;

    assert_preauth_ok(parse(content_length_response, 0));
    assert_preauth_ok(parse(chunked_response, 7));

    r = parse("HTTP/1.1 429 Too Many Requests\r\n"
              "Content-Length: 2\r\n"
              "Retry-After: 5\r\n"
              "\r\n"
              "{}", 0);
    TEST_ASSERT_EQUAL(HTTPS_OK, r.rc);
    TEST_ASSERT_EQUAL(429, r.code);
    TEST_ASSERT_TRUE(r.retry_after > 0);

    /* Header state from the 429 must not leak into the next response. */
    assert_preauth_ok(parse(content_length_response, 0));
}

static void test_non_200_status(void)
{
    struct response r = parse(
        "HTTP/1.1 401 Unauthorized\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 53\r\n"
        "\r\n"
        "{\"stat\": \"FAIL\", \"code\": 40101, \"message\": \"Invalid\"}", 0);

    TEST_ASSERT_EQUAL(HTTPS_OK, r.rc);
    TEST_ASSERT_EQUAL(401, r.code);
    TEST_ASSERT_EQUAL_STRING(
        "{\"stat\": \"FAIL\", \"code\": 40101, \"message\": \"Invalid\"}", r.body);
}

static void test_retry_after_seconds(void)
{
    time_t before = time(NULL);
    struct response r = parse(
        "HTTP/1.1 429 Too Many Requests\r\n"
        "Retry-After: 30\r\n"
        "Content-Length: 0\r\n"
        "\r\n", 1);
    time_t after = time(NULL);

    TEST_ASSERT_EQUAL(HTTPS_OK, r.rc);
    TEST_ASSERT_EQUAL(429, r.code);
    TEST_ASSERT_EQUAL(0, r.len);
    TEST_ASSERT_TRUE(r.retry_after >= before + 30);
    TEST_ASSERT_TRUE(r.retry_after <= after + 30);
}

/* Header names are case-insensitive, and X-Retry-After is honoured too. */
static void test_retry_after_header_names(void)
{
    struct response r;

    r = parse("HTTP/1.1 429 Too Many Requests\r\n"
              "retry-after: 30\r\n"
              "Content-Length: 0\r\n"
              "\r\n", 0);
    TEST_ASSERT_TRUE(r.retry_after > 0);

    r = parse("HTTP/1.1 429 Too Many Requests\r\n"
              "X-RETRY-AFTER: 30\r\n"
              "Content-Length: 0\r\n"
              "\r\n", 0);
    TEST_ASSERT_TRUE(r.retry_after > 0);
}

/* A present-but-empty Retry-After is invalid, not absent. */
static void test_empty_retry_after_is_invalid(void)
{
    struct response r = parse(
        "HTTP/1.1 429 Too Many Requests\r\n"
        "Retry-After:\r\n"
        "Content-Length: 0\r\n"
        "\r\n", 0);

    TEST_ASSERT_EQUAL(HTTPS_OK, r.rc);
    TEST_ASSERT_TRUE(r.retry_after == DUO_RETRY_AFTER_INVALID);
}

/* An empty value on an unrelated header must not corrupt the name of the
   header that follows it. */
static void test_empty_header_before_retry_after(void)
{
    struct response r = parse(
        "HTTP/1.1 429 Too Many Requests\r\n"
        "X-Empty:\r\n"
        "Retry-After: 30\r\n"
        "Content-Length: 0\r\n"
        "\r\n", 0);

    TEST_ASSERT_EQUAL(HTTPS_OK, r.rc);
    TEST_ASSERT_TRUE(r.retry_after > 0);
}

/* When the header is repeated, the last value wins. */
static void test_repeated_retry_after_last_wins(void)
{
    struct response r = parse(
        "HTTP/1.1 429 Too Many Requests\r\n"
        "Retry-After: 30\r\n"
        "Retry-After: soon\r\n"
        "Content-Length: 0\r\n"
        "\r\n", 0);

    TEST_ASSERT_TRUE(r.retry_after == DUO_RETRY_AFTER_INVALID);
}

/* The same malformed reply tests/mockduo.py --malformed sends: an invalid
   header-name byte must fail cleanly with an error string. */
static void test_invalid_header_token(void)
{
    struct response r = parse(
        "HTTP/1.1 200 OK\r\nAAAAAAAAAAAAAAAAAAAA(: x\r\n\r\n", 0);

    TEST_ASSERT_EQUAL(HTTPS_ERR_SERVER, r.rc);
    TEST_ASSERT_NOT_NULL(https_geterr());
}

static void test_invalid_status_line(void)
{
    struct response r = parse("HTTP/1.1 OK\r\nContent-Length: 0\r\n\r\n", 0);

    TEST_ASSERT_EQUAL(HTTPS_ERR_SERVER, r.rc);
    TEST_ASSERT_NOT_NULL(https_geterr());
}

static void test_invalid_chunk_size(void)
{
    struct response r = parse(
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "zz\r\n"
        "{}\r\n"
        "0\r\n"
        "\r\n", 0);

    TEST_ASSERT_EQUAL(HTTPS_ERR_SERVER, r.rc);
    TEST_ASSERT_NOT_NULL(https_geterr());
}

/* Conflicting framing is the classic request-smuggling shape; it is rejected
   rather than resolved one way or the other. */
static void test_content_length_with_chunked_rejected(void)
{
    struct response r = parse(
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 2\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "2\r\n"
        "{}\r\n"
        "0\r\n"
        "\r\n", 0);

    TEST_ASSERT_EQUAL(HTTPS_ERR_SERVER, r.rc);
    TEST_ASSERT_NOT_NULL(https_geterr());
}

/* A body cut short of its Content-Length is not a complete response. */
static void test_truncated_body_is_incomplete(void)
{
    struct response r = parse(
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 81\r\n"
        "\r\n"
        "{\"stat\": \"OK\"", 0);

    TEST_ASSERT_EQUAL(HTTPS_ERR_SERVER, r.rc);
    TEST_ASSERT_EQUAL_STRING("Incomplete HTTP response", https_geterr());
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_content_length_body);
    RUN_TEST(test_chunked_body);
    RUN_TEST(test_byte_at_a_time);
    RUN_TEST(test_keep_alive_reuses_parser);
    RUN_TEST(test_non_200_status);
    RUN_TEST(test_retry_after_seconds);
    RUN_TEST(test_retry_after_header_names);
    RUN_TEST(test_empty_retry_after_is_invalid);
    RUN_TEST(test_empty_header_before_retry_after);
    RUN_TEST(test_repeated_retry_after_last_wins);
    RUN_TEST(test_invalid_header_token);
    RUN_TEST(test_invalid_status_line);
    RUN_TEST(test_invalid_chunk_size);
    RUN_TEST(test_content_length_with_chunked_rejected);
    RUN_TEST(test_truncated_body_is_incomplete);
    return UNITY_END();
}
