/*
 * SPDX-License-Identifier: GPL-2.0-with-classpath-exception
 *
 * https.c
 *
 * Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved.
 */

#include "config.h"

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "cacert.h"
#include "http_parser.h"
#include "https.h"
#include "match.h"

#ifdef HAVE_X509_TEA_SET_STATE
extern void X509_TEA_set_state(int change);
#endif

struct https_ctx {
    SSL_CTX *ssl_ctx;

    char *proxy;
    char *proxy_port;
    char *proxy_auth;

    const char *errstr;
    char errbuf[512];

    http_parser_settings parse_settings;
    char parse_buf[4096];
};

struct https_ctx ctx;

typedef enum
{
	CB_NONE = 0, /* First callback*/
	CB_KEY,      /* Last was key */
	CB_VAL       /* Last was value */
} callback_status_t;

struct https_request {
    BIO *cbio;
    BIO *body;
    SSL *ssl;

    char *host;
    const char *port;

    http_parser *parser;
    int done;

    int sigpipe_ignored;
    struct sigaction old_sigpipe;

    time_t retry_after;

    char *value;
    size_t value_size;
    char* key; /* current header name */
    size_t key_size; /* size of header name */
    callback_status_t last_cb;
};

static int
__on_body(http_parser *p, const char *buf, size_t len)
{
    struct https_request *req = (struct https_request *)p->data;

    return (BIO_write(req->body, buf, len) != len);
}

time_t
_parse_retry_after(const char *header_value)
{
    if (header_value == NULL) {
        return (time_t)-1;
    }

    /* Try to parse as an integer (delay in seconds) */
    char *endptr;
    long delay_seconds = strtol(header_value, &endptr, 10);
    if (*endptr == '\0') {
        return time(NULL) + delay_seconds;
    }

    /* Try to parse as a date */
    struct tm tm;
    memset(&tm, 0, sizeof(struct tm));
    if (strptime(header_value, "%a, %d %b %Y %H:%M:%S %Z", &tm) != NULL) {
        return timegm(&tm);
    }

    return (time_t)-1;
}

static int
__on_message_complete(http_parser *p)
{
    struct https_request *req = (struct https_request *)p->data;

    req->retry_after = _parse_retry_after(req->value);

    free(req->value);
    req->value = NULL;
    req->value_size = 0;
    free(req->key);
    req->key = NULL;
    req->key_size = 0;
    req->last_cb = CB_NONE;

    req->done = 1;
    return (0);
}

static const char retry_after_header[] = "Retry-After";
static const char x_retry_after_header[] = "X-Retry-After";

static int
__on_header_field(http_parser* p, const char* at, size_t length)
{
    struct https_request *client = p->data;

    if (client->last_cb == CB_VAL)
        client->key_size = 0;

    client->key = realloc(client->key, client->key_size + length + 1);
    memcpy(client->key + client->key_size, at, length);
    client->key_size += length;
    client->key[client->key_size] = 0;

	client->last_cb = CB_KEY;

	return 0;
}

static int
__on_header_value(http_parser* p, const char* at, size_t length)
{
    struct https_request *client = p->data;

    if (strcasecmp(client->key, retry_after_header) == 0
        || strcasecmp(client->key, x_retry_after_header) == 0)
    {
        if (client->last_cb != CB_VAL)
            client->value_size = 0;

        client->value = realloc(client->value, client->value_size + length + 1);
        memcpy(client->value + client->value_size, at, length);
        client->value_size += length;
        client->value[client->value_size] = 0;
    }

	client->last_cb = CB_VAL;

	return 0;
}

static const char *
_SSL_strerror(void)
{
    unsigned long code = ERR_get_error();
    const char *p = NULL;

    if (code == 0x0906D06C) {
        /* XXX - bad "PEM_read_bio:no start line" alias */
        errno = ECONNREFUSED;
    } else {
        p = ERR_reason_error_string(code);
    }
    return (p ? p : strerror(errno));
}

/* Server certificate name check, logic adapted from libcurl */
static int
_SSL_check_server_cert(SSL *ssl, const char *hostname)
{
    X509 *cert;
    X509_NAME *subject;
    STACK_OF(GENERAL_NAME) *altnames;
    ASN1_STRING *tmp;
    int i, n, match = -1;
    struct in6_addr addr;
    int hostnametype = GEN_DNS;
    size_t addrsize;

    if (SSL_get_verify_mode(ssl) == SSL_VERIFY_NONE ||
        (cert = SSL_get_peer_certificate(ssl)) == NULL) {
        return (1);
    }

    /* Check if hostname is an IP address */
    if (inet_pton(AF_INET6, hostname, &addr) == 1) {
        hostnametype = GEN_IPADD;
        addrsize = sizeof(struct in6_addr);
    } else if (inet_pton(AF_INET, hostname, &addr) == 1) {
        hostnametype = GEN_IPADD;
        addrsize = sizeof(struct in_addr);
    }

    /* Check subjectAltName */
    if ((altnames = X509_get_ext_d2i(cert, NID_subject_alt_name,
                NULL, NULL)) != NULL) {
        n = sk_GENERAL_NAME_num(altnames);

        for (i = 0; i < n && match != 1; i++) {
            const GENERAL_NAME *altname = sk_GENERAL_NAME_value(altnames, i);
            if (hostnametype == altname->type) {
                char *altptr = (char *)ASN1_STRING_data(altname->d.ia5);
                size_t altsize = (size_t)ASN1_STRING_length(altname->d.ia5);

                if (altname->type == GEN_DNS) {
                    match = (altsize == strlen(altptr) && match_pattern(hostname, altptr));
                } else if (altname->type == GEN_IPADD) {
                    if ((altsize == addrsize) && !memcpy(altptr, &addr, altsize)) {
                        match = 1;
                    } else {
                        match = 0;
                    }
                }
            }
        }
        GENERAL_NAMES_free(altnames);
    }
    /* No subjectAltName, try CN */
    if (match == -1 &&
        (subject = X509_get_subject_name(cert)) != NULL) {
        for (i = -1; (n = X509_NAME_get_index_by_NID(subject,
                    NID_commonName, i)) >= 0; ) {
            i = n;
        }
        if (i >= 0) {
            if ((tmp = X509_NAME_ENTRY_get_data(
                       X509_NAME_get_entry(subject, i))) != NULL &&
                ASN1_STRING_type(tmp) == V_ASN1_UTF8STRING) {
                const char *pattern = (char *)ASN1_STRING_data(tmp);
                size_t patternsize = (size_t)ASN1_STRING_length(tmp);
                if (patternsize == strlen(pattern)) {
                    if (!strchr(pattern, '*')) {
                        match = strcasecmp(hostname, pattern) == 0;
                    } else if (hostnametype == GEN_DNS) {
                        match = match_pattern(hostname, pattern);
                    }
                }
            }
        }
    }
    X509_free(cert);

    return (match > 0);
}

/* Wait msecs milliseconds for the fd to become writable.  Return
 * -1 on error, 0 on timeout, and >0 if the fd is writable.
 */
static int
_fd_wait(int fd, int msecs)
{
    struct pollfd pfd;
    int result;

    pfd.fd = fd;
    pfd.events = POLLOUT | POLLWRBAND;
    pfd.revents = 0;

    if (msecs < 0) {
        msecs = -1;
    }

    do {
        result = poll(&pfd, 1, msecs);
    } while (result == -1 && errno == EINTR);

    if (result <= 0) {
        return result;
    }
    if (pfd.revents & POLLERR) {
        return -1;
    }
    return (pfd.revents & pfd.events ? 1 : -1);
}

/* Return -1 on hard error (abort), 0 on timeout, >= 1 on successful wakeup */
static int
_BIO_wait(BIO *cbio, int msecs)
{
    int result;
    if (!BIO_should_retry(cbio)) {
            return (-1);
    }

    struct pollfd pfd;
    BIO_get_fd(cbio, &pfd.fd);
    pfd.events = 0;
    pfd.revents = 0;

    if (BIO_should_io_special(cbio)) {
        pfd.events = POLLOUT | POLLWRBAND;
    } else if (BIO_should_read(cbio)) {
        pfd.events = POLLIN | POLLPRI | POLLRDBAND;
    } else if (BIO_should_write(cbio)) {
        pfd.events = POLLOUT | POLLWRBAND;
    } else {
        return (-1);
    }

    if (msecs < 0) {
        /* POSIX requires -1 for "no timeout" although some libcs
           accept any negative value. */
        msecs = -1;
    }
    do {
        result = poll(&pfd, 1, msecs);
    } while (result == -1 && errno == EINTR);

    /* Timeout or poll internal error */
    if (result <= 0) {
        return (result);
    }
    if (pfd.revents & POLLERR) {
        return -1;
    }

    /* Return 1 if the event was not an error */
    return (pfd.revents & pfd.events ? 1 : -1);
}

static BIO *
_BIO_new_base64(void)
{
    BIO *b64;

    b64 = BIO_push(BIO_new(BIO_f_base64()), BIO_new(BIO_s_mem()));
    BIO_set_flags(b64,BIO_FLAGS_BASE64_NO_NL);
    return (b64);
}

/*
 * Establishes SSL connection on an existing BIO connection.
 * Returns HTTPS_OK on success, error code on failure.
 */
static HTTPScode
_establish_ssl_connection(struct https_request * const req,
        const char * const hostname)
{
    BIO *sbio;
    int n;

    /* Establish SSL connection */
    if ((sbio = BIO_new_ssl(ctx.ssl_ctx, 1)) == NULL) {
        ctx.errstr = _SSL_strerror();
        return (HTTPS_ERR_LIB);
    }

    req->cbio = BIO_push(sbio, req->cbio);
    BIO_get_ssl(req->cbio, &req->ssl);

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    /* Enable SNI support */
    if (SSL_set_tlsext_host_name(req->ssl, hostname) != 1) {
        ctx.errstr = "Setting SNI failed";
        return (HTTPS_ERR_LIB);
    }
#endif

    while (BIO_do_handshake(req->cbio) <= 0) {
        if ((n = _BIO_wait(req->cbio, 5000)) != 1) {
            ctx.errstr = n ? _SSL_strerror() : "SSL handshake timed out";
            return (n ? HTTPS_ERR_SYSTEM : HTTPS_ERR_SERVER);
        }
    }
    /* Validate server certificate name */
    if (_SSL_check_server_cert(req->ssl, hostname) != 1) {
        ctx.errstr = "Certificate name validation failed";
        return (HTTPS_ERR_LIB);
    }

    return (HTTPS_OK);
}

/*
 * Establishes connection and SSL handshake with multiple IP retry logic.
 * Tries each resolved IP address until SSL handshake succeeds.
 * Return HTTPS_OK on success, error code on failure.
 */
static HTTPScode
_establish_connection_with_ssl_retry(struct https_request * const req,
        const char * const api_host,
        const char * const api_port,
        const char * const hostname)
{
#ifndef HAVE_GETADDRINFO
    /* Systems that don't have getaddrinfo: establish TCP, then SSL */
    HTTPScode tcp_result = _establish_connection(req, api_host, api_port);
    if (tcp_result != HTTPS_OK) {
        return tcp_result;
    }

    /* TCP connection successful, now establish SSL */
    return _establish_ssl_connection(req, hostname);

#else /* HAVE_GETADDRINFO */

    /* IPv6 Support with SSL retry logic
     * Try each resolved IP address for both TCP connection and SSL handshake
     */
    int connected_socket = -1;
    int socket_error = 0;
    struct addrinfo *res = NULL;
    struct addrinfo *cur_res = NULL;
    struct addrinfo hints;
    int error;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    error = getaddrinfo(
        api_host,
        api_port,
        &hints,
        &res
    );
    if (error) {
        ctx.errstr = gai_strerror(error);
        return HTTPS_ERR_SYSTEM;
    }

    /* Try each address for both TCP connection and SSL handshake */
    HTTPScode ssl_error = HTTPS_ERR_SERVER; /* Default fallback */
    for (cur_res = res; cur_res; cur_res = cur_res->ai_next) {
        int sock_flags;

        connected_socket = socket(
            cur_res->ai_family,
            cur_res->ai_socktype,
            cur_res->ai_protocol
        );
        if (connected_socket == -1) {
            continue;
        }
        if ((sock_flags = fcntl(connected_socket, F_GETFL, 0)) == -1) {
            goto ssl_fail;
        }

        if (fcntl(connected_socket, F_SETFL, sock_flags|O_NONBLOCK) == -1) {
            goto ssl_fail;
        }

        if (connect(connected_socket, cur_res->ai_addr, cur_res->ai_addrlen) != 0
                && errno != EINPROGRESS) {
            goto ssl_fail;
        }

        socket_error = _fd_wait(connected_socket, 10000);
        if (socket_error != 1) {
            goto ssl_fail;
        }

        /* TCP connection successful, set up BIO */
        if ((req->cbio = BIO_new_socket(connected_socket, BIO_CLOSE)) == NULL) {
            ctx.errstr = _SSL_strerror();
            goto ssl_fail;
        }
        BIO_set_conn_hostname(req->cbio, api_host);
        BIO_set_conn_port(req->cbio, api_port);
        BIO_set_nbio(req->cbio, 1);

        /* BIO now owns the socket */
        connected_socket = -1;

        /* Try SSL connection on this socket */
        if ((ssl_error = _establish_ssl_connection(req, hostname)) == HTTPS_OK) {
            freeaddrinfo(res);
            return HTTPS_OK;
        }

        /* SSL failed, clean up and try next address */
    ssl_fail:
        if (req->cbio != NULL) {
            BIO_free_all(req->cbio);
            req->cbio = NULL;
            req->ssl = NULL;
        } else if (connected_socket != -1) {
            close(connected_socket);
        }
    }

    freeaddrinfo(res);

    /* If we get here, all addresses failed */
    if (ctx.errstr == NULL) {
        /* No specific error was set, likely TCP connection failure */
        ctx.errstr = "Failed to connect";
        return socket_error ? HTTPS_ERR_SYSTEM : HTTPS_ERR_SERVER;
    }
    /* Return the last SSL error we encountered */
    return ssl_error;

#endif /* HAVE_GETADDRINFO */
}

/*
 * Establishes the connection to the Duo server.  On successful return,
 * req->cbio is connected and ready to use.
 * Return HTTPS_OK on success, error code on failure.
 */
static HTTPScode
_establish_connection(struct https_request * const req,
        const char * const api_host,
        const char * const api_port)
{
#ifndef HAVE_GETADDRINFO
    /* Systems that don't have getaddrinfo can use the BIO
       wrappers, but only get IPv4 support. */
    int n;

    if ((req->cbio = BIO_new(BIO_s_connect())) == NULL) {
        ctx.errstr = _SSL_strerror();
        return HTTPS_ERR_LIB;
    }
    BIO_set_conn_hostname(req->cbio, api_host);
    BIO_set_conn_port(req->cbio, api_port);
    BIO_set_nbio(req->cbio, 1);

    while (BIO_do_connect(req->cbio) <= 0) {
        if ((n = _BIO_wait(req->cbio, 10000)) != 1) {
            ctx.errstr = n ? _SSL_strerror() : "Connection timed out";
            return (n ? HTTPS_ERR_SYSTEM : HTTPS_ERR_SERVER);
        }
    }

    return HTTPS_OK;

#else /* HAVE_GETADDRINFO */

    /* IPv6 Support
     * BIO wrapped io does not support IPv6 addressing.  To work around,
     * resolve the address and connect the socket manually.  Then pass
     * the connected socket to the BIO wrapper with BIO_new_socket.
     */
    int connected_socket = -1;
    int socket_error = 0;
    /* Address Lookup */
    struct addrinfo *res = NULL;
    struct addrinfo *cur_res = NULL;
    struct addrinfo hints;
    int error;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    error = getaddrinfo(
        api_host,
        api_port,
        &hints,
        &res
    );
    if (error) {
        ctx.errstr = gai_strerror(error);
        return HTTPS_ERR_SYSTEM;
    }

    /* Connect */
    for (cur_res = res; cur_res; cur_res = cur_res->ai_next) {
        int sock_flags;

        connected_socket = socket(
            cur_res->ai_family,
            cur_res->ai_socktype,
            cur_res->ai_protocol
        );
        if (connected_socket == -1) {
            continue;
        }
        if ((sock_flags = fcntl(connected_socket, F_GETFL, 0)) == -1) {
            goto fail;
        }

        if (fcntl(connected_socket, F_SETFL, sock_flags|O_NONBLOCK) == -1) {
            goto fail;
        }

        if (connect(connected_socket, cur_res->ai_addr, cur_res->ai_addrlen) != 0
                && errno != EINPROGRESS) {
            goto fail;
        }

        socket_error = _fd_wait(connected_socket, 10000);
        if (socket_error != 1) {
            goto fail;
        }

        /* Connected! */
        break;
    fail:
        close(connected_socket);
        connected_socket = -1;
    }
    cur_res = NULL;
    freeaddrinfo(res);
    res = NULL;

    if (connected_socket == -1) {
        ctx.errstr = "Failed to connect";
        return socket_error ? HTTPS_ERR_SYSTEM : HTTPS_ERR_SERVER;
    }

    if ((req->cbio = BIO_new_socket(connected_socket, BIO_CLOSE)) == NULL) {
        ctx.errstr = _SSL_strerror();
        return (HTTPS_ERR_LIB);
    }
    BIO_set_conn_hostname(req->cbio, api_host);
    BIO_set_conn_port(req->cbio, api_port);
    BIO_set_nbio(req->cbio, 1);

    return HTTPS_OK;

#endif /* HAVE_GETADDRINFO */
}

/* Provide implementations for HMAC_CTX_new and HMAC_CTX_free when
 * building for OpenSSL versions older than 1.1.0
 * or LibreSSL versions older than 2.7.0
 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x2070000fL
static HMAC_CTX *
HMAC_CTX_new(void)
{
    HMAC_CTX *ctx = OPENSSL_malloc(sizeof(*ctx));
    if (ctx != NULL) {
        HMAC_CTX_init(ctx);
    }
    return ctx;
}

static void
HMAC_CTX_free(HMAC_CTX *ctx)
{
    if (ctx != NULL) {
        HMAC_CTX_cleanup(ctx);
        OPENSSL_free(ctx);
    }
}
#endif

HTTPScode
https_init(const char *cafile, const char *http_proxy)
{
    X509_STORE *store;
    X509 *cert;
    BIO *bio;
    char *p;

    /* Initialize SSL context */
#ifdef HAVE_X509_TEA_SET_STATE
    /* If applicable, disable use of Apple's Trust Evaluation Agent for certificate
     * validation, to enforce proper CA pinning:
     * http://www.opensource.apple.com/source/OpenSSL098/OpenSSL098-35.1/src/crypto/x509/x509_vfy_apple.h
     */
    X509_TEA_set_state(0);
#endif
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    /* XXX - ape openssl s_client -rand for testing on ancient systems */
    if (!RAND_status()) {
        if ((p = getenv("RANDFILE")) != NULL) {
            RAND_load_file(p, 8192);
        } else {
            ctx.errstr = "No /dev/random, EGD, or $RANDFILE";
            return (HTTPS_ERR_LIB);
        }
    }
    if ((ctx.ssl_ctx = SSL_CTX_new(SSLv23_client_method())) == NULL) {
        ctx.errstr = _SSL_strerror();
        return (HTTPS_ERR_LIB);
    }
    /* Blacklist SSLv23 */
    const long blacklist = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;
    SSL_CTX_set_options(ctx.ssl_ctx, blacklist);
    /* Set up our CA cert */
    if (cafile == NULL) {
        /* Load default CA cert from memory */
        if ((bio = BIO_new_mem_buf((void *)CACERT_PEM, -1)) == NULL ||
            (store = SSL_CTX_get_cert_store(ctx.ssl_ctx)) == NULL) {
            ctx.errstr = _SSL_strerror();
            return (HTTPS_ERR_LIB);
        }
        while ((cert = PEM_read_bio_X509(bio, NULL, 0, NULL)) != NULL) {
            X509_STORE_add_cert(store, cert);
            X509_free(cert);
        }
        BIO_free_all(bio);
        SSL_CTX_set_verify(ctx.ssl_ctx, SSL_VERIFY_PEER, NULL);
    } else if (cafile[0] == '\0') {
        /* Skip verification */
        SSL_CTX_set_verify(ctx.ssl_ctx, SSL_VERIFY_NONE, NULL);
    } else {
        /* Load CA cert from file */
        if (!SSL_CTX_load_verify_locations(ctx.ssl_ctx,
                cafile, NULL)) {
            SSL_CTX_free(ctx.ssl_ctx);
            ctx.errstr = _SSL_strerror();
            return (HTTPS_ERR_CLIENT);
        }
        SSL_CTX_set_verify(ctx.ssl_ctx, SSL_VERIFY_PEER, NULL);
    }
    /* Save our proxy config if any */
    if (http_proxy != NULL) {
        if (strstr(http_proxy, "://") != NULL) {
            if (strncmp(http_proxy, "http://", 7) != 0) {
                ctx.errstr = "http_proxy must be HTTP";
                return (HTTPS_ERR_CLIENT);
            }
            http_proxy += 7;
        }
        p = strdup(http_proxy);

        if ((ctx.proxy = strchr(p, '@')) != NULL) {
            *ctx.proxy++ = '\0';
            ctx.proxy_auth = p;
        } else {
            ctx.proxy = p;
        }
        strtok(ctx.proxy, "/");

        if ((ctx.proxy_port = strchr(ctx.proxy, ':')) != NULL) {
            *ctx.proxy_port++ = '\0';
        } else {
            ctx.proxy_port = "80";
        }
    }
    /* Set HTTP parser callbacks */
    ctx.parse_settings.on_body = __on_body;
    ctx.parse_settings.on_message_complete = __on_message_complete;
    ctx.parse_settings.on_header_field = __on_header_field;
    ctx.parse_settings.on_header_value = __on_header_value;

    return (0);
}

HTTPScode
https_open(struct https_request **reqp, const char *host, const char *useragent)
{
    struct https_request *req;
    BIO *b64;
    char *p;
    int n;
    int connection_error = 0;
    struct sigaction sigpipe;

    /* Set up our handle */
    if ((req = calloc(1, sizeof(*req))) == NULL ||
        (req->host = strdup(host)) == NULL ||
        (req->parser = malloc(sizeof(http_parser))) == NULL) {
        ctx.errstr = strerror(errno);
        https_close(&req);
        return (HTTPS_ERR_SYSTEM);
    }

    memset(&sigpipe, 0, sizeof(sigpipe));
    sigpipe.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sigpipe, &req->old_sigpipe) == 0) {
      req->sigpipe_ignored = 1;
    }

    if ((p = strchr(req->host, ':')) != NULL) {
        *p = '\0';
        req->port = p + 1;
    } else {
        req->port = "443";
    }
    if ((req->body = BIO_new(BIO_s_mem())) == NULL) {
        ctx.errstr = _SSL_strerror();
        https_close(&req);
        return (HTTPS_ERR_LIB);
    }
    http_parser_init(req->parser, HTTP_RESPONSE);
    req->parser->data = req;

    /* Connect to server */
    if (!ctx.proxy) {
        /* For direct connections, establish TCP + SSL with retry on multiple IPs */
        connection_error = _establish_connection_with_ssl_retry(req, req->host, req->port, req->host);
        if (connection_error != HTTPS_OK) {
            https_close(&req);
            return connection_error;
        }

        /* SSL already established, skip to the end */
        *reqp = req;
        return (HTTPS_OK);
    }

    /* For proxy connections, establish TCP connection first */
    connection_error = _establish_connection(req, ctx.proxy, ctx.proxy_port);
    if (connection_error != HTTPS_OK) {
        https_close(&req);
        return connection_error;
    }

    /* Tunnel through proxy, if specified */
    if (ctx.proxy != NULL) {
        BIO_printf(req->cbio,
            "CONNECT %s:%s HTTP/1.0\r\n"
            "User-Agent: %s\r\n",
            req->host, req->port, useragent
        );

        if (ctx.proxy_auth != NULL) {
            b64 = _BIO_new_base64();
            BIO_write(b64, ctx.proxy_auth,
                strlen(ctx.proxy_auth));
            (void)BIO_flush(b64);
            n = BIO_get_mem_data(b64, &p);

            BIO_puts(req->cbio, "Proxy-Authorization: Basic ");
            BIO_write(req->cbio, p, n);
            BIO_puts(req->cbio, "\r\n");
            BIO_free_all(b64);
        }
        BIO_puts(req->cbio, "\r\n");
        (void)BIO_flush(req->cbio);

        while ((n = BIO_read(req->cbio, ctx.parse_buf,
                    sizeof(ctx.parse_buf))) <= 0) {
            if ((n = _BIO_wait(req->cbio, 5000)) != 1) {
                if (n == 0) {
                    ctx.errstr = "Proxy connection timed out";
                } else {
                    ctx.errstr = "Proxy connection error";
                }
                https_close(&req);
                return HTTPS_ERR_SERVER;
            }
        }
        /* Tolerate HTTP proxies that respond with an
           incorrect HTTP version number */
        if ((strncmp("HTTP/1.0 200", ctx.parse_buf, 12) != 0)
            && (strncmp("HTTP/1.1 200", ctx.parse_buf, 12) != 0)) {
            snprintf(ctx.errbuf, sizeof(ctx.errbuf),
                "Proxy error: %s", ctx.parse_buf);
            ctx.errstr = strtok(ctx.errbuf, "\r\n");
            https_close(&req);
            if (n < 12 || atoi(ctx.parse_buf + 9) < 500) {
                return (HTTPS_ERR_CLIENT);
            }
            return (HTTPS_ERR_SERVER);
        }
    }
    /* Establish SSL connection */
    connection_error = _establish_ssl_connection(req, req->host);
    if (connection_error != HTTPS_OK) {
        https_close(&req);
        return connection_error;
    }
    *reqp = req;

    return (HTTPS_OK);
}

static int
__argv_cmp(const void *a0, const void *b0)
{
    const char **a = (const char **)a0;
    const char **b = (const char **)b0;

    return (strcmp(*a, *b));
}

static char *
_argv_to_qs(int argc, char *argv[])
{
    BIO *bio;
    BUF_MEM *bp;
    char *p;
    int i;

    if ((bio = BIO_new(BIO_s_mem())) == NULL) {
        return (NULL);
    }
    qsort(argv, argc, sizeof(argv[0]), __argv_cmp);

    for (i = 0; i < argc; i++) {
        BIO_printf(bio, "&%s", argv[i]);
    }
    BIO_get_mem_ptr(bio, &bp);
    if (bp->length && (p = malloc(bp->length)) != NULL) {
        memcpy(p, bp->data + 1, bp->length - 1);
        p[bp->length - 1] = '\0';
    } else {
        p = strdup("");
    }
    BIO_free_all(bio);

    return (p);
}

HTTPScode
https_send(struct https_request *req, const char *method, const char *uri,
    int argc, char *argv[], const char *ikey, const char *skey, const char *useragent, long time_offset)
{
    BIO *b64;
    HMAC_CTX *hmac;
    unsigned char MD[SHA512_DIGEST_LENGTH];
    char *qs, *p, date[128];
    int i, n, is_get;
    time_t t;

    req->done = 0;

    t = time(NULL) + time_offset; /* adjust time by offset */
    strftime(date, sizeof date, "%a, %d %b %Y %T %z", localtime(&t));

    /* Generate query string and canonical request to sign */
    if ((qs = _argv_to_qs(argc, argv)) == NULL) {
        ctx.errstr = strerror(errno);
        return (HTTPS_ERR_LIB);
    }
    /* Format request */
    is_get = (strcmp(method, "GET") == 0);

    if (asprintf(&p, "%s\n%s\n%s\n%s\n%s", date, method, req->host, uri, qs) < 0) {
        free(qs);
        ctx.errstr = strerror(errno);
        return (HTTPS_ERR_LIB);
    }
    if (is_get) {
        BIO_printf(req->cbio, "GET %s?%s HTTP/1.1\r\n", uri, qs);
    } else {
        BIO_printf(req->cbio, "%s %s HTTP/1.1\r\n", method, uri);
    }
    if (strcmp(req->port, "443") == 0) {
        BIO_printf(req->cbio, "Host: %s\r\n", req->host);
    } else {
        BIO_printf(req->cbio, "Host: %s:%s\r\n", req->host, req->port);
    }
    /* Add User-Agent header */
    BIO_printf(req->cbio,
               "User-Agent: %s\r\n",
               useragent);
    /* Add signature */
    BIO_printf(req->cbio, "X-Duo-Date: %s\r\n", date);
    BIO_puts(req->cbio, "Authorization: Basic ");

    if ((hmac = HMAC_CTX_new()) == NULL) {
        free(qs);
        free(p);
        ctx.errstr = strerror(errno);
        return (HTTPS_ERR_LIB);
    }
    HMAC_Init(hmac, skey, strlen(skey), EVP_sha512());
    HMAC_Update(hmac, (unsigned char *)p, strlen(p));
    HMAC_Final(hmac, MD, NULL);
    HMAC_CTX_free(hmac);
    free(p);

    b64 = _BIO_new_base64();
    BIO_printf(b64, "%s:", ikey);
    for (i = 0; i < sizeof(MD); i++) {
        BIO_printf(b64, "%02x", MD[i]);
    }
    (void)BIO_flush(b64);
    n = BIO_get_mem_data(b64, &p);
    BIO_write(req->cbio, p, n);
    BIO_free_all(b64);

    /* Finish request */
    if (!is_get) {
        BIO_printf(req->cbio,
            "\r\nContent-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: %d\r\n\r\n%s",
            (int)strlen(qs), qs);
    } else {
        BIO_puts(req->cbio, "\r\n\r\n");
    }
    /* Send request */
    while (BIO_flush(req->cbio) != 1) {
        if ((n = _BIO_wait(req->cbio, -1)) != 1) {
            ctx.errstr = n ? _SSL_strerror() : "Write timed out";
            free(qs);
            return (HTTPS_ERR_SERVER);
        }
    }
    free(qs);
    return (HTTPS_OK);
}

HTTPScode
https_recv(struct https_request *req, int *code, const char **body, int *len,
        time_t *retry_after, int msecs)
{
    int n, err;

    if (BIO_reset(req->body) != 1) {
        ctx.errstr = _SSL_strerror();
        return (HTTPS_ERR_LIB);
    }
    /* Read loop sentinel set by parser in __on_message_done() */
    while (!req->done) {
        while ((n = BIO_read(req->cbio, ctx.parse_buf,
                    sizeof(ctx.parse_buf))) <= 0) {
            if ((n = _BIO_wait(req->cbio, msecs)) != 1) {
                ctx.errstr = n ? _SSL_strerror() : "Connection closed";
                return (HTTPS_ERR_SERVER);
            }
        }
        if ((err = http_parser_execute(req->parser,
                    &ctx.parse_settings, ctx.parse_buf, n)) != n) {
            ctx.errstr = http_errno_description(err);
            return (HTTPS_ERR_SERVER);
        }
    }
    *len = BIO_get_mem_data(req->body, (char **)body);
    *code = req->parser->status_code;
    if (retry_after)
        *retry_after = req->retry_after;

    return (HTTPS_OK);
}

const char *
https_geterr(void)
{
    const char *p = ctx.errstr;
    ctx.errstr = NULL;
    return (p);
}

void
https_close(struct https_request **reqp)
{
    struct https_request *req = *reqp;

    if (req != NULL) {
        if (req->body != NULL) {
            BIO_free_all(req->body);
        }
        if (req->cbio != NULL) {
            BIO_free_all(req->cbio);
        }
        if (req->sigpipe_ignored) {
          sigaction(SIGPIPE, &req->old_sigpipe, NULL);
        }
        free(req->parser);
        free(req->host);
        free(req);
        *reqp = NULL;
    }
}
