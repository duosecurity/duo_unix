/*
 * https.c
 *
 * Copyright (c) 2011 Duo Security
 * All rights reserved, all wrongs reversed.
 */

#include "config.h"

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

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
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
        SSL_CTX              *ssl_ctx;
        char	             *ikey;
        char	             *skey;
        char	             *useragent;

        char		     *proxy;
        char		     *proxy_port;
        char		     *proxy_auth;
        
        const char           *errstr;
        char	              errbuf[512];
        
        http_parser_settings  parse_settings;
        char	              parse_buf[4096];
} *ctx;

struct https_request {
        BIO                  *cbio;
        BIO                  *body;
        SSL                  *ssl;
        
        char                 *host;	/* host */
        const char           *port;	/* port */
        
        http_parser          *parser;
        int	              done;
};

static int
__on_body(http_parser *p, const char *buf, size_t len)
{
        struct https_request *req = (struct https_request *)p->data;

        return (BIO_write(req->body, buf, len) != len);
}

static int
__on_message_complete(http_parser *p)
{
        struct https_request *req = (struct https_request *)p->data;
        
        req->done = 1;
        return (0);
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
        const GENERAL_NAME *altname;
        STACK_OF(GENERAL_NAME) *altnames;
        ASN1_STRING *tmp;
        int i, n, match = -1;
        const char *p;
        if (SSL_get_verify_mode(ssl) == SSL_VERIFY_NONE ||
            (cert = SSL_get_peer_certificate(ssl)) == NULL) {
                return (1);
        }
        /* Check subjectAltName */
        if ((altnames = X509_get_ext_d2i(cert, NID_subject_alt_name,
                    NULL, NULL)) != NULL) {
                n = sk_GENERAL_NAME_num(altnames);
                
                for (i = 0; i < n && match != 1; i++) {
                        altname = sk_GENERAL_NAME_value(altnames, i);
                        p = (char *)ASN1_STRING_data(altname->d.ia5);
                        if (altname->type == GEN_DNS) {
                                match = (ASN1_STRING_length(altname->d.ia5) ==
                                    strlen(p) && match_pattern(hostname, p));
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
                                p = (char *)ASN1_STRING_data(tmp);
                                match = (ASN1_STRING_length(tmp) ==
                                    strlen(p) && match_pattern(hostname, p));
                        }
                }
        }
        X509_free(cert);
        
        return (match > 0);
}

// Return -1 on hard error (abort), 0 on timeout, >= 1 on successful wakeup
static int
_BIO_wait(BIO *cbio, int msecs)
{
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
        int result = poll(&pfd, 1, msecs);

        // Timeout or poll internal error
        if (result <= 0) {
                return (result);
        }

        // Return 1 if the event was not an error
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

HTTPScode
https_init(const char *ikey, const char *skey,
    const char *useragent, const char *cafile)
{
        X509_STORE *store;
        X509 *cert;
        BIO *bio;
        char *p;

        if ((ctx = calloc(1, sizeof(*ctx))) == NULL ||
            (ctx->ikey = strdup(ikey)) == NULL ||
            (ctx->skey = strdup(skey)) == NULL ||
            (ctx->useragent = strdup(useragent)) == NULL) {
                ctx->errstr = strerror(errno);
                return (HTTPS_ERR_SYSTEM);
        }
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
                        ctx->errstr = "No /dev/random, EGD, or $RANDFILE";
                        return (HTTPS_ERR_LIB);
                }
        }
        if ((ctx->ssl_ctx = SSL_CTX_new(TLSv1_client_method())) == NULL) {
                ctx->errstr = _SSL_strerror();
                return (HTTPS_ERR_LIB);
        }
        /* Set up our CA cert */
        if (cafile == NULL) {
                /* Load default CA cert from memory */
                if ((bio = BIO_new_mem_buf((void *)CACERT_PEM, -1)) == NULL ||
                    (store = SSL_CTX_get_cert_store(ctx->ssl_ctx)) == NULL) {
                        ctx->errstr = _SSL_strerror();
                        return (HTTPS_ERR_LIB);
                }
                while ((cert = PEM_read_bio_X509(bio, NULL, 0, NULL)) != NULL) {
                        X509_STORE_add_cert(store, cert);
                        X509_free(cert);
                }
                BIO_free_all(bio);
                SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_PEER, NULL);
        } else if (cafile[0] == '\0') {                
                /* Skip verification */
                SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_NONE, NULL);
        } else {
                /* Load CA cert from file */
                if (!SSL_CTX_load_verify_locations(ctx->ssl_ctx,
                        cafile, NULL)) {
                        SSL_CTX_free(ctx->ssl_ctx);
                        ctx->errstr = _SSL_strerror();
                        return (HTTPS_ERR_CLIENT);
                }
                SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_PEER, NULL);
        }
        /* Save our proxy config if any */
        if ((p = getenv("http_proxy")) != NULL) {
                if (strstr(p, "://") != NULL) {
                        if (strncmp(p, "http://", 7) != 0) {
                                ctx->errstr = "http_proxy must be HTTP";
                                return (HTTPS_ERR_CLIENT);
                        }
                        p += 7;
                }
                p = strdup(p);
                
                if ((ctx->proxy = strchr(p, '@')) != NULL) {
                        *ctx->proxy++ = '\0';
                        ctx->proxy_auth = p;
                } else {
                        ctx->proxy = p;
                }
                strtok(ctx->proxy, "/");
                
                if ((ctx->proxy_port = strchr(ctx->proxy, ':')) != NULL) {
                        *ctx->proxy_port++ = '\0';
                } else {
                        ctx->proxy_port = "80";
                }
        }
        /* Set HTTP parser callbacks */
        ctx->parse_settings.on_body = __on_body;
        ctx->parse_settings.on_message_complete = __on_message_complete;

        signal(SIGPIPE, SIG_IGN);
        
        return (0);
}

HTTPScode
https_open(struct https_request **reqp, const char *host)
{
        struct https_request *req;
        BIO *b64, *sbio;
        char *p;
        int n;

        /* Set up our handle */
        n = 1;
        if ((req = calloc(1, sizeof(*req))) == NULL ||
            (req->host = strdup(host)) == NULL ||
            (req->parser = malloc(sizeof(http_parser))) == NULL) {
                ctx->errstr = strerror(errno);
                https_close(&req);
                return (HTTPS_ERR_SYSTEM);
        }
        if ((p = strchr(req->host, ':')) != NULL) {
                *p = '\0';
                req->port = p + 1;
        } else {
                req->port = "443";
        }
        if ((req->cbio = BIO_new(BIO_s_connect())) == NULL ||
            (req->body = BIO_new(BIO_s_mem())) == NULL) {
                ctx->errstr = _SSL_strerror();
                https_close(&req);
                return (HTTPS_ERR_LIB);
        }
        http_parser_init(req->parser, HTTP_RESPONSE);
        req->parser->data = req;

        /* Connect to server */
        if (ctx->proxy) {
                BIO_set_conn_hostname(req->cbio, ctx->proxy);
                BIO_set_conn_port(req->cbio, ctx->proxy_port);
        } else {
                BIO_set_conn_hostname(req->cbio, req->host);
                BIO_set_conn_port(req->cbio, req->port);
        }
        BIO_set_nbio(req->cbio, 1);
        
        while (BIO_do_connect(req->cbio) <= 0) {
                if ((n = _BIO_wait(req->cbio, 10000)) != 1) {
                        ctx->errstr = n ? _SSL_strerror() :
                            "Connection timed out";
                        https_close(&req);
                        return (n ? HTTPS_ERR_SYSTEM : HTTPS_ERR_SERVER);
                }
        }
        /* Tunnel through proxy, if specified */
        if (ctx->proxy != NULL) {
                BIO_printf(req->cbio,
                    "CONNECT %s:%s HTTP/1.0\r\n"
                    "User-Agent: %s\r\n",
                    req->host, req->port, ctx->useragent);
                
                if (ctx->proxy_auth != NULL) {
                        b64 = _BIO_new_base64();
                        BIO_write(b64, ctx->proxy_auth,
                            strlen(ctx->proxy_auth));
                        (void)BIO_flush(b64);
                        n = BIO_get_mem_data(b64, &p);

                        BIO_puts(req->cbio, "Proxy-Authorization: Basic ");
                        BIO_write(req->cbio, p, n);
                        BIO_puts(req->cbio, "\r\n");
                        BIO_free_all(b64);
                }
                BIO_puts(req->cbio, "\r\n");
                (void)BIO_flush(req->cbio);
                
                while ((n = BIO_read(req->cbio, ctx->parse_buf,
                            sizeof(ctx->parse_buf))) <= 0) {
                        _BIO_wait(req->cbio, 5000);
                }
                /* Tolerate HTTP proxies that respond with an
                   incorrect HTTP version number */
                if ((strncmp("HTTP/1.0 200", ctx->parse_buf, 12) != 0)
                    && (strncmp("HTTP/1.1 200", ctx->parse_buf, 12) != 0)) {
                        snprintf(ctx->errbuf, sizeof(ctx->errbuf),
                            "Proxy error: %s", ctx->parse_buf);
                        ctx->errstr = strtok(ctx->errbuf, "\r\n");
                        https_close(&req);
                        if (n < 12 || atoi(ctx->parse_buf + 9) < 500)
                                return (HTTPS_ERR_CLIENT);
                        return (HTTPS_ERR_SERVER);
                }
        }
        /* Establish SSL connection */
        if ((sbio = BIO_new_ssl(ctx->ssl_ctx, 1)) == NULL) {
                https_close(&req);
                return (HTTPS_ERR_LIB);
        }
        req->cbio = BIO_push(sbio, req->cbio);
        BIO_get_ssl(req->cbio, &req->ssl);
        
        while (BIO_do_handshake(req->cbio) <= 0) {
                if ((n = _BIO_wait(req->cbio, 5000)) != 1) {
                        ctx->errstr = n ? _SSL_strerror() :
                            "SSL handshake timed out";
                        https_close(&req);
                        return (n ? HTTPS_ERR_SYSTEM : HTTPS_ERR_SERVER);
                }
        }
        /* Validate server certificate name */
        if (_SSL_check_server_cert(req->ssl, req->host) != 1) {
                ctx->errstr = "Certificate name validation failed";
                https_close(&req);
                return (HTTPS_ERR_LIB);
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
    int argc, char *argv[])
{
        BIO *b64;
	HMAC_CTX hmac;
	unsigned char MD[SHA_DIGEST_LENGTH];
        char *qs, *p;
        int i, n, is_get;
            
        req->done = 0;
        
        /* Generate query string and canonical request to sign */
	if ((qs = _argv_to_qs(argc, argv)) == NULL ||
            (asprintf(&p, "%s\n%s\n%s\n%s", method, req->host, uri, qs)) < 0) {
                free(qs);
                ctx->errstr = strerror(errno);
                return (HTTPS_ERR_LIB);
        }
        /* Format request */
        if ((is_get = (strcmp(method, "GET") == 0))) {
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
                   ctx->useragent);
        /* Add signature */
        BIO_puts(req->cbio, "Authorization: Basic ");

	HMAC_CTX_init(&hmac);
	HMAC_Init(&hmac, ctx->skey, strlen(ctx->skey), EVP_sha1());
	HMAC_Update(&hmac, (unsigned char *)p, strlen(p));
	HMAC_Final(&hmac, MD, NULL);
	HMAC_CTX_cleanup(&hmac);
        free(p);
        
        b64 = _BIO_new_base64();
        BIO_printf(b64, "%s:", ctx->ikey);
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
                        ctx->errstr = n ? _SSL_strerror() : "Write timed out";
                        return (HTTPS_ERR_SERVER);
                }
        }
        return (HTTPS_OK);
}

HTTPScode
https_recv(struct https_request *req, int *code, const char **body, int *len)
{
        int n, err;
        
        if (BIO_reset(req->body) != 1) {
                ctx->errstr = _SSL_strerror();
                return (HTTPS_ERR_LIB);
        }
        /* Read loop sentinel set by parser in __on_message_done() */
        while (!req->done) {
                while ((n = BIO_read(req->cbio, ctx->parse_buf,
                            sizeof(ctx->parse_buf))) <= 0) {
                        if ((n = _BIO_wait(req->cbio, -1)) != 1) {
                                ctx->errstr = n ? _SSL_strerror() :
                                    "Connection closed";
                                return (HTTPS_ERR_SERVER);
                        }
                }
                if ((err = http_parser_execute(req->parser,
                            &ctx->parse_settings, ctx->parse_buf, n)) != n) {
                        ctx->errstr = http_errno_description(err);
                        return (HTTPS_ERR_SERVER);
                }
        }
        *len = BIO_get_mem_data(req->body, (char **)body);
        *code = req->parser->status_code;
        
        return (HTTPS_OK);
}

const char *
https_geterr(void)
{
        const char *p = ctx->errstr;
        ctx->errstr = NULL;
        return (p);
}

void
https_close(struct https_request **reqp)
{
        struct https_request *req = *reqp;

        if (req != NULL) {
                if (req->body != NULL)
                        BIO_free_all(req->body);
                if (req->cbio != NULL)
                        BIO_free_all(req->cbio);
                free(req->parser);
                free(req->host);
                free(req);
                *reqp = NULL;
        }
}
