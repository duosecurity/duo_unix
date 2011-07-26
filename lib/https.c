/*
 * https.c
 *
 * Copyright (c) 2011 Duo Security
 * All rights reserved, all wrongs reversed.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "cacert.h"
#include "http_parser.h"
#include "https.h"
#include "match.h"

struct https_ctx {
        SSL_CTX              *ssl_ctx;
        http_parser_settings  parser_settings;
        const char           *errstr;
        char	              errbuf[512];
        char	             *ikey;
        char	             *skey;
        char	             *useragent;
} ctx[1];

struct https_request {
        char	      *orighost;
        char          *host;
        const char    *port;
        http_parser   *parser;
        SSL           *ssl;
        BIO           *bio;
        BIO           *b64;
        int	       fd;
        int	       done;
};

#define OPEN_TIMEOUT   10

static int
__on_body(http_parser *p, const char *buf, size_t len)
{
        struct https_request *req = (struct https_request *)p->data;

        return (BIO_write(req->bio, buf, len) != len);
}

static int
__on_message_complete(http_parser *p)
{
        ((struct https_request *)p->data)->done = 1;
        return (0);
}

static const char *
_SSL_strerror(void)
{
        return (ERR_error_string(ERR_get_error(), NULL));
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

HTTPScode
https_init(const char *ikey, const char *skey,
    const char *useragent, const char *cafile)
{
        X509_STORE *store;
        X509 *cert;
        BIO *bio;
        
        if ((ctx->ikey = strdup(ikey)) == NULL ||
            (ctx->skey = strdup(skey)) == NULL ||
            (ctx->useragent = strdup(useragent)) == NULL) {
                ctx->errstr = strerror(errno);
                return (HTTPS_ERR_SYSTEM);
        }
        /* Initialize SSL context */
        SSL_library_init();
        SSL_load_error_strings();
        SSLeay_add_ssl_algorithms();
        
        if ((ctx->ssl_ctx = SSL_CTX_new(SSLv23_client_method())) == NULL) {
                ctx->errstr = _SSL_strerror();
                return (HTTPS_ERR_LIB);
        }
        SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_ALL);
#ifdef SSL_MODE_AUTO_RETRY
        SSL_CTX_set_mode(ctx->ssl_ctx, SSL_MODE_AUTO_RETRY);
#endif
        
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
        /* Set HTTP parser callbacks */
        ctx->parser_settings.on_body = __on_body;
        ctx->parser_settings.on_message_complete = __on_message_complete;

        signal(SIGPIPE, SIG_IGN);
        
        return (0);
}

HTTPScode
https_open(struct https_request **reqp, const char *host)
{
        struct https_request *req;
        struct addrinfo hints, *res;
        struct timeval tv;
        fd_set rfds, wfds;
        char *p;
        int n;

        /* Set up our handle */
        n = 1;
        if ((req = calloc(1, sizeof(*req))) == NULL ||
            (req->orighost = strdup(host)) == NULL ||
            (req->host = strdup(host)) == NULL ||
            (req->parser = malloc(sizeof(http_parser))) == NULL) {
                ctx->errstr = strerror(errno);
                https_close(&req);
                return (HTTPS_ERR_SYSTEM);
        }
        if ((req->bio = BIO_new(BIO_s_mem())) == NULL ||
            (req->b64 = BIO_new(BIO_f_base64())) == NULL ||
            (req->ssl = SSL_new(ctx->ssl_ctx)) == NULL) {
                ctx->errstr = _SSL_strerror();
                https_close(&req);
                return (HTTPS_ERR_LIB);
        }
        BIO_set_flags(req->b64,BIO_FLAGS_BASE64_NO_NL);
        BIO_push(req->b64, req->bio);
        
        http_parser_init(req->parser, HTTP_RESPONSE);
        req->parser->data = req;

        /* Resolve host to sockaddr */
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = PF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        if ((p = strchr(req->host, ':')) != NULL) {
                *p = '\0';
                req->port = p + 1;
        }
        if ((n = getaddrinfo(req->host, req->port ? req->port : "443",
                    &hints, &res)) != 0) {
                https_close(&req);
                if (n == EAI_MEMORY || n == EAI_SYSTEM) {
                        ctx->errstr = strerror(errno);
                        return (HTTPS_ERR_SYSTEM);
                }
                ctx->errstr = gai_strerror(n);
                if (n == EAI_NONAME) {
                        return (HTTPS_ERR_CLIENT);
                } else if (n == EAI_AGAIN || n == EAI_FAIL) {
                        return (HTTPS_ERR_SERVER);
                }
                return (HTTPS_ERR_LIB);
        }
        /* Connect to server */
        if ((req->fd = socket(res->ai_family, res->ai_socktype, 0)) < 0 ||
            BIO_socket_ioctl(req->fd, FIONBIO, &n) < 0 ||
            (connect(req->fd, res->ai_addr, res->ai_addrlen) < 0 &&
                errno != EINPROGRESS)) {
                ctx->errstr = strerror(errno);
                https_close(&req);
                return ((errno == ECONNREFUSED) ?
                    HTTPS_ERR_SERVER : HTTPS_ERR_SYSTEM);
        }
        if (!SSL_set_fd(req->ssl, req->fd)) {
                ctx->errstr = _SSL_strerror();
                https_close(&req);
                return (HTTPS_ERR_LIB);
        }
        /* Non-blocking connect loop. */
        for (;;) {
                FD_ZERO(&rfds); FD_ZERO(&wfds);
                FD_SET(req->fd, &rfds); FD_SET(req->fd, &wfds);
                tv.tv_sec = OPEN_TIMEOUT;
                tv.tv_usec = 0;
                
                if ((n = select(req->fd + 1, &rfds, &wfds, NULL, &tv)) <= 0) {
                        if (n == 0) errno = ETIMEDOUT;
                        ctx->errstr = strerror(errno);
                        https_close(&req);
                        return (HTTPS_ERR_SERVER);
                }
                if ((n = SSL_connect(req->ssl)) == 1) { 
                        /* Connected! Restore blocking I/O. */
                        n = 0;
                        BIO_socket_ioctl(req->fd, FIONBIO, &n);
                        break;
                }
                n = SSL_get_error(req->ssl, n);
                if (n != SSL_ERROR_WANT_READ && n != SSL_ERROR_WANT_WRITE) {
                        ctx->errstr = (n == SSL_ERROR_SYSCALL) ?
                            strerror(errno) : _SSL_strerror();
                        https_close(&req);
                        return (HTTPS_ERR_LIB);
                }
        }
        /* Validate server certificate name */
        if (_SSL_check_server_cert(req->ssl, req->host) != 1) {
                ctx->errstr = "Invalid server certificate";
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
	HMAC_CTX hmac;
	unsigned char MD[SHA_DIGEST_LENGTH];
        char *qs, *p, sig[SHA_DIGEST_LENGTH * 2 + 1];
        long len;
        int i, n;
            
        /* Set up request */
        req->done = 0;
        (void)BIO_reset(req->bio);

        /* Generate query string and signature for request */
	if ((qs = _argv_to_qs(argc, argv)) == NULL ||
            (asprintf(&p, "%s\n%s\n%s\n%s", method, req->host,
                uri, qs)) < 0) {
                free(qs);
                ctx->errstr = strerror(errno);
                return (HTTPS_ERR_LIB);
        }
	HMAC_CTX_init(&hmac);
	HMAC_Init(&hmac, ctx->skey, strlen(ctx->skey), EVP_sha1());
	HMAC_Update(&hmac, (unsigned char *)p, strlen(p));
	HMAC_Final(&hmac, MD, NULL);
	HMAC_CTX_cleanup(&hmac);
        for (i = 0; i < sizeof(MD); i++) {
                snprintf(sig + (i * 2), 3, "%02x", MD[i]);
        }
        free(p);

        if (strcmp(method, "GET") == 0) {
                BIO_printf(req->bio, "GET %s?%s HTTP/1.1\r\n", uri, qs);
        } else {
                BIO_printf(req->bio, "%s %s HTTP/1.1\r\n", method, uri);
        }
        BIO_printf(req->bio, "Host: %s\r\n", req->orighost);
        BIO_puts(req->bio, "Authorization: Basic ");
        BIO_printf(req->b64, "%s:%s", ctx->ikey, sig);
        (void)BIO_flush(req->b64);
        
        if (strcmp(method, "GET") != 0) {
                BIO_printf(req->bio,
                    "\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                    "Content-Length: %d\r\n\r\n%s",
                    (int)strlen(qs), qs);
        } else {
                BIO_puts(req->bio, "\r\n\r\n");
        }
        /* Send request */
        len = BIO_get_mem_data(req->bio, &p);
        n = SSL_write(req->ssl, p, len);
        if (n != len) {
                ctx->errstr = _SSL_strerror();
                return (HTTPS_ERR_SERVER);
        }
        return (HTTPS_OK);
}

HTTPScode
https_recv(struct https_request *req, int *code, const char **body, int *len)
{
        char *buf;
        int n, err;
        
        if (BIO_reset(req->bio) != 1) {
                ctx->errstr = _SSL_strerror();
                return (HTTPS_ERR_LIB);
        }
        if ((buf = malloc(4096)) == NULL) {
                ctx->errstr = strerror(errno);
                return (HTTPS_ERR_SYSTEM);
        }
        /* Read loop sentinel set by parser in __on_message_done() */
        while (!req->done) {
                n = SSL_read(req->ssl, buf, 4096);
                if (n <= 0) {
                        ctx->errstr = n ? _SSL_strerror(): "Connection closed";
                        free(buf);
                        return (HTTPS_ERR_SERVER);
                } else if ((err = http_parser_execute(req->parser,
                            &ctx->parser_settings, buf, n)) != n) {
                        free(buf);
                        ctx->errstr = http_errno_description(err);
                        return (HTTPS_ERR_SERVER);
                }
        }
        free(buf);
        
        *len = BIO_get_mem_data(req->bio, (char **)body);
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
                if (req->ssl != NULL)
                        SSL_free(req->ssl);
                if (req->b64 != NULL)
                        BIO_vfree(req->b64);
                if (req->bio != NULL)
                        BIO_vfree(req->bio);
                if (req->fd > 0)
                        close(req->fd);
                free(req->parser);
                free(req->host);
                free(req->orighost);
                free(req);
                *reqp = NULL;
        }
}
