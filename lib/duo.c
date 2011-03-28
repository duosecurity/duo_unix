/*
 * duo.c
 *
 * Copyright (c) 2010 Duo Security
 * All rights reserved, all wrongs reversed.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/safestack.h>

#include <curl/curl.h>

#include "bson.h"
#include "cacert.h"
#include "duo.h"
#include "ini.h"
#include "urlenc.h"

#define DUO_LIB_VERSION		"libduo/" PACKAGE_VERSION
#define DUO_API_VERSION		"/rest/v1"

typedef char *PARAM;

DECLARE_STACK_OF(PARAM)

#define sk_PARAM_new(cmp) SKM_sk_new(PARAM, (cmp))
#define sk_PARAM_pop_free(st, free_func) SKM_sk_pop_free(PARAM, (st), (free_func))
#define sk_PARAM_push(st, val) SKM_sk_push(PARAM, (st), (val))
#define sk_PARAM_sort(st) SKM_sk_sort(PARAM, (st))
#define sk_PARAM_shift(st) SKM_sk_shift(PARAM, (st))

struct duo_ctx {
	CURL	*curl;			 /* curl handle */
	int	 verf;			 /* verify SSL peer? */
	
	char	 host[256];		 /* MAXHOSTNAMELEN */
	char	 ikey[128];		 /* integration key */
	char	 skey[128];		 /* secret key */
	char	 err[256];		 /* error message */
	
	STACK_OF(PARAM)	*params;	 /* stack of allocated strings */
	BIO	*bio;			 /* response body */

	char  *(*conv_prompt)(void *arg, const char *prompt, char *buf, size_t bufsize);
	void   (*conv_status)(void *arg, const char *msg);
        void	*conv_arg;
};

static int
__param_cmp(const char * const *a, const char * const *b)
{
	return (strcmp(*(char **)a, *(char **)b));
}

static size_t
__bio_write(void *ptr, size_t size, size_t nmemb, void *userp)
{
	return (BIO_write((BIO *)userp, ptr, size * nmemb));
}

static CURLcode
__sslctx_add_cert(CURL *curl, void *sslctx, void *arg)
{
	X509_STORE *store;
	X509 *cert;
	BIO *bio;
	CURLcode ret = CURLE_OK;
	
	if ((bio = BIO_new_mem_buf(CACERT_PEM, -1)) == NULL) {
		return (CURLE_OUT_OF_MEMORY);
	}
	store = SSL_CTX_get_cert_store((SSL_CTX *)sslctx);

	while ((cert = PEM_read_bio_X509(bio, NULL, 0, NULL)) != NULL) {
		X509_STORE_add_cert(store, cert);
		X509_free(cert);
	}
	BIO_free_all(bio);
	
	return (ret);
}

static char *
__prompt_fn(void *arg, const char *prompt, char *buf, size_t bufsz)
{
	printf("%s", prompt);
	fflush(stdout);
	return (fgets(buf, bufsz, stdin));
}

static void
__status_fn(void *arg, const char *msg)
{
	printf("%s\n", msg);
}

struct duo_ctx *
duo_open(const char *ikey, const char *skey, const char *progname)
{
	struct duo_ctx *ctx;
	char buf[80];

	curl_global_init(CURL_GLOBAL_ALL);

	if ((ctx = calloc(1, sizeof(*ctx))) == NULL)
		return (NULL);
	
	if ((ctx->curl = curl_easy_init()) == NULL) {
		duo_close(ctx);
		return (NULL);
	}
	ctx->verf = 1;
	strlcpy(ctx->host, DUO_API_HOST, sizeof(ctx->host));
	strlcpy(ctx->ikey, ikey, sizeof(ctx->ikey));
	strlcpy(ctx->skey, skey, sizeof(ctx->skey));
	ctx->params = sk_PARAM_new(__param_cmp);
	ctx->bio = BIO_new(BIO_s_mem());
	ctx->conv_prompt = __prompt_fn;
	ctx->conv_status = __status_fn;
	
	if (ctx->params == NULL || ctx->bio == NULL) {
		duo_close(ctx);
		return (NULL);
	}
	curl_easy_setopt(ctx->curl, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt(ctx->curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(ctx->curl, CURLOPT_DNS_CACHE_TIMEOUT, 0);
	snprintf(buf, sizeof(buf), "%s (%s) libduo/%s",
	    progname, CANONICAL_HOST, PACKAGE_VERSION);
	curl_easy_setopt(ctx->curl, CURLOPT_USERAGENT, buf);
	curl_easy_setopt(ctx->curl, CURLOPT_ERRORBUFFER, ctx->err);
	curl_easy_setopt(ctx->curl, CURLOPT_WRITEDATA, (void *)ctx->bio);
	curl_easy_setopt(ctx->curl, CURLOPT_WRITEFUNCTION, __bio_write);
	curl_easy_setopt(ctx->curl, CURLOPT_SSLCERTTYPE, "PEM");
	curl_easy_setopt(ctx->curl, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(ctx->curl, CURLOPT_SSL_VERIFYHOST, 2L);
	curl_easy_setopt(ctx->curl, CURLOPT_SSL_CTX_FUNCTION,
	    __sslctx_add_cert);
	return (ctx);
}

int
duo_parse_config(const char *filename,
    int (*callback)(void *arg, const char *section,
	const char *name, const char *val), void *arg)
{
	FILE *fp;
	struct stat st;
	int fd, ret;
	
	if ((fd = open(filename, O_RDONLY)) < 0) {
		return (-1);
	}
	if (fstat(fd, &st) < 0 ||(fp = fdopen(fd, "r")) == NULL) {
		close(fd);
		return (-1);
	}
	if ((st.st_mode & (S_IRGRP|S_IROTH)) != 0) {
		fclose(fp);
		return (-2);
	}
	ret = ini_parse(fp, callback, arg);
	fclose(fp);
	return (ret);
}

static duo_code_t
duo_reset(struct duo_ctx *ctx)
{
	curl_easy_setopt(ctx->curl, CURLOPT_CUSTOMREQUEST, NULL);
	
	*ctx->err = '\0';
	
	sk_PARAM_pop_free(ctx->params, free);
	if ((ctx->params = sk_PARAM_new(__param_cmp)) == NULL) {
		return (DUO_LIB_ERROR);
	}
	(void)BIO_reset(ctx->bio);

	return (DUO_OK);
}

void
duo_close(struct duo_ctx *ctx)
{
	if (ctx != NULL) {
		if (ctx->curl)
			curl_easy_cleanup(ctx->curl);
		if (ctx->params)
			sk_PARAM_pop_free(ctx->params, free);
		if (ctx->bio)
			BIO_free_all(ctx->bio);
		free(ctx);
	}
}

void
duo_set_conv_funcs(struct duo_ctx *ctx,
    char *(*prompt_fn)(void *arg, const char *prompt, char *buf, size_t bufsz),
    void (*status_fn)(void *arg, const char *msg),
    void *arg)
{
	ctx->conv_prompt = prompt_fn;
	ctx->conv_status = status_fn;
	ctx->conv_arg = arg;
}

void
duo_set_host(struct duo_ctx *ctx, const char *hostname)
{
	char *p;

	strlcpy(ctx->host, hostname, sizeof(ctx->host));
	
	for (p = ctx->host; *p != '\0'; p++) {
		*p = tolower(*p);
	}
}

static duo_code_t
duo_add_param(struct duo_ctx *ctx, const char *name, const char *value)
{
	duo_code_t ret;
	char *k, *v, *p;

	if (name == NULL || value == NULL) {
		return (DUO_CLIENT_ERROR);
	}
	ret = DUO_LIB_ERROR;

	k = urlenc_encode(name);
	v = urlenc_encode(value);
	
	if (k && v && asprintf(&p, "%s=%s", k, v) > 2) {
		sk_PARAM_push(ctx->params, p);
		ret = DUO_OK;
	}
	free(k);
	free(v);

	return (ret);
}

void
duo_set_ssl_verify(struct duo_ctx *ctx, int bool)
{
	ctx->verf = (bool != 0);
	curl_easy_setopt(ctx->curl, CURLOPT_SSL_VERIFYPEER, (long)ctx->verf);
	curl_easy_setopt(ctx->curl, CURLOPT_SSL_VERIFYHOST, (bool ? 2L : 0L));
}

static int
_hmac_sha1(const char *key, const char *inbuf, int inlen, char *outbuf, int outlen)
{
	HMAC_CTX hmac;
	unsigned char MD[SHA_DIGEST_LENGTH];
	int i;
	
	if (outlen < sizeof(MD) * 2 + 1) {
		return (-1);
	}
	HMAC_CTX_init(&hmac);
	HMAC_Init(&hmac, key, strlen(key), EVP_sha1());
	HMAC_Update(&hmac, (unsigned char *)inbuf, inlen);
	HMAC_Final(&hmac, MD, NULL);
	HMAC_CTX_cleanup(&hmac);

	for (i = 0; i < sizeof(MD); i++) {
		sprintf(outbuf + (i * 2), "%02x", MD[i]);
	}
	return (0);
}

static char *
_params_pop_to_qs(struct duo_ctx *ctx)
{
	BIO *bio;
	BUF_MEM *bp;
	char *p, *ret;

	if ((bio = BIO_new(BIO_s_mem())) == NULL) {
		return (NULL);
	}
	sk_PARAM_sort(ctx->params);
	
	while ((p = (char *)sk_PARAM_shift(ctx->params)) != NULL) {
		BIO_printf(bio, "&%s", p);
		free(p);
	}
	BIO_get_mem_ptr(bio, &bp);
	if (bp->length && (ret = malloc(bp->length)) != NULL) {
		memcpy(ret, bp->data + 1, bp->length - 1);
		ret[bp->length - 1] = '\0';
	} else {
		ret = calloc(1, sizeof(*ret));
	}
	BIO_free_all(bio);
	
	return (ret);
}

static void
_duo_seterr(struct duo_ctx *ctx, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(ctx->err, sizeof(ctx->err), fmt, ap);
	va_end(ap);
}

#define _BSON_FIND(ctx, it, obj, name, type) do {			\
	if (bson_find(it, obj, name) != type) {				\
		_duo_seterr(ctx, "BSON missing valid '%s'", name);	\
		return (DUO_SERVER_ERROR);				\
	}								\
} while (0)

static duo_code_t
_duo_bson_response(struct duo_ctx *ctx, bson *resp)
{
	BUF_MEM *bp;
	bson obj;
	bson_iterator it;
	duo_code_t ret;
	const char *p;
	int code;
	
	BIO_get_mem_ptr(ctx->bio, &bp);
	bson_init(&obj, bp->data, 0);
	
	ret = DUO_SERVER_ERROR;
	
	if (bson_size(&obj) > bp->length) {
		_duo_seterr(ctx, "invalid BSON response");
		return (ret);
	}
	_BSON_FIND(ctx, &it, &obj, "stat", bson_string);
	p = bson_iterator_string(&it);
	
	if (strcasecmp(p, "OK") == 0) {
		_BSON_FIND(ctx, &it, &obj, "response", bson_object);
		if (resp)
			bson_iterator_subobject(&it, resp);
		ret = DUO_OK;
	} else if (strcasecmp(p, "FAIL") == 0) {
		_BSON_FIND(ctx, &it, &obj, "code", bson_int);
		code = bson_iterator_int(&it);
		_BSON_FIND(ctx, &it, &obj, "message", bson_string);
		_duo_seterr(ctx, "%d: %s", code, bson_iterator_string(&it));
		ret = DUO_FAIL;
	}
	return (ret);
}

static duo_code_t
duo_call(struct duo_ctx *ctx, const char *method, const char *fmt, ...)
{
	va_list ap;
	CURLcode ccode;
	long rcode;
	int n, ret;
	char *uri, *qs, *sign, *url, *userpwd;
	char sig[SHA_DIGEST_LENGTH * 2 + 1];

	uri = qs = sign = url = userpwd = NULL;
	ret = DUO_LIB_ERROR;
        ctx->err[0] = '\0';
	
	/* Format URI & (sorted) query string */
	va_start(ap, fmt);
	vasprintf(&uri, fmt, ap);
	va_end(ap);
	if (uri == NULL || (qs = _params_pop_to_qs(ctx)) == NULL) {
		goto call_cleanup;
	}
	/* Prepare request */
	if (duo_reset(ctx) != DUO_OK) {
		goto call_cleanup;
	}
	if (strcmp(method, "GET") == 0) {
		curl_easy_setopt(ctx->curl, CURLOPT_HTTPGET, 1);
		if (asprintf(&url, "https://%s%s%s%s", ctx->host, uri, *qs ? "?" : "", qs) < 0)
			goto call_cleanup;
	} else {
		curl_easy_setopt(ctx->curl, CURLOPT_POST, 1);
		if (asprintf(&url, "https://%s%s", ctx->host, uri) < 0)
			goto call_cleanup;
		curl_easy_setopt(ctx->curl, CURLOPT_POSTFIELDS, qs);
		curl_easy_setopt(ctx->curl, CURLOPT_CUSTOMREQUEST, method);
	}
	curl_easy_setopt(ctx->curl, CURLOPT_URL, url);
	
	/* Sign request */
	if ((n = asprintf(&sign, "%s\n%s\n%s\n%s", method, ctx->host, uri, qs)) < 0 ||
	    _hmac_sha1(ctx->skey, sign, n, sig, sizeof(sig)) < 0) {
		goto call_cleanup;
	}
	curl_easy_setopt(ctx->curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
	if (asprintf(&userpwd, "%s:%s", ctx->ikey, sig) < 0)
		goto call_cleanup;
	curl_easy_setopt(ctx->curl, CURLOPT_USERPWD, userpwd);
	
	/* Execute request */
	ret = DUO_CONN_ERROR;
	if ((ccode = curl_easy_perform(ctx->curl)) == CURLE_OK) {
		if (curl_easy_getinfo(ctx->curl, CURLINFO_RESPONSE_CODE, &rcode) == 0) {
			if (rcode / 100 == 2) {
				ret = DUO_OK;
			} else {
				ret = (rcode < 500) ? DUO_CLIENT_ERROR : DUO_SERVER_ERROR;
				if (_duo_bson_response(ctx, NULL) != DUO_FAIL)
					_duo_seterr(ctx, "HTTP %ld", rcode);
			}
		}
	} else if (ccode == CURLE_SSL_CONNECT_ERROR) {
		ret = DUO_CLIENT_ERROR;
	} else if (ccode == CURLE_SSL_CACERT
#if LIBCURL_VERSION_NUM < 0x071101
	    || ccode == CURLE_SSL_PEER_CERTIFICATE
#else
	    || ccode == CURLE_PEER_FAILED_VERIFICATION
#endif
	    ) {
		ret = DUO_SERVER_ERROR;
	}
call_cleanup:
	/* Cleanup */
	free(uri); free(url); free(sign); free(qs); free(userpwd);
	
	return (ret);
}

const char *
duo_geterr(struct duo_ctx *ctx)
{
	return (ctx->err[0] ? ctx->err : NULL);
}

duo_code_t
duo_login(struct duo_ctx *ctx, const char *username,
    const char *client_ip, int flags)
{
	bson obj;
	bson_iterator it;
	duo_code_t ret;
	char buf[256];
	const char *p;
	int i;

	if (username == NULL) {
		_duo_seterr(ctx, "need username to authenticate");
		return (DUO_CLIENT_ERROR);
	}
	/* Check preauth result */
	if (duo_add_param(ctx, "user", username) != DUO_OK) {
		return (DUO_LIB_ERROR);
	}
	if ((ret = duo_call(ctx, "POST", DUO_API_VERSION "/preauth.bson")) != DUO_OK ||
	    (ret = _duo_bson_response(ctx, &obj)) != DUO_OK) {
		return (ret);
	}
	_BSON_FIND(ctx, &it, &obj, "result", bson_string);
	p = bson_iterator_string(&it);

	if (strcasecmp(p, "auth") != 0) {
		_BSON_FIND(ctx, &it, &obj, "status", bson_string);
		if (strcasecmp(p, "allow") == 0) {
                        _duo_seterr(ctx, "%s", bson_iterator_string(&it));
			ret = DUO_OK;
		} else if (strcasecmp(p, "deny") == 0) {
			_duo_seterr(ctx, "%s", bson_iterator_string(&it));
			ret = DUO_ABORT;
		} else if (strcasecmp(p, "enroll") == 0) {
			if (ctx->conv_status != NULL)
				ctx->conv_status(ctx->conv_arg,
				    bson_iterator_string(&it));
			_duo_seterr(ctx, "User enrollment required");
			ret = DUO_ABORT;
		} else {
			_duo_seterr(ctx, "BSON invalid 'result': %s", p);
			ret = DUO_SERVER_ERROR;
		}
		return (ret);
	}
	/* Handle factor selection */
	if ((flags & DUO_FLAG_AUTO) != 0) {
		/* Find default OOB factor for automatic login */
		_BSON_FIND(ctx, &it, &obj, "factors", bson_object);
		bson_iterator_subobject(&it, &obj);
		
		if (bson_find(&it, &obj, "default") != bson_string) {
			_duo_seterr(ctx, "No default factor found for automatic login");
			return (DUO_ABORT);
		}
		p = bson_iterator_string(&it);
	} else {
		/* Prompt user for factor choice / token */
		if (ctx->conv_prompt == NULL) {
			_duo_seterr(ctx, "No prompt function set");
			return (DUO_CLIENT_ERROR);
		}
		_BSON_FIND(ctx, &it, &obj, "prompt", bson_string);
		p = bson_iterator_string(&it);
		
		if (ctx->conv_prompt(ctx->conv_arg, p, buf,
			sizeof(buf)) == NULL) {
			_duo_seterr(ctx, "Invalid user response");
			return (DUO_FAIL);
		}
		strtok(buf, "\r\n");

		_BSON_FIND(ctx, &it, &obj, "factors", bson_object);
		bson_iterator_subobject(&it, &obj);
		
		if (bson_find(&it, &obj, buf) == bson_string) {
			p = bson_iterator_string(&it);
		} else {
			p = buf;
		}
	}
	/* Try Duo authentication */
	if (duo_add_param(ctx, "user", username) != DUO_OK ||
	    duo_add_param(ctx, "factor", "auto") != DUO_OK ||
	    duo_add_param(ctx, "auto", p) != DUO_OK ||
	    duo_add_param(ctx, "async",
		(flags & DUO_FLAG_SYNC) ? "0" : "1") != DUO_OK ||
	    duo_add_param(ctx, "ipaddr",
		client_ip ? client_ip : "0.0.0.0") != DUO_OK) {
		return (DUO_LIB_ERROR);
	}
	if ((ret = duo_call(ctx, "POST", DUO_API_VERSION "/auth.bson")) != DUO_OK ||
	    (ret = _duo_bson_response(ctx, &obj)) != DUO_OK) {
		return (ret);
	}
	/* Handle sync status */
	if ((flags & DUO_FLAG_SYNC) != 0) {
		_BSON_FIND(ctx, &it, &obj, "status", bson_string);
		if (ctx->conv_status != NULL) {
			ctx->conv_status(ctx->conv_arg,
			    bson_iterator_string(&it));
		}
		_BSON_FIND(ctx, &it, &obj, "result", bson_string);
		p = bson_iterator_string(&it);
		
		if (strcasecmp(p, "allow") == 0) {
			ret = DUO_OK;
		} else if (strcasecmp(p, "deny") == 0) {
			ret = DUO_FAIL;
		} else {
			_duo_seterr(ctx, "BSON invalid 'result': %s", p);
			ret = DUO_SERVER_ERROR;
		}
		return (ret);
	}
	/* Async status - long-poll on txid */
	_BSON_FIND(ctx, &it, &obj, "txid", bson_string);
	
	if (strlcpy(buf, bson_iterator_string(&it), sizeof(buf)) >=
	    sizeof(buf) || duo_reset(ctx) != DUO_OK) {
		return (DUO_LIB_ERROR);
	}
	/* XXX newline between prompt and async status lines */
	if (ctx->conv_status != NULL)
		ctx->conv_status(ctx->conv_arg, "");
	ret = DUO_SERVER_ERROR;
	
	for (i = 0; i < 20; i++) {
		if ((ret = duo_add_param(ctx, "txid", buf)) != DUO_OK ||
		    (ret = duo_call(ctx, "GET",
			DUO_API_VERSION "/status.bson")) != DUO_OK ||
		    (ret = _duo_bson_response(ctx, &obj)) != DUO_OK) {
			break;
		}
		if (bson_find(&it, &obj, "status") == bson_string) {
			if (ctx->conv_status != NULL)
				ctx->conv_status(ctx->conv_arg,
				    bson_iterator_string(&it));
		}
		if (bson_find(&it, &obj, "result") == bson_string) {
			p = bson_iterator_string(&it);
			
			if (strcasecmp(p, "allow") == 0) {
				ret = DUO_OK;
			} else if (strcasecmp(p, "deny") == 0) {
				ret = DUO_FAIL;
			} else {
				_duo_seterr(ctx, "BSON invalid 'result': %s",
				    p);
				ret = DUO_SERVER_ERROR;
			}
			break;
		}
	}
	return (ret);
}
