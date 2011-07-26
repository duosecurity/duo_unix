/*
 * duo.c
 *
 * Copyright (c) 2010 Duo Security
 * All rights reserved, all wrongs reversed.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifndef HAVE_GETADDRINFO
# include "getaddrinfo.h"
#endif

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>

#include "bson.h"
#include "duo.h"
#include "https.h"
#include "ini.h"
#include "urlenc.h"

#define DUO_LIB_VERSION		"libduo/" PACKAGE_VERSION
#define DUO_API_VERSION		"/rest/v1"
#define DUO_CACERT		DUO_CONF_DIR "/duo.crt"

struct duo_ctx {
	https_t    *https;		 /* HTTPS handle */
	char	   *host;		 /* host[:port] */
	char        err[512];		 /* error message */
        
        char       *argv[16];		 /* request arguments */
        int	    argc;

        const char *body;		 /* response body */
        int	    body_len;
        
	char *(*conv_prompt)(void *arg, const char *pr, char *buf, size_t sz);
	void  (*conv_status)(void *arg, const char *msg);
        void   *conv_arg;
};

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
duo_open(const char *host, const char *ikey, const char *skey,
    const char *progname, const char *cafile)
{
	struct duo_ctx *ctx;
        char *useragent;
	
	if ((ctx = calloc(1, sizeof(*ctx))) == NULL ||
            (ctx->host = strdup(host)) == NULL) {
		return (duo_close(ctx));
	}
	if (asprintf(&useragent, "%s (%s) libduo/%s",
                progname, CANONICAL_HOST, PACKAGE_VERSION) == -1) {
		return (duo_close(ctx));
	}
	if (https_init(ikey, skey, useragent, cafile) != HTTPS_OK) {
                ctx = duo_close(ctx);
        }
        free(useragent);

        ctx->conv_prompt = __prompt_fn;
	ctx->conv_status = __status_fn;

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
        int i;

        for (i = 0; i < ctx->argc; i++) {
                free(ctx->argv[i]);
                ctx->argv[i] = NULL;
        }
        ctx->argc = 0;
	*ctx->err = '\0';
        
	return (DUO_OK);
}

struct duo_ctx *
duo_close(struct duo_ctx *ctx)
{
	if (ctx != NULL) {
                if (ctx->https != NULL)
                        https_close(&ctx->https);
                duo_reset(ctx);
                free(ctx->host);
		free(ctx);
	}
        return (NULL);
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

	if (k && v && asprintf(&p, "%s=%s", k, v) > 2 &&
            ctx->argc + 1 < (sizeof(ctx->argv) / sizeof(ctx->argv[0]))) {
                ctx->argv[ctx->argc++] = p;
		ret = DUO_OK;
	}
	free(k);
	free(v);

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
	bson obj;
	bson_iterator it;
	duo_code_t ret;
	const char *p;
	int code;
	
	bson_init(&obj, (char *)ctx->body, 0);
	
	ret = DUO_SERVER_ERROR;
	
	if (ctx->body_len <= 0 || bson_size(&obj) > ctx->body_len) {
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
duo_call(struct duo_ctx *ctx, const char *method, const char *uri)
{
        int i, code, err, ret;

        code = 0;
        ctx->body = NULL;
        ctx->body_len = 0;
        
        for (i = 0; i < 3; i++) {
                if (ctx->https == NULL &&
                    (err = https_open(&ctx->https, ctx->host)) != HTTPS_OK) {
                        if (err == HTTPS_ERR_SERVER) {
                                sleep(1 << i);
                                continue;
                        }
                        break;
                }
                if ((err = https_send(ctx->https, method, uri,
                            ctx->argc, ctx->argv)) == HTTPS_OK &&
                    (err = https_recv(ctx->https, &code,
                        &ctx->body, &ctx->body_len)) == HTTPS_OK) {
                        break;
                }
                https_close(&ctx->https);
        }
        duo_reset(ctx);

        if (code == 0) {
                ret = DUO_CONN_ERROR;
                _duo_seterr(ctx, "Couldn't connect to %s: %s\n",
                    ctx->host, https_geterr());
        } else if (code / 100 == 2) {
                ret = DUO_OK;
        } else {
                ret = (code < 500) ? DUO_CLIENT_ERROR : DUO_SERVER_ERROR;
                if (_duo_bson_response(ctx, NULL) != DUO_FAIL)
                        _duo_seterr(ctx, "HTTP %d", code);
        }
	return (ret);
}

const char *
duo_geterr(struct duo_ctx *ctx)
{
	return (ctx->err[0] ? ctx->err : NULL);
}

static const char *
_local_ip(const char *dst)
{
        const char *ip = "0.0.0.0";
	struct addrinfo hints, *info;
	struct sockaddr sa;
	socklen_t sa_len;
	static char buf[128];
        int fd;
	
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	if (getaddrinfo(dst, "53", &hints, &info) != 0) {
		return (ip);
	}
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == 0) {
		if (connect(fd, info->ai_addr, info->ai_addrlen) != -1 &&
		    getsockname(fd, (struct sockaddr *)&sa, &sa_len) == 0 &&
		    getnameinfo(&sa, sa_len, buf, sizeof(buf), NULL, 0,
			NI_NUMERICHOST) == 0) {
			ip = buf;
		}
		close(fd);
	}
	freeaddrinfo(info);
	
        return (ip);
}

duo_code_t
_duo_preauth(struct duo_ctx *ctx, bson *obj, const char *username)
{
	bson_iterator it;
	duo_code_t ret;
	const char *p;

	/* Check preauth result */
	if (duo_add_param(ctx, "user", username) != DUO_OK) {
		return (DUO_LIB_ERROR);
	}
	if ((ret = duo_call(ctx, "POST", DUO_API_VERSION "/preauth.bson")) != DUO_OK ||
	    (ret = _duo_bson_response(ctx, obj)) != DUO_OK) {
		return (ret);
	}
	_BSON_FIND(ctx, &it, obj, "result", bson_string);
	p = bson_iterator_string(&it);

	if (strcasecmp(p, "auth") != 0) {
		_BSON_FIND(ctx, &it, obj, "status", bson_string);
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
        return (-1);
}

duo_code_t
_duo_prompt(struct duo_ctx *ctx, bson *obj, int flags, char *buf,
    size_t sz, const char **p)
{
	bson_iterator it;
        
	if ((flags & DUO_FLAG_AUTO) != 0) {
		/* Find default OOB factor for automatic login */
		_BSON_FIND(ctx, &it, obj, "factors", bson_object);
		bson_iterator_subobject(&it, obj);
		
		if (bson_find(&it, obj, "default") != bson_string) {
			_duo_seterr(ctx, "No default factor found for automatic login");
			return (DUO_ABORT);
		}
		*p = bson_iterator_string(&it);
	} else {
		/* Prompt user for factor choice / token */
		if (ctx->conv_prompt == NULL) {
			_duo_seterr(ctx, "No prompt function set");
			return (DUO_CLIENT_ERROR);
		}
		_BSON_FIND(ctx, &it, obj, "prompt", bson_string);
		*p = bson_iterator_string(&it);
		
		if (ctx->conv_prompt(ctx->conv_arg, *p, buf, sz) == NULL) {
			_duo_seterr(ctx, "Error gathering user response");
			return (DUO_ABORT);
		}
		strtok(buf, "\r\n");

		_BSON_FIND(ctx, &it, obj, "factors", bson_object);
		bson_iterator_subobject(&it, obj);
		
		if (bson_find(&it, obj, buf) == bson_string) {
			*p = bson_iterator_string(&it);
		} else {
			*p = buf;
		}
	}
        return (-1);
}

duo_code_t
duo_login(struct duo_ctx *ctx, const char *username,
    const char *client_ip, int flags, const char *command)
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
        /* Check preauth status */
        if ((ret = _duo_preauth(ctx, &obj, username)) != -1) {
                return (ret);
        }
	/* Handle factor selection */
        if ((ret = _duo_prompt(ctx, &obj, flags, buf, sizeof(buf), &p)) != -1) {
                return (ret);
        }
	/* Try Duo authentication */
	if (duo_add_param(ctx, "user", username) != DUO_OK ||
	    duo_add_param(ctx, "factor", "auto") != DUO_OK ||
	    duo_add_param(ctx, "auto", p) != DUO_OK ||
	    duo_add_param(ctx, "async",
		(flags & DUO_FLAG_SYNC) ? "0" : "1") != DUO_OK ||
	    duo_add_param(ctx, "ipaddr",
		client_ip ? client_ip : _local_ip(ctx->host)) != DUO_OK) {
		return (DUO_LIB_ERROR);
	}
        if (command != NULL) {
                char *p, *v;
                if ((v = urlenc_encode(command)) == NULL || 
                    asprintf(&p, "Command=%s", v) < 0) {
                        free(v);
                        return (DUO_LIB_ERROR);
                }
                duo_add_param(ctx, "pushinfo", p);
                free(p);
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
	p = bson_iterator_string(&it);
	if (strlcpy(buf, p, sizeof(buf)) >= sizeof(buf)) {
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
