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

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>

#include "util.h"
#include "bson.h"
#include "duo.h"
#include "https.h"
#include "ini.h"
#include "urlenc.h"

#define DUO_LIB_VERSION     "libduo/" PACKAGE_VERSION
#define DUO_API_VERSION     "/rest/v1"
#define AUTOPUSH_MSG        "Autopushing login request to phone..."
#define AUTOPHONE_MSG       "Calling your phone..."
#define AUTODEFAULT_MSG     "Using default second-factor authentication."
#define ENV_VAR_MSG         "Reading $DUO_PASSCODE..."


struct duo_ctx {
    https_t *https;    /* HTTPS handle */
    char    *host;     /* host[:port] */
    char    err[512];  /* error message */

    char    *argv[16]; /* request arguments */
    int     argc;

    const char *body;  /* response body */
    int     body_len;

    int     https_timeout; /* milliseconds */

    char *ikey;
    char *skey;
    char *useragent;

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
    const char *progname, const char *cafile, int https_timeout, const char* http_proxy)
{
    struct duo_ctx *ctx;

    if ((ctx = calloc(1, sizeof(*ctx))) == NULL ||
            (ctx->host = strdup(host)) == NULL ||
            (ctx->ikey = strdup(ikey)) == NULL ||
            (ctx->skey = strdup(skey)) == NULL) {
        return (duo_close(ctx));
    }
    if (asprintf(&ctx->useragent, "%s (%s) libduo/%s",
            progname, CANONICAL_HOST, PACKAGE_VERSION) == -1) {
        return (duo_close(ctx));
    }
    if (https_init(cafile, http_proxy) != HTTPS_OK) {
        ctx = duo_close(ctx);
    } else {
        ctx->conv_prompt = __prompt_fn;
        ctx->conv_status = __status_fn;
        ctx->https_timeout = https_timeout;
    }

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
    if (fstat(fd, &st) < 0 || (fp = fdopen(fd, "r")) == NULL) {
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
        if (ctx->https != NULL) {
            https_close(&ctx->https);
        }
        duo_reset(ctx);
        free(ctx->host);

        if (ctx->ikey != NULL) {
            duo_zero_free(ctx->ikey, strlen(ctx->ikey));
            ctx->ikey = NULL;
        }
        if (ctx->skey != NULL) {
            duo_zero_free(ctx->skey, strlen(ctx->skey));
            ctx->skey = NULL;
        }
        if (ctx->useragent != NULL) {
            duo_zero_free(ctx->useragent, strlen(ctx->useragent));
            ctx->useragent = NULL;
        }

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

void
duo_reset_conv_funcs(struct duo_ctx *ctx)
{
    ctx->conv_prompt = __prompt_fn;
    ctx->conv_status = __status_fn;
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

#define _BSON_FIND(ctx, it, obj, name, type) do {           \
    if (bson_find(it, obj, name) != type) {             \
        _duo_seterr(ctx, "BSON missing valid '%s'", name);  \
        return (DUO_SERVER_ERROR);              \
    }                               \
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
        if (resp) {
            bson_iterator_subobject(&it, resp);
        }
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
duo_call(struct duo_ctx *ctx, const char *method, const char *uri, int msecs)
{
    int i, code, err, ret;

    code = 0;
    ctx->body = NULL;
    ctx->body_len = 0;

    for (i = 0; i < 3; i++) {
        if (ctx->https == NULL &&
            (err = https_open(&ctx->https, ctx->host, ctx->useragent)) != HTTPS_OK) {
            if (err == HTTPS_ERR_SERVER) {
                sleep(1 << i);
                continue;
            }
            break;
        }
        if ((err = https_send(ctx->https, method, uri,
                    ctx->argc, ctx->argv, ctx->ikey, ctx->skey, ctx->useragent)) == HTTPS_OK &&
            (err = https_recv(ctx->https, &code,
                &ctx->body, &ctx->body_len, msecs)) == HTTPS_OK) {
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
        /* 2xx indicates DUO_OK */
        ret = DUO_OK;
    } else if (code == 401) {
        /* 401 indicates an invalid ikey or skey */
        ret = DUO_CLIENT_ERROR;
        _duo_seterr(ctx, "Invalid ikey or skey");
    } else if (code / 100 == 5) {
        /* 5xx indicates an internal server error */
        ret = DUO_SERVER_ERROR;
        _duo_seterr(ctx, "HTTP %d", code);
    } else {
        /* abort on any other HTTP codes */
        ret = DUO_ABORT;
        _duo_seterr(ctx, "HTTP %d", code);
    }
    return (ret);
}

const char *
duo_geterr(struct duo_ctx *ctx)
{
    return (ctx->err[0] ? ctx->err : NULL);
}

duo_code_t
_duo_preauth(struct duo_ctx *ctx, bson *obj, const char *username,
    const char *client_ip)
{
    bson_iterator it;
    duo_code_t ret;
    const char *p;

    /* Check preauth result */
    if (duo_add_param(ctx, "user", username) != DUO_OK) {
        return (DUO_LIB_ERROR);
    }

    if (client_ip) {
        if (duo_add_param(ctx, "ipaddr", client_ip) != DUO_OK) {
            return (DUO_LIB_ERROR);
        }
    }

    if ((ret = duo_call(ctx, "POST", DUO_API_VERSION "/preauth.bson", ctx->https_timeout)) != DUO_OK ||
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
            if (ctx->conv_status != NULL) {
                ctx->conv_status(ctx->conv_arg,
                    bson_iterator_string(&it));
            }
            _duo_seterr(ctx, "User enrollment required");
            ret = DUO_ABORT;
        } else {
            _duo_seterr(ctx, "BSON invalid 'result': %s", p);
            ret = DUO_SERVER_ERROR;
        }
        return (ret);
    }
    return (DUO_CONTINUE);
}

duo_code_t
_duo_prompt(struct duo_ctx *ctx, bson *obj, int flags, char *buf,
    size_t sz, const char **p)
{
    bson_iterator it;
    char *pos, *passcode;

    passcode = getenv(DUO_ENV_VAR_NAME);

    if ((flags & DUO_FLAG_ENV) && (passcode != NULL)) {
        *p = passcode;
        if (ctx->conv_status != NULL) {
            ctx->conv_status(ctx->conv_arg, ENV_VAR_MSG);
        }
    } else if ((flags & DUO_FLAG_AUTO) != 0) {
        /* Find default OOB factor for automatic login */
        _BSON_FIND(ctx, &it, obj, "factors", bson_object);
        bson_iterator_subobject(&it, obj);

        if (bson_find(&it, obj, "default") != bson_string) {
            _duo_seterr(ctx, "No default factor found for automatic login");
            return (DUO_ABORT);
        }
        *p = bson_iterator_string(&it);
        if (ctx->conv_status) {
            if ((pos = strstr(*p, "push"))) {
                ctx->conv_status(ctx->conv_arg, AUTOPUSH_MSG);
            } else if ((pos = strstr(*p, "phone"))) {
                ctx->conv_status(ctx->conv_arg, AUTOPHONE_MSG);
            } else {
                ctx->conv_status(ctx->conv_arg, AUTODEFAULT_MSG);
            }
        }
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
    return (DUO_CONTINUE);
}

duo_code_t
duo_login(struct duo_ctx *ctx, const char *username,
    const char *client_ip, int flags, const char *command)
{
    bson obj;
    bson_iterator it;
    duo_code_t ret;
    char buf[256];
    char *pushinfo = NULL;
    const char *p;
    int i;
    const char *local_ip;

    if (username == NULL) {
        _duo_seterr(ctx, "need username to authenticate");
        return (DUO_CLIENT_ERROR);
    }

    /* Check preauth status */
    if ((ret = _duo_preauth(ctx, &obj, username, client_ip)) != DUO_CONTINUE) {
        return (ret);
    }

    /* Handle factor selection */
    if ((ret = _duo_prompt(ctx, &obj, flags, buf, sizeof(buf), &p)) != DUO_CONTINUE) {
        return (ret);
    }

    /* Add request parameters */
    if (duo_add_param(ctx, "user", username) != DUO_OK ||
        duo_add_param(ctx, "factor", "auto") != DUO_OK ||
        duo_add_param(ctx, "auto", p) != DUO_OK ||
        duo_add_param(ctx, "async",
        (flags & DUO_FLAG_SYNC) ? "0" : "1") != DUO_OK) {
        return (DUO_LIB_ERROR);
    }

    /* Add client IP, if passed in */
    if (client_ip) {
        if (duo_add_param(ctx, "ipaddr", client_ip) != DUO_OK) {
            return (DUO_LIB_ERROR);
        }
    }

    /* Add pushinfo parameters */
    local_ip = duo_local_ip();
    if (asprintf(&pushinfo, "Server+IP=%s&Command=%s",
        local_ip, command ? urlenc_encode(command) : "") < 0 ||
        duo_add_param(ctx, "pushinfo", pushinfo) != DUO_OK) {
        return (DUO_LIB_ERROR);
    }
    free(pushinfo);

    /* Try Duo authentication.  Only use the configured timeout if
     * the call is asynchronous, because async calls should return
     * immediately.
     */
    if ((ret = duo_call(ctx, "POST", DUO_API_VERSION "/auth.bson",
                   flags & DUO_FLAG_SYNC ? DUO_NO_TIMEOUT : ctx->https_timeout)) != DUO_OK ||
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
    if (ctx->conv_status != NULL) {
        ctx->conv_status(ctx->conv_arg, "");
    }
    ret = DUO_SERVER_ERROR;

    for (i = 0; i < 20; i++) {
        if ((ret = duo_add_param(ctx, "txid", buf)) != DUO_OK ||
            (ret = duo_call(ctx, "GET",
            DUO_API_VERSION "/status.bson", DUO_NO_TIMEOUT)) != DUO_OK ||
            (ret = _duo_bson_response(ctx, &obj)) != DUO_OK) {
            break;
        }
        if (bson_find(&it, &obj, "status") == bson_string) {
            if (ctx->conv_status != NULL) {
                ctx->conv_status(ctx->conv_arg,
                    bson_iterator_string(&it));
            }
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
