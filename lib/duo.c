/*
 * SPDX-License-Identifier: GPL-2.0-with-classpath-exception
 *
 * duo.c
 *
 * Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>

#include "util.h"
#include "duo.h"
#include "parson.h"
#include "duo_private.h"
#include "ini.h"
#include "urlenc.h"

#define DUO_LIB_VERSION     "libduo/" PACKAGE_VERSION
#define DUO_API_VERSION     "/auth/v2"
#define AUTOPUSH_MSG        "Autopushing login request to phone..."
#define AUTOPHONE_MSG       "Calling your phone..."
#define AUTODEFAULT_MSG     "Using default second-factor authentication."
#define ENV_VAR_MSG         "Reading $DUO_PASSCODE..."

/*
 * Finding the maximum length for the machine's hostname
 * Idea and technique originated from https://github.com/openssh/openssh-portable
 */
#ifndef HOST_NAME_MAX
# include "netdb.h" /* for MAXHOSTNAMELEN */
# if defined(_POSIX_HOST_NAME_MAX)
#  define HOST_NAME_MAX _POSIX_HOST_NAME_MAX
# elif defined(MAXHOSTNAMELEN)
#  define HOST_NAME_MAX MAXHOSTNAMELEN
# else
#  define HOST_NAME_MAX 255
# endif
#endif /* HOST_NAME_MAX */

/* For sizing buffers; sufficient to cover the longest possible DNS FQDN */
#define DNS_MAXNAMELEN 256

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

        // We need to add 1 here for the terminating \0 byte which strlen doesn't include
        if (ctx->ikey != NULL) {
            duo_zero_free(ctx->ikey, strlen(ctx->ikey) + 1);
            ctx->ikey = NULL;
        }
        if (ctx->skey != NULL) {
            duo_zero_free(ctx->skey, strlen(ctx->skey) + 1);
            ctx->skey = NULL;
        }
        if (ctx->useragent != NULL) {
            duo_zero_free(ctx->useragent, strlen(ctx->useragent) + 1);
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

duo_code_t
duo_add_param(struct duo_ctx *ctx, const char *name, const char *value)
{
    duo_code_t ret;
    char *k, *v, *p;

    if (name == NULL || value == NULL || strlen(name) == 0 || strlen(value) == 0) {
        return (DUO_CLIENT_ERROR);
    }
    ret = DUO_LIB_ERROR;

    k = urlenc_encode(name);
    v = urlenc_encode(value);

    if (k && v && ctx->argc + 1 < (sizeof(ctx->argv) / sizeof(ctx->argv[0]))
            && (asprintf(&p, "%s=%s", k, v) > 2)) {
        ctx->argv[ctx->argc++] = p;
        ret = DUO_OK;
    }

    free(k);
    free(v);

    return (ret);
}

duo_code_t
duo_add_optional_param(struct duo_ctx *ctx, const char *name, const char *value)
{
    /* Wrapper around duo_add_param for optional arguments.
       If a parameter's value doesn't exist we don't add the param.
    */
    if (value == NULL || strlen(value) == 0) {
        return DUO_OK;
    }
    else {
        return duo_add_param(ctx, name, value);
    }
}

static void
_duo_seterr(struct duo_ctx *ctx, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(ctx->err, sizeof(ctx->err), fmt, ap);
    va_end(ap);
}


static void
_duo_get_hostname(char *dns_fqdn, size_t dns_fqdn_size)
{
    struct addrinfo hints, *info;
    char hostname[HOST_NAME_MAX + 1];

    /* gethostname may not insert a null terminator when it needs to truncate the hostname.
     * See gethostname's man page under "Description" for more info.
     */
    hostname[HOST_NAME_MAX] = '\0';
    gethostname(hostname, HOST_NAME_MAX);
    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;
    strlcpy(dns_fqdn, hostname, dns_fqdn_size);

    if (getaddrinfo(hostname, NULL, &hints, &info) == 0) {
        if(info->ai_canonname != NULL && strlen(info->ai_canonname) > 0) {
            strlcpy(dns_fqdn, info->ai_canonname, dns_fqdn_size);
        }
        freeaddrinfo(info);
    }
}

int
_duo_add_hostname_param(struct duo_ctx *ctx)
{
    char dns_fqdn[DNS_MAXNAMELEN];
    _duo_get_hostname(dns_fqdn, sizeof(dns_fqdn));

    return duo_add_optional_param(ctx, "hostname", dns_fqdn);
}

int _duo_add_failmode_param(struct duo_ctx *ctx, const int failmode)
{
    const char *failmode_str = (failmode == DUO_FAIL_SECURE) ? ("closed") : ("open");

    return duo_add_optional_param(ctx, "failmode", failmode_str);
}

#define _JSON_FIND_OBJECT(out_obj, in_obj, name, json_value) do { \
  out_obj = json_object_get_object(in_obj, name); \
  if (out_obj == NULL) { \
        _duo_seterr(ctx, "JSON missing valid '%s'", name);  \
        _JSON_VALUE_FREE(json_value); \
        return (DUO_SERVER_ERROR); \
  } \
} while(0)

#define _JSON_FIND_STRING(buf, json_obj, name, json_value) do { \
  buf = json_object_get_string(json_obj, name); \
  if (buf == NULL) { \
        _duo_seterr(ctx, "JSON missing valid '%s'", name);  \
        _JSON_VALUE_FREE(json_value); \
        return (DUO_SERVER_ERROR); \
  } \
} while(0)

# define _JSON_VALUE_FREE(value) do { \
  json_value_free(value); \
  value = NULL; \
} while(0)

static duo_code_t
_duo_json_response(struct duo_ctx *ctx) {
    JSON_Value *json;
    JSON_Object *json_obj;
    const char *p;
    int code = DUO_SERVER_ERROR;

    json = json_parse_string(ctx->body);
    if(json == NULL) {
        _duo_seterr(ctx, "invalid JSON response");
        return (DUO_SERVER_ERROR);
    }
    json_obj = json_value_get_object(json);

    _JSON_FIND_STRING(p, json_obj, "stat", json);
    if (strcasecmp(p, "OK") == 0) {
        code = DUO_OK;
    }
    if (strcasecmp(p, "FAIL") == 0) {
        const char *message;
        code = json_object_get_number(json_obj, "code");
        // json_object_get_number will return 0 if "code" not found
        if (code == 0) {
               _duo_seterr(ctx, "JSON missing valid 'code'");
               _JSON_VALUE_FREE(json);
               return (DUO_SERVER_ERROR);
        }
        _JSON_FIND_STRING(message, json_obj, "message", json);
        _duo_seterr(ctx, "%d: %s", code, message);
        code = DUO_FAIL;
    }
    _JSON_VALUE_FREE(json);
    return code;
}

int
_duo_https_exchange(struct duo_ctx *ctx, const char *method, const char *uri, int msecs, int *code)
{
    const int max_int_digits = (241 * sizeof(int) / 100 + 1);
    const int max_backoff_wait_secs = 32;
    const int initial_backof_wait_secs = 1;
    const int backoff_factor = 2;

    static const char fmt[] = "Rate-limiting response received from server. Waiting for %ld seconds before retrying.";
    char msg[(sizeof fmt) + max_int_digits];
    int wait_secs = initial_backof_wait_secs;

    while (1) {
        HTTPScode rc;
        time_t retry_after;

        rc = https_send(ctx->https, method, uri,
            ctx->argc, ctx->argv, ctx->ikey, ctx->skey, ctx->useragent,
            ctx->time_offset);
        if (rc != HTTPS_OK)
            return rc;
        rc = https_recv(ctx->https, code, &ctx->body, &ctx->body_len, &retry_after, msecs);
        if (retry_after != (time_t)-1)
            wait_secs = retry_after - time(NULL);

        if (rc != HTTPS_OK || *code != 429 || wait_secs > max_backoff_wait_secs)
            return rc;

        struct timespec timeout = {
            .tv_sec = wait_secs,
            .tv_nsec = (float)rand() / RAND_MAX * 1000000000
        };

        snprintf(msg, sizeof msg, fmt, (long)timeout.tv_sec);
        if (ctx->conv_status)
            ctx->conv_status(NULL, msg);
        nanosleep(&timeout, NULL);
        if (retry_after == (time_t)-1)
            wait_secs *= backoff_factor;
    }
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
        if (_duo_https_exchange(ctx, method, uri, msecs, &code) == HTTPS_OK)
            break;
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
_duo_preauth(struct duo_ctx *ctx, const char *username,
    const char *client_ip, int flags, int failmode)
{
    duo_code_t ret;
    JSON_Value *json;
    JSON_Object *json_obj;

    if (duo_add_param(ctx, "text_prompt", "1") != DUO_OK) return DUO_LIB_ERROR;
    if (duo_add_param(ctx, "username", username) != DUO_OK) return DUO_LIB_ERROR;
    if (duo_add_optional_param(ctx, "ipaddr", client_ip) != DUO_OK) return DUO_LIB_ERROR;
    if (_duo_add_hostname_param(ctx) != DUO_OK) return DUO_LIB_ERROR;
    if (_duo_add_failmode_param(ctx, failmode) != DUO_OK) return DUO_LIB_ERROR;
    if (duo_add_optional_param(ctx, "client_supports_verified_push",
        (flags & DUO_FLAG_VERIFIED_PUSH) ? "1" : NULL) != DUO_OK) return DUO_LIB_ERROR;

    ret = duo_call(ctx, "POST", DUO_API_VERSION "/preauth", ctx->https_timeout);
    if (ret != DUO_OK) return ret;
    ret = _duo_json_response(ctx);
    if (ret != DUO_OK) return ret;

    json = json_parse_string(ctx->body);
    json_obj = json_value_get_object(json);
    JSON_Object *response;
    _JSON_FIND_OBJECT(response, json_obj, "response", json);
    const char *result;
    _JSON_FIND_STRING(result, response, "result", json);

    if (strcasecmp(result, "auth") == 0) {
        ret = DUO_CONTINUE;
        if (flags & DUO_FLAG_VERIFIED_PUSH) {
            const char *txid = json_object_get_string(response, "txid");
            if (duo_add_optional_param(ctx, "txid", txid) != DUO_OK) {
                ret = DUO_LIB_ERROR;
            }
        }
        _JSON_VALUE_FREE(json);
        return ret;
    }

    const char *output;
    _JSON_FIND_STRING(output, response, "status_msg", json);

    if (strcasecmp(result, "allow") == 0) {
        _duo_seterr(ctx, "%s", output);
        ret = DUO_OK;
    } else if (strcasecmp(result, "deny") == 0) {
        _duo_seterr(ctx, "%s", output);
        if (ctx->conv_status != NULL) {
            ctx->conv_status(ctx->conv_arg, output);
        }
        ret = DUO_ABORT;
    } else if (strcasecmp(result, "enroll") == 0) {
        if (ctx->conv_status != NULL) {
            ctx->conv_status(ctx->conv_arg, output);
        }
        _duo_seterr(ctx, "User enrollment required");
        ret = DUO_ABORT;
    } else {
        _duo_seterr(ctx, "JSON invalid 'result': %s", result);
        ret = DUO_SERVER_ERROR;
    }

    _JSON_VALUE_FREE(json);
    return (ret);
}

duo_code_t
_duo_prompt(struct duo_ctx *ctx, int flags, char *buf,
    size_t sz,  char *p, size_t sp)
{
    char *pos, *passcode;

    passcode = getenv(DUO_ENV_VAR_NAME);

    if ((flags & DUO_FLAG_ENV) && (passcode != NULL)) {
        if (strlcpy(p, passcode, sp) >= sp) {
            return (DUO_LIB_ERROR);
        }
        if (ctx->conv_status != NULL) {
            ctx->conv_status(ctx->conv_arg, ENV_VAR_MSG);
        }
        return (DUO_CONTINUE);
    } else if ((flags & DUO_FLAG_AUTO) != 0) {
        /* Find default OOB factor for automatic login */
        JSON_Value *json = json_parse_string(ctx->body);
        JSON_Object *json_obj = json_value_get_object(json);
        JSON_Object *response_obj;
        _JSON_FIND_OBJECT(response_obj, json_obj, "response", json);
        JSON_Object *prompt_obj;
        _JSON_FIND_OBJECT(prompt_obj, response_obj, "prompt", json);
        JSON_Object *factors_obj;
        _JSON_FIND_OBJECT(factors_obj, prompt_obj, "factors", json);

        const char* default_factor;
        _JSON_FIND_STRING(default_factor, factors_obj, "default", json);
        if (ctx->conv_status) {
            if ((pos = strstr(default_factor, "push"))) {
                ctx->conv_status(ctx->conv_arg, AUTOPUSH_MSG);
            } else if ((pos = strstr(default_factor, "phone"))) {
                ctx->conv_status(ctx->conv_arg, AUTOPHONE_MSG);
            } else {
                ctx->conv_status(ctx->conv_arg, AUTODEFAULT_MSG);
            }
        }
        if (strlcpy(p, default_factor, sp) >= sp) {
            _JSON_VALUE_FREE(json);
            return (DUO_LIB_ERROR);
        } else {
            _JSON_VALUE_FREE(json);
            return (DUO_CONTINUE);
        }
    } else {
        /* Prompt user for factor choice / token */
        if (ctx->conv_prompt == NULL) {
            _duo_seterr(ctx, "No prompt function set");
            return (DUO_CLIENT_ERROR);
        }
        JSON_Value *json = json_parse_string(ctx->body);
        JSON_Object *json_obj = json_value_get_object(json);
        JSON_Object *response_obj;
        _JSON_FIND_OBJECT(response_obj, json_obj, "response", json);
        JSON_Object *prompt_obj;
        _JSON_FIND_OBJECT(prompt_obj, response_obj, "prompt", json);

        const char* prompt;
        _JSON_FIND_STRING(prompt, prompt_obj, "text", json);

        if (ctx->conv_prompt(ctx->conv_arg, prompt, buf, sz) == NULL) {
            _duo_seterr(ctx, "Error gathering user response");
            _JSON_VALUE_FREE(json);
            return (DUO_ABORT);
        }
        strtok(buf, "\r\n");

        JSON_Object *factors_obj;
        _JSON_FIND_OBJECT(factors_obj, prompt_obj, "factors", json);

        // buf might not exist in factors JSON_Object, like if the user input
        // a passcode
        const char *factor_str = json_object_get_string(factors_obj, buf);
        if (factor_str == NULL) {
            factor_str = buf;
        }
        if (strlcpy(p, factor_str, sp) >= sp) {
            _JSON_VALUE_FREE(json);
            return (DUO_LIB_ERROR);
        }
        _JSON_VALUE_FREE(json);
        return (DUO_CONTINUE);
    }
}

duo_code_t
duo_login(struct duo_ctx *ctx, const char *username,
    const char *client_ip, int flags, const char *command, const int failmode)
{
    duo_code_t ret;
    int size;
    char buf[256];
    char *pushinfo = NULL;
    char p[256];
    int i;
    const char *local_ip;

    if (username == NULL) {
        _duo_seterr(ctx, "need username to authenticate");
        return (DUO_CLIENT_ERROR);
    }

    ret = duo_sync_time_offset(ctx);

    if (ret == DUO_OK) {
        ret = _duo_preauth(ctx, username, client_ip, flags, failmode);
    }
    /* Check preauth status */
    if (ret != DUO_CONTINUE) {
        if(ret == DUO_SERVER_ERROR || ret == DUO_CONN_ERROR || ret == DUO_CLIENT_ERROR) {
            return (failmode == DUO_FAIL_SAFE) ? (DUO_FAIL_SAFE_ALLOW) : (DUO_FAIL_SECURE_DENY);
        }
        return (ret);
    }

    /* Handle factor selection */
    if ((ret = _duo_prompt(ctx, flags, buf, sizeof(buf), p, sizeof(p))) != DUO_CONTINUE) {
        return (ret);
    }

    /* Add request parameters */
    if (duo_add_param(ctx, "username", username) != DUO_OK ||
        duo_add_param(ctx, "factor", "prompt") != DUO_OK ||
        duo_add_param(ctx, "prompt", p) != DUO_OK ||
        duo_add_param(ctx, "async",
        (flags & DUO_FLAG_SYNC) ? "0" : "1") != DUO_OK) {
        return (DUO_LIB_ERROR);
    }

    /* Add client IP, if passed in */
    if (duo_add_optional_param(ctx, "ipaddr", client_ip) != DUO_OK) {
        return (DUO_LIB_ERROR);
    }

    if(_duo_add_hostname_param(ctx) != DUO_OK) {
        return (DUO_LIB_ERROR);
    }

    /* Add pushinfo parameters */
    char *encoded_command = urlenc_encode(command);
    if (encoded_command == NULL) {
        return (DUO_LIB_ERROR);
    }

    local_ip = duo_local_ip();
    size = asprintf(&pushinfo, "Server+IP=%s&Command=%s", local_ip, encoded_command);
    free(encoded_command);
    if (size < 0) {
        return (DUO_LIB_ERROR);
    }

    ret = duo_add_param(ctx, "pushinfo", pushinfo);
    free(pushinfo);
    if (ret != DUO_OK) {
        return (DUO_LIB_ERROR);
    }

    /* Try Duo authentication.  Only use the configured timeout if
     * the call is asynchronous, because async calls should return
     * immediately.
     */
    if ((ret = duo_call(ctx, "POST", DUO_API_VERSION "/auth",
                   flags & DUO_FLAG_SYNC ? DUO_NO_TIMEOUT : ctx->https_timeout)) != DUO_OK ||
         (ret = _duo_json_response(ctx)) != DUO_OK) {
        return (ret);
    }

    /* Handle sync status */
    if ((flags & DUO_FLAG_SYNC) != 0) {
        JSON_Value *json = json_parse_string(ctx->body);
        JSON_Object *json_obj = json_value_get_object(json);
        JSON_Object *json_response;
        _JSON_FIND_OBJECT(json_response, json_obj, "response", json);
        const char *status_msg;
        _JSON_FIND_STRING(status_msg, json_response, "status_msg", json);
        if (ctx->conv_status != NULL) {
            ctx->conv_status(ctx->conv_arg,
            status_msg);
        }
        const char* result;
        _JSON_FIND_STRING(result, json_response, "result", json);

        if (strcasecmp(result, "allow") == 0) {
            ret = DUO_OK;
        } else if (strcasecmp(result, "deny") == 0) {
            ret = DUO_FAIL;
        } else {
            _duo_seterr(ctx, "JSON invalid 'result': %s", result);
            ret = DUO_SERVER_ERROR;
        }
        _JSON_VALUE_FREE(json);
        return (ret);
    }
    /* Async status - long-poll on txid */
    JSON_Value *json = json_parse_string(ctx->body);
    JSON_Object *json_obj = json_value_get_object(json);
    JSON_Object *json_response;
    _JSON_FIND_OBJECT(json_response, json_obj, "response", json);

    const char* txid;
    _JSON_FIND_STRING(txid, json_response, "txid", json);
    if (strlcpy(buf, txid, sizeof(buf)) >= sizeof(buf)) {
        _JSON_VALUE_FREE(json);
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
            DUO_API_VERSION "/auth_status", DUO_NO_TIMEOUT)) != DUO_OK ||
            (ret = _duo_json_response(ctx)) != DUO_OK) {
            break;
        }

        JSON_Value *json_new = json_parse_string(ctx->body);
        JSON_Object *json_obj_new = json_value_get_object(json_new);
        JSON_Object *json_response_new;
        _JSON_FIND_OBJECT(json_response_new, json_obj_new, "response", json);
        const char *status_json_obj;
        _JSON_FIND_STRING(status_json_obj, json_response_new, "status_msg", json);
        if (status_json_obj != NULL) {
            if (ctx->conv_status != NULL) {
                ctx->conv_status(ctx->conv_arg, status_json_obj);
            }
        }

        //We might not have 'result' defined but we don't want to quit the program
        //if it's not in our object yet
        const char* result;
        _JSON_FIND_STRING(result, json_response_new, "result", json);
        if (strcasecmp(result, "waiting") != 0) {
            if (strcasecmp(result, "allow") == 0) {
                ret = DUO_OK;
            } else if (strcasecmp(result, "deny") == 0) {
                ret = DUO_FAIL;
            } else {
                _duo_seterr(ctx, "JSON invalid 'result': %s",
                    result);
                ret = DUO_SERVER_ERROR;
            }
            _JSON_VALUE_FREE(json_new);
            break;
        }
        _JSON_VALUE_FREE(json_new);
    }
    _JSON_VALUE_FREE(json);
    return (ret);
}

duo_code_t
duo_sync_time_offset(struct duo_ctx *ctx) {
    const char *body = NULL;
    int body_len = 0;
    long duo_time = 0;
    long local_time = 0;
    JSON_Value *json = NULL;
    JSON_Object *json_obj = NULL;
    JSON_Object *response_obj = NULL;
    duo_code_t ret;

    ctx->argc = 0; /* no params */
    ret = duo_call(ctx, "GET", DUO_API_VERSION "/ping", ctx->https_timeout);
    if (ret != DUO_OK) {
        return ret;
    }
    body = ctx->body;
    body_len = ctx->body_len;
    if (!body || body_len == 0) {
        _duo_seterr(ctx, "No response body from server");
        return DUO_SERVER_ERROR;
    }
    json = json_parse_string(body);
    if (!json) {
        _duo_seterr(ctx, "invalid JSON response");
        return DUO_SERVER_ERROR;
    }
    json_obj = json_value_get_object(json);
    if (!json_obj) {
        _duo_seterr(ctx, "No JSON object in response");
        json_value_free(json);
        return DUO_SERVER_ERROR;
    }
    response_obj = json_object_get_object(json_obj, "response");
    if (!response_obj) {
        _duo_seterr(ctx, "JSON missing valid 'response'");
        json_value_free(json);
        return DUO_SERVER_ERROR;
    }
    duo_time = (long)json_object_get_number(response_obj, "time");
    if (duo_time == 0) {
        _duo_seterr(ctx, "JSON missing valid 'time'");
        json_value_free(json);
        return DUO_SERVER_ERROR;
    }
    local_time = (long)time(NULL);
    ctx->time_offset = duo_time - local_time;
    json_value_free(json);
    return DUO_OK;
}
