/*
 * SPDX-License-Identifier: GPL-2.0-with-classpath-exception
 *
 * util.c
 *
 * Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved.
 */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>

#include "util.h"
#include "groupaccess.h"

int duo_debug = 0;

void
duo_config_default(struct duo_config *cfg)
{
    memset(cfg, 0, sizeof(struct duo_config));
    cfg->failmode = DUO_FAIL_SAFE;
    cfg->prompts = MAX_PROMPTS;
    cfg->local_ip_fallback = 0;
    cfg->https_timeout = -1;
    cfg->gecos_username_pos = -1;
    cfg->gecos_delim = ',';
}

int
duo_set_boolean_option(const char *val)
{
    if (strcmp(val, "yes") == 0 || strcmp(val, "true") == 0 ||
        strcmp(val, "on") == 0 || strcmp(val, "1") == 0) {
        return (1);
    } else {
        return (0);
    }
}

int
duo_common_ini_handler(struct duo_config *cfg, const char *section,
    const char *name, const char*val)
{
    if (strcmp(name, "ikey") == 0) {
        char *new_val = strdup(val);
        if (new_val == NULL) {
            return (0);
        }
        if (cfg->ikey != NULL) {
            duo_zero_free(cfg->ikey, strlen(cfg->ikey));
        }
        cfg->ikey = new_val;
    } else if (strcmp(name, "skey") == 0) {
        char *new_val = strdup(val);
        if (new_val == NULL) {
            return (0);
        }
        if (cfg->skey != NULL) {
            duo_zero_free(cfg->skey, strlen(cfg->skey));
        }
        cfg->skey = new_val;
    } else if (strcmp(name, "host") == 0) {
        char *new_val = strdup(val);
        if (new_val == NULL) {
            return (0);
        }
        if (cfg->apihost != NULL) {
            duo_zero_free(cfg->apihost, strlen(cfg->apihost));
        }
        cfg->apihost = new_val;
    } else if (strcmp(name, "cafile") == 0) {
        char *new_val = strdup(val);
        if (new_val == NULL) {
            return (0);
        }
        if (cfg->cafile != NULL) {
            duo_zero_free(cfg->cafile, strlen(cfg->cafile));
        }
        cfg->cafile = new_val;
    } else if (strcmp(name, "http_proxy") == 0) {
        char *new_val = strdup(val);
        if (new_val == NULL) {
            return (0);
        }
        if (cfg->http_proxy != NULL) {
            duo_zero_free(cfg->http_proxy, strlen(cfg->http_proxy));
        }
        cfg->http_proxy = new_val;
    } else if (strcmp(name, "groups") == 0 || strcmp(name, "group") == 0) {
        size_t len = strlen(val);
        size_t i = 0, j = 0;
        int inEscape = 0;
        char *currWord;
        if ((currWord = malloc(len + 1)) == NULL) {
            fprintf(stderr, "Out of memory parsing groups\n");
            return (0);
        }

        for (i = 0; i <= len; ++i) {
            if (val[i] == '\\' && val[i + 1] == ' ' && !inEscape) {
                inEscape = 1;
                continue;
            }

            if (inEscape) {
                currWord[j++] = ' ';
                inEscape = 0;
            } else if (val[i] == ' ' || val[i] == '\0') {
                if (j > 0) {
                    currWord[j] = '\0';
                    cfg->groups[cfg->groups_cnt++] = strdup(currWord);
                    if (cfg->groups_cnt >= MAX_GROUPS) {
                        fprintf(stderr, "Exceeded max %d groups\n", MAX_GROUPS);
                        cleanup_config_groups(cfg);
                        free(currWord);
                        return (0);
                    }
                    j = 0;
                }
                if (val[i] == '\0') {
                    break;
                }
            } else {
                currWord[j++] = val[i];
            }
        }
        free(currWord);
    } else if (strcmp(name, "failmode") == 0) {
        if (strcmp(val, "secure") == 0) {
            cfg->failmode = DUO_FAIL_SECURE;
        } else if (strcmp(val, "safe") == 0) {
            cfg->failmode = DUO_FAIL_SAFE;
        } else {
            fprintf(stderr, "Invalid failmode: '%s'\n", val);
            return (0);
        }
    } else if (strcmp(name, "pushinfo") == 0) {
        cfg->pushinfo = duo_set_boolean_option(val);
    } else if (strcmp(name, "noverify") == 0) {
        cfg->noverify = duo_set_boolean_option(val);
    } else if (strcmp(name, "prompts") == 0) {
        int int_val = atoi(val);
        /* Clamp the value into acceptable range */
        if (int_val <= 0) {
            int_val = 1;
        } 
        if (int_val < cfg->prompts) {
            cfg->prompts = int_val;
        }
    } else if (strcmp(name, "autopush") == 0) {
        cfg->autopush = duo_set_boolean_option(val);
    } else if (strcmp(name, "accept_env_factor") == 0) {
        cfg->accept_env = duo_set_boolean_option(val);
    } else if (strcmp(name, "fallback_local_ip") == 0) {
        cfg->local_ip_fallback = duo_set_boolean_option(val);
    } else if (strcmp(name, "https_timeout") == 0) {
        cfg->https_timeout = atoi(val);
        if (cfg->https_timeout <= 0) {
            cfg->https_timeout = -1; /* no timeout */
        } else {
            /* Make timeout milliseconds */
            cfg->https_timeout *= 1000;
        }
    } else if (strcmp(name, "send_gecos") == 0) {
        cfg->send_gecos = duo_set_boolean_option(val);
    } else if (strcmp(name, "gecos_parsed") == 0) {
        duo_log(LOG_ERR, "The gecos_parsed configuration item for Duo Unix is deprecated and no longer has any effect. Use gecos_delim and gecos_username_pos instead", NULL, NULL, NULL);
    } else if (strcmp(name, "dev_fips_mode") == 0) {
        /* Accepted as a no-op for backward compatibility. This option was
           removed, but rejecting it would abort parsing of the rest of the
           config file (including any later failmode directive) and could
           silently disable 2FA on upgrade for configs that still set it. */
        duo_log(LOG_ERR, "The dev_fips_mode configuration item for Duo Unix is deprecated and no longer has any effect", NULL, NULL, NULL);
    } else if (strcmp(name, "gecos_delim") == 0) {
        if (strlen(val) != 1) {
            fprintf(stderr, "Invalid character option length. Character fields must be 1 character long: '%s'\n", val);
            return (0);
        }

        char delim = val[0];
        if (!ispunct(delim) || delim == ':') {
            fprintf(stderr, "Invalid gecos_delim '%c' (delimiter must be punctuation other than ':')\n", delim);
            return (0);
        }
        cfg->gecos_delim = delim;
    } else if (strcmp(name, "gecos_username_pos") == 0) {
        int gecos_username_pos = atoi(val);
        if (gecos_username_pos < 1) {
            fprintf(stderr, "Gecos position starts at 1\n");
            return (0);
        }
        else {
            // Offset the position so user facing first position is 1
            cfg->gecos_username_pos = gecos_username_pos - 1;
        }
    } else if (strcmp(name, "verified_push") == 0) {
        cfg->verified_push = duo_set_boolean_option(val);
    } else {
        /* Couldn't handle the option, maybe it's target specific? */
        return (0);
    }
    return (1);
}

void
close_config(struct duo_config *cfg)
{
    if (cfg == NULL) {
        return;
    }
    /* Zero strlen + 1 to include the NUL terminator, matching duo_close(). */
    if (cfg->ikey != NULL) {
        duo_zero_free(cfg->ikey, strlen(cfg->ikey) + 1);
        cfg->ikey = NULL;
    }
    if (cfg->skey != NULL) {
        duo_zero_free(cfg->skey, strlen(cfg->skey) + 1);
        cfg->skey = NULL;
    }
    if (cfg->apihost != NULL) {
        duo_zero_free(cfg->apihost, strlen(cfg->apihost) + 1);
        cfg->apihost = NULL;
    }
    if (cfg->cafile != NULL) {
        duo_zero_free(cfg->cafile, strlen(cfg->cafile) + 1);
        cfg->cafile = NULL;
    }
    if (cfg->http_proxy != NULL) {
        duo_zero_free(cfg->http_proxy, strlen(cfg->http_proxy) + 1);
        cfg->http_proxy = NULL;
    }
    cleanup_config_groups(cfg);
}

void
cleanup_config_groups(struct duo_config *cfg)
{
    int i = 0;
    for (i = 0; i < MAX_GROUPS; ++i) {
        if (cfg->groups[i] != NULL) {
            free(cfg->groups[i]);
            cfg->groups[i] = NULL;
        }
    }
    cfg->groups_cnt = 0;
}


int
duo_check_groups(struct passwd *pw, char **groups, int groups_cnt)
{
    int i;

    if (groups_cnt > 0) {
        int matched = 0;

        if (ga_init(pw->pw_name, pw->pw_gid) <= 0) {
            duo_log(LOG_ERR, "Couldn't get groups",
                pw->pw_name, NULL, strerror(errno));
            return (-1);
        }
        for (i = 0; i < groups_cnt; i++) {
            if (ga_match_pattern_list(groups[i])) {
                matched = 1;
                break;
            }
        }
        ga_free();

        /* User in configured groups for Duo auth? */
        return matched;
    } else {
        return 1;
    }
}

int
duo_groups_all_negated(const struct duo_config *cfg)
{
    int i;

    if (cfg->groups_cnt <= 0) {
        return 0;
    }
    for (i = 0; i < cfg->groups_cnt; i++) {
        const char *p = cfg->groups[i];

        if (p == NULL) {
            return 0;
        }
        /*
         * Each stored token is a comma-separated pattern-list, and only
         * the individual patterns can be negated. A single non-negated
         * subpattern (e.g. the "admin" in "!wheel,admin") can still match
         * a user, so the filter is not all-negated.
         */
        while (*p != '\0') {
            if (*p != '!') {
                return 0;
            }
            while (*p != '\0' && *p != ',') {
                p++;
            }
            if (*p == ',') {
                p++;
            }
        }
    }
    return 1;
}

int
_add_to_log(char *buf, size_t buf_sz, int pos, const char *format,
           const char *s) {
    if (s == NULL) {
        return pos;
    }
    else {
        size_t remaining = buf_sz - pos;
        int i = snprintf(buf + pos, remaining, format, s);
        if (i < 0) {
            return pos;
        }
        else if (i >= remaining) {
            return buf_sz;
        }
        else {
            return pos + i;
        }
    }
}

void
duo_sanitize_str(char *s)
{
    for (; *s != '\0'; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '\t' || c == '\n')
            continue;
        if (c < 0x20 || c == 0x7F)
            *s = '?';
    }
}

void
duo_log(int priority, const char *msg, const char *user, const char *ip,
        const char *err)
{
    char buf[512];
    int pos = snprintf(buf, sizeof(buf), "%s", msg);
    pos = _add_to_log(buf, sizeof(buf), pos, " for '%s'", user);
    pos = _add_to_log(buf, sizeof(buf), pos, " from %s", ip);
    pos = _add_to_log(buf, sizeof(buf), pos, ": %s", err);
    duo_sanitize_str(buf);
    duo_syslog(priority, "%s", buf);
}

void
duo_syslog(int priority, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    if (duo_debug) {
        fprintf(stderr, "[%d] ", priority);
        vfprintf(stderr, fmt, ap);
        fputs("\n", stderr);
    } else {
        vsyslog(priority, fmt, ap);
    }
    va_end(ap);
}

const char *
duo_local_ip()
{
    struct sockaddr_in sin;
    socklen_t slen;
    int fd;
    const char *ip = NULL;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    /* RFC 5737 TEST-NET-1 example IP; no traffic is sent, the kernel
       only performs a routing table lookup to determine the local IP. */
    sin.sin_addr.s_addr = inet_addr("192.0.2.1");
    sin.sin_port = htons(53);
    slen = sizeof(sin);

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) != -1) {
        if (connect(fd, (struct sockaddr *)&sin, slen) != -1 &&
            getsockname(fd, (struct sockaddr *)&sin, &slen) != -1) {
            ip = inet_ntoa(sin.sin_addr); /* XXX statically allocated */
        }
        close(fd);
    }
    return (ip);
}

char *
duo_split_at(char *s, char delimiter, unsigned int position)
{
    unsigned int count = 0;
    char *iter = NULL;
    char *result = s;

    for (iter = s; *iter; iter++) {
        if (*iter == delimiter) {
            if (count < position) {
                result = iter + 1;
                count++;
            }
            *iter = '\0';
        }
    }

    if (count < position) {
        return NULL;
    }

    return result;
}

void
duo_zero_free(void *ptr, size_t size)
{
    /*
     * A compiler's usage of dead store optimization may skip the memory
     * zeroing if it doesn't detect futher usage. Different systems use explicit
     * zeroing functions to prevent this. If none of those are available we fall back
     * on volatile pointers to prevent optimization. There is no guarantee in the standard
     * that this will work, but gcc and other major compilers will respect it.
     * Idea and technique borrowed from https://github.com/openssh/openssh-portable
     */
    if (ptr != NULL) {
#ifdef HAVE_EXPLICIT_BZERO
        explicit_bzero(ptr, size);
#elif HAVE_MEMSET_S
        (void)memset_s(ptr, size, 0, size);
#else
        static void* (* volatile duo_memset)(void *, int, size_t) = memset;
        duo_memset(ptr, 0, size);
#endif
        free(ptr);
    }
}
