/*
 * util.h
 *
 * Copyright (c) 2013 Duo Security
 * All rights reserved, all wrongs reversed
 */

#ifndef DUO_UTIL_H
#define DUO_UTIL_H

#define MAX_GROUPS 256
#define MAX_PROMPTS 3

#include <pwd.h>
#include <syslog.h>
#include <stdarg.h>

extern int duo_debug;

enum {
    DUO_FAIL_SAFE = 0,
    DUO_FAIL_SECURE
};

struct duo_config {
    char *ikey;
    char *skey;
    char *apihost;
    char *cafile;
    char *http_proxy;
    char *groups[MAX_GROUPS];
    int  groups_cnt;
    int  groups_mode;
    int  failmode;  /* Duo failure handling: DUO_FAIL_* */
    int  pushinfo;
    int  noverify;
    int  autopush;
    int  motd; /* login_duo only */
    int  prompts;
    int  accept_env;
    int  local_ip_fallback;
    int  https_timeout;
    int  send_gecos;
    int  gecos_parsed;
};

void duo_config_default(struct duo_config *cfg);

int duo_set_boolean_option(const char *val);

int duo_common_ini_handler(
    struct duo_config *cfg,
    const char *section,
    const char *name,
    const char *val
);

/* Clean up config memory. */
void close_config(struct duo_config *cfg);

int duo_check_groups(struct passwd *pw, char **groups, int groups_cnt);

void duo_log(
    int priority,
    const char *msg,
    const char *user,
    const char *ip,
    const char *err
);

void duo_syslog(int priority, const char *fmt, ...);

const char *duo_resolve_name(const char *hostname);

const char *duo_local_ip();

char *duo_split_at(char *s, char delimiter, unsigned int position);

/* Free and zero out memory */
void duo_zero_free(void *ptr, size_t size);

#endif
