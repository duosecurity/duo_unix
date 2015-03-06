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
/* maximum number of bytes in a user map line */
#define USER_MAP_MAX 1024

#include <pwd.h>
#include <syslog.h>
#include <stdarg.h>

extern int duo_debug;

enum {
    DUO_FAIL_SAFE = 0,
    DUO_FAIL_SECURE
};

struct user_map {
    char from[USER_MAP_MAX];
    char to[USER_MAP_MAX];
    struct user_map *next;
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
    struct user_map *user_map;
};

void duo_config_default(struct duo_config *cfg);

int duo_set_boolean_option(const char *val);

int duo_common_ini_handler(struct duo_config *cfg, const char *section, 
    const char *name, const char*val);

const char* duo_map_user(const char *user, const struct user_map *user_map);

int duo_check_groups(struct passwd *pw, char **groups, int groups_cnt);

void duo_log(int priority, const char*msg, const char *user, const char *ip,
             const char *err);

void duo_syslog(int priority, const char *fmt, ...);

const char *
duo_resolve_name(const char *hostname);

const char *
duo_local_ip();


#endif
