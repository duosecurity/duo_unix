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

#define MAX_GECOS_FIELDS 122 // Maximum possible number of GECOS fields
/*
 * Reasoning: GECOS_MAX length is 127 characters. Assume all fields except
 * a minimal length email address (3 characters) are empty (i.e. all commas).
 * That leaves 123 commas minus a null terminator. Adjusting for human counting
 * tendencies, that leaves 123 possible fields ranging from indicies 0 to 122.
 *
 * Reference: https://www.qualys.com/2015/07/23/cve-2015-3245-cve-2015-3246/cve-2015-3245-cve-2015-3246.txt
 */

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
    char gecos_delim;
    int  gecos_fieldnum;
    int  fips_mode;
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
