//
// SPDX-License-Identifier: GPL-2.0-with-classpath-exception
//
// Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
// All rights reserved.
//
// groups_preload.c
//

#include "config.h"

#include <sys/types.h>

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>

FILE *(*_fopen)(const char* filename, const char* mode);

static struct passwd _passwd[8] = {
        { "user1", "*", 1000, 1000, .pw_gecos = "gecos", .pw_dir = "/",
          .pw_shell = "/bin/sh" },
        { "user2", "*", 1001, 100, .pw_gecos = "gecos", .pw_dir = "/",
          .pw_shell = "/bin/sh" },
        { "admin1", "*", 1002, 10, .pw_gecos = "gecos", .pw_dir = "/",
          .pw_shell = "/bin/sh" },
        { "admin2", "*", 1003, 1003, .pw_gecos = "gecos", .pw_dir = "/",
          .pw_shell = "/bin/sh" },
        { "weirdo", "*", 1004, 1004, .pw_gecos = "gecos", .pw_dir = "/",
          .pw_shell = "/bin/sh" },
        { "noshell", "*", 1005, 1005, .pw_gecos = "gecos", .pw_dir = "/",
          .pw_shell = NULL },
        { "orphan", "*", 1006, 59999, .pw_gecos = "gecos", .pw_dir = "/",
          .pw_shell = "/bin/sh" },
        { "partial", "*", 1007, 59999, .pw_gecos = "gecos", .pw_dir = "/",
          .pw_shell = "/bin/sh" },
};

/* Supplemental groups */
static char *_gr_users[] = { "user1", "admin1", "partial", NULL };
static char *_gr_admin[] = { "admin2", NULL };
static char *_gr_spaces[] = { "user2", NULL };
static char *_gr_no_spaces[] = { "weirdo", NULL };
static char *_gr_more_spaces[] = { "admin1", NULL };
static char *_gr_empty[] = { NULL };

static struct group _groups[9] = {
        { "users", NULL, 100, _gr_users },
        { "admin", NULL, 10, _gr_admin },
        { "users with spaces", NULL, 200, _gr_spaces },
        { "no_spaces\\here", NULL, 201, _gr_no_spaces },
        { "more spaces", NULL, 202, _gr_more_spaces },
        { "user1grp", NULL, 1000, _gr_empty },
        { "admin2grp", NULL, 1003, _gr_empty },
        { "weirdogrp", NULL, 1004, _gr_empty },
        { "noshellgrp", NULL, 1005, _gr_empty },
};

static int _group_ptr = 0;

uid_t
getuid(void)
{
        char *p = getenv("UID");

        return (p ? atoi(p) : 1004);
}

uid_t
geteuid(void)
{
        return (getuid());
}

struct passwd *
getpwuid(uid_t uid)
{
        int i;

        for (i = 0; i < sizeof(_passwd) / sizeof(_passwd[0]); i++) {
                if (_passwd[i].pw_uid == uid)
                        return (&_passwd[i]);
        }
        errno = ENOENT;
        return (NULL);
}

struct group *
getgrgid(gid_t gid)
{
        int i;
        char *fail_gid_str = getenv("GETGRGID_FAIL");

        if (fail_gid_str != NULL) {
                gid_t fail_gid = (gid_t)atoi(fail_gid_str);
                if (gid == fail_gid) {
                        errno = EIO;
                        return (NULL);
                }
        }

        for (i = 0; i < sizeof(_groups) / sizeof(_groups)[0]; i++) {
                if (_groups[i].gr_gid == gid)
                        return (&_groups[i]);
        }
        errno = ENOENT;
        return (NULL);
}

void
setgrent(void)
{
        _group_ptr = 0;
}

void
endgrent(void)
{
        _group_ptr = 0;
}

struct group *
getgrent(void)
{
        if (_group_ptr >= sizeof(_groups) / sizeof(_groups)[0]) {
                return (NULL);
        }
        return (&_groups[_group_ptr++]);
}

FILE *
fopen(const char *filename, const char *mode)
{
    if (strcmp(filename, "/etc/motd") == 0) {
        char *m = getenv("MOTD_FILE");
        if(m) {
            _fopen = dlsym(RTLD_NEXT, "fopen");
            return (*_fopen)(m, mode);
        }
    }
    _fopen = dlsym(RTLD_NEXT, "fopen");
    return (*_fopen)(filename, mode);
}

int
#ifdef __APPLE__
getgrouplist(const char *user, int group, int *groups, int *ngroups)
#else
getgrouplist(const char *user, gid_t group, gid_t *groups, int *ngroups)
#endif
{
        struct group *gr;
        char **pp;
        int i, n;

        *groups = group;
        n = 1;

        for (i = 0; i < sizeof(_groups) / sizeof(_groups)[0]; i++) {
                gr = &_groups[i];
                for (pp = gr->gr_mem; *pp != NULL; pp++) {
                        if (strcmp(*pp, user) == 0 && n < *ngroups)
                                groups[n++] = gr->gr_gid;
                }
        }
        return ((*ngroups = n));
}
