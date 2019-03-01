
#include "config.h"

#include <sys/types.h>

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

static struct passwd _passwd[6] = {
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
};

/* Supplemental groups */
static char *_gr_users[] = { "user1", "admin1", NULL };
static char *_gr_admin[] = { "admin2", NULL };
static char *_gr_spaces[] = { "user2", NULL };
static char *_gr_no_spaces[] = { "weirdo", NULL };
static char *_gr_more_spaces[] = { "admin1", NULL };

static struct group _groups[5] = {
        { "users", NULL, 100, _gr_users },
        { "admin", NULL, 10, _gr_admin },
        { "users with spaces", NULL, 200, _gr_spaces },
        { "no_spaces\\here", NULL, 201, _gr_no_spaces },
        { "more spaces", NULL, 202, _gr_more_spaces },
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
