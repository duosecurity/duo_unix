/*
 * SPDX-License-Identifier: GPL-2.0-with-classpath-exception
 *
 * testpam_preload.c
 *
 * Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved.
 *
 * Fake test environment to run PAM tests unprivileged.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <netdb.h>

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif
#ifdef HAVE_SECURITY_PAM_EXT_H
#include <security/pam_ext.h>  /* Linux-PAM */
#endif

#ifdef __APPLE__
# define _PATH_LIBC       "libc.dylib"
#elif defined(__linux__)
# define _PATH_LIBC       "libc.so.6"
#else
# define _PATH_LIBC       "libc.so"
#endif

#ifdef __sun
typedef void **pam_item;
#else
typedef const void **pam_item;
#endif

int (*_sys_open)(const char *pathname, int flags, ...);
int (*_sys_open64)(const char *pathname, int flags, ...);
FILE *(*_sys_fopen)(const char *filename, const char *mode);
FILE *(*_sys_fopen64)(const char *filename, const char *mode);
char *(*_sys_inet_ntoa)(struct in_addr in);
struct passwd *(* _getpwuid)(uid_t uid);
int (*_pam_get_item)(const pam_handle_t *pamh, int item_type, pam_item item);

void modify_gecos(const char *username, struct passwd *pass);

int
_isfallback(void)
{
        char *t = getenv("FALLBACK");
        return (t ? atoi(t) : 0);
}

/*
 * When TESTPAM_OPEN_FAIL_PATH and TESTPAM_OPEN_FAIL_ERRNO are set, opening
 * that exact path fails with that errno, so tests can check how pam_duo
 * handles a specific open() error. Every other open() passes through.
 */
static int
_open_should_fail(const char *pathname)
{
    const char *path = getenv("TESTPAM_OPEN_FAIL_PATH");
    const char *err = getenv("TESTPAM_OPEN_FAIL_ERRNO");

    if (path == NULL || err == NULL || strcmp(pathname, path) != 0)
        return 0;
    errno = atoi(err);
    return 1;
}

static mode_t
_open_mode(int flags, va_list ap)
{
#ifdef O_TMPFILE
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE)
#else
    if (flags & O_CREAT)
#endif
        return (mode_t)va_arg(ap, int);
    return 0;
}

int
open(const char *pathname, int flags, ...)
{
    va_list ap;
    mode_t mode;

    va_start(ap, flags);
    mode = _open_mode(flags, ap);
    va_end(ap);
    if (_open_should_fail(pathname))
        return -1;
    if (_sys_open == NULL)
        _sys_open = dlsym(RTLD_NEXT, "open");
    return (*_sys_open)(pathname, flags, mode);
}

int
open64(const char *pathname, int flags, ...)
{
    va_list ap;
    mode_t mode;

    va_start(ap, flags);
    mode = _open_mode(flags, ap);
    va_end(ap);
    if (_open_should_fail(pathname))
        return -1;
    if (_sys_open64 == NULL)
        _sys_open64 = dlsym(RTLD_NEXT, "open64");
    if (_sys_open64 == NULL) {
        if (_sys_open == NULL)
            _sys_open = dlsym(RTLD_NEXT, "open");
        return (*_sys_open)(pathname, flags, mode);
    }
    return (*_sys_open64)(pathname, flags, mode);
}

char *
inet_ntoa(struct in_addr in)
{
    if (_isfallback()) {
       return "1.2.3.4";
    }
    else {
        _sys_inet_ntoa = dlsym(RTLD_NEXT, "inet_ntoa");
        return (*_sys_inet_ntoa)(in);
    }
}

void
modify_gecos(const char *username, struct passwd *pass)
{
    if (strcmp(username, "gecos/6") == 0) {
       pass->pw_gecos = strdup("1/2/3/4/5/gecos_user_gecos_field6");
    } else if (strcmp(username, "gecos/3") == 0) {
       pass->pw_gecos = strdup("1/2/gecos_user_gecos_field3/4/5/6");
    } else if (strcmp(username, "gecos,6") == 0) {
       pass->pw_gecos = strdup("1,2,3,4,5,gecos_user_gecos_field6");
    } else if (strcmp(username, "gecos,3") == 0) {
       pass->pw_gecos = strdup("1,2,gecos_user_gecos_field3,4,5,6");
    } else if (strcmp(username, "fullgecos") == 0) {
       pass->pw_gecos = strdup("full_gecos_field");
    } else if (strcmp(username, "fullgecos") == 0) {
       pass->pw_gecos = strdup("full_gecos_field");
    } else if (strcmp(username, "emptygecos") == 0) {
       pass->pw_gecos = strdup("");
    } else if (strcmp(username, "onlydelim") == 0) {
       pass->pw_gecos = strdup(",,,,,,,");
    }
}

struct passwd *
getpwuid(uid_t uid)
{
    char *t = getenv("NO_USER");
    if(t) {
        return NULL;
    }
    else {
        _getpwuid = dlsym(RTLD_NEXT, "getpwuid");
        return (*_getpwuid)(uid);
    }
}


struct passwd *
getpwnam(const char *name)
{
    char *t = getenv("NO_USER");
    if(t) {
        return NULL;
    }

    // Tests rely on the username being correctly set.
    static char username[1024];
    strncpy(username, name, 1024);
    username[1024 - 1] = '\0';

    static struct passwd ret;
    memcpy(&ret, getpwuid(getuid()), sizeof(struct passwd));
    modify_gecos(username, &ret);
    ret.pw_name = username;

    return &ret;
}

/* Count how many descriptors (up to max) can be allocated right now. */
static int
count_free_fds(int max)
{
    int fds[64];
    int i, n;

    if (max > 64)
        max = 64;
    if ((fds[0] = open("/dev/null", O_RDONLY)) < 0)
        return 0;
    for (n = 1; n < max; n++) {
        if ((fds[n] = dup(fds[0])) < 0)
            break;
    }
    for (i = 0; i < n; i++)
        close(fds[i]);
    return n;
}

/* When TESTPAM_REPORT_RLIMITS is set, print the current resource limits so
 * tests can check what a PAM module sees and what the caller gets back. */
static void
report_rlimits(const char *when)
{
    static const struct { int res; const char *name; } lims[] = {
        { RLIMIT_AS, "AS" }, { RLIMIT_DATA, "DATA" }, { RLIMIT_NOFILE, "NOFILE" },
    };
    struct rlimit rl;
    size_t i;

    if (getenv("TESTPAM_REPORT_RLIMITS") == NULL)
        return;
    fprintf(stderr, "TESTPAM rlimits %s:", when);
    for (i = 0; i < sizeof(lims) / sizeof(lims[0]); i++) {
        if (getrlimit(lims[i].res, &rl) != 0)
            continue;
        fprintf(stderr, " %s=", lims[i].name);
        if (rl.rlim_cur == RLIM_INFINITY)
            fprintf(stderr, "inf");
        else
            fprintf(stderr, "%llu", (unsigned long long)rl.rlim_cur);
        if (rl.rlim_max == RLIM_INFINITY)
            fprintf(stderr, ":inf");
        else
            fprintf(stderr, ":%llu", (unsigned long long)rl.rlim_max);
    }
    fprintf(stderr, " FREEFD=%d", count_free_fds(64));
    fputc('\n', stderr);
}

int pam_get_item(const pam_handle_t *pamh, int item_type, pam_item item) {
    report_rlimits("during");
    if(item_type == PAM_SERVICE) {
        char *s = getenv("SIMULATE_SERVICE");
        if(s) {
            *item = s;
            return PAM_SUCCESS;
        }
    }
    _pam_get_item  = dlsym(RTLD_NEXT, "pam_get_item");
    return (*_pam_get_item)(pamh, item_type, item);
}
