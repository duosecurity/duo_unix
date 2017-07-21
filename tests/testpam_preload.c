/*
 * testpam_preload.c
 *
 * Fake test environment to run PAM tests unprivileged.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <dlfcn.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef __APPLE__
# define _PATH_LIBC       "libc.dylib"
#elif defined(__linux__)
# define _PATH_LIBC       "libc.so.6"
#else
# define _PATH_LIBC       "libc.so"
#endif

static void _preload_init(void) __attribute((constructor));

int (*_sys_open)(const char *pathname, int flags, ...);
int (*_sys_open64)(const char *pathname, int flags, ...);
FILE *(*_sys_fopen)(const char *filename, const char *mode);
FILE *(*_sys_fopen64)(const char *filename, const char *mode);
char *(*_sys_inet_ntoa)(struct in_addr in);

static void
_fatal(const char *msg)
{
	perror(msg);
	exit(1);
}

static void
_preload_init(void)
{
	void *libc;

#ifndef DL_LAZY
# define DL_LAZY RTLD_LAZY
#endif
	if (!(libc = dlopen(_PATH_LIBC, DL_LAZY))) {
		_fatal("couldn't dlopen " _PATH_LIBC);
	} else if (!(_sys_open = dlsym(libc, "open"))) {
		_fatal("couldn't dlsym 'open'");
#ifdef HAVE_OPEN64
	} else if (!(_sys_open = dlsym(libc, "open64"))) {
		_fatal("couldn't dlsym 'open64'");
#endif
	} else if (!(_sys_fopen = dlsym(libc, "fopen"))) {
		_fatal("couldn't dlsym 'fopen'");
#ifdef HAVE_FOPEN64
	} else if (!(_sys_fopen64 = dlsym(libc, "fopen64"))) {
		_fatal("couldn't dlsym 'fopen64'");
#endif
	}
}

const char *
_replace(const char *filename)
{
	if (strcmp(filename, "/etc/pam.d/testpam") == 0 ||
            strcmp(filename, "/etc/pam.conf") == 0) {
		return (getenv("PAM_CONF"));
	}
	return (filename);
}

int
_isfallback(void)
{
        char *t = getenv("FALLBACK");
        return (t ? atoi(t) : 0);
}

int
open(const char *filename, int flags, ...)
{
	return ((*_sys_open)(_replace(filename), flags));
}

int
open64(const char *filename, int flags, ...)
{
	return ((*_sys_open64)(_replace(filename), flags));
}

FILE *
fopen(const char *filename, const char *mode)
{
	return ((*_sys_fopen)(_replace(filename), mode));
}

FILE *
fopen64(const char *filename, const char *mode)
{
	return ((*_sys_fopen64)(_replace(filename), mode));
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

struct passwd *
getpwnam(const char *name)
{
	// Tests rely on the username being correctly set.
	static char username[1024];
	strncpy(username, name, 1024);
	username[1024 - 1] = '\0';

	static struct passwd ret;
	memcpy(&ret, getpwuid(getuid()), sizeof(struct passwd));
	ret.pw_name = username;

	return &ret;
}

