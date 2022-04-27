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

int (*_sys_open)(const char *pathname, int flags, ...);
int (*_sys_open64)(const char *pathname, int flags, ...);
FILE *(*_sys_fopen)(const char *filename, const char *mode);
FILE *(*_sys_fopen64)(const char *filename, const char *mode);
char *(*_sys_inet_ntoa)(struct in_addr in);
struct passwd *(* _getpwuid)(uid_t uid);
int (*_pam_get_item)(const pam_handle_t *pamh, int item_type, const void **item);

void modify_gecos(const char *username, struct passwd *pass);

int
_isfallback(void)
{
        char *t = getenv("FALLBACK");
        return (t ? atoi(t) : 0);
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

int pam_get_item(const pam_handle_t *pamh, int item_type, const void **item) {
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
