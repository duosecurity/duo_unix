#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <dlfcn.h>
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <poll.h>

#include <netinet/in.h>
#include <arpa/inet.h>

int (*_sys_poll)(struct pollfd *fds, nfds_t nfds, int timeout);
int (*_sys_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int (*_sys_getaddrinfo)(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
char *(*_sys_inet_ntoa)(struct in_addr in);
struct passwd *(*_getpwnam)(const char* name);
FILE *(*_fopen)(const char* filename, const char* mode);

static struct passwd _passwd[11] = {
        { "sshd", "*", 1000, 100, .pw_gecos = "gecos", .pw_dir = "/",
          .pw_shell = "/bin/sh" },
        { "user1", "*", 1001, 100, .pw_gecos = "gecos", .pw_dir = "/",
          .pw_shell = "/bin/sh" },
        { "gecos/6", "*", 1010, 100, .pw_gecos = "1/2/3/4/5/gecos_user_gecos_field6", .pw_dir = "/", .pw_shell = "/bin/sh" },
        { "gecos/3", "*", 1011, 100, .pw_gecos = "1/2/gecos_user_gecos_field3/4/5/6", .pw_dir = "/", .pw_shell = "/bin/sh" },
        { "gecos,6", "*", 1012, 100, .pw_gecos = "1,2,3,4,5,gecos_user_gecos_field6", .pw_dir = "/", .pw_shell = "/bin/sh" },
        { "gecos,3", "*", 1013, 100, .pw_gecos = "1,2,gecos_user_gecos_field3,4,5,6", .pw_dir = "/", .pw_shell = "/bin/sh" },
        { "fullgecos", "*", 1014, 100, .pw_gecos = "full_gecos_field", .pw_dir = "/", .pw_shell = "/bin/sh" },
        { "noshell", "*", 1015, 100, .pw_gecos = "full_gecos_field", .pw_dir = "/", .pw_shell = NULL},
        { "emptygecos", "*", 1016, 100, .pw_gecos = "", .pw_dir = "/", .pw_shell = "/bin/sh" },
        { "slashshell", "*", 1017, 100, .pw_gecos = "full_gecos_field", .pw_dir = "/", .pw_shell = "/bin/echo"},
        { "preauth-allow", "*", 1018, 100, .pw_gecos = "gecos", .pw_dir = "/",
          .pw_shell = "/bin/sh" },
};

int
_istimeout(void)
{
        char *t = getenv("TIMEOUT");
        return (t ? atoi(t) : 0);
}

int
_isfallback(void)
{
        char *t = getenv("FALLBACK");
        return (t ? atoi(t) : 0);
}

int
poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
        _sys_poll = dlsym(RTLD_NEXT, "poll");
        int retval = (*_sys_poll)(fds, nfds, timeout);
        //Mock a timeout response in the poll
        return (_istimeout() ? 0 : retval);
}

int
connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
        if (_istimeout())
        {
            /* Only print if address is IPV4 or IPV6 and the port connecting to is our mock_duo server.
            This prevents accidentally mocking for other connections. */
            int ipv4_or_ipv6 = (addr->sa_family == AF_INET || addr->sa_family == AF_INET6) ? 1 : 0;
            struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
            int server_port = (int) ntohs(addr_in->sin_port);

            if (ipv4_or_ipv6 && server_port==4443)
            {
                fprintf(stderr, "Attempting connection\n");
            }
        }
        _sys_connect = dlsym(RTLD_NEXT, "connect");
        return (*_sys_connect)(sockfd, addr, addrlen);
}

int
getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res)
{
        _sys_getaddrinfo = dlsym(RTLD_NEXT, "getaddrinfo");
        int retval = (*_sys_getaddrinfo)(node, service, hints, res);
        if (_istimeout())
        {
            //Leaking memory here, but we don't care because it's just a test
            (*res)->ai_next = NULL;
        }
        return retval;
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

uid_t
getuid(void)
{
        char *p = getenv("UID");

        return (p ? atoi(p) : 1004);
}

uid_t
geteuid(void)
{
        char *p = getenv("EUID");

        return (p ? atoi(p) : getuid());
}

struct passwd *
getpwuid(uid_t uid)
{
        int i;

        for (i = 0; i < sizeof(_passwd) / sizeof(_passwd[0]); i++) {
                if (_passwd[i].pw_uid == uid) {
                    // we have to copy the pw_gecos field because it might be modified
                    // by `duo_split_at` which casues a segfault if we leave it as a
                    // constant literal
                    _passwd[i].pw_gecos = strdup(_passwd[i].pw_gecos);
                    return (&_passwd[i]);
                }
        }
        errno = ENOENT;
        return (NULL);
}

struct passwd *
getpwnam(const char *name)
{
    char *u = getenv("NO_PRIVSEP_USER");
    int i;
    if(u) {
        return NULL;
    }
    for (i = 0; i < sizeof(_passwd) / sizeof(_passwd[0]); i++) {
            if (strcmp(_passwd[i].pw_name, name) == 0) {
                return (&_passwd[i]);
            }
    }
    _getpwnam = dlsym(RTLD_NEXT, "getpwnam");
    return (*_getpwnam)(name);
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
