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

int (*_sys_poll)(struct pollfd *fds, nfds_t nfds, int timeout);
int (*_sys_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int (*_sys_getaddrinfo)(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
char *(*_sys_inet_ntoa)(struct in_addr in);

static struct passwd _passwd[1] = {
        { "user1", "*", 1001, 100, .pw_gecos = "gecos", .pw_dir = "/",
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
            //Only print if address is IPV4 or IPV6. Prevents accidentally mocking for other connections
            //such as AF_UNIX when communicating between local processes
            if (addr->sa_family == AF_INET || addr->sa_family == AF_INET6)
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
