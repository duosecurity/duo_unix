/*
 * SPDX-License-Identifier: GPL-2.0-with-classpath-exception
 *
 * pam_duo.c
 *
 * Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved.
 */

#include <sys/syslog.h>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/param.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <netdb.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

/* These #defines must be present according to PAM documentation. */
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

/* NetBSD PAM b0rkage (gnat 39313) */
#ifdef __NetBSD__
#define NO_STATIC_MODULES
#endif

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif
#ifdef HAVE_SECURITY_PAM_EXT_H
#include <security/pam_ext.h>  /* Linux-PAM */
#endif

/* OpenGroup RFC86.0 and XSSO specify no "const" on arguments */
#if defined(__LINUX_PAM__) || defined(OPENPAM)
# define duopam_const   const   /* LinuxPAM, OpenPAM */
#else
# define duopam_const           /* Solaris, HP-UX, AIX */
#endif

#include "util.h"
#include "duo.h"
#include "groupaccess.h"
#include "pam_extra.h"
#include "pam_duo_private.h"

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#ifndef DUO_PRIVSEP_USER
# define DUO_PRIVSEP_USER      "duo"
#endif
#define DUO_CONF               DUO_CONF_DIR "/pam_duo.conf"

static int
__ini_handler(void *u, const char *section, const char *name, const char *val)
{
    struct duo_config *cfg = (struct duo_config *)u;
    if (!duo_common_ini_handler(cfg, section, name, val)) {
        /* There are no options specific to pam_duo yet */
        duo_syslog(LOG_ERR, "Invalid pam_duo option: '%s'", name);
        return (0);
    }
    return (1);
}

static void
__duo_status(void *arg, const char *msg)
{
    char *sanitized = strdup(msg);
    if (sanitized != NULL) {
        duo_sanitize_str(sanitized);
        pam_info((pam_handle_t *)arg, "%s", sanitized);
        free(sanitized);
    }
}

static char *
__duo_prompt(void *arg, const char *prompt, char *buf, size_t bufsz)
{
    char *p = NULL;
    char *sanitized = strdup(prompt);

    if (sanitized == NULL)
        return (NULL);

    duo_sanitize_str(sanitized);
    if (pam_prompt((pam_handle_t *)arg, PAM_PROMPT_ECHO_ON, &p,
        "%s", sanitized) != PAM_SUCCESS || p == NULL) {
        free(sanitized);
        return (NULL);
    }
    free(sanitized);
    strlcpy(buf, p, bufsz);
    free(p);
    return (buf);
}

/*
 * Minimum resource limits for authentication.
 *
 * pam_duo runs inside the calling application and inherits its resource
 * limits. Make sure authentication has a reasonable minimum budget of
 * memory and file descriptors to work with, independent of the limits the
 * application was started with. Limits below their floor are raised to it,
 * nothing is ever lowered, and the original limits are restored before
 * returning to the application. RLIMIT_NOFILE may additionally be raised
 * past its floor if too few descriptors are actually free (see
 * __duo_rlimits_ensure_fd_headroom()).
 *
 * The floors follow sudo's approach (unlimit_sudo()/restore_limits() in
 * sudo's src/limits.c), including its 1 GB floor for the memory limits and
 * its retry when restoring a limit below current usage. sudo compares the
 * descriptor limit's value only; the free-descriptor check is additional.
 */
#define DUO_RLIMIT_MEM_FLOOR    ((rlim_t)1024 * 1024 * 1024)  /* 1 GB */
#define DUO_RLIMIT_NOFILE_FLOOR ((rlim_t)1024)

struct duo_rlimit {
    int resource;
    const char *name;
    rlim_t floor;
    struct rlimit saved;
    int saved_ok;
    int changed;
};

static void
__duo_rlimits_init(struct duo_rlimit *lims, size_t *nlims)
{
    size_t n = 0;

#ifdef RLIMIT_AS
    lims[n].resource = RLIMIT_AS;
    lims[n].name = "RLIMIT_AS";
    lims[n].floor = DUO_RLIMIT_MEM_FLOOR;
    n++;
#endif
#ifdef RLIMIT_DATA
    lims[n].resource = RLIMIT_DATA;
    lims[n].name = "RLIMIT_DATA";
    lims[n].floor = DUO_RLIMIT_MEM_FLOOR;
    n++;
#endif
    lims[n].resource = RLIMIT_NOFILE;
    lims[n].name = "RLIMIT_NOFILE";
    lims[n].floor = DUO_RLIMIT_NOFILE_FLOOR;
    n++;

    *nlims = n;
}

static void
__duo_rlimits_raise(struct duo_rlimit *lims, size_t nlims)
{
    size_t i;

    for (i = 0; i < nlims; i++) {
        struct duo_rlimit *lim = &lims[i];
        struct rlimit want;
        int err;

        lim->changed = 0;
        lim->saved_ok = 0;
        if (getrlimit(lim->resource, &lim->saved) != 0) {
            continue;
        }
        lim->saved_ok = 1;
        if (lim->saved.rlim_cur == RLIM_INFINITY ||
            lim->saved.rlim_cur >= lim->floor) {
            continue;
        }

        want = lim->saved;
        want.rlim_cur = lim->floor;
        if (want.rlim_max != RLIM_INFINITY && want.rlim_max < lim->floor) {
            /* Raising the hard limit requires privilege. */
            want.rlim_max = lim->floor;
        }
        if (setrlimit(lim->resource, &want) == 0) {
            lim->changed = 1;
            continue;
        }
        err = errno;

        /* Unprivileged: the soft limit can still go up to the hard limit. */
        if (lim->saved.rlim_max != RLIM_INFINITY &&
            lim->saved.rlim_max > lim->saved.rlim_cur) {
            want = lim->saved;
            want.rlim_cur = want.rlim_max;
            if (setrlimit(lim->resource, &want) == 0) {
                lim->changed = 1;
            }
        }
        duo_syslog(LOG_WARNING, "Could not raise %s to the minimum "
            "required for authentication: %s", lim->name, strerror(err));
    }
}

/*
 * RLIMIT_NOFILE bounds descriptor numbers, not how many descriptors are
 * free: descriptors the application already has open use up part of it,
 * whatever the limit's value. Authentication only needs a few at a time
 * (configuration and CA files, sockets, syslog), so check that
 * DUO_FD_HEADROOM descriptors can actually be allocated, and raise the soft
 * limit until they can or no further increase is possible.
 */
#define DUO_FD_HEADROOM 16

/* Returns how many descriptors (up to max) could be allocated, or -1 if
 * the check itself could not be done. */
static int
__duo_count_free_fds(int max)
{
    int fds[DUO_FD_HEADROOM];
    int fd, i, n;

    if (max > DUO_FD_HEADROOM) {
        max = DUO_FD_HEADROOM;
    }
    if ((fds[0] = open("/dev/null", O_RDONLY)) < 0) {
        return (errno == EMFILE ? 0 : -1);
    }
    for (n = 1; n < max; n++) {
        if ((fd = dup(fds[0])) < 0) {
            break;
        }
        fds[n] = fd;
    }
    for (i = 0; i < n; i++) {
        close(fds[i]);
    }
    return (n);
}

static void
__duo_rlimits_ensure_fd_headroom(struct duo_rlimit *lim)
{
    struct rlimit cur, want;
    rlim_t step = DUO_FD_HEADROOM;
    int n;

    /*
     * Keep raising the soft limit in doubling steps until enough
     * descriptors are free or the system refuses a further increase. There
     * is no fixed number of rounds: any number of descriptors may already
     * be open above the starting limit.
     */
    for (;;) {
        if ((n = __duo_count_free_fds(DUO_FD_HEADROOM)) < 0 ||
            n >= DUO_FD_HEADROOM) {
            return;
        }
        if (getrlimit(RLIMIT_NOFILE, &cur) != 0 ||
            cur.rlim_cur == RLIM_INFINITY) {
            return;
        }
        if (RLIM_INFINITY - cur.rlim_cur <= step) {
            /* No representable limit left above the current one. */
            break;
        }

        want = cur;
        want.rlim_cur = cur.rlim_cur + step;
        if (want.rlim_max != RLIM_INFINITY && want.rlim_max < want.rlim_cur) {
            /* Raising the hard limit requires privilege. */
            want.rlim_max = want.rlim_cur;
        }
        if (setrlimit(RLIMIT_NOFILE, &want) != 0) {
            /* Unprivileged: go as far as the hard limit allows. */
            if (cur.rlim_max == RLIM_INFINITY ||
                cur.rlim_max <= cur.rlim_cur) {
                break;
            }
            want = cur;
            want.rlim_cur = cur.rlim_max;
            if (setrlimit(RLIMIT_NOFILE, &want) != 0) {
                break;
            }
            lim->changed = 1;
            if (__duo_count_free_fds(DUO_FD_HEADROOM) >= DUO_FD_HEADROOM) {
                return;
            }
            break;
        }
        lim->changed = 1;
        if (step < RLIM_INFINITY / 2) {
            step *= 2;
        }
    }
    duo_syslog(LOG_WARNING, "Could not make %d file descriptors available "
        "for authentication", DUO_FD_HEADROOM);
}

static void
__duo_rlimits_restore(const struct duo_rlimit *lims, size_t nlims)
{
    size_t i;
    int tries;

    for (i = 0; i < nlims; i++) {
        const struct duo_rlimit *lim = &lims[i];
        struct rlimit rl;
        int restored = 0;

        if (!lim->changed) {
            continue;
        }
        rl = lim->saved;
        for (tries = 0; tries < 10; tries++) {
            if (setrlimit(lim->resource, &rl) == 0) {
                restored = 1;
                break;
            }
            /* Some systems reject a soft limit below current usage. Step
             * the soft limit up towards the floor and try again, so the
             * result is as close to the original as the system allows. */
            if (errno != EINVAL || rl.rlim_cur >= lim->floor) {
                break;
            }
            rl.rlim_cur = (rl.rlim_cur == 0) ? 1 : rl.rlim_cur * 2;
            if (rl.rlim_cur > lim->floor) {
                rl.rlim_cur = lim->floor;
            }
            if (rl.rlim_max != RLIM_INFINITY && rl.rlim_max < rl.rlim_cur) {
                rl.rlim_max = rl.rlim_cur;
            }
        }
        if (!restored) {
            duo_syslog(LOG_WARNING, "Could not restore %s after "
                "authentication: %s", lim->name, strerror(errno));
        }
    }
}

static int
__pam_duo_authenticate(pam_handle_t *pamh, int pam_flags,
    int argc, const char *argv[]);

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int pam_flags,
    int argc, const char *argv[])
{
    struct duo_rlimit lims[3];
    size_t i, nlims;
    int pam_err;

    __duo_rlimits_init(lims, &nlims);
    __duo_rlimits_raise(lims, nlims);
    for (i = 0; i < nlims; i++) {
        if (lims[i].resource == RLIMIT_NOFILE && lims[i].saved_ok) {
            __duo_rlimits_ensure_fd_headroom(&lims[i]);
        }
    }
    pam_err = __pam_duo_authenticate(pamh, pam_flags, argc, argv);
    __duo_rlimits_restore(lims, nlims);

    return (pam_err);
}

static int
__pam_duo_authenticate(pam_handle_t *pamh, int pam_flags,
    int argc, const char *argv[])
{
    struct duo_config cfg;
    struct passwd *pw;
    struct in_addr addr;
    struct in6_addr addr6;
    duo_t *duo;
    duo_code_t code;

    /*
     * Only variables that will be passed to a pam_* function
     * need to be marked as 'duopam_const char *', anything else
     * should be 'const char *'. This is because there are different
     * PAM implementations, some with the const qualifier, and some
     * without.
     */
    duopam_const char *ip, *service, *user;
    const char *cmd, *p, *host, *cafile;
    const char *config = DUO_CONF;

    int i, flags, pam_err, matched;

    duo_syslog(LOG_INFO, "starting Duo Unix: PAM Duo");
    duo_config_default(&cfg);

    /* Parse configuration */
    duo_syslog(LOG_INFO, "Loading config file %s", config);
    if(parse_argv(&config, argc, argv) == 0) {
        return (PAM_SERVICE_ERR);
    }

    i = duo_parse_config(config, __ini_handler, &cfg);
    if (i == -3) {
        close_config(&cfg);
        duo_syslog(LOG_ERR, "Internal error reading %s", config);
        return (PAM_SERVICE_ERR);
    } else if (i == -2) {
        int failmode = cfg.failmode;
        duo_syslog(LOG_ERR, "%s must not be readable by other users "
            "(a root-owned file may also be group-readable)", config);
        close_config(&cfg);
        return (failmode == DUO_FAIL_SAFE ? PAM_SUCCESS : PAM_SERVICE_ERR);
    } else if (i == -1) {
        int failmode = cfg.failmode;
        duo_syslog(LOG_ERR, "Couldn't open %s: %s",
            config, strerror(errno));
        close_config(&cfg);
        return (failmode == DUO_FAIL_SAFE ? PAM_SUCCESS : PAM_SERVICE_ERR);
    } else if (i > 0) {
        int failmode = cfg.failmode;
        duo_syslog(LOG_ERR, "Parse error in %s, line %d", config, i);
        close_config(&cfg);
        return (failmode == DUO_FAIL_SAFE ? PAM_SUCCESS : PAM_SERVICE_ERR);
    } else if (!cfg.apihost || !cfg.apihost[0] ||
            !cfg.skey || !cfg.skey[0] || !cfg.ikey || !cfg.ikey[0]) {
        int failmode = cfg.failmode;
        duo_syslog(LOG_ERR, "Missing host, ikey, or skey in %s", config);
        close_config(&cfg);
        return (failmode == DUO_FAIL_SAFE ? PAM_SUCCESS : PAM_SERVICE_ERR);
    } else if (cfg.autopush && cfg.verified_push) {
        int failmode = cfg.failmode;
        duo_syslog(LOG_ERR, "autopush and verified_push cannot both be enabled in %s", config);
        close_config(&cfg);
        return (failmode == DUO_FAIL_SAFE ? PAM_SUCCESS : PAM_SERVICE_ERR);
    }

    if (duo_groups_all_negated(&cfg)) {
        duo_log(LOG_WARNING, "All configured groups are negated; no user "
            "can match, so Duo 2FA is disabled for every user (use "
            "\"*,!group\" to require 2FA for everyone except a group)",
            NULL, NULL, NULL);
    }

    /* Check user */
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS ||
        (pw = getpwnam(user)) == NULL) {
        close_config(&cfg);
        return (PAM_USER_UNKNOWN);
    }
    /* XXX - Service-specific behavior */
    flags = 0;
    cmd = NULL;
    if (pam_get_item(pamh, PAM_SERVICE, (duopam_const void **)
        (duopam_const void *)&service) != PAM_SUCCESS) {
        close_config(&cfg);
        return (PAM_SERVICE_ERR);
    }
    if (strcmp(service, "sshd") == 0) {
        /*
         * Disable incremental status reporting for sshd :-(
         * OpenSSH accumulates PAM_TEXT_INFO from modules to send in
         * an SSH_MSG_USERAUTH_BANNER post-auth, not real-time!
         * (OpenSSH bug 2876, https://bugzilla.mindrot.org/show_bug.cgi?id=2876)
         *
         * Workaround: with this flag set, libduo shows the Verified Push
         * code in the factor prompt instead (see _duo_vp_prompt() in
         * lib/duo.c). Once sshd builds with the upstream fix for bug 2876
         * are in wide use, remove this flag so sshd gets the same
         * asynchronous, real-time status messages (including the Verified
         * Push code) as other services, and drop the prompt workaround.
         */
        flags |= DUO_FLAG_SYNC;
    } else if (strcmp(service, "sudo") == 0) {
        cmd = getenv("SUDO_COMMAND");
    } else if (strcmp(service, "su") == 0 || strcmp(service, "su-l") == 0) {
        /* Check if target user is "root" */
        if(pw->pw_uid == 0) {
            /* If so, check calling user for Duo auth, just like sudo */
            if ((pw = getpwuid(getuid())) == NULL) {
                close_config(&cfg);
                return (PAM_USER_UNKNOWN);
            }
            user = pw->pw_name;
        }
    }
    /* Check group membership */
    matched = duo_check_groups(pw, cfg.groups, cfg.groups_cnt);
    if (matched == -1) {
        close_config(&cfg);
        return (PAM_SERVICE_ERR);
    } else if (matched == 0) {
        duo_syslog(LOG_INFO, "User %s bypassed Duo 2FA due to user's UNIX group", user);
        close_config(&cfg);
        return (PAM_SUCCESS);
    }

    /*
     * Use GECOS field if called for.
     *
     * SECURITY NOTE: the GECOS field is user-controlled data. On most
     * systems chfn(1) lets an unprivileged user edit their own GECOS
     * sub-fields (subject to CHFN_RESTRICT in login.defs), so send_gecos
     * and gecos_username_pos let a user choose the Duo identity presented
     * for their own second-factor challenge, decoupling it from the OS
     * identity that primary auth established. These options are deprecated
     * in favor of Duo username aliases; administrators enabling them must
     * restrict chfn. We log both identities below so a substitution is
     * visible in host audit logs.
     */
    if (cfg.send_gecos || cfg.gecos_username_pos >= 0) {
        if (strlen(pw->pw_gecos) > 0) {
            if (cfg.gecos_username_pos >= 0) {
                user = duo_split_at(pw->pw_gecos, cfg.gecos_delim, cfg.gecos_username_pos);
                if (user == NULL || (strcmp(user, "") == 0)) {
                    duo_log(LOG_DEBUG, "Could not parse GECOS field", pw->pw_name, NULL, NULL);
                    user = pw->pw_name;
                }
            } else {
                user = pw->pw_gecos;
            }
            if (strcmp(user, pw->pw_name) != 0) {
                /* duo_log() sanitizes the assembled message; the
                   GECOS-derived name is user-controlled, so it must not go
                   to syslog unsanitized. Logs as:
                   "... for '<os user>': <gecos-derived duo username>" */
                duo_log(LOG_INFO, "Presenting GECOS-derived Duo username",
                    pw->pw_name, NULL, user);
            }
        } else {
            duo_log(LOG_WARNING, "Empty GECOS field", pw->pw_name, NULL, NULL);
        }
    }

    /* Grab the remote host */
    ip = NULL;
    pam_get_item(pamh, PAM_RHOST,
        (duopam_const void **)(duopam_const void *)&ip);
    host = ip;
    /* PAM is weird, check to see if PAM_RHOST is IP or hostname */
    if (ip == NULL) {
        ip = ""; /* XXX inet_addr needs a non-null IP */
    }
    if (!inet_aton(ip, &addr) &&
        inet_pton(AF_INET6, ip, &addr6) != 1) {
        /* Not an IPv4 or IPv6 literal — likely a hostname, check fallback */
        if (cfg.local_ip_fallback) {
            host = duo_local_ip();
            /* Only a non-empty PAM_RHOST is a real remote client; the empty
               case is a local (su/sudo) session and must stay silent. */
            if (ip[0] != '\0') {
                duo_log(LOG_WARNING, "fallback_local_ip is replacing the "
                    "remote client address with this server's IP; the "
                    "address reported to Duo is not the client's",
                    NULL, ip, NULL);
            }
        } else if (ip[0] != '\0') {
            /* PAM_RHOST is not an IP literal (typically a resolved hostname);
               it is still sent as-is but Duo network policies match on IP, so
               they will not apply. */
            duo_log(LOG_WARNING, "Client address is not a valid IP address; "
                "Duo network policies will not match this login (if this is "
                "sshd, set \"UseDNS no\" in sshd_config so the client IP is "
                "passed)",
                NULL, ip, NULL);
        }
    }

    /* Try Duo auth */
    if (cfg.noverify) {
        cafile = "";
    } else if (cfg.disable_ca_pinning) {
        cafile = DUO_USE_SYSTEM_CERTS;
    } else {
        cafile = cfg.cafile;
    }
    duo_syslog(LOG_INFO, "CA bundle version: %s", DUO_CA_BUNDLE_VERSION);
    if (cfg.disable_ca_pinning) {
        duo_log(LOG_WARNING, "CA certificate pinning is disabled",
            NULL, NULL, NULL);
    }
    if ((duo = duo_open(cfg.apihost, cfg.ikey, cfg.skey,
                    "pam_duo/" PACKAGE_VERSION,
                    cafile, cfg.https_timeout, cfg.http_proxy,
                    cfg.min_tls)) == NULL) {
        duo_log(LOG_ERR, "Couldn't open Duo API handle", pw->pw_name, host, NULL);
        close_config(&cfg);
        return (PAM_SERVICE_ERR);
    }
    duo_set_conv_funcs(duo, __duo_prompt, __duo_status, pamh);

    if (cfg.autopush) {
        flags |= DUO_FLAG_AUTO;
    }

    if (cfg.verified_push) {
        flags |= DUO_FLAG_VERIFIED_PUSH;
    }

    pam_err = PAM_SERVICE_ERR;

    for (i = 0; i < cfg.prompts; i++) {
        code = duo_login(duo, user, host, flags,
                    cfg.pushinfo ? cmd : NULL, cfg.failmode);
        if (code == DUO_FAIL) {
            duo_log(LOG_WARNING, "Failed Duo login",
                pw->pw_name, host, duo_geterr(duo));
            if ((flags & DUO_FLAG_SYNC) == 0) {
                pam_info(pamh, "%s", "");
            }
            /* Keep going */
            continue;
        }
        /* Terminal conditions */
        if (code == DUO_OK) {
            if ((p = duo_geterr(duo)) != NULL) {
                duo_log(LOG_WARNING, "Skipped Duo login",
                    user, host, p);
            } else {
                duo_log(LOG_INFO, "Successful Duo login",
                    user, host, NULL);
            }
            pam_err = PAM_SUCCESS;
        } else if (code == DUO_ABORT) {
            duo_log(LOG_WARNING, "Aborted Duo login",
                user, host, duo_geterr(duo));
            pam_err = PAM_ABORT;
        } else if (code == DUO_FAIL_SAFE_ALLOW) {
            duo_log(LOG_WARNING, "Failsafe Duo login",
                user, host, duo_geterr(duo));
            pam_err = PAM_SUCCESS;
        } else if (code == DUO_FAIL_SECURE_DENY) {
            duo_log(LOG_WARNING, "Failsecure Duo login",
                user, host, duo_geterr(duo));
            pam_err = PAM_SERVICE_ERR;
        } else {
            duo_log(LOG_ERR, "Error in Duo login",
                user, host, duo_geterr(duo));
            pam_err = PAM_SERVICE_ERR;
        }
        break;
    }

    if (i == cfg.prompts) {
        pam_err = PAM_MAXTRIES;
    }

    duo_close(duo);
    close_config(&cfg);

    return (pam_err);
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{
    return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{
    return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{
    return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{
    return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{
    return (PAM_SERVICE_ERR);
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_duo");
#endif
