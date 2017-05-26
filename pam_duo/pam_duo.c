/*
 * pam_duo.c
 *
 * Copyright (c) 2010 Duo Security
 * All rights reserved, all wrongs reversed.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <netdb.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

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
#include <security/pam_ext.h>	/* Linux-PAM */
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

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#ifndef DUO_PRIVSEP_USER
# define DUO_PRIVSEP_USER	"duo"
#endif
#define DUO_CONF		DUO_CONF_DIR "/pam_duo.conf"

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
    pam_info((pam_handle_t *)arg, "%s", msg);
}

static char *
__duo_prompt(void *arg, const char *prompt, char *buf, size_t bufsz)
{
    char *p = NULL;

    if (pam_prompt((pam_handle_t *)arg, PAM_PROMPT_ECHO_ON, &p,
        "%s", prompt) != PAM_SUCCESS || p == NULL) {
        return (NULL);
    }
    strlcpy(buf, p, bufsz);
    free(p);
    return (buf);
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int pam_flags,
    int argc, const char *argv[])
{
	struct duo_config cfg;
	struct passwd *pw;
	struct in_addr addr;
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
	const char *cmd, *p, *config, *host;

	int i, flags, pam_err, matched;

	/*
	 * Handle a delimited GECOS field. E.g.
	 *
	 *     username:x:0:0:code1/code2/code3//textField/usergecosparsed:/username:/bin/bash
	 *
	 * Parse the username from the appropriate position in the GECOS field.
	 */
	const char delimiter = '/';
	const unsigned int delimited_position = 5;

	duo_config_default(&cfg);

	/* Parse configuration */
	config = DUO_CONF;
	for (i = 0; i < argc; i++) {
		if (strncmp("conf=", argv[i], 5) == 0) {
			config = argv[i] + 5;
		} else if (strcmp("debug", argv[i]) == 0) {
			duo_debug = 1;
		} else {
			duo_syslog(LOG_ERR, "Invalid pam_duo option: '%s'",
			    argv[i]);
			return (PAM_SERVICE_ERR);
		}
	}
	i = duo_parse_config(config, __ini_handler, &cfg);
	if (i == -2) {
		duo_syslog(LOG_ERR, "%s must be readable only by user 'root'",
		    config);
		return (cfg.failmode == DUO_FAIL_SAFE ? PAM_SUCCESS : PAM_SERVICE_ERR);
	} else if (i == -1) {
		duo_syslog(LOG_ERR, "Couldn't open %s: %s",
		    config, strerror(errno));
		return (cfg.failmode == DUO_FAIL_SAFE ? PAM_SUCCESS : PAM_SERVICE_ERR);
	} else if (i > 0) {
		duo_syslog(LOG_ERR, "Parse error in %s, line %d", config, i);
		return (cfg.failmode == DUO_FAIL_SAFE ? PAM_SUCCESS : PAM_SERVICE_ERR);
	} else if (!cfg.apihost || !cfg.apihost[0] ||
            !cfg.skey || !cfg.skey[0] || !cfg.ikey || !cfg.ikey[0]) {
        duo_syslog(LOG_ERR, "Missing host, ikey, or skey in %s", config);
        return (cfg.failmode == DUO_FAIL_SAFE ? PAM_SUCCESS : PAM_SERVICE_ERR);
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
         */
        flags |= DUO_FLAG_SYNC;
    } else if (strcmp(service, "sudo") == 0) {
        cmd = getenv("SUDO_COMMAND");
    } else if (strcmp(service, "su") == 0 || strcmp(service, "su-l") == 0) {
        /* Check calling user for Duo auth, just like sudo */
        if ((pw = getpwuid(getuid())) == NULL) {
            close_config(&cfg);
            return (PAM_USER_UNKNOWN);
        }
        user = pw->pw_name;
    }
    /* Check group membership */
    matched = duo_check_groups(pw, cfg.groups, cfg.groups_cnt);
    if (matched == -1) {
        close_config(&cfg);
        return (PAM_SERVICE_ERR);
    } else if (matched == 0) {
        close_config(&cfg);
        return (PAM_SUCCESS);
    }

    /* Use GECOS field if called for */
    if (cfg.send_gecos || cfg.gecos_parsed) {
        if (strlen(pw->pw_gecos) > 0) {
            if (cfg.gecos_parsed) {
                user = duo_split_at(pw->pw_gecos, delimiter, delimited_position);
                if (user == NULL || (strcmp(user, "") == 0)) {
                    duo_log(LOG_DEBUG, "Could not parse GECOS field", pw->pw_name, NULL, NULL);
                    user = pw->pw_name;
                }
            } else {
                user = pw->pw_gecos;
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
    if (!inet_aton(ip, &addr)) {
        /* We have a hostname, don't try to resolve, check fallback */
        if (cfg.local_ip_fallback) {
            host = duo_local_ip();
        }
    }

    /* Try Duo auth */
    if ((duo = duo_open(cfg.apihost, cfg.ikey, cfg.skey,
                    "pam_duo/" PACKAGE_VERSION,
                    cfg.noverify ? "" : cfg.cafile, cfg.https_timeout, cfg.http_proxy)) == NULL) {
        duo_log(LOG_ERR, "Couldn't open Duo API handle", pw->pw_name, host, NULL);
        close_config(&cfg);
        return (PAM_SERVICE_ERR);
    }
    duo_set_conv_funcs(duo, __duo_prompt, __duo_status, pamh);

    if (cfg.autopush) {
        flags |= DUO_FLAG_AUTO;
    }

    pam_err = PAM_SERVICE_ERR;

    for (i = 0; i < cfg.prompts; i++) {
        code = duo_login(duo, user, host, flags,
                    cfg.pushinfo ? cmd : NULL);
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
                    pw->pw_name, host, p);
            } else {
                duo_log(LOG_INFO, "Successful Duo login",
                    pw->pw_name, host, NULL);
            }
            pam_err = PAM_SUCCESS;
        } else if (code == DUO_ABORT) {
            duo_log(LOG_WARNING, "Aborted Duo login",
                pw->pw_name, host, duo_geterr(duo));
            pam_err = PAM_ABORT;
        } else if (cfg.failmode == DUO_FAIL_SAFE &&
                    (code == DUO_CONN_ERROR ||
                     code == DUO_CLIENT_ERROR || code == DUO_SERVER_ERROR)) {
            duo_log(LOG_WARNING, "Failsafe Duo login",
                pw->pw_name, host, duo_geterr(duo));
            pam_err = PAM_SUCCESS;
        } else {
            duo_log(LOG_ERR, "Error in Duo login",
                pw->pw_name, host, duo_geterr(duo));
            pam_err = PAM_SERVICE_ERR;
        }
        break;
    }
    if (i == MAX_PROMPTS) {
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
