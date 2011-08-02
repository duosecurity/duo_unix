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
#define MAX_RETRIES		3
#define MAX_GROUPS		256

enum {
	DUO_FAIL_SAFE = 0,
	DUO_FAIL_SECURE,
};

int debug = 0;

struct duo_config {
	char	*ikey;
	char	*skey;
	char	*host;
	char	*cafile;
	char	*groups[MAX_GROUPS];
	int	 groups_cnt;
	int	 failmode;	/* Duo failure handling: DUO_FAIL_* */
        int	 pushinfo;
	int	 noverify;
};

static void
_syslog(int priority, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (debug) {
		fprintf(stderr, "[%d] ", priority);
		vfprintf(stderr, fmt, ap);
		fputs("\n", stderr);
	} else {
		vsyslog(priority, fmt, ap);
	}
	va_end(ap);
}

static int
__ini_handler(void *u, const char *section, const char *name, const char *val)
{
	struct duo_config *cfg = (struct duo_config *)u;
	char *buf, *p;
	
	if (strcmp(name, "ikey") == 0) {
		cfg->ikey = strdup(val);
	} else if (strcmp(name, "skey") == 0) {
		cfg->skey = strdup(val);
	} else if (strcmp(name, "host") == 0) {
		cfg->host = strdup(val);
	} else if (strcmp(name, "cafile") == 0) {
		cfg->cafile = strdup(val);
	} else if (strcmp(name, "groups") == 0 || strcmp(name, "group") == 0) {
		if ((buf = strdup(val)) == NULL) {
			_syslog(LOG_ERR, "Out of memory parsing groups");
			return (0);
		}
		for (p = strtok(buf, " "); p != NULL; p = strtok(NULL, " ")) {
			if (cfg->groups_cnt >= MAX_GROUPS) {
			        _syslog(LOG_ERR, "Exceeded max %d groups",
				    MAX_GROUPS);
				cfg->groups_cnt = 0;
				free(buf);
				return (0);
			}
			cfg->groups[cfg->groups_cnt++] = p;
		}
	} else if (strcmp(name, "failmode") == 0) {
		if (strcmp(val, "secure") == 0) {
			cfg->failmode = DUO_FAIL_SECURE;
		} else if (strcmp(val, "safe") == 0) {
			cfg->failmode = DUO_FAIL_SAFE;
		} else {
			_syslog(LOG_ERR, "Invalid failmode: '%s'", val);
			return (0);
		}
	} else if (strcmp(name, "pushinfo") == 0) {
		if (strcmp(val, "yes") == 0 || strcmp(val, "true") == 0 ||
		    strcmp(val, "on") == 0 || strcmp(val, "1") == 0) {
			cfg->pushinfo = 1;
		}
	} else if (strcmp(name, "noverify") == 0) {
		if (strcmp(val, "yes") == 0 || strcmp(val, "true") == 0 ||
		    strcmp(val, "on") == 0 || strcmp(val, "1") == 0) {
			cfg->noverify = 1;
		}
	} else {
		_syslog(LOG_ERR, "Invalid pam_duo option: '%s'", name);
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
	char *p;
	
	if (pam_prompt((pam_handle_t *)arg, PAM_PROMPT_ECHO_ON, &p,
		"%s", prompt) != PAM_SUCCESS) {
		return (NULL);
	}
	strlcpy(buf, p, bufsz);
	free(p);
	return (buf);
}

static void
_log(int priority, const char *msg,
    const char *user, const char *ip, const char *err)
{
	char buf[512];
	int i, n;

	n = snprintf(buf, sizeof(buf), "%s", msg);

	if (user != NULL &&
	    (i = snprintf(buf + n, sizeof(buf) - n, " for '%s'", user)) > 0) {
		n += i;
	}
	if (ip != NULL &&
	    (i = snprintf(buf + n, sizeof(buf) - n, " from %s", ip)) > 0) {
		n += i;
	}
	if (err != NULL &&
	    (i = snprintf(buf + n, sizeof(buf) - n, ": %s", err)) > 0) {
		n += i;
	}
	_syslog(priority, "%s", buf);
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int pam_flags,
    int argc, const char *argv[])
{
	struct duo_config cfg;
	struct passwd *pw;
	duo_t *duo;
	duo_code_t code;
	duopam_const char *config, *cmd, *ip, *p, *service, *user;
	int i, flags, pam_err;

	memset(&cfg, 0, sizeof(cfg));
        cfg.failmode = DUO_FAIL_SAFE;
        
	/* Check user */
	if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS ||
	    (pw = getpwnam(user)) == NULL) {
		return (PAM_USER_UNKNOWN);
	}
	/* Parse configuration */
	config = DUO_CONF;
	for (i = 0; i < argc; i++) {
		if (strncmp("conf=", argv[i], 5) == 0) {
			config = argv[i] + 5;
		} else if (strcmp("debug", argv[i]) == 0) {
			debug = 1;
		} else {
			_syslog(LOG_ERR, "Invalid pam_duo option: '%s'",
			    argv[i]);
			return (PAM_SERVICE_ERR);
		}
	}
	i = duo_parse_config(config, __ini_handler, &cfg);
	if (i == -2) {
		_syslog(LOG_ERR, "%s must be readable only by user 'root'",
		    config);
		return (PAM_SERVICE_ERR);
	} else if (i == -1) {
		_syslog(LOG_ERR, "Couldn't open %s: %s",
		    config, strerror(errno));
		return (PAM_SERVICE_ERR);
	} else if (i > 0) {
		_syslog(LOG_ERR, "Parse error in %s, line %d", config, i);
		return (PAM_SERVICE_ERR);
	} else if (!cfg.host || !cfg.host[0] ||
            !cfg.skey || !cfg.skey[0] || !cfg.ikey || !cfg.ikey[0]) {
		_syslog(LOG_ERR, "Missing host, ikey, or skey in %s", config);
		return (PAM_SERVICE_ERR);
	}
	/* Check group membership */
	if (cfg.groups_cnt > 0) {
		int matched = 0;

		if (ga_init(pw->pw_name, pw->pw_gid) < 0) {
			_log(LOG_ERR, "Couldn't get groups",
			    pw->pw_name, NULL, strerror(errno));
			return (PAM_SERVICE_ERR);
		}
		for (i = 0; i < cfg.groups_cnt; i++) {
			if (ga_match_pattern_list(cfg.groups[i])) {
				matched = 1;
				break;
			}
		}
		ga_free();

		/* User in configured groups for Duo auth? */
		if (!matched)
			return (PAM_SUCCESS);
	}

	/*
	 * XXX - Disable incremental status reporting for sshd :-(
	 * OpenSSH accumulates PAM_TEXT_INFO from modules to send in
	 * an SSH_MSG_USERAUTH_BANNER post-auth, not real-time!
	 */
	flags = 0;
        cmd = NULL;
	if (pam_get_item(pamh, PAM_SERVICE, (duopam_const void **)
		(duopam_const void *)&service) == PAM_SUCCESS) {
		if (strcmp(service, "sshd") == 0) {
			flags |= DUO_FLAG_SYNC;
                } else if (strcmp(service, "sudo") == 0) {
                        cmd = getenv("SUDO_COMMAND");
                }
	}
	ip = NULL;
	pam_get_item(pamh, PAM_RHOST,
	    (duopam_const void **)(duopam_const void *)&ip);
	
	/* Try Duo auth */
	if ((duo = duo_open(cfg.host, cfg.ikey, cfg.skey,
                    "pam_duo/" PACKAGE_VERSION,
                    cfg.noverify ? "" : cfg.cafile)) == NULL) {
		_log(LOG_ERR, "Couldn't open Duo API handle", user, ip, NULL);
		return (PAM_SERVICE_ERR);
	}
	duo_set_conv_funcs(duo, __duo_prompt, __duo_status, pamh);

	pam_err = PAM_SERVICE_ERR;
	
	for (i = 0; i < MAX_RETRIES; i++) {
		code = duo_login(duo, user, ip, flags,
                    cfg.pushinfo ? cmd : NULL);
		if (code == DUO_FAIL) {
			_log(LOG_WARNING, "Failed Duo login",
			    user, ip, duo_geterr(duo));
			if ((flags & DUO_FLAG_SYNC) == 0) {
				pam_info(pamh, "%s", "");
                        }
			/* Keep going */
			continue;
		}
		/* Terminal conditions */
		if (code == DUO_OK) {
			if ((p = duo_geterr(duo)) != NULL) {
				_log(LOG_WARNING, "Skipped Duo login",
				    user, ip, p);
			} else {
				_log(LOG_INFO, "Successful Duo login",
				    user, ip, NULL);
			}
			pam_err = PAM_SUCCESS;
		} else if (code == DUO_ABORT) {
			_log(LOG_WARNING, "Aborted Duo login",
			    user, ip, duo_geterr(duo));
			pam_err = PAM_ABORT;
		} else if (cfg.failmode == DUO_FAIL_SAFE &&
                    (code == DUO_CONN_ERROR ||
                     code == DUO_CLIENT_ERROR || code == DUO_SERVER_ERROR)) {
			_log(LOG_WARNING, "Failsafe Duo login",
			    user, ip, duo_geterr(duo));
			pam_err = PAM_SUCCESS;
		} else {
			_log(LOG_ERR, "Error in Duo login",
			    user, ip, duo_geterr(duo));
			pam_err = PAM_SERVICE_ERR;
		}
		break;
	}
	if (i == MAX_RETRIES) {
		pam_err = PAM_MAXTRIES;
	}
	duo_close(duo);
	
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
