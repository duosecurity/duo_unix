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
#include "pam_extra.h"

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#define DUO_CONF	"/etc/duo/pam_duo.conf"
#define MAX_RETRIES	3

#define _err(...)	syslog(LOG_ERR, __VA_ARGS__)
#define _info(...)	syslog(LOG_INFO, __VA_ARGS__)
#define _warn(...)	syslog(LOG_WARNING, __VA_ARGS__)

enum {
	DUO_OPT_DENY = 0,
	DUO_OPT_ALLOW,
};

struct duo_config {
	char	*ikey;
	char	*skey;
	char	*host;
	int	 minuid;
	int	 gid;
	int	 noconn;	/* Duo connection failure: DUO_OPT_* */
	int	 noverify;
};

static int
__ini_handler(void *u, const char *section, const char *name, const char *val)
{
	struct duo_config *cfg = (struct duo_config *)u;

	if (strcmp(name, "ikey") == 0) {
		cfg->ikey = strdup(val);
	} else if (strcmp(name, "skey") == 0) {
		cfg->skey = strdup(val);
	} else if (strcmp(name, "host") == 0) {
		cfg->host = strdup(val);
	} else if (strcmp(name, "group") == 0) {
		struct group *gr;
		if ((gr = getgrnam(val)) == NULL) {
			_err("No such group: '%s'", val);
			return (0);
		}
		cfg->gid = gr->gr_gid;
	} else if (strcmp(name, "minuid") == 0) {
		char *p;
		cfg->minuid = strtol(val, &p, 10);
		if (p == val) {
			_err("Invalid minimum UID: '%s'", val);
			return (0);
		}
	} else if (strcmp(name, "noconn") == 0) {
		if (strcmp(val, "deny") == 0) {
			cfg->noconn = DUO_OPT_DENY;
		} else if (strcmp(val, "allow") == 0) {
			cfg->noconn = DUO_OPT_ALLOW;
		} else {
			_err("Invalid noconn value: '%s'", val);
			return (0);
		}
	} else if (strcmp(name, "noverify") == 0) {
		if (strcmp(val, "yes") == 0 || strcmp(val, "true") == 0 ||
		    strcmp(val, "1") == 0) {
			cfg->noverify = 1;
		}
	} else {
		_err("Invalid login_duo option: '%s'", name);
		return (0);
	}
	return (1);
}

static int
_check_group(const char *user, int gid)
{
#ifdef __APPLE__
	int *groups;
#else
	gid_t *groups;
#endif
	int i, ret = 0, count = NGROUPS_MAX;

	if ((groups = malloc(count * sizeof(*groups))) != NULL) {
		if (getgrouplist(user, 0, groups, &count) >= 0) {
			for (i = 0; i < count; i++) {
				if (groups[i] == gid) {
					ret = 1;
					break;
				}
			}
		} else ret = -1;
		
		free(groups);
	}
	return (ret);
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

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int pam_flags,
    int argc, const char *argv[])
{
	struct duo_config cfg;
	struct passwd *pw;
	duo_t *duo;
	duo_code_t code;
	duopam_const char *config, *ip, *service, *user;
	char buf[128];
	int i, flags, pam_err;

	memset(&cfg, 0, sizeof(cfg));
	cfg.minuid = cfg.gid = -1;

	/* Parse configuration */
	config = DUO_CONF;
	if (argc == 1 && strncmp("conf=", argv[0], 5) == 0) {
		config = argv[0] + 5;
	} else if (argc > 0) {
		_err("Invalid pam_duo configuration");
		return (PAM_SERVICE_ERR);
	}
	i = duo_parse_config(config, __ini_handler, &cfg);
	if (i == 0) {
		if (!cfg.skey || !cfg.ikey) {
			_err("Missing ikey or skey in %s", config);
			return (PAM_SERVICE_ERR);
		}
	} else {
		if (i == -2) {
			_err("%s must be readable only by owner", config);
		} else if (i == -1) {
			_err("Couldn't open %s: %s", config, strerror(errno));
		} else {
			_err("Parse error in %s, line %d", config, i);
		}
		return (PAM_SERVICE_ERR);
	}
	/* Check user */
	if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS ||
	    (pw = getpwnam(user)) == NULL) {
		return (PAM_USER_UNKNOWN);
	}
	/* Check group membership */
	if (cfg.gid >= 0) {
		if ((i = _check_group(user, cfg.gid)) < 0) {
			_err("Couldn't get groups for '%s': %m", user);
			return (PAM_SERVICE_ERR);
		} else if (i == 0) {
			/* User not in configured group for Duo auth */
			return (PAM_SUCCESS);
		}
	}
	/* Check UID range */
	if (cfg.minuid >= 0 && pw->pw_uid < cfg.minuid) {
		/* User below minimum UID - skip Duo auth */
		return (PAM_SUCCESS);
	}
	/*
	 * XXX - Disable incremental status reporting for sshd :-(
	 * OpenSSH accumulates PAM_TEXT_INFO from modules to send in
	 * an SSH_MSG_USERAUTH_BANNER post-auth, not real-time!
	 */
	flags = 0;
	if (pam_get_item(pamh, PAM_SERVICE, (duopam_const void **)
		(duopam_const void *)&service) == PAM_SUCCESS) {
		if (strcmp(service, "sshd") == 0)
			flags |= DUO_FLAG_SYNC;
	}
	ip = NULL;
	if (pam_get_item(pamh, PAM_RHOST, (duopam_const void **)
		(duopam_const void *)&ip) == PAM_SUCCESS) {
		struct addrinfo hints, *info;
		
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		if (getaddrinfo(ip, NULL, &hints, &info) == 0) {
			getnameinfo(info->ai_addr, info->ai_addrlen,
			    buf, sizeof(buf), NULL, 0, NI_NUMERICHOST);
			freeaddrinfo(info);
			ip = buf;
		} else {
			ip = NULL;
		}
	}
	/* Try Duo auth */
	if ((duo = duo_open(cfg.ikey, cfg.skey)) == NULL) {
		_err("Couldn't open Duo API handle");
		return (PAM_SERVICE_ERR);
	}
	duo_set_conv_funcs(duo, __duo_prompt, __duo_status, pamh);

	if (cfg.host)
		duo_set_host(duo, cfg.host);
	if (cfg.noverify)
		duo_set_ssl_verify(duo, 0);
	pam_err = PAM_SERVICE_ERR;
	
	for (i = 0; i < MAX_RETRIES; i++) {
		code = duo_login(duo, user, ip, flags);

		pam_info(pamh, "%s", "");
		
		if (code == DUO_OK) {
			_info("Successful Duo login for %s", user);
			pam_err = PAM_SUCCESS;
		} else if (code == DUO_FAIL) {
			_warn("Failed Duo login for %s: %s",
			    user, duo_geterr(duo));
			pam_err = PAM_AUTH_ERR;
		} else if (code == DUO_ABORT) {
			_warn("Aborted Duo login for %s: %s",
			    user, duo_geterr(duo));
			pam_err = PAM_ABORT;
		} else if (code == DUO_CONN_ERROR && cfg.noconn) {
			_warn("Allowed Duo login for '%s' on connection failure: %s",
			    user, duo_geterr(duo));
			pam_err = PAM_SUCCESS;
		} else {
			_err("Error in Duo login for %s: (%d) %s",
			    user, code, duo_geterr(duo));
			pam_err = PAM_SERVICE_ERR;
		}
		if (pam_err == PAM_SUCCESS || pam_err != PAM_AUTH_ERR)
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
