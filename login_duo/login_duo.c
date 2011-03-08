/*
 * login_duo.c
 *
 * Copyright (c) 2010 Duo Security
 * All rights reserved, all wrongs reversed.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "duo.h"
#include "ini.h"

#ifndef DUO_PRIVSEP_USER
# define DUO_PRIVSEP_USER	"duo"
#endif
#define DUO_CONF		"/etc/duo/login_duo.conf"
#define MAX_RETRIES		3

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

struct login_ctx {
	struct passwd	*pw;
	const char	*config;
	const char	*host;
	const char	*duouser;
};

#define _err(...)	syslog(LOG_ERR, __VA_ARGS__)
#define _info(...)	syslog(LOG_INFO, __VA_ARGS__)
#define _warn(...)	syslog(LOG_WARNING, __VA_ARGS__)

static void
die(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fprintf(stderr, "\n");
	exit(EXIT_FAILURE);
}

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
			fprintf(stderr, "No such group: '%s'\n", val);
			return (0);
		}
		cfg->gid = gr->gr_gid;
	} else if (strcmp(name, "minuid") == 0) {
		char *p;
		cfg->minuid = strtol(val, &p, 10);
		if (p == val) {
			fprintf(stderr, "Invalid minimum UID: '%s'\n", val);
			return (0);
		}
	} else if (strcmp(name, "noconn") == 0) {
		if (strcmp(val, "deny") == 0) {
			cfg->noconn = DUO_OPT_DENY;
		} else if (strcmp(val, "allow") == 0) {
			cfg->noconn = DUO_OPT_ALLOW;
		} else {
			fprintf(stderr, "Invalid noconn value: '%s'\n", val);
			return (0);
		}
	} else if (strcmp(name, "noverify") == 0) {
		if (strcmp(val, "yes") == 0 || strcmp(val, "true") == 0 ||
		    strcmp(val, "1") == 0) {
			cfg->noverify = 1;
		}
	} else {
		fprintf(stderr, "Invalid login_duo option: '%s'\n", name);
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

static int
drop_privs(uid_t uid, gid_t gid)
{
	if (setgid(gid) < 0)
		return (-1);
	if (setuid(uid) < 0)
		return (-1);
	if (getgid() != gid || getuid() != uid)
		return (-1);
	return (0);
}

static int
do_auth(struct login_ctx *ctx)
{
	struct duo_config cfg;
	duo_t *duo;
	duo_code_t code;
	const char *config, *user;
	char *ip, *p, buf[32];
	int i, flags, ret, tries;

	user = ctx->duouser ? ctx->duouser : ctx->pw->pw_name;
	config = ctx->config ? ctx->config : DUO_CONF;
	flags = 0;
	tries = MAX_RETRIES;
	
	memset(&cfg, 0, sizeof(cfg));
	cfg.minuid = cfg.gid = -1;
	cfg.noconn = DUO_OPT_ALLOW;
	
	/* Load our private config. */
	i = duo_parse_config(config, __ini_handler, &cfg);
	if (i == -2) {
		struct passwd *pw;
		if ((pw = getpwuid(getuid())) == NULL)
			die("who are you?");
		die("%s must be readable only by user '%s'",
		    config, pw->pw_name);
	} else if (i == -1) {
		die("Couldn't open %s: %s", config, strerror(errno));
	} else if (i > 0) {
		die("Parse error in %s, line %d", config, i);
	} else if (!cfg.skey || !cfg.skey[0] || !cfg.ikey || !cfg.ikey[0]) {
		die("Missing ikey or skey in %s", config);
	}
	/* Check group membership. */
	if (cfg.gid != -1) {
		if ((i = _check_group(user, cfg.gid)) < 0) {
			_err("Couldn't get groups for '%s': %m", user);
			return (EXIT_FAILURE);
		} else if (i == 0) {
			/* User not in configured group for Duo auth */
			return (EXIT_SUCCESS);
		}
	}
	/* Check UID range */
	if (cfg.minuid != -1 && ctx->pw->pw_uid < cfg.minuid) {
		/* User below minimum UID for Duo auth */
		return (EXIT_SUCCESS);
	}
	/* Try Duo auth. */
	if ((duo = duo_open(cfg.ikey, cfg.skey)) == NULL) {
		_err("Couldn't open Duo API handle");
		return (EXIT_FAILURE);
	}
	if (cfg.host)
		duo_set_host(duo, cfg.host);
	if (cfg.noverify)
		duo_set_ssl_verify(duo, 0);
	
	/* Special SSH handling */
	if ((ip = getenv("SSH_CONNECTION")) != NULL) {
		strlcpy(buf, ip, sizeof(buf));
		ip = strtok(buf, " ");

		if ((p = getenv("SSH_ORIGINAL_COMMAND")) != NULL) {
			/* Try to support automatic one-shot login */
			duo_set_conv_funcs(duo, NULL, NULL, NULL);
			flags = (DUO_FLAG_SYNC|DUO_FLAG_AUTO);
			tries = 1;
		}
	}
	ret = EXIT_FAILURE;
	
	for (i = 0; i < tries; i++) {
		code = duo_login(duo, user, ip, flags);

		if (code == DUO_FAIL) {
			_warn("Failed Duo login for %s: %s",
			    user, duo_geterr(duo));
			if ((flags & DUO_FLAG_SYNC) == 0)
				printf("\n");
			/* Keep going */
			continue;
		}
		/* Terminal conditions */
		if (code == DUO_OK) {
			_info("Successful Duo login for %s", user);
			ret = EXIT_SUCCESS;
		} else if (code == DUO_ABORT) {
			_warn("Aborted Duo login for %s: %s",
			    user, duo_geterr(duo));
		} else if (code == DUO_CONN_ERROR && cfg.noconn) {
			_warn("Allowed Duo login for '%s' on connection failure: %s",
			    user, duo_geterr(duo));
		} else if (code == DUO_CLIENT_ERROR) {
			fprintf(stderr, "%s\n", duo_geterr(duo));
		} else {
			_err("Error in Duo login for %s: (%d) %s",
			    user, code, duo_geterr(duo));
		}
		break;
	}
	duo_close(duo);

	return (ret);
}

static char *
_argv_to_string(int argc, char *argv[])
{
	char *s;
	int i, j, n;
	
	for (n = i = 0; i < argc; i++) {
		n += strlen(argv[i]) + 1;
	}
	if (n == 0 || (s = malloc(n)) == NULL) {
		return (NULL);
	}
	for (n = i = 0; i < argc; i++) {
		for (j = 0; argv[i][j] != '\0'; j++) {
			s[n++] = argv[i][j];
		}
		s[n++] = ' ';
	}
	s[--n] = '\0';
	
	return (s);
}

static void
do_exec(struct login_ctx *ctx, int argc, char *argv[])
{
	const char *shell0;
	char *cmd, argv0[256];
	int n;
	
	if (argc > 0) {
		if ((cmd = _argv_to_string(argc, argv)) == NULL)
			die("error converting arguments to command");
	} else {
		cmd = getenv("SSH_ORIGINAL_COMMAND");
	}
	if ((shell0 = strrchr(ctx->pw->pw_shell, '/')) != NULL) {
		shell0++;
	} else {
		shell0 = ctx->pw->pw_shell;
	}
	if (cmd != NULL) {
		execl(ctx->pw->pw_shell, shell0, "-c", cmd, NULL);
	} else {
		n = snprintf(argv0, sizeof(argv0), "-%s", shell0);
		if (n == -1 || n >= sizeof(argv0)) {
			die("%s: Invalid argument", ctx->pw->pw_shell);
		}
		execl(ctx->pw->pw_shell, argv0, NULL);
	}
	die("%s: %s", ctx->pw->pw_shell, strerror(errno));
}

static void
usage(void)
{
	die("Usage: login_duo [-c config] [-h host] [-f duouser] [prog [args...]]");
}

int
main(int argc, char *argv[])
{
	struct login_ctx ctx[1];
	struct passwd *duo_pw;
	pid_t pid;
	int c, stat;
	
	memset(ctx, 0, sizeof(ctx));
	
	while ((c = getopt(argc, argv, "sc:h:f:")) != -1) {
		switch (c) {
		case 'c':
			ctx->config = optarg;
			break;
		case 'h':
			ctx->host = optarg;
			break;
		case 'f':
			ctx->duouser = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	
	if ((ctx->pw = getpwuid(getuid())) == NULL) {
		die("Who are you?");
	}
	if (geteuid() != getuid()) {
		/* Setuid-root operation protecting private config. */
		if (ctx->config != NULL || ctx->duouser != NULL ||
		    ctx->host != NULL) {
			die("Only root may specify -c, -f, or -h");
		}
		if ((duo_pw = getpwnam(DUO_PRIVSEP_USER)) == NULL) {
			die("User '%s' not found", DUO_PRIVSEP_USER);
		}
		endpwent();
		
		if ((pid = fork()) == 0) {
			/* Unprivileged auth child. */
			if (drop_privs(duo_pw->pw_uid, duo_pw->pw_gid) != 0) {
				die("couldn't drop privileges: %s",
				    strerror(errno));
			}
			exit(do_auth(ctx));
		} else {
			/* Parent continues as user. */
			if (drop_privs(getuid(), getgid()) != 0) {
				die("couldn't drop privileges: %s",
				    strerror(errno));
			}
			/* Check auth child status. */
			if (waitpid(pid, &stat, 0) != pid) {
				die("waitpid: %s", strerror(errno));
			}
			if (WEXITSTATUS(stat) == 0) {
				do_exec(ctx, argc, argv);
			}
		}
	} else {
		/* Non-setuid root operation or running as root. */
		if (getuid() != 0 && ctx->duouser != NULL) {
			die("Only root may specify an alternate user");
		}
		if (do_auth(ctx) == EXIT_SUCCESS) {
			do_exec(ctx, argc, argv);
		}
	}
	exit(EXIT_FAILURE);
}
