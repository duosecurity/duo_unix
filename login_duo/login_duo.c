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
#include <limits.h>
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
#define DUO_CONF		DUO_CONF_DIR "/login_duo.conf"
#define DUO_IP_DIR		DUO_CONF_DIR "/ip"
#define MAX_RETRIES		3

enum {
	DUO_FAIL_SAFE = 0,
	DUO_FAIL_SECURE,
};

struct duo_config {
	char	*ikey;
	char	*skey;
	char	*host;
	int	 minuid;
	int	 gid;
	int	 failmode;	/* Duo failure handling: DUO_FAIL_* */
        int	 pushinfo;
	int	 noverify;
	int	 onlynewip;
};

struct login_ctx {
	const char	*config;
	const char	*host;
	const char	*duouser;
        uid_t		 uid;
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
	} else if (strcmp(name, "failmode") == 0) {
		if (strcmp(val, "secure") == 0) {
			cfg->failmode = DUO_FAIL_SECURE;
		} else if (strcmp(val, "safe") == 0) {
			cfg->failmode = DUO_FAIL_SAFE;
		} else {
			fprintf(stderr, "Invalid failmode: '%s'\n", val);
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
	} else if (strcmp(name, "onlynewip") == 0) {
		if (strcmp(val, "yes") == 0 || strcmp(val, "true") == 0 ||
		    strcmp(val, "on") == 0 || strcmp(val, "1") == 0) {
			cfg->onlynewip = 1;
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
do_auth(struct login_ctx *ctx, const char *cmd)
{
	struct duo_config cfg;
        struct passwd *pw;
	duo_t *duo;
	duo_code_t code;
	const char *config, *p, *user;
	char *ip, ipfpname[MAXPATHLEN], buf[39], lastip[39];
	FILE *ipfp;
	struct stat st;
	int i, flags, ret, tries;

        if ((pw = getpwuid(ctx->uid)) == NULL)
                die("Who are you?");
        
	user = ctx->duouser ? ctx->duouser : pw->pw_name;
	config = ctx->config ? ctx->config : DUO_CONF;
	flags = 0;
	tries = MAX_RETRIES;
	
	memset(&cfg, 0, sizeof(cfg));
	cfg.minuid = cfg.gid = -1;
        cfg.failmode = DUO_FAIL_SAFE;
        
	/* Load our private config. */
	if ((i = duo_parse_config(config, __ini_handler, &cfg)) != 0 ||
            (!cfg.host || !cfg.host[0] || !cfg.skey || !cfg.skey[0] ||
                !cfg.ikey || !cfg.ikey[0])) {
                switch (i) {
                case -2:
                        if ((pw = getpwuid(getuid())) == NULL)
                                die("Who are you?");
                        fprintf(stderr, "%s must be readable only by "
                            "user '%s'\n", config, pw->pw_name);
                        break;
                case -1:
                        fprintf(stderr, "Couldn't open %s: %s\n",
                            config, strerror(errno));
                        break;
                case 0:
                        fprintf(stderr, "Missing host, ikey, or skey in %s\n",
                            config);
                        break;
                default:
                        fprintf(stderr, "Parse error in %s, line %d\n",
                            config, i);
                        break;
                }
                /* Implicit "safe" failmode for local configuration errors */
                if (cfg.failmode == DUO_FAIL_SAFE) {
                        return (EXIT_SUCCESS);
                }
                return (EXIT_FAILURE);
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
	if (cfg.minuid != -1 && ctx->uid < cfg.minuid) {
		/* User below minimum UID for Duo auth */
		return (EXIT_SUCCESS);
	}
	/* Try Duo auth. */
	if ((duo = duo_open(cfg.host, cfg.ikey, cfg.skey,
                    "login_duo/" PACKAGE_VERSION)) == NULL) {
		_err("Couldn't open Duo API handle");
		return (EXIT_FAILURE);
	}
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

	/* If onlynewip is enabled, skip auth if this user is coming from the
	 * same IP */
	if (cfg.onlynewip && ip != NULL) {
		do {
			if (snprintf(ipfpname, sizeof(ipfpname), "%s/%s",
			    DUO_IP_DIR, user) > sizeof(ipfpname)) {
				_warn("Couldn't build IP file path");
				ipfpname[0] = '\0';
				break;
			}

			if ((ipfp = fopen(ipfpname, "r")) == NULL)
				break;

			fgets(lastip, sizeof(lastip), ipfp);

			if (lastip != NULL && strcmp(lastip, ip) == 0) {
				/* User is at the same IP */
                                _info("Skipping Duo login for %s from same IP %s",
				    user, ip);
				duo_close(duo);
				return (DUO_OK);
			}
			fclose(ipfp);
		} while (0);
	}
	
	for (i = 0; i < tries; i++) {
		code = duo_login(duo, user, ip, flags,
                    cfg.pushinfo ? cmd : NULL);
		if (code == DUO_FAIL) {
                        if ((p = duo_geterr(duo)) != NULL) {
                                _warn("Failed Duo login for %s: %s", user, p);
                        } else {
			        _warn("Failed Duo login for %s", user);
                        }
			if ((flags & DUO_FLAG_SYNC) == 0) {
				printf("\n");
                        }
			/* Keep going */
			continue;
		}
		/* Terminal conditions */
		if (code == DUO_OK) {
                        if ((p = duo_geterr(duo)) != NULL) {
                                _warn("Skipping Duo login for %s: %s",
                                    user, p);
                        } else {
                                _info("Successful Duo login for %s", user);
                        }
			ret = EXIT_SUCCESS;
		} else if (code == DUO_ABORT) {
			_warn("Aborted Duo login for %s: %s",
			    user, duo_geterr(duo));
		} else if (cfg.failmode == DUO_FAIL_SAFE &&
                    (code == DUO_CONN_ERROR ||
                     code == DUO_CLIENT_ERROR || code == DUO_SERVER_ERROR)) {
			_warn("Allowed Duo login for '%s' on failure: %s",
			    user, duo_geterr(duo));
                        ret = EXIT_SUCCESS;
		} else {
			_err("Error in Duo login for %s: (%d) %s",
			    user, code, duo_geterr(duo));
		}

		/* Store the user's IP */
		if (cfg.onlynewip && ip != NULL && code == DUO_OK) {
			if (!strlen(ipfpname)) {
				_warn("No IP filename?");
				break;
			}

			if (!(stat(DUO_IP_DIR, &st) == 0 && S_ISDIR(st.st_mode)))
				if (mkdir(DUO_IP_DIR, 0700)) {
					_warn("Could not create dir %s: %m",
					    DUO_IP_DIR);
					break;
				}

			if ((ipfp = fopen(ipfpname, "w")) < 0) {
				_warn("Could not create %s: %m", ipfpname);
				break;
			}

			fputs(ip, ipfp);
			fclose(ipfp);
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
	if (n <= 0 || (s = malloc(n)) == NULL) {
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
do_exec(struct login_ctx *ctx, const char *cmd)
{
        struct passwd *pw;
	const char *shell0;
	char argv0[256];
	int n;

        if ((pw = getpwuid(ctx->uid)) == NULL)
                die("Who are you?");
        
	if ((shell0 = strrchr(pw->pw_shell, '/')) != NULL) {
		shell0++;
	} else {
		shell0 = pw->pw_shell;
	}
	if (cmd != NULL) {
		execl(pw->pw_shell, shell0, "-c", cmd, NULL);
	} else {
		n = snprintf(argv0, sizeof(argv0), "-%s", shell0);
		if (n == -1 || n >= sizeof(argv0)) {
			die("%s: Invalid argument", pw->pw_shell);
		}
		execl(pw->pw_shell, argv0, NULL);
	}
	die("%s: %s", pw->pw_shell, strerror(errno));
}

static char *
get_command(int argc, char *argv[])
{
        char *cmd;
        
        if (argc > 0) {
                if ((cmd = _argv_to_string(argc, argv)) == NULL)
                        die("error converting arguments to command");
        } else {
                cmd = getenv("SSH_ORIGINAL_COMMAND");
        }
        return (cmd);
}

static void
usage(void)
{
	die("Usage: login_duo [-c config] [-f duouser] [prog [args...]]");
}

int
main(int argc, char *argv[])
{
	struct login_ctx ctx[1];
	struct passwd *pw;
	pid_t pid;
	int c, stat;
	
	memset(ctx, 0, sizeof(ctx));
	
	while ((c = getopt(argc, argv, "sc:f:")) != -1) {
		switch (c) {
		case 'c':
			ctx->config = optarg;
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

        ctx->uid = getuid();
        
	if (geteuid() != ctx->uid) {
		/* Setuid-root operation protecting private config. */
		if (ctx->config != NULL || ctx->duouser != NULL) {
			die("Only root may specify -c or -f");
		}
		if ((pw = getpwnam(DUO_PRIVSEP_USER)) == NULL) {
			die("User '%s' not found", DUO_PRIVSEP_USER);
		}
		if ((pid = fork()) == 0) {
			/* Unprivileged auth child. */
			if (drop_privs(pw->pw_uid, pw->pw_gid) != 0) {
				die("couldn't drop privileges: %s",
				    strerror(errno));
			}
			exit(do_auth(ctx, get_command(argc, argv)));
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
 				do_exec(ctx, get_command(argc, argv));
			}
		}
	} else {
                char *cmd = get_command(argc, argv);
                
		/* Non-setuid root operation or running as root. */
		if (do_auth(ctx, cmd) == EXIT_SUCCESS) {
			do_exec(ctx, cmd);
		}
	}
	exit(EXIT_FAILURE);
}
