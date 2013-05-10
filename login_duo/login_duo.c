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
#include "groupaccess.h"

#ifndef DUO_PRIVSEP_USER
# define DUO_PRIVSEP_USER	"duo"
#endif
#define DUO_CONF		DUO_CONF_DIR "/login_duo.conf"
#define MAX_RETRIES		3
#define MAX_GROUPS		256
#define MOTD_FILE		"/etc/motd"

enum {
	DUO_FAIL_SAFE = 0,
	DUO_FAIL_SECURE,
};

struct duo_config {
	char	*ikey;
	char	*skey;
	char	*apihost;
	char	*cafile;
	char	*http_proxy;
	char	*groups[MAX_GROUPS];
	int	 groups_cnt;
	int	 failmode;	/* Duo failure handling: DUO_FAIL_* */
    int	 pushinfo;
	int	 noverify;
	int  autopush;
	int  motd;
};

struct login_ctx {
	const char	*config;
	const char	*duouser;
	const char	*host;
        uid_t		 uid;
};

int debug = 0;

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
	char *buf, *p;
	
	if (strcmp(name, "ikey") == 0) {
		cfg->ikey = strdup(val);
	} else if (strcmp(name, "skey") == 0) {
		cfg->skey = strdup(val);
	} else if (strcmp(name, "host") == 0) {
		cfg->apihost = strdup(val);
	} else if (strcmp(name, "cafile") == 0) {
		cfg->cafile = strdup(val);
	} else if (strcmp(name, "http_proxy") == 0) {
		cfg->http_proxy = strdup(val);
	} else if (strcmp(name, "groups") == 0 || strcmp(name, "group") == 0) {
		if ((buf = strdup(val)) == NULL) {
			fprintf(stderr, "Out of memory parsing groups\n");
			return (0);
		}
		for (p = strtok(buf, " "); p != NULL; p = strtok(NULL, " ")) {
			if (cfg->groups_cnt >= MAX_GROUPS) {
				fprintf(stderr, "Exceeded max %d groups\n",
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
	} else if (strcmp(name, "autopush") == 0) {
		if (strcmp(val, "yes") == 0 || strcmp(val, "true") == 0 ||
			strcmp(val, "on") == 0 || strcmp(val, "1") == 0) {
			cfg->autopush = 1;
		}
	} else if (strcmp(name, "motd") == 0) {
		if (strcmp(val, "yes") == 0 || strcmp(val, "true") == 0 ||
			strcmp(val, "on") == 0 || strcmp(val, "1") == 0) {
			cfg->motd = 1;
		}		
	} else {
		fprintf(stderr, "Invalid login_duo option: '%s'\n", name);
		return (0);
	}
	return (1);
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
	if (debug) {
		fprintf(stderr, "[%d] %s\n", priority, buf);
	} else {
		syslog(priority, "%s", buf);
	}
}

static int
_print_motd()
{
	FILE *fp;
	struct stat st;
	int fd, bytes_read;
	size_t nbytes = 80;
	char *line;

	if ((line = (char *) malloc(nbytes + 1)) == NULL) {
		fprintf(stderr, "Out of memory printing MOTD\n");
		return (-1);
	}
	if ((fd = open(MOTD_FILE, O_RDONLY)) < 0 ) {
		return (-1);
	}
	if (fstat(fd, &st) < 0 || (fp = fdopen(fd, "r")) == NULL) {
		close(fd);
		return (-1);
	}

	while ((bytes_read = getline(&line, &nbytes, fp)) > 0) {
		printf("%s", line);
	}
	free(line);
	line = NULL;
	return (0);
}

static int
do_auth(struct login_ctx *ctx, const char *cmd)
{
	struct duo_config cfg;
    struct passwd *pw;
	duo_t *duo;
	duo_code_t code;
	const char *config, *p, *duouser;
	char *ip, buf[64];
	int i, flags, ret, tries;
	int headless = 0;

        if ((pw = getpwuid(ctx->uid)) == NULL)
                die("Who are you?");
        
	duouser = ctx->duouser ? ctx->duouser : pw->pw_name;
	config = ctx->config ? ctx->config : DUO_CONF;
	flags = 0;
	tries = MAX_RETRIES;
	
	memset(&cfg, 0, sizeof(cfg));
        cfg.failmode = DUO_FAIL_SAFE;
        
	/* Load our private config. */
	if ((i = duo_parse_config(config, __ini_handler, &cfg)) != 0 ||
            (!cfg.apihost || !cfg.apihost[0] || !cfg.skey || !cfg.skey[0] ||
                !cfg.ikey || !cfg.ikey[0])) {
                switch (i) {
                case -2:
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
	if (cfg.groups_cnt > 0) {
		int matched = 0;
		
		if (ga_init(pw->pw_name, pw->pw_gid) < 0) {
			_log(LOG_ERR, "Couldn't get groups",
			    pw->pw_name, NULL, strerror(errno));
			return (EXIT_FAILURE);
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
			return (EXIT_SUCCESS);
	}
	/* Check for remote login host */
	if ((ip = getenv("SSH_CONNECTION")) != NULL ||
	    (ip = (char *)ctx->host) != NULL) {
		strlcpy(buf, ip, sizeof(buf));
		ip = strtok(buf, " ");
	}

	/* Honor configured http_proxy */
	if (cfg.http_proxy != NULL) {
		setenv("http_proxy", cfg.http_proxy, 1);
	}

	/* Try Duo auth. */
	if ((duo = duo_open(cfg.apihost, cfg.ikey, cfg.skey,
                    "login_duo/" PACKAGE_VERSION,
                    cfg.noverify ? "" : cfg.cafile)) == NULL) {
		_log(LOG_ERR, "Couldn't open Duo API handle",
		    pw->pw_name, ip, NULL);
		return (EXIT_FAILURE);
	}
	/* Special handling for non-interactive sessions */
	if ((p = getenv("SSH_ORIGINAL_COMMAND")) != NULL ||
	    !isatty(STDIN_FILENO)) {
		/* Try to support automatic one-shot login */
		duo_set_conv_funcs(duo, NULL, NULL, NULL);
		flags = (DUO_FLAG_SYNC|DUO_FLAG_AUTO);
		tries = 1;
		headless = 1;
    }

    /* Special handling for autopush */
    if (cfg.autopush) {
		duo_set_conv_funcs(duo, NULL, NULL, NULL);
		flags = (DUO_FLAG_SYNC|DUO_FLAG_AUTO);
    }

	ret = EXIT_FAILURE;
	
	for (i = 0; i < tries; i++) {
		code = duo_login(duo, duouser, ip, flags,
                    cfg.pushinfo ? cmd : NULL);
		if (code == DUO_FAIL) {
			_log(LOG_WARNING, "Failed Duo login",
			    duouser, ip, duo_geterr(duo));
			if ((flags & DUO_FLAG_SYNC) == 0) {
				printf("\n");
			}
			/* The autopush failed, fall back to regular process */
			if (cfg.autopush && i == 0) {
				flags = 0;
				duo_reset_conv_funcs(duo);
			}
			/* Keep going */
			continue;
		}
		/* Terminal conditions */
		if (code == DUO_OK) {
            if ((p = duo_geterr(duo)) != NULL) {
				_log(LOG_WARNING, "Skipped Duo login",
				    duouser, ip, p);
            } else {
				_log(LOG_INFO, "Successful Duo login",
				    duouser, ip, NULL);
            }
			if (cfg.motd && !headless) {
				_print_motd();
			}
			ret = EXIT_SUCCESS;
		} else if (code == DUO_ABORT) {
			_log(LOG_WARNING, "Aborted Duo login",
			    duouser, ip, duo_geterr(duo));
		} else if (cfg.failmode == DUO_FAIL_SAFE &&
                    (code == DUO_CONN_ERROR ||
                     code == DUO_CLIENT_ERROR || code == DUO_SERVER_ERROR)) {
			_log(LOG_WARNING, "Failsafe Duo login",
			    duouser, ip, duo_geterr(duo));
                        ret = EXIT_SUCCESS;
		} else {
			_log(LOG_ERR, "Error in Duo login",
			    duouser, ip, duo_geterr(duo));
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
		execl(pw->pw_shell, shell0, "-c", cmd, (char *)NULL);
	} else {
		n = snprintf(argv0, sizeof(argv0), "-%s", shell0);
		if (n == -1 || n >= sizeof(argv0)) {
			die("%s: Invalid argument", pw->pw_shell);
		}
		execl(pw->pw_shell, argv0, (char *)NULL);
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
version(void)
{
	die("login_duo " PACKAGE_VERSION);
}

static void
usage(void)
{
	die("Usage: login_duo [-v] [-c config] [-d] [-f duouser] [-h host] [prog [args...]]");
}

int
main(int argc, char *argv[])
{
	struct login_ctx ctx[1];
	struct passwd *pw;
	pid_t pid;
	int c, stat;
	
	memset(ctx, 0, sizeof(ctx));
	
	while ((c = getopt(argc, argv, "vc:df:h:?")) != -1) {
		switch (c) {
		case 'v':
			version();
			break;
		case 'c':
			ctx->config = optarg;
			break;
		case 'd':
			debug = 1;
			break;
		case 'f':
			ctx->duouser = optarg;
			break;
		case 'h':
			ctx->host = optarg;
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
