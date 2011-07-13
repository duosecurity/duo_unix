/*
 * pam-test-harness.c:
 * 
 * This is basically a heavily-instrumented PAM test application.  It is
 * intended to help debug PAM/sshd problems and study the behaviour of
 * PAM on various platforms.
 *
 * Compile with:
 * cc pam-test-harness.c -o pam-test-harness -lpam
 */

static const char rcsid[] =
    "$Id: pam-test-harness.c,v 1.31 2007/08/19 02:27:40 dtucker Exp $";

/* Copyright (c) 2004 Darren Tucker <dtucker at zip.com.au>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *
 * Based in part on OpenSSH's auth-pam.c which is under the following
 * copyright:
 *
 * Copyright (c) 2002 Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by ThinkSec AS and
 * NAI Labs, the Security Research Division of Network Associates, Inc.
 * under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"), as part of the
 * DARPA CHATS research program.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <sys/time.h>

#ifdef HAVE_PAM_PAM_APPL_H
# include <pam/pam_appl.h>
#else
# include <security/pam_appl.h>
#endif

#ifndef MAXHOSTNAMELEN
# define MAXHOSTNAMELEN 256
#endif

#ifdef LINUX_PAM	/* XXX: and OpenPAM? */
# define PAM_MSG_MEMBER(msg, n, member) ((msg)[(n)]->member)
#else
# define PAM_MSG_MEMBER(msg, n, member) ((*(msg))[(n)].member)
#endif

/* Globals */
static pam_handle_t *pamh = NULL;
static int verbose = 0;
extern char **environ;
static void *appdata = NULL;

void
usage(void)
{
	printf("usage: pam-test-harness [-?ahrtT] [-s servicename] [-u user]\n");
	printf("\n");
	printf("\t-a: Skip pam_authenticate\n");
	printf("\t-h: Don't define PAM_RHOST\n");
	printf("\t-r: Don't define PAM_RUSER\n");
	printf("\t-t: Don't define PAM_TTY\n");
	printf("\t-T: Set PAM_TTY to \"ssh\" (equivalent to PAM_TTY_KLUDGE)\n");
	printf("\t-v: Verbose mode (timestamps each message)\n");
	exit(0);
}

static const char *
timestamp(void)
{
	static char stamp[1024] = "";
	static struct timeval tv, start = {0, 0};
	double d = 0.0;

	if (gettimeofday(&tv, NULL) == -1)
		stamp[0] = '\0';
	else if (start.tv_sec == 0 && start.tv_usec == 0)
		start = tv;
	d = (tv.tv_sec - start.tv_sec) + (tv.tv_usec - start.tv_usec) / 1e6;
	snprintf(stamp, sizeof(stamp), "%0.2lf", d);
	return stamp;
}

static void
output(int newline, const char *fmt, ...)
{
	va_list ap;

	if (verbose)
		fprintf(stderr, "%-5s ", timestamp());
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (newline)
		fprintf(stderr, "\n");
}

char *
myreadpass(int echo /* unused */)
{
	char *p, buf[PAM_MAX_MSG_SIZE];
	
	fgets(buf, sizeof(buf), stdin);
	p = strchr(buf, '\n');
	if (p != NULL)
		*p = '\0';
	if (verbose)
		output(1, "%8s[conversation function returned]", "");
	return(strdup(buf));
}

void
print_result(result)
{
	output(1, " = %d (%s)", result, pam_strerror(pamh, result));
}

static void
check_pam_item(int item, const char *name, char *oldval)
{
	int result, changed = 0;
	char *value = NULL;

	output(verbose, "pam_get_item(pamh, %s, ...)", name);
	result = pam_get_item(pamh, item, (const void **)&value);
	print_result(result);
	if (result == PAM_SUCCESS) {
		if (value == NULL && oldval == NULL)
			changed = 0;
		else if ((value != NULL && oldval == NULL) ||
		    (value == NULL && oldval != NULL) ||
		    strcmp(oldval, value) != 0)
			changed = 1;
	}
	output(1, "    %s = %s (%s)", name, value ? value : "(null)",
	    changed ? "CHANGED" : "unchanged");
}

static int
my_conv(int n, const struct pam_message **msg,
    struct pam_response **resp, void *data)
{
	struct pam_response *reply;
	int i;

	output(1, "    conversation called with %d messages data 0x%x",
	    n, data ? data : "(null)");
	if (data != &appdata) {
		output(1, "   ERROR: conversation data does not match");
		output(1, "          (trashed by buggy PAM module?)");
	}

	*resp = NULL;
	if (n <= 0 || n > PAM_MAX_NUM_MSG)
		return (PAM_CONV_ERR);

	if ((reply = malloc(n * sizeof(*reply))) == NULL)
		return (PAM_CONV_ERR);
	memset(reply, 0, n * sizeof(*reply));

	for (i = 0; i < n; ++i) {
		switch (PAM_MSG_MEMBER(msg, i, msg_style)) {
		case PAM_PROMPT_ECHO_ON:
			output(0, "%8sPROMPT_ECHO_ON: %s", "",
			    PAM_MSG_MEMBER(msg, i, msg));
			reply[i].resp = myreadpass(1);
			reply[i].resp_retcode = PAM_SUCCESS;
			break;
		case PAM_PROMPT_ECHO_OFF:
			output(0, "%8sPROMPT_ECHO_OFF: %s", "",
			    PAM_MSG_MEMBER(msg, i, msg));
			reply[i].resp = myreadpass(0);
			reply[i].resp_retcode = PAM_SUCCESS;
			break;
		case PAM_ERROR_MSG:
			output(1, "%8sERROR_MSG: %s", "",
			    PAM_MSG_MEMBER(msg, i, msg));
			reply[i].resp = strdup("");
			reply[i].resp_retcode = PAM_SUCCESS;
			break;
		case PAM_TEXT_INFO:
			output(1, "%8sTEXT_INFO: %s", "",
			    PAM_MSG_MEMBER(msg, i, msg));
			reply[i].resp = strdup("");
			reply[i].resp_retcode = PAM_SUCCESS;
			break;
		default:
			output(1, "%8sUnknown message style %d", "",
			    PAM_MSG_MEMBER(msg, i, msg_style));
			goto fail;
		}
	}

	*resp = reply;
	return (PAM_SUCCESS);

 fail:
	for(i = 0; i < n; i++) {
		if (reply[i].resp != NULL)
			free(reply[i].resp);
	}
	free(reply);
	return (PAM_CONV_ERR);
}

static struct pam_conv conv = { my_conv, NULL };

int main(int argc, char *argv[])
{
	int i, opt, result, flags = 0, session_open = 0;
	int skip_auth = 0, no_tty = 0, tty_ssh = 0, no_host = 0, no_ruser = 0;
	char *service = NULL, *user = NULL, *tty = NULL;
	char **env, host[MAXHOSTNAMELEN];
	char *pamuser = NULL;
	struct passwd *pw;

	while ((opt = getopt(argc, argv, "?ahrs:StTu:v")) != -1) {
		switch (opt) {
		case 'a':
			skip_auth = 1;
			break;
		case 'h':
			no_host = 1;
			break;
		case 'r':
			no_ruser = 1;
			break;
		case 's':
			service = strdup(optarg);
			break;
		case 'S':
			flags |= PAM_SILENT;
		case 't':
			no_tty = 1;
			break;
		case 'T':
			tty_ssh = 1;
			break;
		case 'u':
			user = strdup(optarg);
			break;
		case 'v':
			verbose = 1;
			break;
		case '?':
			usage();
			break;
		}
	}

	if (no_tty && tty_ssh) {
		fprintf(stderr, "%s: -t and -T are mutually exclusive\n",
		    argv[0]);
		exit(1);
	}

	output(1, "%s", rcsid);

	environ[0] = NULL;

	if (service == NULL)
		service = strdup("testpam");

	appdata = malloc(1024);
	conv.appdata_ptr = &appdata;
	output(1, "conversation struct {conv=0x%x, appdata_ptr=0x%x}",
	    conv.conv, conv.appdata_ptr);

	output(verbose, "pam_start(%s, %s, &conv, &pamh)", service,
	    user == NULL ? "(NULL)" : user);
	result = pam_start(service, user, &conv, &pamh);
	print_result(result);
	if (result != PAM_SUCCESS)
		goto fail;

	check_pam_item(PAM_SERVICE, "PAM_SERVICE", service);

	if (!no_tty) {
		if (tty_ssh) {
			tty = "ssh";
		} else {
			tty = ttyname(0);
			if (tty == NULL) {
				output(0, "Can't get ttyname\n");
				goto fail;
			}
		}
		output(verbose, "pam_set_item(pamh, PAM_TTY, \"%s\")", tty);
		result = pam_set_item(pamh, PAM_TTY, tty);
		print_result(result);
		if (result != PAM_SUCCESS)
			goto fail;
	}

	if (!no_host) {
		if (gethostname(host, sizeof(host)) == -1) {
			output(1, "Can't get hostname");
			goto fail;
		}
		output(verbose, "pam_set_item(pamh, PAM_RHOST, \"%s\")", host);
		result = pam_set_item(pamh, PAM_RHOST, host);
		print_result(result);
		if (result != PAM_SUCCESS)
			goto fail;
	}
	
	if (!no_ruser) {
		pamuser = getlogin();
		if (pamuser == NULL) {
			output(verbose, "getlogin returned NULL (%s) "
			    ", skipping PAM_RUSER", strerror(errno));
		} else {
			output(verbose, "pam_set_item(pamh, PAM_RUSER, \"%s\")",
			    pamuser);
			result = pam_set_item(pamh, PAM_RUSER, pamuser);
			print_result(result);
			if (result != PAM_SUCCESS)
				goto fail;
		}
	}

	if (!skip_auth) {
		output(1, "pam_authenticate(pamh, 0x%x)", flags);
		result = pam_authenticate(pamh, flags);
		print_result(result);
		if (result != PAM_SUCCESS && result != PAM_IGNORE)
			goto fail;
	}

	output(verbose, "pam_acct_mgmt(pamh, 0x%x)", flags);
	result = pam_acct_mgmt(pamh, flags);
	print_result(result);
	if (result != PAM_SUCCESS && result != PAM_NEW_AUTHTOK_REQD &&
	    result != PAM_IGNORE)
		goto fail;

	if (result == PAM_NEW_AUTHTOK_REQD) {
		output(verbose, "pam_chauthtok(pamh, 0x%x)", flags);
		result = pam_chauthtok(pamh, PAM_CHANGE_EXPIRED_AUTHTOK);
		print_result(result);
		if (result != PAM_SUCCESS)
			goto fail;
	}

	output(verbose, "pam_open_session(pamh, 0x%x)", flags);
	result = pam_open_session(pamh, 0);
	print_result(result);
	if (result != PAM_SUCCESS && result != PAM_IGNORE)
		goto fail;
	session_open = 1;

	output(verbose, "pam_setcred(pamh, 0x%x)", flags);
	result = pam_setcred(pamh, 0);
	print_result(result);
	if (result != PAM_SUCCESS && result != PAM_IGNORE)
		goto fail;

	check_pam_item(PAM_SERVICE, "PAM_SERVICE", service);
	check_pam_item(PAM_USER, "PAM_USER", user);
	check_pam_item(PAM_TTY, "PAM_TTY", tty);

	output(1, "Standard environment variables:");
	for (i = 0; environ[i] != NULL; i++)
		output(1, "    %s\n", environ[i]);

#ifdef HAVE_PAM_GETENVLIST
	output(1, "PAM environment variables:");
	env = pam_getenvlist(pamh);
	for (i = 0; env[i] != NULL; i++)
		output(1, "    %s", env[i]);
#endif

	if ((pw = getpwnam(pamuser)) == NULL) {
		output(1, "getpwnam(%s) failed: %s\n", pamuser, strerror(errno));
		goto fail;
	}

	output(1, "uid %d euid %d gid %d egid %d", getuid(), geteuid(),
	    getgid(), getegid());

fail:
	if (session_open) {
		output(verbose, "pam_close_session(pamh, %d)", flags);
		result = pam_close_session(pamh, flags);
		print_result(result);
	}

	output(verbose, "pam_end(pamh, %d)", flags);
	result = pam_end(pamh, flags);
	print_result(result);
	if (result != PAM_SUCCESS)
		exit(6);
	
	exit(0);
}
