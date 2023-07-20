/*
 * SPDX-License-Identifier: BSD-3-Clause OR GPL-1.0-only
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef HAVE_PAM_VPROMPT

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif

#include "pam_extra.h"

/* OpenGroup RFC86.0 and XSSO specify no "const" on arguments */
#if defined(__LINUX_PAM__) || defined(OPENPAM)
# define duopam_const   const   /* LinuxPAM, OpenPAM */
#else
# define duopam_const           /* Solaris, HP-UX, AIX */
#endif

#define __overwrite(x)				  \
	do {					  \
		register char *__xx__;		  \
		if ((__xx__=(x)))		  \
			while (*__xx__)		  \
				*__xx__++ = '\0'; \
	} while (0)

#define __drop(X)		     \
	do {			     \
		if (X) {	     \
			free(X);     \
			X=NULL;      \
		}		     \
	} while (0)

int
pam_vprompt(pam_handle_t *pamh, int style, char **response,
    const char *fmt, va_list args)
{
    struct pam_message msg;
    struct pam_response *pam_resp = NULL;
    const struct pam_conv *conv;
    duopam_const struct pam_message *pmsg;
    duopam_const void *convp;
    char *msgbuf;
    int retval;

    if (response) {
        *response = NULL;
    }

    retval = pam_get_item(pamh, PAM_CONV, &convp);
    if (retval != PAM_SUCCESS) {
        return retval;
    }
    conv = convp;
    if (conv == NULL || conv->conv == NULL) {
        syslog(LOG_ERR, "no conversation function");
        return PAM_SYSTEM_ERR;
    }

    if (vasprintf(&msgbuf, fmt, args) < 0) {
        syslog(LOG_ERR, "vasprintf: %m");
        return PAM_BUF_ERR;
    }

    msg.msg_style = style;
    msg.msg = msgbuf;
    pmsg = &msg;

    retval = conv->conv(1, &pmsg, &pam_resp, conv->appdata_ptr);
    if (retval != PAM_SUCCESS && pam_resp != NULL) {
        syslog(LOG_WARNING,
            "unexpected response from failed conversation function");
    }
    if (response) {
        *response = pam_resp == NULL ? NULL : pam_resp->resp;
    } else if (pam_resp && pam_resp->resp) {
        __overwrite(pam_resp->resp);
        __drop(pam_resp->resp);
    }
    __overwrite(msgbuf);
    __drop(pam_resp);
    free(msgbuf);
    if (retval != PAM_SUCCESS) {
        syslog(LOG_ERR, "conversation failed");
    }

    return retval;
}

int
pam_prompt(pam_handle_t *pamh, int style, char **response,
    const char *fmt, ...)
{
    va_list args;
    int retval;

    va_start(args, fmt);
    retval = pam_vprompt(pamh, style, response, fmt, args);
    va_end(args);

    return retval;
}

#endif /* HAVE_PAM_VPROMPT */
