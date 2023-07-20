/*
 * SPDX-License-Identifier: BSD-4-Clause
 *
 * Copyright (c) 1983, 1988, 1993
 *   The Regents of the University of California.  All rights reserved.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#if defined(LIBC_SCCS) && !defined(lint)
static char rcsid[] = "$OpenBSD: syslog.c,v 1.8 1998/03/19 00:30:03 millert Exp $";
#endif /* LIBC_SCCS and not lint */

void
vsyslog(pri, fmt, ap)
        int pri;
        register const char *fmt;
        va_list ap;
{
        register char ch, *t;

        int saved_errno;
#define   TBUF_LEN   2048
#define   FMT_LEN      1024
        char tbuf[TBUF_LEN], fmt_cpy[FMT_LEN];
        int fmt_left, prlen;

        saved_errno = errno;

        /* Build the message. */

        /*
         * We wouldn't need this mess if printf handled %m, or if
         * strerror() had been invented before syslog().
         */
        for (t = fmt_cpy, fmt_left = FMT_LEN; (ch = *fmt); ++fmt) {
                if (ch == '%' && fmt[1] == 'm') {
                        ++fmt;
                        prlen = snprintf(t, fmt_left, "%s",
                            strerror(saved_errno));
                        if (prlen >= fmt_left)
                                prlen = fmt_left - 1;
                        t += prlen;
                        fmt_left -= prlen;
                } else {
                        if (fmt_left > 1) {
                                *t++ = ch;
                                fmt_left--;
                        }
                }
        }
        *t = '\0';

        prlen = vsnprintf(tbuf, TBUF_LEN, fmt_cpy, ap);

        syslog(pri, "%s", tbuf);

        return;
}
