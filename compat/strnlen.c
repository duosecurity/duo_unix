/*	$OpenBSD: strnlen.c,v 1.9 2019/01/25 00:19:25 millert Exp $	*/

/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2010 Todd C. Miller <millert@openbsd.org>
 */

#include <sys/types.h>

#include <string.h>

size_t
strnlen(const char *str, size_t maxlen)
{
	const char *cp;

	for (cp = str; maxlen != 0 && *cp != '\0'; cp++, maxlen--)
		;

	return (size_t)(cp - str);
}
// XXX DUO MOD. Remove weak symbol declaration as it's not supported on all systems
// DEF_WEAK(strnlen);
