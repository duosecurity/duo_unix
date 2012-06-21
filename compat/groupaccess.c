/* $OpenBSD: groupaccess.c,v 1.13 2008/07/04 03:44:59 djm Exp $ */
/*
 * Copyright (c) 2001 Kevin Steves.  All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>

#include <grp.h>
#ifdef HAVE_LIMITS_H
# include <limits.h>
#endif
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "groupaccess.h"
#include "match.h"

static int ngroups;
static char **groups_byname;

/*
 * Initialize group access list for user with primary (base) and
 * supplementary groups.  Return the number of groups in the list.
 */
int
ga_init(const char *user, gid_t base)
{
	gid_t *groups_bygid;
	int i, j;
	struct group *gr;

	if (ngroups > 0)
		ga_free();

	ngroups = NGROUPS_MAX;
#if defined(HAVE_SYSCONF) && defined(_SC_NGROUPS_MAX)
#ifndef MAX
# define MAX(a,b) (((a)>(b))?(a):(b))
#endif        
	ngroups = MAX(NGROUPS_MAX, sysconf(_SC_NGROUPS_MAX));
#endif

	if (!(groups_bygid = calloc(ngroups, sizeof(*groups_bygid))) ||
	    !((groups_byname = calloc(ngroups, sizeof(*groups_byname))))) {
		free(groups_bygid);
		free(groups_byname);
		return (-1);
	}
	if (getgrouplist(user, base, groups_bygid, &ngroups) == -1)
		return (-1);
	for (i = 0, j = 0; i < ngroups; i++)
		if ((gr = getgrgid(groups_bygid[i])) != NULL)
			groups_byname[j++] = strdup(gr->gr_name);
	free(groups_bygid);
	return (ngroups = j);
}

/*
 * Return 1 if one of user's groups is contained in groups.
 * Return 0 otherwise.  Use match_pattern() for string comparison.
 */
int
ga_match(char * const *groups, int n)
{
	int i, j;

	for (i = 0; i < ngroups; i++)
		for (j = 0; j < n; j++)
			if (match_pattern(groups_byname[i], groups[j]))
				return 1;
	return 0;
}

/*
 * Return 1 if one of user's groups matches group_pattern list.
 * Return 0 on negated or no match.
 */
int
ga_match_pattern_list(const char *group_pattern)
{
	int i, found = 0;
	size_t len = strlen(group_pattern);

	for (i = 0; i < ngroups; i++) {
		switch (match_pattern_list(groups_byname[i],
		    group_pattern, len, 0)) {
		case -1:
			return 0;	/* Negated match wins */
		case 0:
			continue;
		case 1:
			found = 1;
		}
	}
	return found;
}

/*
 * Free memory allocated for group access list.
 */
void
ga_free(void)
{
	int i;

	if (ngroups > 0) {
		for (i = 0; i < ngroups; i++)
			free(groups_byname[i]);
		ngroups = 0;
		free(groups_byname);
	}
}
