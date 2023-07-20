/* $OpenBSD: match.h,v 1.15 2010/02/26 20:29:54 djm Exp $ */

/*
 * SPDX-License-Identifier: SSH-short
 *
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 */
#ifndef MATCH_H
#define MATCH_H

int	 match_pattern(const char *, const char *);
int	 match_pattern_list(const char *, const char *, u_int, int);

#endif
