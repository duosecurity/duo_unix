/*
 * SPDX-License-Identifier: GPL-2.0-with-classpath-exception
 *
 * shell.h
 *
 * Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved.
 */

#ifndef SHELL_H
#define SHELL_H

/* Which shell should we use by default if there's not one provided by getpwuid(3)? */
#ifndef _DEFAULT_SHELL
#define _DEFAULT_SHELL "/bin/sh"
#endif

#endif
