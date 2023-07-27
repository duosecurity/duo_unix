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
  #if defined(WIN32)
    #define _DEFAULT_SHELL  "c:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe"
  #else
    #define _DEFAULT_SHELL "/bin/sh"
  #endif
#endif

#endif
