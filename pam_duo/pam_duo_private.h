/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * pam_duo_private.h
 *
 * Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved.
 */

#include <stdlib.h>
#include <string.h>
#include "util.h"

/* Parses argv to get the configuration file location and the debug/quiet modes */
int
parse_argv(const char **config, int argc, const char *argv[]);
