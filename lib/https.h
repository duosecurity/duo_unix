/*
 * SPDX-License-Identifier: GPL-2.0-with-classpath-exception
 *
 * https.h
 *
 * Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved.
 */

#ifndef HTTPS_H
#define HTTPS_H

#include <time.h>

typedef struct https_request https_t;

typedef enum {
    HTTPS_OK,
    HTTPS_ERR_SYSTEM,   /* system problem */
    HTTPS_ERR_LIB,      /* library problem */
    HTTPS_ERR_CLIENT,   /* something you did */
    HTTPS_ERR_SERVER,   /* something the server did */
} HTTPScode;

/* Initialize HTTPS library. min_tls is a DUO_MIN_TLS_* value (0 leaves the
 * negotiated floor at the library default). */
HTTPScode https_init(const char *cafile, const char *http_proxy, int min_tls);

/* Open HTTPS connection to host[:port] */
HTTPScode https_open(https_t **hp, const char *host, const char *useragent);

/* Send request, return 0 for success or -1 on error */
HTTPScode https_send(
    https_t *h,
    const char *method,
    const char *uri,
    int param_cnt,
    char *params[],
    const char *ikey,
    const char *skey,
    const char *useragent,
    long time_offset
);

/* Read response, return HTTP status code, set body and length if available.
 * Wait msecs milliseconds for a response.  To disable a timeout, set msecs
 * to -1.
 */
HTTPScode https_recv(
    https_t *h,
    int *code,
    const char **body,
    int *length,
    time_t *retry_after,
    int msecs
);

/* Return and clear last API error */
const char *https_geterr(void);

/* Close HTTP connection */
void https_close(https_t **hp);

#endif /* HTTPS_H */
