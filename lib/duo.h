/*
 * duo.h
 *
 * Copyright (c) 2010 Duo Security
 * All rights reserved, all wrongs reversed.
 */

#ifndef DUO_H
#define DUO_H

typedef enum {
	DUO_CONTINUE = -1,		/* continue authentication */
	DUO_OK = 0,			/* great success! */
	DUO_FAIL,			/* nice try */
	DUO_ABORT,			/* give up */
	DUO_LIB_ERROR,			/* unexpected library error */
	DUO_CONN_ERROR,			/* problem connecting */
	DUO_CLIENT_ERROR,		/* you screwed up */
	DUO_SERVER_ERROR,		/* we screwed up */
} duo_code_t;

#define DUO_FLAG_SYNC	(1 << 0)	/* no incremental status reporting */
#define DUO_FLAG_AUTO	(1 << 1)	/* use default factor without prompt */
#define DUO_FLAG_ENV    (1 << 2)    /* Get factor from environment variable */

#define DUO_ENV_VAR_NAME "DUO_PASSCODE"

#define DUO_NO_TIMEOUT -1

typedef struct duo_ctx duo_t;

/* Parse INI config file */
int duo_parse_config(
    const char *filename,
    int (*callback)(void *arg, const char *section, const char *name, const char *val),
    void *arg
);

/* Open Duo API handle */
duo_t *duo_open(
    const char *host,
    const char *ikey,
    const char *skey,
    const char *progname,
    const char *cafile,
    int https_timeout,
    const char *http_proxy
);

/* Override conversation prompt/status functions */
void duo_set_conv_funcs(
    duo_t *d,
    char *(*conv_prompt)(void *conv_arg, const char *prompt, char *buf, size_t bufsz),
    void (*conv_status)(void *conv_arg, const char *msg),
    void *conv_arg
);

/* Reset the conversation prompt/status functions back to default */
void duo_reset_conv_funcs(duo_t *d);

/* Perform Duo authentication */
duo_code_t duo_login(
    duo_t *d,
    const char *username,
    const char *client_ip,
    int flags,
    const char *command
);

/* Return error message from last API call */
const char *duo_geterr(duo_t *d);

/* Close API handle. */
duo_t *duo_close(duo_t *d);

#endif /* DUO_H */
