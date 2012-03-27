/*
 * pam_duo_options.h
 *
 * Copyright (c) 2012 Diego Elio Pettenò
 * All rights reserved, all wrongs reversed.
 */

#ifndef PAM_DUO_OPTIONS_H__
#define PAM_DUO_OPTIONS_H__

#define PAM_OPT_DEBUG		0x01
#define PAM_OPT_TRY_FIRST_PASS	0x02
#define PAM_OPT_USE_FIRST_PASS	0x04
#define PAM_OPT_ECHO_PASS	0x08
#define PAM_OPT_USE_UID		0x10

int  pam_get_pass(pam_handle_t *, int, const char **, const char *, int);

#endif
