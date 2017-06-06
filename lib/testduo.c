/*
 * testduo.c
 *
 * Copyright (c) 2010 Duo Security
 * All rights reserved, all wrongs reversed.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "duo.h"

int
main(int argc, char *argv[])
{
	duo_t *duo;
	duo_code_t code;
	char *host, *ikey, *skey, *username;
	int i, flags, retries;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <username>\n", argv[0]);
		exit(1);
	}
	username = argv[1];
	flags = 0;
	retries = 3;
	
	if ((host = getenv("DUO_API_HOST")) == NULL ||
            (ikey = getenv("DUO_IKEY")) == NULL ||
            (skey = getenv("DUO_SKEY")) == NULL) {
		fprintf(stderr, "missing DUO_API_HOST or DUO_IKEY or "
                    "DUO_SKEY environment\n");
		exit(1);
	}
	if ((duo = duo_open(host, ikey, skey, "testduo", NULL, DUO_NO_TIMEOUT, NULL)) == NULL) {
		fprintf(stderr, "duo_open failed\n");
		exit(1);
	}
	if (getenv("DUO_SYNC")) {
		flags |= DUO_FLAG_SYNC;
	}
	if (getenv("DUO_AUTO")) {
		    flags |= DUO_FLAG_AUTO;
		    retries = 1;
	}
	for (i = 0; i < retries; i++) {
		code = duo_login(duo, username, NULL, flags, "test");
		
		printf("\n");
		
		if (code == DUO_OK) {
			fprintf(stderr, "(log) OK %s\n", duo_geterr(duo));
		} else if (code == DUO_FAIL) {
			fprintf(stderr, "(log) FAIL %s\n", duo_geterr(duo));
		} else if (code == DUO_ABORT) {
			fprintf(stderr, "(log) ABORT %s\n", duo_geterr(duo));
		} else {
			fprintf(stderr, "(log) ERROR(%d) %s\n", code, duo_geterr(duo));
		}
		if (code == DUO_OK || code != DUO_FAIL)
			break;
	}
	duo_close(duo);
		
	return (0);
}
