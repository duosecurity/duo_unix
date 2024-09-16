/*
  urlenc.c

  SPDX-License-Identifier: LicenseRef-URLEnc-MIT

  Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
  Copyright (c) 1996 - 2010, Daniel Stenberg, <daniel@haxx.se>.
  All rights reserved.
*/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
  Adapted from libcurl to honor RFC 3986 unreserved characters, add
  '+' space encoding, and check memory allocation failures
*/

char *
urlenc_encode(const char *string)
{
	size_t alloc, newlen;
	char *ns = NULL, *testing_ptr = NULL;
	unsigned char in;
	size_t strindex=0;
	size_t length;
	
	if (!string) return strdup("");
	
	alloc = strlen(string) + 1;
	newlen = alloc;
	
	if ((ns = malloc(alloc)) == NULL)
		return (NULL);
	
	length = alloc-1;
	while (length--) {
		in = *string;
		
		switch(in){
		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
		case 'a': case 'b': case 'c': case 'd': case 'e':
		case 'f': case 'g': case 'h': case 'i': case 'j':
		case 'k': case 'l': case 'm': case 'n': case 'o':
		case 'p': case 'q': case 'r': case 's': case 't':
		case 'u': case 'v': case 'w': case 'x': case 'y': case 'z':
		case 'A': case 'B': case 'C': case 'D': case 'E':
		case 'F': case 'G': case 'H': case 'I': case 'J':
		case 'K': case 'L': case 'M': case 'N': case 'O':
		case 'P': case 'Q': case 'R': case 'S': case 'T':
		case 'U': case 'V': case 'W': case 'X': case 'Y': case 'Z':
		case '_': case '~': case '.': case '-':
			ns[strindex++] = in;
			break;
		default:
			newlen += 2; /* this'll become a %XX */
			if (newlen > alloc) {
				alloc *= 2;
				if ((testing_ptr = realloc(ns, alloc)) == NULL) {
					free(ns);
					return (NULL);
				}
				ns = testing_ptr;
			}
			snprintf(&ns[strindex], 4, "%%%02X", in);
			strindex += 3;
			break;
		}
		string++;
	}
	ns[strindex] = 0;
	return (ns);
}
