/*
  urlenc.c

  Copyright (c) 2010 Duo Security
  Copyright (c) 1996 - 2010, Daniel Stenberg, <daniel@haxx.se>.
  
  All rights reserved.
  
  Permission to use, copy, modify, and distribute this software for any purpose
  with or without fee is hereby granted, provided that the above copyright
  notice and this permission notice appear in all copies.
  
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS. IN
  NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
  DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
  OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
  OR OTHER DEALINGS IN THE SOFTWARE.
  
  Except as contained in this notice, the name of a copyright holder shall not
  be used in advertising or otherwise to promote the sale, use or other dealings
  in this Software without prior written authorization of the copyright holder.
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

char *
urlenc_decode(const char *string, size_t *olen)
{
	size_t alloc, strindex=0;
	char *ns = NULL;
	unsigned char in;
	long hex;
	
	if (!string) return NULL;
	alloc = strlen(string) + 1;
	if ((ns = malloc(alloc)) == NULL)
		return (NULL);
	
	while(--alloc > 0) {
		in = *string;
		if (('%' == in) && isxdigit(string[1]) && isxdigit(string[2])) {
			char hexstr[3]; /* '%XX' */
			hexstr[0] = string[1];
			hexstr[1] = string[2];
			hexstr[2] = 0;
			hex = strtol(hexstr, NULL, 16);
			in = (unsigned char)hex; /* hex is always < 256 */
			string += 2;
			alloc -= 2;
		} else if ('+' == in) {
			in = ' ';
		}
		ns[strindex++] = in;
		string++;
	}
	ns[strindex] = 0;
	if (olen) *olen = strindex;
	return (ns);
}
