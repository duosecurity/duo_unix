/* 
SPDX-License-Identifier: BSD-3-Clause
 
inih -- simple .INI file parser

Copyright (c) 2009, Ben Hoyt
All rights reserved.

inih is released under the New BSD license (see LICENSE.txt). Go to the project
home page for more info:

http://code.google.com/p/inih/

*/

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <limits.h>
#include <string.h>

#include "ini.h"

#define INITIAL_LINE 200
#define MAX_SECTION 50
#define MAX_NAME 50

/* Strip whitespace chars off end of given string, in place. Return s. */
static char* rstrip(char* s)
{
    char* p = s + strlen(s);
    while (p > s && isspace(*--p))
        *p = '\0';
    return s;
}

/* Return pointer to first non-whitespace char in given string. */
static char* lskip(const char* s)
{
    while (*s && isspace(*s))
        s++;
    return (char*)s;
}

/* Return pointer to first char c or ';' comment in given string, or pointer to
   null at end of string if neither found. ';' must be prefixed by a whitespace
   character to register as a comment. */
static char* find_char_or_comment(const char* s, char c)
{
    int was_whitespace = 0;
    while (*s && *s != c && !(was_whitespace && *s == ';')) {
        was_whitespace = isspace(*s);
        s++;
    }
    return (char*)s;
}

/* Version of strncpy that ensures dest (size bytes) is null-terminated. */
static char* strncpy0(char* dest, const char* src, size_t size)
{
    strncpy(dest, src, size);
    dest[size - 1] = '\0';
    return dest;
}

/* Zero memory in a way the compiler can't optimize away. Config lines may
   contain secrets (skey), so line buffers are always scrubbed before they're
   freed. */
static void ini_zero(void* p, size_t n)
{
#ifdef HAVE_EXPLICIT_BZERO
    explicit_bzero(p, n);
#else
    static void* (* volatile ini_memset)(void *, int, size_t) = memset;
    ini_memset(p, 0, n);
#endif
}

/* Read one whole line (including its newline, if any) into *buf, growing the
   buffer as needed so long lines are never split. *buf and *size describe a
   heap buffer owned by the caller, which must scrub and free it. Returns 1 if
   a line was read, 0 at end of file, or -1 on allocation failure. */
static int read_line(FILE* file, char** buf, size_t* size)
{
    size_t len = 0;

    for (;;) {
        char* bigger;
        size_t new_size;

        if (fgets(*buf + len, (int)(*size - len), file) == NULL) {
            /* End of file, possibly after a final line with no newline. */
            return (len > 0);
        }
        len += strlen(*buf + len);
        if (len < *size - 1 || (*buf)[len - 1] == '\n') {
            /* fgets() stopped before filling the buffer (newline or EOF). */
            return 1;
        }

        /* The buffer filled up without reaching the end of the line. Grow it
           by hand rather than with realloc(), so the old copy can be scrubbed
           before it's freed. */
        if (*size > INT_MAX / 2) {
            return -1;
        }
        new_size = *size * 2;
        bigger = malloc(new_size);
        if (bigger == NULL) {
            return -1;
        }
        memcpy(bigger, *buf, len + 1);
        ini_zero(*buf, *size);
        free(*buf);
        *buf = bigger;
        *size = new_size;
    }
}

/* See documentation in header file. */
int ini_parse(FILE *file,
              int (*handler)(void*, const char*, const char*, const char*),
              void* user)
{
    char* line;
    size_t line_size = INITIAL_LINE;
    int rc;
    char section[MAX_SECTION] = "";
    char prev_name[MAX_NAME] = "";

    char* start;
    char* end;
    char* name;
    char* value;
    int lineno = 0;
    int error = 0;

    line = malloc(line_size);
    if (line == NULL) {
        return -3;
    }

    /* Scan through file line by line */
    while ((rc = read_line(file, &line, &line_size)) > 0) {
        lineno++;
        start = lskip(rstrip(line));

#if INI_ALLOW_MULTILINE
        if (*prev_name && *start && start > line) {
            /* Non-black line with leading whitespace, treat as continuation
               of previous name's value (as per Python ConfigParser). */
            value = lskip(start);
            /* Skip line if this line is a comment with whitespace infront.
               Both ';' and '#' start a comment, as on an unindented line. */
            if (*value == ';' || *value == '#') {
                continue;
            }
            if (!handler(user, section, prev_name, start) && !error) {
                error = lineno;
                break;
            }
        }
        else
#endif
        if (*start == ';' || *start == '#') {
            /* Per Python ConfigParser, allow '#' comments at start of line */
        }
        else if (*start == '[') {
            /* A "[section]" line */
            end = find_char_or_comment(start + 1, ']');
            if (*end == ']') {
                *end = '\0';
                strncpy0(section, start + 1, sizeof(section));
                *prev_name = '\0';
            }
            else if (!error) {
                /* No ']' found on section line */
                error = lineno;
                break;
            }
        }
        else if (*start && *start != ';') {
            /* Not a comment, must be a name=value pair */
            end = find_char_or_comment(start, '=');
            if (*end == '=') {
                *end = '\0';
                name = rstrip(start);
                value = lskip(end + 1);
                end = find_char_or_comment(value, '\0');
                if (*end == ';')
                    *end = '\0';
                rstrip(value);

                /* Valid name=value pair found, call handler */
                strncpy0(prev_name, name, sizeof(prev_name));
                if (!handler(user, section, name, value) && !error) {
                    error = lineno;
                    break;
                }
            }
            else if (!error) {
                /* No '=' found on name=value line */
                error = lineno;
                break;
            }
        }
    }

    if (rc < 0 && !error) {
        /* Out of memory. Report it as an internal error rather than a parse
           error, since this isn't a problem with the config file. */
        error = -3;
    }

    ini_zero(line, line_size);
    free(line);
    return error;
}
