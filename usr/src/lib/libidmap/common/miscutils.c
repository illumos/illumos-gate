/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Miscellaneous utility functions not specifically related to
 * the application.
 */

#include <string.h>
#include <sys/types.h>
#include <stdarg.h>
#include <stdio.h>
#include <malloc.h>
#include <ctype.h>
#include "miscutils.h"

/* Return true if strings are equal */
boolean_t
streq(const char *a, const char *b)
{
	return (strcmp(a, b) == 0);
}

/* Return true if strings are equal, case-insensitively */
boolean_t
strcaseeq(const char *a, const char *b)
{
	return (strcasecmp(a, b) == 0);
}

/* Return true if string a Begins With string b */
boolean_t
strbw(const char *a, const char *b)
{
	return (strncmp(a, b, strlen(b)) == 0);
}

/*
 * Duplicate up to n bytes of a string.  Kind of sort of like
 * strdup(strlcpy(s, n)).
 */
char *
strndup(const char *s, int n)
{
	int len;
	char *p;

	len = strnlen(s, n);
	p = malloc(len + 1);
	if (p == NULL)
		return (NULL);

	if (len > 0)
		(void) memcpy(p, s, len);
	p[len] = '\0';

	return (p);
}

/*
 * Duplicate a block of memory.  Combines malloc with memcpy, much as
 * strdup combines malloc, strlen, and strcpy.
 */
void *
memdup(const void *buf, size_t sz)
{
	void *p;

	p = malloc(sz);
	if (p == NULL)
		return (NULL);
	(void) memcpy(p, buf, sz);
	return (p);
}

/*
 * Dump a block of memory in hex+ascii, for debugging
 */
void
dump(FILE *out, const char *prefix, const void *buf, size_t len)
{
	const unsigned char *p = buf;
	int i;

	for (i = 0; i < len; i += 16) {
		int j;

		(void) fprintf(out, "%s", prefix);
		for (j = 0; j < 16 && i + j < len; j++) {
			(void) fprintf(out, "%2.2x ", p[i + j]);
		}
		for (; j < 16; j++) {
			(void) fprintf(out, "   ");
		}
		for (j = 0; j < 16 && i + j < len; j++) {
			(void) fprintf(out, "%c",
			    isprint(p[i + j]) ? p[i + j] : '.');
		}
		(void) fprintf(out, "\n");
	}
}
