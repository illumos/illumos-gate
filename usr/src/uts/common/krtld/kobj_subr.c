/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>

/*
 * Standalone copies of some basic routines.
 */

int
strcmp(const char *s1, const char *s2)
{
	if (s1 == s2)
		return (0);
	while (*s1 == *s2++)
		if (*s1++ == '\0')
			return (0);
	return (*s1 - s2[-1]);
}

/*
 * Compare strings (at most n bytes): return *s1-*s2 for the last
 * characters in s1 and s2 which were compared.
 */
int
strncmp(const char *s1, const char *s2, size_t n)
{
	if (s1 == s2)
		return (0);
	n++;
	while (--n != 0 && *s1 == *s2++)
		if (*s1++ == '\0')
			return (0);
	return ((n == 0) ? 0 : *s1 - *--s2);
}

size_t
strlen(const char *s)
{
	const char *s0 = s + 1;

	while (*s++ != '\0')
		;
	return (s - s0);
}

char *
strcpy(char *s1, const char *s2)
{
	char *os1 = s1;

	while (*s1++ = *s2++)
		;
	return (os1);
}

char *
strncpy(char *s1, const char *s2, size_t n)
{
	char *os1 = s1;

	n++;
	while ((--n != 0) && ((*s1++ = *s2++) != '\0'))
		;
	if (n != 0)
		while (--n != 0)
			*s1++ = '\0';
	return (os1);
}

char *
strcat(char *s1, const char *s2)
{
	char *os1 = s1;

	while (*s1++)
		;
	--s1;
	while (*s1++ = *s2++)
		;
	return (os1);
}

char *
strchr(const char *sp, int c)
{

	do {
		if (*sp == (char)c)
			return ((char *)sp);
	} while (*sp++);
	return (NULL);
}

void
bzero(void *p_arg, size_t count)
{
	char zero = 0;
	caddr_t p = p_arg;

	while (count != 0)
		*p++ = zero, count--;	/* Avoid clr for 68000, still... */
}

void
bcopy(const void *src_arg, void *dest_arg, size_t count)
{
	caddr_t src = (caddr_t)src_arg;
	caddr_t dest = dest_arg;

	if (src < dest && (src + count) > dest) {
		/* overlap copy */
		while (--count != -1)
			*(dest + count) = *(src + count);
	} else {
		while (--count != -1)
			*dest++ = *src++;
	}
}
