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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#include "lint.h"
#include <string.h>
#include <stddef.h>
#include <sys/types.h>

/*
 * strstr() locates the first occurrence in the string as1 of
 * the sequence of characters (excluding the terminating null
 * character) in the string as2.  strstr() returns a pointer
 * to the located string, or a null pointer if the string is
 * not found.  If as2 is empty, the function returns as1.
 */

char *
strstr(const char *as1, const char *as2)
{
	const char *s1, *s2;
	const char *tptr;
	char c;

	s1 = as1;
	s2 = as2;

	if (s2 == NULL || *s2 == '\0')
		return ((char *)s1);

	c = *s2;
	while (*s1 != '\0') {
		if (c == *s1++) {
			tptr = s1;
			while ((c = *++s2) == *s1++ && c != '\0')
				continue;
			if (c == '\0')
				return ((char *)tptr - 1);
			s1 = tptr;
			s2 = as2;
			c = *s2;
		}
	}

	return (NULL);
}

/*
 * strnstr() locates the first occurrence in the string as1 of
 * the sequence of characters (excluding the terminating null
 * character) in the string as2, where not more than n characters
 * from the string as1 are searched.  strnstr() returns a pointer
 * to the located string, or a null pointer if the string is
 * not found.  If as2 is empty, the function returns as1.
 */

char *
strnstr(const char *as1, const char *as2, size_t n)
{
	const char *s1, *s2;
	const char *tptr;
	size_t k;
	char c;

	s1 = as1;
	s2 = as2;

	if (s2 == NULL || *s2 == '\0')
		return ((char *)s1);

	c = *s2;
	while (*s1 != '\0' && n--) {
		if (c == *s1++) {
			k = n;
			tptr = s1;
			while ((c = *++s2) == *s1++ && c != '\0' && k--)
				continue;
			if (c == '\0')
				return ((char *)tptr - 1);
			s1 = tptr;
			s2 = as2;
			c = *s2;
		}
	}

	return (NULL);
}
