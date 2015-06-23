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
 * Copyright 2013 Garrett D'Amore <garrett@damore.org>
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#include "lint.h"
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <locale.h>
#include "lctype.h"
#include "localeimpl.h"

/*
 * strcasestr() locates the first occurrence in the string s1 of the
 * sequence of characters (excluding the terminating null character)
 * in the string s2, ignoring case.  strcasestr() returns a pointer
 * to the located string, or a null pointer if the string is not found.
 * If s2 is empty, the function returns s1.
 */

char *
strcasestr_l(const char *s1, const char *s2, locale_t loc)
{
	const int *cm = loc->ctype->lc_trans_lower;
	const uchar_t *us1 = (const uchar_t *)s1;
	const uchar_t *us2 = (const uchar_t *)s2;
	const uchar_t *tptr;
	int c;

	if (us2 == NULL || *us2 == '\0')
		return ((char *)us1);

	c = cm[*us2];
	while (*us1 != '\0') {
		if (c == cm[*us1++]) {
			tptr = us1;
			while (cm[c = *++us2] == cm[*us1++] && c != '\0')
				continue;
			if (c == '\0')
				return ((char *)tptr - 1);
			us1 = tptr;
			us2 = (const uchar_t *)s2;
			c = cm[*us2];
		}
	}

	return (NULL);
}

char *
strcasestr(const char *s1, const char *s2)
{
	return (strcasestr_l(s1, s2, uselocale(NULL)));
}
