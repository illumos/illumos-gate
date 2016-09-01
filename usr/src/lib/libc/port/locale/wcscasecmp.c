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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Garrett D'Amore <garrett@damore.org>
 * Copyright 2016 Joyent, Inc.
 */

/*
 * Compare strings ignoring case difference.
 *	returns:  s1>s2: >0  s1==s2: 0  s1<s2: <0
 * All letters are converted to the lowercase and compared.
 */

#include "lint.h"
#include <stdlib.h>
#include <wchar.h>
#include <locale.h>
#include "libc.h"

/* Legacy Sun interfaces */
#pragma weak wscasecmp = wcscasecmp
#pragma weak wsncasecmp = wcsncasecmp

int
wcscasecmp_l(const wchar_t *s1, const wchar_t *s2, locale_t loc)
{
	if (s1 == s2)
		return (0);

	while (towlower_l(*s1, loc) == towlower_l(*s2, loc)) {
		if (*s1 == 0)
			return (0);
		s1++;
		s2++;
	}
	return (towlower_l(*s1, loc) - towlower_l(*s2, loc));
}

int
wcscasecmp(const wchar_t *s1, const wchar_t *s2)
{
	return (wcscasecmp_l(s1, s2, uselocale(NULL)));
}

int
wcsncasecmp_l(const wchar_t *s1, const wchar_t *s2, size_t n, locale_t loc)
{
	if (s1 == s2 || n == 0)
		return (0);

	while ((towlower_l(*s1, loc) == towlower_l(*s2, loc)) && --n) {
		if (*s1 == 0)
			return (0);
		s1++;
		s2++;
	}
	return (towlower_l(*s1, loc) - towlower_l(*s2, loc));
}

int
wcsncasecmp(const wchar_t *s1, const wchar_t *s2, size_t n)
{
	return (wcsncasecmp_l(s1, s2, n, uselocale(NULL)));
}
