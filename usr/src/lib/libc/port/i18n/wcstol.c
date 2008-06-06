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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1986 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef	_WCS_LONGLONG
#pragma weak _wcstol = wcstol
#endif

#include "lint.h"
#include <limits.h>
#include <errno.h>
#include <wchar.h>
#define	DIGIT(x)	(iswdigit(x) ? (x) - L'0' : \
			iswlower(x) ? (x) + 10 - L'a' : (x) + 10 - L'A')
#define	MBASE	(L'z' - L'a' + 1 + 10)

#ifdef	_WCS_LONGLONG
#define	_WLONG_T	long long
#define	_WLONG_MAX	LLONG_MAX
#define	_WLONG_MIN	LLONG_MIN
#else  /* _WCS_LONGLONG */
#define	_WLONG_T	long
#define	_WLONG_MAX	LONG_MAX
#define	_WLONG_MIN	LONG_MIN
#endif /* _WCS_LONGLONG */

#ifdef	_WCS_LONGLONG
long long
wcstoll(const wchar_t *_RESTRICT_KYWD str, wchar_t **_RESTRICT_KYWD ptr,
    int base)
#else  /* _WCS_LONGLONG */
long
wcstol(const wchar_t *str, wchar_t **ptr, int base)
#endif /* _WCS_LONGLONG */
{
	_WLONG_T	val;
	wchar_t	c;
	int	xx, neg = 0;
	_WLONG_T	multmin, limit;

	if (ptr != NULL)
		*ptr = (wchar_t *)str; /* in case no number is formed */
	if (base < 0 || base > MBASE) {
		errno = EINVAL;
		return (0); /* base is invalid -- should be a fatal error */
	}

	if (!iswalnum(c = *str)) {
		while (iswspace(c)) {
			c = *++str;
		}
		switch (c) {
		case L'-':
			neg++;
			/*FALLTHRU*/
		case L'+':
			c = *++str;
		}
	}
	if (base == 0) {
		if (c != L'0')
			base = 10;
		else if (str[1] == L'x' || str[1] == L'X')
			base = 16;
		else
			base = 8;
	}
	/*
	 * for any base > 10, the digits incrementally following
	 *	9 are assumed to be "abc...z" or "ABC...Z"
	 */
	if (!iswalnum(c) || (xx = DIGIT(c)) >= base) {
		errno = EINVAL;
		return (0); /* no number formed */
	}

	if (base == 16 && c == L'0' && iswxdigit(str[2]) &&
	    (str[1] == L'x' || str[1] == L'X')) {
		c = *(str += 2); /* skip over leading "0x" or "0X" */
	}

	if (neg) {
		limit = _WLONG_MIN;
	} else {
		limit = -_WLONG_MAX;
	}
	multmin = limit / base;

	val = -DIGIT(c);
	for (; iswalnum(c = *++str) && (xx = DIGIT(c)) < base; ) {
		/* accumulate neg avoids surprises near MAXLONG */
		if (val < multmin)
			goto overflow;
		val *= base;
		if (val < limit + xx)
			goto overflow;
		val -= xx;
	}
	if (ptr != NULL)
		*ptr = (wchar_t *)str;
	return (neg ? val : -val);

overflow:
	while (iswalnum(c = *++str) && (xx = DIGIT(c)) < base)
		;

	if (ptr != NULL)
		*ptr = (wchar_t *)str;
	errno = ERANGE;
	return (neg ? _WLONG_MIN : _WLONG_MAX);
}
