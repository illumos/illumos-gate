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

/*	Copyright (c) 1988 AT&T	*/
/*	All Rights Reserved */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/ddi.h>
#include <sys/errno.h>

/*
 * String to integer conversion routines.
 *
 * This file is derived from usr/src/common/util/strtol.c
 *
 * We cannot use the user land versions as there is no errno to report
 * error in kernel.  So the return value is used to return an error,
 * and the result is stored in an extra parameter passed by reference.
 * Otherwise, the following functions are identical to the user land
 * versions.
 */

/*
 * We should have a kernel version of ctype.h.
 */
#define	isalnum(ch)	(isalpha(ch) || isdigit(ch))
#define	isalpha(ch)	(isupper(ch) || islower(ch))
#define	isdigit(ch)	((ch) >= '0' && (ch) <= '9')
#define	islower(ch)	((ch) >= 'a' && (ch) <= 'z')
#define	isspace(ch)	(((ch) == ' ') || ((ch) == '\r') || ((ch) == '\n') || \
			((ch) == '\t') || ((ch) == '\f'))
#define	isupper(ch)	((ch) >= 'A' && (ch) <= 'Z')
#define	isxdigit(ch)	(isdigit(ch) || ((ch) >= 'a' && (ch) <= 'f') || \
			((ch) >= 'A' && (ch) <= 'F'))

#define	DIGIT(x)	\
	(isdigit(x) ? (x) - '0' : islower(x) ? (x) + 10 - 'a' : (x) + 10 - 'A')

#define	MBASE	('z' - 'a' + 1 + 10)

/*
 * The following macro is a local version of isalnum() which limits
 * alphabetic characters to the ranges a-z and A-Z; locale dependent
 * characters will not return 1. The members of a-z and A-Z are
 * assumed to be in ascending order and contiguous
 */
#define	lisalnum(x)	\
	(isdigit(x) || ((x) >= 'a' && (x) <= 'z') || ((x) >= 'A' && (x) <= 'Z'))

int
ddi_strtol(const char *str, char **nptr, int base, long *result)
{
	long val;
	int c;
	int xx, neg = 0;
	long	multmin;
	long	limit;
	const char **ptr = (const char **)nptr;
	const unsigned char	*ustr = (const unsigned char *)str;

	if (ptr != (const char **)0)
		*ptr = (char *)ustr; /* in case no number is formed */
	if (base < 0 || base > MBASE || base == 1) {
		/* base is invalid -- should be a fatal error */
		return (EINVAL);
	}
	if (!isalnum(c = *ustr)) {
		while (isspace(c))
			c = *++ustr;
		switch (c) {
		case '-':
			neg++;
			/* FALLTHROUGH */
		case '+':
			c = *++ustr;
		}
	}
	if (base == 0)
		if (c != '0')
			base = 10;
		else if (ustr[1] == 'x' || ustr[1] == 'X')
			base = 16;
		else
			base = 8;
	/*
	 * for any base > 10, the digits incrementally following
	 *	9 are assumed to be "abc...z" or "ABC...Z"
	 */
	if (!lisalnum(c) || (xx = DIGIT(c)) >= base)
		return (EINVAL); /* no number formed */
	if (base == 16 && c == '0' && (ustr[1] == 'x' || ustr[1] == 'X') &&
		isxdigit(ustr[2]))
		c = *(ustr += 2); /* skip over leading "0x" or "0X" */

	/* this code assumes that abs(LONG_MIN) >= abs(LONG_MAX) */
	if (neg)
		limit = LONG_MIN;
	else
		limit = -LONG_MAX;
	multmin = limit / (long)base;
	val = -DIGIT(c);
	for (c = *++ustr; lisalnum(c) && (xx = DIGIT(c)) < base; ) {
		/* accumulate neg avoids surprises near MAXLONG */
		if (val < multmin)
			goto overflow;
		val *= base;
		if (val < limit + xx)
			goto overflow;
		val -= xx;
		c = *++ustr;
	}
	if (ptr != (const char **)0)
		*ptr = (char *)ustr;
	*result = neg ? val : -val;
	return (0);

overflow:
	for (c = *++ustr; lisalnum(c) && (xx = DIGIT(c)) < base; (c = *++ustr))
		;
	if (ptr != (const char **)0)
		*ptr = (char *)ustr;
	return (ERANGE);
}

int
ddi_strtoul(const char *str, char **nptr, int base, unsigned long *result)
{
	unsigned long val;
	int c;
	int xx;
	unsigned long	multmax;
	int neg = 0;
	const char **ptr = (const char **)nptr;
	const unsigned char	*ustr = (const unsigned char *)str;

	if (ptr != (const char **)0)
		*ptr = (char *)ustr; /* in case no number is formed */
	if (base < 0 || base > MBASE || base == 1) {
		/* base is invalid -- should be a fatal error */
		return (EINVAL);
	}
	if (!isalnum(c = *ustr)) {
		while (isspace(c))
			c = *++ustr;
		switch (c) {
		case '-':
			neg++;
			/* FALLTHROUGH */
		case '+':
			c = *++ustr;
		}
	}
	if (base == 0)
		if (c != '0')
			base = 10;
		else if (ustr[1] == 'x' || ustr[1] == 'X')
			base = 16;
		else
			base = 8;
	/*
	 * for any base > 10, the digits incrementally following
	 *	9 are assumed to be "abc...z" or "ABC...Z"
	 */
	if (!lisalnum(c) || (xx = DIGIT(c)) >= base)
		return (EINVAL); /* no number formed */
	if (base == 16 && c == '0' && (ustr[1] == 'x' || ustr[1] == 'X') &&
	    isxdigit(ustr[2]))
		c = *(ustr += 2); /* skip over leading "0x" or "0X" */

	multmax = ULONG_MAX / (unsigned long)base;
	val = DIGIT(c);
	for (c = *++ustr; lisalnum(c) && (xx = DIGIT(c)) < base; ) {
		if (val > multmax)
			goto overflow;
		val *= base;
		if (ULONG_MAX - val < xx)
			goto overflow;
		val += xx;
		c = *++ustr;
	}
	if (ptr != (const char **)0)
		*ptr = (char *)ustr;
	*result = neg ? -val : val;
	return (0);

overflow:
	for (c = *++ustr; lisalnum(c) && (xx = DIGIT(c)) < base; (c = *++ustr))
		;
	if (ptr != (const char **)0)
		*ptr = (char *)ustr;
	return (ERANGE);
}
