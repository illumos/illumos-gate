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

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/varargs.h>

/*
 * SunOS-specific extensions to libc's standard set of string routines.
 *
 * NOTE: The standard libc string routines are in $SRC/common/util/string.c,
 * to facilitate sharing with standalone.
 */

/*
 * Historical entry point: remove in Solaris 2.8.
 */
char *
vsprintf_len(size_t buflen, char *buf, const char *fmt, va_list args)
{
	(void) vsnprintf(buf, buflen, fmt, args);
	return (buf);
}

/*
 * Historical entry point: remove in Solaris 2.8.
 */
/*PRINTFLIKE3*/
char *
sprintf_len(size_t buflen, char *buf, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	(void) vsnprintf(buf, buflen, fmt, args);
	va_end(args);

	return (buf);
}

/*
 * Simple-minded conversion of a long into a null-terminated character
 * string.  Caller must ensure there's enough space to hold the result.
 */
void
numtos(unsigned long num, char *s)
{
	char prbuf[40];

	char *cp = prbuf;

	do {
		*cp++ = "0123456789"[num % 10];
		num /= 10;
	} while (num);

	do {
		*s++ = *--cp;
	} while (cp > prbuf);
	*s = '\0';
}

/*
 * Returns the integer value of the string of decimal numeric
 * chars beginning at **str.  Does no overflow checking.
 * Note: updates *str to point at the last character examined.
 */
int
stoi(char **str)
{
	char	*p = *str;
	int	n;
	int	c;

	for (n = 0; (c = *p) >= '0' && c <= '9'; p++) {
		n = n * 10 + c - '0';
	}
	*str = p;
	return (n);
}

/*
 * Like strrchr(), except
 * (a) it takes a maximum length for the string to be searched, and
 * (b) if the string ends with a null, it is not considered part of the string.
 */
char *
strnrchr(const char *sp, int c, size_t n)
{
	const char *r = 0;

	while (n-- > 0 && *sp) {
		if (*sp == c)
			r = sp;
		sp++;
	}

	return ((char *)r);
}

/*
 * NOTE: These routines aren't shared with standalone because the DDI mandates
 *	 that they return the buffer rather than its length.
 */
/*PRINTFLIKE2*/
char *
sprintf(char *buf, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	(void) vsnprintf(buf, INT_MAX, fmt, args);
	va_end(args);

	return (buf);
}

char *
vsprintf(char *buf, const char *fmt, va_list args)
{
	(void) vsnprintf(buf, INT_MAX, fmt, args);
	return (buf);
}

/*
 * Do not change the length of the returned string; it must be freed
 * with strfree().
 */
char *
kmem_asprintf(const char *fmt, ...)
{
	int size;
	va_list adx;
	char *buf;

	va_start(adx, fmt);
	size = vsnprintf(NULL, 0, fmt, adx) + 1;
	va_end(adx);

	buf = kmem_alloc(size, KM_SLEEP);

	va_start(adx, fmt);
	size = vsnprintf(buf, size, fmt, adx);
	va_end(adx);

	return (buf);
}
