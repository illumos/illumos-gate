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
 * Copyright 1995 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * UNIX shell
 */

#include	"defs.h"


/* ========	general purpose string handling ======== */


unsigned char *
movstr(unsigned char *a, unsigned char *b)
{
	while (*b++ = *a++);
	return(--b);
}

int
any(wchar_t c, unsigned char *s)
{
	unsigned int d;

	while (d = *s++)
	{
		if (d == c)
			return(TRUE);
	}
	return(FALSE);
}

int anys(c, s)
unsigned char *c, *s;
{
	wchar_t f, e;
	wchar_t d;
	int n;
	if((n = mbtowc(&f, (char *)c, MULTI_BYTE_MAX)) <= 0)
		return(FALSE);
	d = f;
	while(1) {
		if((n = mbtowc(&e, (char *)s, MULTI_BYTE_MAX)) <= 0)
			return(FALSE);
		if(d == e)
			return(TRUE);
		s += n;
	}
}

int
cf(unsigned char *s1, unsigned char *s2)
{
	while (*s1++ == *s2)
		if (*s2++ == 0)
			return(0);
	return(*--s1 - *s2);
}

int length(as)
unsigned char	*as;
{
	unsigned char	*s;

	if (s = as)
		while (*s++);
	return(s - as);
}

unsigned char *
movstrn(unsigned char *a, unsigned char *b, int n)
{
	while ((n-- > 0) && *a)
		*b++ = *a++;

	return(b);
}
