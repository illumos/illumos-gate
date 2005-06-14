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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright  (c) 1986 AT&T
 *	All Rights Reserved
 */

#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.1 */

#include	<stdio.h>
#include	<ctype.h>
#include	"wish.h"

char	*strchr();

static char	withbs[] = "\b\f\n\r\t\\\33";
static char	woutbs[] = "bfnrt\\E";

char *
backslash(s, n)
char	*s;
int	n;
{
	char	*_backslash();

	return _backslash(s, n, withbs, woutbs);
}

char *
_backslash(s, n, in, out)
char	*s;
int	n;
char	*in;
char	*out;
{
	register char	*dst;
	register char	*p;

	n -= strlen(s);
	for (dst = s; *dst; dst++) {
		if (!isprint(*dst)) {
			if ((p = strchr(in, *dst)) && n > 0) {
				*dst++ = '\\';
				memshift(dst + 1, dst, strlen(dst) + 1);
				*dst = out[p - in];
				n--;
			}
			else {
				register int	c;

				memshift(dst + 3, dst, strlen(dst) + 1);
				c = *dst;
				*dst++ = '\\';
				*dst++ = ((c >> 6) & 3) + '0';
				*dst++ = ((c >> 3) & 7) + '0';
				*dst = (c & 7) + '0';
			}
		}
	}
	return s;
}

char *
unbackslash(s)
char	*s;
{
	register char	*src;
	register char	*dst;
	register char	*p;

	for (dst = src = s; *src; src++) {
		if (*src == '\\') {
			if (p = strchr(woutbs, src[1])) {
				*dst++ = withbs[p - woutbs];
				src++;
			}
			else if (isdigit(src[1])) {
				register int	c;

				c = *++src - '0';
				if (isdigit(src[1])) {
					c = (c << 3) + *++src - '0';
					if (isdigit(src[1]))
						c = (c << 3) + *++src - '0';
				}
				*dst++ = c;
			}
		}
		else
			*dst++ = *src;
	}
	*dst = '\0';
	return s;
}
