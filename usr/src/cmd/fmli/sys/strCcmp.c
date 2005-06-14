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
 * Copyright  (c) 1985 AT&T
 *	All Rights Reserved
 */
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.1 */

#include	<stdio.h>
#include	<ctype.h>

int
strCcmp(s1, s2)
char	*s1;
char	*s2;
{
	register int	c1;
	register int	c2;

	while ((c1 = *s1++) != 0 & (c2 = *s2++) != 0) {
		if (isupper(c1))
			c1 = tolower(c1);
		if (isupper(c2))
			c2 = tolower(c2);
		if (c1 != c2)
			break;
	}
	return c1 - c2;
}

int
strnCcmp(s1, s2, n)
char	*s1;
char	*s2;
int	n;
{
	register int	c1 = '\0';
	register int	c2 = '\0';

	while (n-- > 0 && (c1 = *s1++) != 0 & (c2 = *s2++) != 0) {
		if (isupper(c1))
			c1 = tolower(c1);
		if (isupper(c2))
			c2 = tolower(c2);
		if (c1 != c2)
			break;
	}
	return c1 - c2;
}
