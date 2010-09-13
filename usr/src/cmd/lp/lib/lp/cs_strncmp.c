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


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.5	*/
/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "ctype.h"

/*
 * Compare strings (at most n bytes) ignoring case
 *	returns: s1>s2; >0  s1==s2; 0  s1<s2; <0
 */

int
#if	defined(__STDC__)
cs_strncmp(
	char *			s1,
	char *			s2,
	int			n
)
#else
cs_strncmp(s1, s2, n)
register char *s1, *s2;
register n;
#endif
{
	if(s1 == s2)
		return(0);
	while(--n >= 0 && toupper(*s1) == toupper(*s2++))
		if(*s1++ == '\0')
			return(0);
	return((n < 0)? 0: (toupper(*s1) - toupper(*--s2)));
}
