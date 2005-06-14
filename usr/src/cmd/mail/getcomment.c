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


#pragma ident	"%Z%%M%	%I%	%E% SMI" 
		/* SVr4.0 2.	*/
#include "mail.h"
/*
 * Get comment field, if any, from line.
 *	1 ==> found comment.
 *	0 ==> no comment found.
 *     -1 ==> no closing (terminating) paren found for comment.
 */

getcomment(s, q)
register char	*s;
register char	*q;	/* Copy comment, if found, to here */
{
	register char	*p, *sav_q;
	register int	depth = 0;
	
	if ((p = strchr(s, '(')) == (char *)NULL) {
		/* no comment found */
		return (0);
	}
	sav_q = q;
	while (*p) {
		*q++ = *p;
		if (*p == ')') {
			/* account for nested parens within comment */
			depth--;
			if (depth == 0) {
				break;
			}
		} else if (*p == '(') {
			depth++;
		}
		p++;
	}
	*q = '\0';
	if (*p != ')') {
		/* closing paren not found */
		*sav_q = '\0';
		return (-1);
	}
	/* found comment */
	return (1);
}
