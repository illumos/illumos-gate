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
/*  Copyright (c) 1988 AT&T */
/*    All Rights Reserved   */


/*
 *      Copyright (c) 1997, by Sun Microsystems, Inc.
 *      All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include	<sys/types.h>
#include	"curses_inc.h"

/*
 *	Get the # of valid characters
 */

int
mbcharlen(char *sp)
{
	int		n, m, k, ty;
	chtype	c;

	n = 0;
	for (; *sp != '\0'; ++sp, ++n)
		if (ISMBIT(*sp)) {
			c = RBYTE(*sp);
			ty = TYPE(c & 0377);
			m  = cswidth[ty] - (ty == 0 ? 1 : 0);
			for (sp += 1, k = 1; *sp != '\0' && k <= m; ++k,
			    ++sp) {
				c = RBYTE(*sp);
				if (TYPE(c) != 0)
					break;
			}
			if (k <= m)
				break;
		}
	return (n);
}
