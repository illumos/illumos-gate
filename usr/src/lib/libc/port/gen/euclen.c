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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include <euc.h>
#include <ctype.h>

/*
 * euccol(s) returns the screen column width of the EUC char.
 */
int
euccol(const unsigned char *s)
{

	if (ISASCII(*s))
		return (1);
	else
		switch (*s) {
		case SS2:
			return (scrw2);
		case SS3:
			return (scrw3);
		default: /* code set 1 */
			return (scrw1);
		}
}

/*
 * euclen(s,n) returns the code width of the  EUC char.
 * May also be implemented as a macro.
 */
int
euclen(const unsigned char *s)
{

	if (ISASCII(*s))
		return (1);
	else
		switch (*s) {
		case SS2:
			return (eucw2 + 1); /* include SS2 */
		case SS3:
			return (eucw3 + 1); /* include SS3 */
		default: /* code set 1 */
			return (eucw1);
		}
}

/* this function will return the number of display column for a */
/* given euc string.						*/
int
eucscol(const unsigned char *s)

{
	int	col = 0;

	while (*s) { /* end if euc char is a NULL character */
		if (ISASCII(*s)) {
			col += 1;
			s++;
		}
		else
			switch (*s) {
			case SS2:
				col += scrw2;
				s += (eucw2 +1);
				break;
			case SS3:
				col += scrw3;
				s += (eucw3 +1);
				break;
			default:	/* code set 1 */
				col += scrw1;
				s += eucw1;
				break;
			}

	}
	return (col);
}
