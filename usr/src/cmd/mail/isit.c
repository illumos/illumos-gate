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
/*	  All Rights Reserved	*/

#include "mail.h"

/*
 * isit(lp, type) --  match "name" portion of
 *		"name: value" pair
 *	lp	->	pointer to line to check
 *	type	->	type of header line to match
 * returns
 *	TRUE	->	lp matches header type (case independent)
 *	FALSE	->	no match
 *
 *  Execpt for H_FORM type, matching is case insensitive (bug 1173101)
 */
int
isit(char *lp, int type)
{
	char	*p;

	switch (type) {
	case H_FROM:
		for (p = header[type].tag; *lp && *p; lp++, p++) {
			if (*p != *lp)  {
				return (FALSE);
			}
		}
		break;
	default:
		for (p = header[type].tag; *lp && *p; lp++, p++) {
			if (toupper(*p) != toupper(*lp))  {
				return (FALSE);
			}
		}
		break;
	}
	if (*p == '\0') {
		return (TRUE);
	}
	return (FALSE);
}
