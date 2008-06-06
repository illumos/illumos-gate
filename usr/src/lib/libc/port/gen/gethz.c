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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma weak _gethz = gethz

#include "lint.h"
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>

/*
 *	gethz -- get the value of the clock hertz from the environment.
 *
 *	return the clock hertz value if the string "HZ" in the environment is:
 *		1) Composed entirely of numbers.
 *		2) Not equal to zero.
 *	Otherwise 0 is returned.
 */
int
gethz(void)
{
	char *sptr, *cptr;

	if ((sptr = getenv("HZ")) == NULL) {
		return (0);
	} else {
		cptr = sptr;

		/* Check that all characters are numeric */
		while (*cptr) {
			if (!isdigit((unsigned char)*cptr))
				return (0);
			cptr++;
		}
		return (atoi(sptr));
	}
}
