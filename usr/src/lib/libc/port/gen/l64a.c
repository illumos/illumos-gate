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

/*
 * convert long int to base 64 ascii
 * char set is [./0-9A-Za-z]
 * two's complement negatives are assumed,
 * but no assumptions are made about sign propagation on right shift
 *
 */

#include "lint.h"
#include "mtlib.h"
#include "libc.h"
#include <values.h>
#include <synch.h>
#include <thread.h>
#include <stdlib.h>
#include <sys/types.h>
#include "tsd.h"

#define	BITSPERCHAR	6 /* to hold entire character set */
#define	BITSUSED	(BITSPERBYTE * sizeof (int))
#define	NMAX		((BITSUSED + BITSPERCHAR - 1)/BITSPERCHAR)
#define	SIGN		(-(1 << (BITSUSED - BITSPERCHAR - 1)))
#define	CHARMASK	((1 << BITSPERCHAR) - 1)
#define	WORDMASK	((1 << ((NMAX - 1) * BITSPERCHAR)) - 1)

char *
l64a(long value)
{
	/* XPG4: only the lower 32 bits are used */
	int lg = (int)value;
	char *buf = tsdalloc(_T_L64A, NMAX + 1, NULL);
	char *s = buf;

	if (buf == NULL)
		return (NULL);

	while (lg != 0) {

		int c = (lg & CHARMASK) + ('0' - 2);

		if (c > '9')
			c += 'A' - '9' - 1;
		if (c > 'Z')
			c += 'a' - 'Z' - 1;
		*s++ = (char)c;
		/* fill high-order CHAR if negative */
		/* but suppress sign propagation */
		lg = ((lg < 0) ? (lg >> BITSPERCHAR) | SIGN :
		    lg >> BITSPERCHAR) & WORDMASK;
	}
	*s = '\0';
	return (buf);
}
