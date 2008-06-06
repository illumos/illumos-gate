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
 * Binary search algorithm, generalized from Knuth (6.2.1) Algorithm B.
 */

#if !defined(_BOOT) && !defined(_KMDB)
#include "lint.h"
#endif /* !_BOOT && !_KMDB */
#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>

void *
bsearch(const void *ky,		/* Key to be located */
	const void *bs,		/* Beginning of table */
	size_t nel,		/* Number of elements in the table */
	size_t width,		/* Width of an element (bytes) */
	int (*compar)(const void *, const void *)) /* Comparison function */
{
	char *base;
	size_t two_width;
	char *last;		/* Last element in table */

	if (nel == 0)
		return (NULL);

	base = (char *)bs;
	two_width = width + width;
	last = base + width * (nel - 1);

	while (last >= base) {

		char *p = base + width * ((last - base)/two_width);
		int res = (*compar)(ky, (void *)p);

		if (res == 0)
			return (p);	/* Key found */
		if (res < 0)
			last = p - width;
		else
			base = p + width;
	}
	return (NULL);		/* Key not found */
}
