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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "cache.h"

nsc_keephot_t *
maken(int n)
{
	nsc_keephot_t	*ret;

	++n;
	ret = (nsc_keephot_t *)calloc(n, sizeof (nsc_keephot_t));
	if (ret == NULL)
		return (NULL);
	ret[0].num = n - 1;
	return (ret);
}

void *
insertn(nsc_keephot_t *table, uint_t n, void *data)
{
	void	*olddata;
	int	size, guess, base, last;

	if (n < 1 || table[1].num > n) {
		return (data);
	}

	size = table[0].num;
	if (table[size].num < n)  /* biggest so far */
		guess = size;
	else {
		base = 1;
		last = size;
		while (last >= base) {
			guess = (last+base)/2;
			if (table[guess].num == n)
				goto doit;
			if (table[guess].num > n)
				last = guess - 1;
			else
				base = guess + 1;
		}
		guess = last;
	}

doit:
	olddata = table[1].ptr;
	(void) memmove(table + 1, table + 2,
			sizeof (nsc_keephot_t) * (guess-1));
	table[guess].ptr = data;
	table[guess].num = n;
	return (olddata);
}
