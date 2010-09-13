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

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include "thr_uberdata.h"
#include <stdlib.h>
#include <atomic.h>

/*
 * We need atomic_cas_uint() protection because a multithreaded process
 * may be calling rand() from different threads and because multiple
 * threads may be calling rand_r() using a pointer to the same seed.
 */

static uint_t rand_seed = 1;

#define	NEXT_SEED(s)	((s) * 1103515245 + 12345)
#define	NEXT_VALUE(s)	(((s) >> 16) & 0x7fff)

static int
rand_mt(uint_t *seed)
{
	uint_t old_seed;
	uint_t new_seed;

	for (;;) {
		/* force reload on every iteration */
		old_seed = *(volatile uint_t *)seed;
		new_seed = NEXT_SEED(old_seed);
		if (atomic_cas_uint(seed, old_seed, new_seed) == old_seed)
			return (NEXT_VALUE(new_seed));
		SMT_PAUSE();
	}
}

int
rand_r(uint_t *seed)
{
	if (curthread->ul_uberdata->uberflags.uf_mt)
		return (rand_mt(seed));
	return (NEXT_VALUE(*seed = NEXT_SEED(*seed)));
}

void
srand(uint_t seed)
{
	rand_seed = seed;
}

int
rand(void)
{
	return (rand_r(&rand_seed));
}
