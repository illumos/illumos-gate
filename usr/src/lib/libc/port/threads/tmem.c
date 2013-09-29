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
 * Copyright (c) 2012, Joyent, Inc.  All rights reserved.
 */

#include "lint.h"
#include "thr_uberdata.h"

/*
 * This file implements the private interface with libumem for per-thread
 * caching umem (ptcumem). For the full details on how tcumem works and how
 * these functions work, see section 8.4 of the big theory statement in
 * lib/libumem/common/umem.c.
 */
static tmem_func_t tmem_cleanup = NULL;

uintptr_t
_tmem_get_base(void)
{
	return ((uintptr_t)&curthread->ul_tmem - (uintptr_t)curthread);
}

int
_tmem_get_nentries(void)
{
	return (NTMEMBASE);
}

void
_tmem_set_cleanup(tmem_func_t f)
{
	tmem_cleanup = f;
}

/*
 * This is called by _thrp_exit() to clean up any per-thread allocations that
 * are still hanging around and haven't been cleaned up.
 */
void
tmem_exit(void)
{
	int ii;
	void *buf, *next;
	tumem_t *tp = &curthread->ul_tmem;


	if (tp->tm_size == 0)
		return;

	/*
	 * Since we have something stored here, we need to ensure we declared a
	 * clean up handler. If we haven't that's broken and our single private
	 * consumer should be shot.
	 */
	if (tmem_cleanup == NULL)
		abort();
	for (ii = 0; ii < NTMEMBASE; ii++) {
		buf = tp->tm_roots[ii];
		while (buf != NULL) {
			next = *(void **)buf;
			tmem_cleanup(buf, ii);
			buf = next;
		}
	}
}
