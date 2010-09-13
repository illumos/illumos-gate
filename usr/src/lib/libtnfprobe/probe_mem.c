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
 *	Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Includes
 */

#include "prb_internals.h"


/*
 * Globals
 *	Memory that prex uses to store combinations in target process
 */

#define	INITMEMSZ 2048

static char	initial_memory[INITMEMSZ];
static tnf_memseg_t	initial_memseg = {
					initial_memory,
					initial_memory + INITMEMSZ,
					DEFAULTMUTEX,
					0
				};

tnf_memseg_t *	__tnf_probe_memseg_p = &initial_memseg;


/*
 * __tnf_probe_alloc() - allocates memory from the global pool
 */

char *
__tnf_probe_alloc(size_t size)
{
	tnf_memseg_t *	memseg_p = __tnf_probe_memseg_p;
	char *		ptr;

	ptr = NULL;

	mutex_lock(&memseg_p->i_lock);

	memseg_p->i_reqsz = size;

	if ((memseg_p->min_p + size) <= memseg_p->max_p) {
	    ptr = memseg_p->min_p;
	    memseg_p->min_p += size;
	}

	memseg_p->i_reqsz = 0;

	mutex_unlock(&memseg_p->i_lock);

	return (ptr);

}   /* end __tnf_probe_alloc */
