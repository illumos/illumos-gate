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
 * Copyright (c) 1994, by Sun Microsytems, Inc.
 */

/*
 * Function to allocate memory in target process (used by combinations).
 */

#ifndef DEBUG
#define	NDEBUG	1
#endif

#include <assert.h>
#include "tnfctl_int.h"
#include "prb_internals.h"
#include "dbg.h"


/*
 * _tnfctl_targmem_alloc() - allocates memory in the target process.
 */
tnfctl_errcode_t
_tnfctl_targmem_alloc(tnfctl_handle_t *hndl, size_t size, uintptr_t *addr_p)
{
	int			miscstat;
	tnf_memseg_t		memseg;

	assert(hndl->memseg_p != NULL);
	*addr_p = 0;

	/* read the memseg block from the target process */
	miscstat = hndl->p_read(hndl->proc_p, hndl->memseg_p, &memseg,
		sizeof (memseg));
	if (miscstat)
		return (TNFCTL_ERR_INTERNAL);

	/* if there is memory left, allocate it */
	if ((memseg.min_p + memseg.i_reqsz) <= (memseg.max_p - size)) {
		memseg.max_p -= size;

		miscstat = hndl->p_write(hndl->proc_p, hndl->memseg_p,
			&memseg, sizeof (memseg));
		if (miscstat)
			return (TNFCTL_ERR_INTERNAL);

		*addr_p = (uintptr_t) memseg.max_p;

		DBG_TNF_PROBE_2(_tnfctl_targmem_alloc_1, "libtnfctl",
			"sunw%verbosity 3",
			tnf_long, size_allocated, size,
			tnf_opaque, at_location, *addr_p);

		return (TNFCTL_ERR_NONE);
	} else {
		return (TNFCTL_ERR_INTERNAL);
	}
}
