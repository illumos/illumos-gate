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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <strings.h>
#include <umem.h>
#include <poll.h>
#include <errno.h>

#include <fmd_alloc.h>
#include <fmd_subr.h>
#include <fmd_module.h>
#include <fmd_scheme.h>
#include <fmd.h>

void *
fmd_alloc(size_t size, int flags)
{
	void *data = umem_alloc(size, UMEM_DEFAULT);
	uint_t try, lim, msecs;

	if (data != NULL || size == 0 || !(flags & FMD_SLEEP))
		return (data); /* in common cases just return result */

	lim = fmd.d_alloc_tries;
	msecs = fmd.d_alloc_msecs;

	for (try = 0; data == NULL && try < lim; try++) {
		(void) poll(NULL, 0, msecs);
		msecs *= 10;
		data = umem_alloc(size, UMEM_DEFAULT);
	}

	if (data == NULL) {
		fmd_modhash_tryapply(fmd.d_mod_hash, fmd_module_trygc);
		fmd_scheme_hash_trygc(fmd.d_schemes);
		data = umem_alloc(size, UMEM_DEFAULT);
	}

	if (data == NULL)
		fmd_panic("insufficient memory (%u bytes needed)\n", size);

	return (data);
}

void *
fmd_zalloc(size_t size, int flags)
{
	void *data = fmd_alloc(size, flags);

	if (data != NULL)
		bzero(data, size);

	return (data);
}

void
fmd_free(void *data, size_t size)
{
	umem_free(data, size);
}
