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

#include <libnvpair.h>
#include <fmd_alloc.h>

/*ARGSUSED*/
static void *
fmd_nv_alloc(nv_alloc_t *nva, size_t size)
{
	return (fmd_alloc(size, FMD_SLEEP));
}

/*ARGSUSED*/
static void
fmd_nv_free(nv_alloc_t *nva, void *buf, size_t size)
{
	fmd_free(buf, size);
}

const nv_alloc_ops_t fmd_nv_alloc_ops = {
	NULL,		/* nv_ao_init() */
	NULL,		/* nv_ao_fini() */
	fmd_nv_alloc,	/* nv_ao_alloc() */
	fmd_nv_free,	/* nv_ao_free() */
	NULL		/* nv_ao_reset() */
};
