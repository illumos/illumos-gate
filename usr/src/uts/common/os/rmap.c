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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/vmem.h>
#include <sys/cmn_err.h>

/* ARGSUSED */
void *
rmallocmap(size_t mapsize)
{
	return (vmem_create("rmap", NULL, 0, 1, NULL, NULL, NULL, 0,
	    VM_NOSLEEP));
}

/* ARGSUSED */
void *
rmallocmap_wait(size_t mapsize)
{
	return (vmem_create("rmap", NULL, 0, 1, NULL, NULL, NULL, 0, VM_SLEEP));
}

void
rmfreemap(void *mp)
{
	vmem_destroy(mp);
}

ulong_t
rmalloc(void *mp, size_t size)
{
	return ((ulong_t)vmem_alloc(mp, size, VM_NOSLEEP));
}

ulong_t
rmalloc_wait(void *mp, size_t size)
{
	return ((ulong_t)vmem_alloc(mp, size, VM_SLEEP));
}

void
rmfree(void *mp, size_t size, ulong_t addr)
{
	if (vmem_contains(mp, (void *)addr, size))
		vmem_free(mp, (void *)addr, size);
	else if (vmem_add(mp, (void *)addr, size, VM_NOSLEEP) == NULL)
		cmn_err(CE_WARN, "rmfree(%p, %lu, %lu): cannot add segment",
		    mp, size, addr);
}
