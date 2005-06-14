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

#include <sys/types.h>
#include <vm/hat.h>
#include <vm/hat_sfmmu.h>
#include <sys/pte.h>
#include <sys/mmu.h>
#include <sys/kdi_impl.h>
#include <sys/errno.h>

extern int kdi_vatotte(uintptr_t, int, tte_t *);
extern int sfmmu_kern_mapped;

int
kdi_vtop(uintptr_t va, uint64_t *pap)
{
	tte_t tte;

	if (!sfmmu_kern_mapped)
		return (EAGAIN);

	if (kdi_vatotte(va, KCONTEXT, &tte) < 0)
		return (ENOENT);

	*pap = (TTE_TO_PFN((caddr_t)va, &tte) << MMU_PAGESHIFT) |
	    (va & MMU_PAGEOFFSET);

	return (0);
}
