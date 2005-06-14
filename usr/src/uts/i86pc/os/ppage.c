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

#include <sys/t_lock.h>
#include <sys/vmem.h>
#include <sys/mman.h>
#include <sys/vm.h>
#include <sys/cpuvar.h>
#include <sys/systm.h>
#include <vm/as.h>
#include <vm/hat.h>
#include <vm/page.h>
#include <vm/seg.h>
#include <vm/seg_kmem.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>

/*
 * ppcopy() and pagezero() have moved to i86/vm/vm_machdep.c
 */

/*
 * Architecures with a vac use this routine to quickly make
 * a vac-aligned mapping.  We don't have a vac, so we don't
 * care about that - just make this simple.
 */
/* ARGSUSED2 */
caddr_t
ppmapin(page_t *pp, uint_t vprot, caddr_t avoid)
{
	caddr_t va;

	va = vmem_alloc(heap_arena, PAGESIZE, VM_SLEEP);
	hat_memload(kas.a_hat, va, pp, vprot | HAT_NOSYNC, HAT_LOAD_LOCK);
	return (va);
}

void
ppmapout(caddr_t va)
{
	hat_unload(kas.a_hat, va, PAGESIZE, HAT_UNLOAD_UNLOCK);
	vmem_free(heap_arena, va, PAGESIZE);
}


/*
 * Map the page pointed to by pp into the kernel virtual address space.
 * This routine is used by the rootnexus.
 */
void
i86_pp_map(page_t *pp, caddr_t kaddr)
{
	hat_devload(kas.a_hat, kaddr, MMU_PAGESIZE, page_pptonum(pp),
	    HAT_STORECACHING_OK | PROT_READ | PROT_WRITE | HAT_NOSYNC,
	    HAT_LOAD_LOCK);
}

/*
 * Map the page containing the virtual address into the kernel virtual address
 * space.  This routine is used by the rootnexus.
 */
void
i86_va_map(caddr_t vaddr, struct as *asp, caddr_t kaddr)
{
	pfn_t pfnum;

	pfnum = hat_getpfnum(asp->a_hat, vaddr);
	hat_devload(kas.a_hat, kaddr, MMU_PAGESIZE, pfnum,
	    HAT_STORECACHING_OK | PROT_READ | PROT_WRITE | HAT_NOSYNC,
	    HAT_LOAD_LOCK);
}
