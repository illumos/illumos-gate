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

#include <sys/debug.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/buf.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/signal.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/map.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/cred.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/vnode.h>
#include <vm/page.h>
#include <vm/as.h>
#include <vm/hat.h>
#include <vm/seg.h>
#include <vm/seg_kmem.h>
#include <vm/hat_i86.h>
#include <sys/vmsystm.h>
#include <sys/ddi.h>
#include <sys/devops.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/fs/snode.h>
#include <sys/pci.h>
#include <sys/modctl.h>
#include <sys/uio.h>
#include <sys/visual_io.h>
#include <sys/fbio.h>
#include <sys/ddidmareq.h>
#include <sys/tnf_probe.h>
#include <sys/kstat.h>
#include <sys/callb.h>
#include <sys/promif.h>
#include <sys/atomic.h>
#include "gfx_private.h"

/*
 * Create a kva mapping for a pa (start..start+size) with
 * the specified cache attributes (mode).
 */
gfxp_kva_t
gfxp_map_kernel_space(uint64_t start, size_t size, uint32_t mode)
{
	uint_t pgoffset;
	uint64_t base;
	pgcnt_t npages;
	caddr_t cvaddr;
	int hat_flags;
	uint_t hat_attr;

	if (size == 0)
		return (0);

	if (mode == GFXP_MEMORY_CACHED)
		hat_attr = HAT_STORECACHING_OK;
	else if (mode == GFXP_MEMORY_WRITECOMBINED)
		hat_attr = HAT_MERGING_OK | HAT_PLAT_NOCACHE;
	else	/* GFXP_MEMORY_UNCACHED */
		hat_attr = HAT_STRICTORDER | HAT_PLAT_NOCACHE;
	hat_flags = HAT_LOAD_LOCK;
	pgoffset = start & PAGEOFFSET;
	base = start - pgoffset;
	npages = btopr(size + pgoffset);
	cvaddr = vmem_alloc(heap_arena, ptob(npages), VM_NOSLEEP);
	if (cvaddr == NULL)
		return (NULL);
	hat_devload(kas.a_hat, cvaddr, ptob(npages), btop(base),
			PROT_READ|PROT_WRITE|hat_attr, hat_flags);
	return (cvaddr + pgoffset);
}

/*
 * Destroy the mapping created by gfxp_map_kernel_space().
 * Physical memory is not reclaimed.
 */
void
gfxp_unmap_kernel_space(gfxp_kva_t address, size_t size)
{
	uint_t pgoffset;
	caddr_t base;
	pgcnt_t npages;

	if (size == 0 || address == NULL)
		return;

	pgoffset = (uintptr_t)address & PAGEOFFSET;
	base = (caddr_t)address - pgoffset;
	npages = btopr(size + pgoffset);
	hat_unload(kas.a_hat, base, ptob(npages), HAT_UNLOAD_UNLOCK);
	vmem_free(heap_arena, base, ptob(npages));
}

/*
 * For a VA return the pfn
 */
int
gfxp_va2pa(struct as *as, caddr_t addr, uint64_t *pa)
{
	*pa = (uint64_t)(hat_getpfnum(as->a_hat, addr) << PAGESHIFT);
	return (0);
}

/*
 * The KVA returned from ddi_dma_mem_alloc() always has WB/cached PTEs.
 * This causes severe coherency problems when the pages are exported to
 * user space with uncached/UC/WC PTEs.  Fix the cache attributes for
 * each page, until ddi_dma_mem_alloc() returns KVAs with the correct
 * cache attributes.
 */
void
gfxp_fix_mem_cache_attrs(caddr_t kva_start, size_t length, int cache_attr)
{
	struct hat *hat = kas.a_hat;
	uint_t hat_attr;
	uint_t hat_flags;
	pfn_t pfnum;
	caddr_t kva;
	caddr_t kva_max;

	if (hat_getattr(hat, kva_start, &hat_attr) == -1)
		return;

	if (cache_attr == GFXP_MEMORY_UNCACHED) {
		hat_attr &= ~HAT_ORDER_MASK;
		hat_attr |= HAT_STRICTORDER | HAT_PLAT_NOCACHE;
	} else if (cache_attr == GFXP_MEMORY_WRITECOMBINED) {
		hat_attr &= ~HAT_ORDER_MASK;
		hat_attr |= HAT_MERGING_OK | HAT_PLAT_NOCACHE;
	} else
		return;

	hat_attr |= HAT_NOSYNC;

	hat_flags = HAT_LOAD_LOCK | HAT_LOAD_NOCONSIST;

	kva = (caddr_t)((uintptr_t)kva_start & (uintptr_t)PAGEMASK);
	kva_max = (caddr_t)((uintptr_t)(kva_start + length + PAGEOFFSET) &
		(uintptr_t)PAGEMASK);

	for (; kva < kva_max; kva += PAGESIZE) {
		pfnum = hat_getpfnum(hat, kva);
		hat_unload(hat, kva, PAGESIZE, HAT_UNLOAD_UNLOCK);
		hat_devload(hat, kva, PAGESIZE, pfnum, hat_attr, hat_flags);
	}
}

int
gfxp_ddi_dma_mem_alloc(ddi_dma_handle_t handle, size_t length,
    ddi_device_acc_attr_t  *accattrp, uint_t flags, int (*waitfp) (caddr_t),
    caddr_t arg, caddr_t *kaddrp, size_t *real_length,
    ddi_acc_handle_t *handlep)
{
	int cache_attr;

	if (ddi_dma_mem_alloc(handle, length, accattrp, flags, waitfp, arg,
	    kaddrp, real_length, handlep) == DDI_FAILURE) {
		return (DDI_FAILURE);
	}

	if (accattrp == NULL)
		return (DDI_SUCCESS);

	if (accattrp->devacc_attr_dataorder == DDI_STRICTORDER_ACC)
		cache_attr = GFXP_MEMORY_UNCACHED;
	else if (accattrp->devacc_attr_dataorder == DDI_MERGING_OK_ACC)
		cache_attr = GFXP_MEMORY_WRITECOMBINED;
	else
		return (DDI_SUCCESS);

	gfxp_fix_mem_cache_attrs(*kaddrp, *real_length, cache_attr);

	return (DDI_SUCCESS);
}

int
gfxp_mlock_user_memory(caddr_t address, size_t length)
{
	struct as *as = ttoproc(curthread)->p_as;
	int error = 0;

	if (((uintptr_t)address & PAGEOFFSET) != 0 || length == 0)
		return (set_errno(EINVAL));

	if (valid_usr_range(address, length, 0, as, as->a_userlimit) !=
	    RANGE_OKAY)
		return (set_errno(ENOMEM));

	error = as_ctl(as, address, length, MC_LOCK, 0, 0, NULL, 0);
	if (error)
		(void) set_errno(error);

	return (error);
}

int
gfxp_munlock_user_memory(caddr_t address, size_t length)
{
	struct as *as = ttoproc(curthread)->p_as;
	int error = 0;

	if (((uintptr_t)address & PAGEOFFSET) != 0 || length == 0)
		return (set_errno(EINVAL));

	if (valid_usr_range(address, length, 0, as, as->a_userlimit) !=
	    RANGE_OKAY)
		return (set_errno(ENOMEM));

	error = as_ctl(as, address, length, MC_UNLOCK, 0, 0, NULL, 0);
	if (error)
		(void) set_errno(error);

	return (error);
}
