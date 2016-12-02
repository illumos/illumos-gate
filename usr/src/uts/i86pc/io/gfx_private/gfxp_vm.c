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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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
#include <sys/gfx_private.h>

#ifdef __xpv
#include <sys/hypervisor.h>
#endif

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
	pfn_t pfn;

	if (size == 0)
		return (0);

#ifdef __xpv
	/*
	 * The hypervisor doesn't allow r/w mappings to some pages, such as
	 * page tables, gdt, etc. Detect %cr3 to notify users of this interface.
	 */
	if (start == mmu_ptob(mmu_btop(getcr3())))
		return (0);
#endif

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

#ifdef __xpv
	ASSERT(DOMAIN_IS_INITDOMAIN(xen_info));
	pfn = xen_assign_pfn(mmu_btop(base));
#else
	pfn = btop(base);
#endif

	hat_devload(kas.a_hat, cvaddr, ptob(npages), pfn,
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
#ifdef __xpv
	ASSERT(DOMAIN_IS_INITDOMAIN(xen_info));
	*pa = pa_to_ma(pfn_to_pa(hat_getpfnum(as->a_hat, addr)));
#else
	*pa = pfn_to_pa(hat_getpfnum(as->a_hat, addr));
#endif
	return (0);
}

/*
 * NOP now
 */
/* ARGSUSED */
void
gfxp_fix_mem_cache_attrs(caddr_t kva_start, size_t length, int cache_attr)
{
}

int
gfxp_ddi_dma_mem_alloc(ddi_dma_handle_t handle, size_t length,
    ddi_device_acc_attr_t  *accattrp, uint_t flags, int (*waitfp) (caddr_t),
    caddr_t arg, caddr_t *kaddrp, size_t *real_length,
    ddi_acc_handle_t *handlep)
{
	uint_t l_flags = flags & ~IOMEM_DATA_MASK; /* clear cache attrs */
	int e;

	/*
	 * Set an appropriate attribute from devacc_attr_dataorder
	 * to keep compatibility. The cache attributes are igonred
	 * if specified.
	 */
	if (accattrp != NULL) {
		if (accattrp->devacc_attr_dataorder == DDI_STRICTORDER_ACC) {
			l_flags |= IOMEM_DATA_UNCACHED;
		} else if (accattrp->devacc_attr_dataorder ==
		    DDI_MERGING_OK_ACC) {
			l_flags |= IOMEM_DATA_UC_WR_COMBINE;
		} else {
			l_flags |= IOMEM_DATA_CACHED;
		}
	}

	e = ddi_dma_mem_alloc(handle, length, accattrp, l_flags, waitfp,
	    arg, kaddrp, real_length, handlep);
	return (e);
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

gfx_maddr_t
gfxp_convert_addr(paddr_t paddr)
{
#ifdef __xpv
	ASSERT(DOMAIN_IS_INITDOMAIN(xen_info));
	return (pfn_to_pa(xen_assign_pfn(btop(paddr))));
#else
	return ((gfx_maddr_t)paddr);
#endif
}

/*
 * Support getting VA space separately from pages
 */

/*
 * A little like gfxp_map_kernel_space, but
 * just the vmem_alloc part.
 */
caddr_t
gfxp_alloc_kernel_space(size_t size)
{
	caddr_t cvaddr;
	pgcnt_t npages;

	npages = btopr(size);
	cvaddr = vmem_alloc(heap_arena, ptob(npages), VM_NOSLEEP);
	return (cvaddr);
}

/*
 * Like gfxp_unmap_kernel_space, but
 * just the vmem_free part.
 */
void
gfxp_free_kernel_space(caddr_t address, size_t size)
{

	uint_t pgoffset;
	caddr_t base;
	pgcnt_t npages;

	if (size == 0 || address == NULL)
		return;

	pgoffset = (uintptr_t)address & PAGEOFFSET;
	base = (caddr_t)address - pgoffset;
	npages = btopr(size + pgoffset);
	vmem_free(heap_arena, base, ptob(npages));
}

/*
 * Like gfxp_map_kernel_space, but
 * just the hat_devload part.
 */
void
gfxp_load_kernel_space(uint64_t start, size_t size,
    uint32_t mode, caddr_t cvaddr)
{
	uint_t pgoffset;
	uint64_t base;
	pgcnt_t npages;
	int hat_flags;
	uint_t hat_attr;
	pfn_t pfn;

	if (size == 0)
		return;

#ifdef __xpv
	/*
	 * The hypervisor doesn't allow r/w mappings to some pages, such as
	 * page tables, gdt, etc. Detect %cr3 to notify users of this interface.
	 */
	if (start == mmu_ptob(mmu_btop(getcr3())))
		return;
#endif

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

#ifdef __xpv
	ASSERT(DOMAIN_IS_INITDOMAIN(xen_info));
	pfn = xen_assign_pfn(mmu_btop(base));
#else
	pfn = btop(base);
#endif

	hat_devload(kas.a_hat, cvaddr, ptob(npages), pfn,
	    PROT_READ|PROT_WRITE|hat_attr, hat_flags);
}

/*
 * Like gfxp_unmap_kernel_space, but
 * just the had_unload part.
 */
void
gfxp_unload_kernel_space(caddr_t address, size_t size)
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
}

/*
 * Note that "mempool" is optional and normally disabled in drm_gem.c
 * (see HAS_MEM_POOL).  Let's just stub these out so we can reduce
 * changes from the upstream in the DRM driver code.
 */

void
gfxp_mempool_init(void)
{
}

void
gfxp_mempool_destroy(void)
{
}

/* ARGSUSED */
int
gfxp_alloc_from_mempool(struct gfxp_pmem_cookie *cookie, caddr_t *kva,
    pfn_t *pgarray, pgcnt_t alen, int flags)
{
	return (-1);
}

/* ARGSUSED */
void
gfxp_free_mempool(struct gfxp_pmem_cookie *cookie, caddr_t kva, size_t len)
{
}
