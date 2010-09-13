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

/*
 * PCI nexus DVMA relocation routines.
 *
 * These routines handle the interactions with the HAT layer to
 * implement page relocation for page(s) which have active DMA handle
 * bindings when DVMA is being used for those handles.
 *
 * The current modus operandi is as follows:
 *
 *   Object binding: register the appropriate callback for each page
 *     of the kernel object while obtaining the PFN for the DVMA page.
 *
 *   Object unbinding: unregister the callback for each page of the
 *     kernel object.
 *
 *   Relocation request:
 *     1) Suspend the bus and sync the caches.
 *     2) Remap the DVMA object using the new provided PFN.
 *     3) Unsuspend the bus.
 *
 *  The relocation code runs with CPUs captured (idling in xc_loop())
 *  so we can only acquire spinlocks at PIL >= 13 for synchronization
 *  within those codepaths.
 */
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/async.h>
#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/machsystm.h>
#include <sys/ddi_impldefs.h>
#include <sys/dvma.h>
#include <vm/hat.h>
#include <sys/pci/pci_obj.h>

/*LINTLIBRARY*/

void
pci_dvma_unregister_callbacks(pci_t *pci_p, ddi_dma_impl_t *mp)
{
	ddi_dma_obj_t *dobj_p = &mp->dmai_object;
	struct as *as_p = dobj_p->dmao_obj.virt_obj.v_as;
	page_t **pplist = dobj_p->dmao_obj.virt_obj.v_priv;
	caddr_t vaddr = dobj_p->dmao_obj.virt_obj.v_addr;
	struct hat *hat_p;
	uint32_t offset;
	int i;

	if (!PCI_DMA_CANRELOC(mp))
		return;

	hat_p = (as_p == NULL)? kas.a_hat : as_p->a_hat;
	ASSERT(hat_p == kas.a_hat);
	ASSERT(pplist == NULL);

	offset = mp->dmai_roffset;
	hat_delete_callback(vaddr, IOMMU_PAGE_SIZE - offset, mp, HAC_PAGELOCK,
	    MP_HAT_CB_COOKIE(mp, 0));
	vaddr = (caddr_t)(((uintptr_t)vaddr + IOMMU_PAGE_SIZE) &
	    IOMMU_PAGE_MASK);
	for (i = 1; i < mp->dmai_ndvmapages; i++) {
		hat_delete_callback(vaddr, IOMMU_PAGE_SIZE, mp, HAC_PAGELOCK,
		    MP_HAT_CB_COOKIE(mp, i));
		vaddr += IOMMU_PAGE_SIZE;
	}
	mp->dmai_flags &= ~DMAI_FLAGS_RELOC;
}

static int
pci_dvma_postrelocator(caddr_t va, uint_t len, uint_t flags, void *mpvoid,
	pfn_t newpfn)
{
	ddi_dma_impl_t *mp = (ddi_dma_impl_t *)mpvoid;
	dev_info_t *rdip = mp->dmai_rdip;
	ddi_dma_obj_t *dobj_p = &mp->dmai_object;
	page_t **pplist = dobj_p->dmao_obj.virt_obj.v_priv;
	caddr_t baseva = dobj_p->dmao_obj.virt_obj.v_addr;
	int index;
	size_t length = IOMMU_PTOB(1);
	off_t offset;

	DEBUG0(DBG_RELOC, rdip, "postrelocator called\n");

	if (flags == HAT_POSTUNSUSPEND) {
		mutex_enter(&pci_reloc_mutex);
		ASSERT(pci_reloc_thread == curthread);
		ASSERT(pci_reloc_presuspend > 0);
		if (--pci_reloc_presuspend == 0) {
			pci_reloc_thread = NULL;
			cv_broadcast(&pci_reloc_cv);
		}
		mutex_exit(&pci_reloc_mutex);
		return (0);
	}

	ASSERT(flags == HAT_UNSUSPEND);
	ASSERT(pci_reloc_suspend > 0);
	pci_reloc_suspend--;

	ASSERT(len <= length);
	ASSERT(pplist == NULL);	/* addr bind handle only */
	ASSERT(dobj_p->dmao_obj.virt_obj.v_as == &kas ||
	    dobj_p->dmao_obj.virt_obj.v_as == NULL);
	ASSERT(PCI_DMA_ISDVMA(mp));
	ASSERT(pci_reloc_thread == curthread);

	offset = va - baseva;
	index = IOMMU_BTOPR(offset);
	ASSERT(index < mp->dmai_ndvmapages);

	DEBUG3(DBG_RELOC, rdip, "index 0x%x, vaddr 0x%llx, baseva 0x%llx\n",
	    index, (int64_t)va, (int64_t)baseva);

	if ((mp)->dmai_ndvmapages == 1) {
		DEBUG2(DBG_RELOC, rdip, "pfn remap (1) 0x%x -> 0x%x\n",
		    mp->dmai_pfnlst, newpfn);
		    mp->dmai_pfnlst = (void *)newpfn;
	} else {
		DEBUG3(DBG_RELOC, rdip, "pfn remap (%d) 0x%x -> 0x%x\n",
		    index, ((iopfn_t *)mp->dmai_pfnlst)[index], newpfn);
		((iopfn_t *)mp->dmai_pfnlst)[index] = (iopfn_t)newpfn;
	}

	if (ddi_dma_mctl(rdip, rdip, (ddi_dma_handle_t)mp, DDI_DMA_REMAP,
	    &offset, &length, NULL, 0) != DDI_SUCCESS)
		return (EIO);
	if (ddi_ctlops(rdip, rdip, DDI_CTLOPS_UNQUIESCE, NULL, NULL) !=
	    DDI_SUCCESS)
		return (EIO);

	return (0);
}

/*
 * Log a warning message if a callback is still registered on
 * a page which is being freed.  This is indicative of a driver
 * bug -- DMA handles are bound, and the memory is being freed by
 * the VM subsystem without an unbind call on the handle first.
 */
static int
pci_dma_relocerr(caddr_t va, uint_t len, uint_t errorcode, void *mpvoid)
{
	int errlevel = pci_dma_panic_on_leak? CE_PANIC : CE_WARN;
	if (errorcode == HAT_CB_ERR_LEAKED) {
		cmn_err(errlevel, "object 0x%p has a bound DMA handle 0x%p\n",
			va, mpvoid);
		return (0);
	}

	/* unknown error code, unhandled so panic */
	return (EINVAL);
}

/*
 * pci DVMA remap entry points
 *
 * Called in response to a DDI_DMA_REMAP DMA ctlops command.
 * Remaps the region specified in the underlying IOMMU. Safe
 * to assume that the bus was quiesced and ddi_dma_sync() was
 * invoked by the caller before we got to this point.
 */
int
pci_dvma_remap(dev_info_t *dip, dev_info_t *rdip, ddi_dma_impl_t *mp,
	off_t offset, size_t length)
{
	pci_t *pci_p = get_pci_soft_state(ddi_get_instance(dip));
	iommu_t *iommu_p = pci_p->pci_iommu_p;
	dvma_addr_t dvma_pg;
	size_t npgs;
	int idx;

	dvma_pg = IOMMU_BTOP(mp->dmai_mapping);
	idx = IOMMU_BTOPR(offset);
	dvma_pg += idx;
	npgs = IOMMU_BTOPR(length);

	DEBUG3(DBG_RELOC, mp->dmai_rdip,
	    "pci_dvma_remap: dvma_pg 0x%llx len 0x%llx idx 0x%x\n",
	    dvma_pg, length, idx);

	ASSERT(pci_p->pci_pbm_p->pbm_quiesce_count > 0);
	iommu_remap_pages(iommu_p, mp, dvma_pg, npgs, idx);

	return (DDI_SUCCESS);
}

void
pci_fdvma_remap(ddi_dma_impl_t *mp, caddr_t kvaddr, dvma_addr_t dvma_pg,
	size_t npages, size_t index, pfn_t newpfn)
{
	fdvma_t *fdvma_p = (fdvma_t *)mp->dmai_fdvma;
	pci_t *pci_p = (pci_t *)fdvma_p->softsp;
	iommu_t *iommu_p = pci_p->pci_iommu_p;
	dev_info_t *dip = pci_p->pci_dip;
	iopfn_t pfn = (iopfn_t)newpfn;
	dvma_addr_t pg_index = dvma_pg - iommu_p->dvma_base_pg;
	int i;
	uint64_t tte;

	/* make sure we don't exceed reserved boundary */
	DEBUG3(DBG_FAST_DVMA, dip, "fast remap index=%x: %p, npgs=%x", index,
	    kvaddr, npages);
	if (index + npages > mp->dmai_ndvmapages) {
		cmn_err(pci_panic_on_fatal_errors ? CE_PANIC : CE_WARN,
			"%s%d: fdvma remap index(%lx)+pgs(%lx) exceeds limit\n",
			ddi_driver_name(dip), ddi_get_instance(dip),
			index, npages);
		return;
	}

	for (i = 0; i < npages; i++, kvaddr += IOMMU_PAGE_SIZE) {
		DEBUG3(DBG_FAST_DVMA, dip, "remap dvma_pg %x -> pfn %x,"
		    " old tte 0x%llx\n", dvma_pg + i, pfn,
		    iommu_p->iommu_tsb_vaddr[pg_index + i]);

		if (pfn == PFN_INVALID)
			goto bad_pfn;

		if (i == 0)
			tte = MAKE_TTE_TEMPLATE(pfn, mp);

		/* XXX assumes iommu and mmu has same page size */
		iommu_p->iommu_tsb_vaddr[pg_index + i] = tte | IOMMU_PTOB(pfn);
		IOMMU_PAGE_FLUSH(iommu_p, (dvma_pg + i));
	}
	return;
bad_pfn:
	cmn_err(CE_WARN, "%s%d: fdvma remap can't get page frame for vaddr %p",
		ddi_driver_name(dip), ddi_get_instance(dip), kvaddr);
}

static int
pci_fdvma_prerelocator(caddr_t va, uint_t len, uint_t flags, void *mpvoid)
{
	ddi_dma_impl_t *mp = (ddi_dma_impl_t *)mpvoid;
	fdvma_t *fdvma_p = (fdvma_t *)mp->dmai_fdvma;
	caddr_t baseva, endva;
	int i;

	/*
	 * It isn't safe to do relocation if all of the IOMMU
	 * mappings haven't yet been established at this index.
	 */
	for (i = 0; i < mp->dmai_ndvmapages; i++) {
		baseva = fdvma_p->kvbase[i];
		endva = baseva + IOMMU_PTOB(fdvma_p->pagecnt[i]);
		if (va >= baseva && va < endva)
			return (0);	/* found a valid index */
	}
	return (EAGAIN);
}

static int
pci_fdvma_postrelocator(caddr_t va, uint_t len, uint_t flags, void *mpvoid,
	pfn_t pfn)
{
	ddi_dma_impl_t *mp = (ddi_dma_impl_t *)mpvoid;
	dev_info_t *rdip = mp->dmai_rdip;
	fdvma_t *fdvma_p = (fdvma_t *)mp->dmai_fdvma;
	caddr_t baseva;
	dvma_addr_t dvma_pg;
	size_t length = PAGESIZE;
	int i;

	DEBUG0(DBG_RELOC, rdip, "fdvma postrelocator called\n");

	if (flags == HAT_POSTUNSUSPEND) {
		mutex_enter(&pci_reloc_mutex);
		ASSERT(pci_reloc_thread == curthread);
		if (--pci_reloc_presuspend == 0) {
			pci_reloc_thread = NULL;
			cv_broadcast(&pci_reloc_cv);
		}
		mutex_exit(&pci_reloc_mutex);
		return (0);
	}

	pci_reloc_suspend--;

	ASSERT(flags == HAT_UNSUSPEND);
	ASSERT(len <= length);
	ASSERT((mp->dmai_rflags & DMP_BYPASSNEXUS) != 0);

	/*
	 * This virtual page can have multiple cookies that refer
	 * to it within the same handle. We must walk the whole
	 * table for this DMA handle finding all the cookies, and
	 * update all of them. Sigh.
	 */
	for (i = 0; i < mp->dmai_ndvmapages; i++) {
		caddr_t endva;
		int index;

		baseva = fdvma_p->kvbase[i];
		endva = baseva + IOMMU_PTOB(fdvma_p->pagecnt[i]);

		if (va >= baseva && va < endva) {
			index = i + IOMMU_BTOP(va - baseva);
			ASSERT(index < mp->dmai_ndvmapages);

			DEBUG4(DBG_RELOC, rdip, "mp %p: index 0x%x, "
			    " vaddr 0x%llx, baseva 0x%llx\n", mp, index,
			    (int64_t)va, (int64_t)baseva);

			dvma_pg = IOMMU_BTOP(mp->dmai_mapping) + index;
			pci_fdvma_remap(mp, va, dvma_pg, IOMMU_BTOP(length),
			    index, pfn);
		}
	}

	if (ddi_ctlops(rdip, rdip, DDI_CTLOPS_UNQUIESCE, NULL, NULL) !=
	    DDI_SUCCESS)
		return (EIO);

	return (0);
}

void
pci_fdvma_unregister_callbacks(pci_t *pci_p, fdvma_t *fdvma_p,
	ddi_dma_impl_t *mp, uint_t index)
{
	size_t npgs = fdvma_p->pagecnt[index];
	caddr_t kva = fdvma_p->kvbase[index];
	int i;

	ASSERT(index + npgs <= mp->dmai_ndvmapages);
	ASSERT(kva != NULL);

	for (i = 0; i < npgs && pci_dvma_remap_enabled;
	    i++, kva += IOMMU_PAGE_SIZE)
		hat_delete_callback(kva, IOMMU_PAGE_SIZE, mp, HAC_PAGELOCK,
		    fdvma_p->cbcookie[index + i]);
}

static int
pci_common_prerelocator(caddr_t va, uint_t len, uint_t flags, void *mpvoid)
{
	ddi_dma_impl_t *mp = (ddi_dma_impl_t *)mpvoid;
	ddi_dma_handle_t h = (ddi_dma_handle_t)mpvoid;
	dev_info_t *rdip = mp->dmai_rdip;
	int ret;

	DEBUG0(DBG_RELOC, rdip, "prerelocator called\n");

	if (flags == HAT_PRESUSPEND) {
		if (!ddi_prop_exists(DDI_DEV_T_ANY, rdip, DDI_PROP_NOTPROM,
		    "dvma-remap-supported"))
			return (ENOTSUP);
		if (!PCI_DMA_ISMAPPED(mp))
			return (EAGAIN);

		if (mp->dmai_rflags & DMP_BYPASSNEXUS) {
			ret = pci_fdvma_prerelocator(va, len, flags, mpvoid);
			if (ret != 0)
				return (ret);
		} else if (!PCI_DMA_ISDVMA(mp))
			return (EINVAL);

		/*
		 * Acquire the exclusive right to relocate a PCI DMA page,
		 * since we later have to pause CPUs which could otherwise
		 * lead to all sorts of synchronization headaches.
		 */
		mutex_enter(&pci_reloc_mutex);
		if (pci_reloc_thread != curthread) {
			while (pci_reloc_thread != NULL) {
				cv_wait(&pci_reloc_cv, &pci_reloc_mutex);
			}
			pci_reloc_thread = curthread;
			ASSERT(pci_reloc_suspend == 0);
		}
		mutex_exit(&pci_reloc_mutex);

		ASSERT(pci_reloc_thread == curthread);
		pci_reloc_presuspend++;

		return (0);
	}

	ASSERT(flags == HAT_SUSPEND);
	ASSERT(PCI_DMA_CANRELOC(mp));
	ASSERT(pci_reloc_thread == curthread);
	pci_reloc_suspend++;

	if (ddi_ctlops(rdip, rdip, DDI_CTLOPS_QUIESCE, NULL, NULL) !=
	    DDI_SUCCESS)
		return (EIO);
	if (ddi_dma_sync(h, 0, 0, DDI_DMA_SYNC_FORKERNEL) != DDI_SUCCESS)
		return (EIO);

	return (0);
}

/*
 * Register two callback types: one for normal DVMA and the
 * other for fast DVMA, since each method has a different way
 * of tracking the PFNs behind a handle.
 */
void
pci_reloc_init(void)
{
	int key = pci_reloc_getkey();

	mutex_init(&pci_reloc_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&pci_reloc_cv, NULL, CV_DEFAULT, NULL);
	pci_dvma_cbid = hat_register_callback(
		key + ('D'<<24 | 'V'<<16 | 'M'<<8 | 'A'),
		pci_common_prerelocator, pci_dvma_postrelocator,
		pci_dma_relocerr, 1);
	pci_fast_dvma_cbid = hat_register_callback(
		key + ('F'<<24 | 'D'<<16 | 'M'<<8 | 'A'),
		pci_common_prerelocator,
		pci_fdvma_postrelocator, pci_dma_relocerr, 1);
}

void
pci_reloc_fini(void)
{
	cv_destroy(&pci_reloc_cv);
	mutex_destroy(&pci_reloc_mutex);
}
