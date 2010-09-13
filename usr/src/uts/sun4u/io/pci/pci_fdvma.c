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
 * Copyright (c) 1998, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Internal PCI Fast DVMA implementation
 */
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/async.h>
#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/dvma.h>
#include <vm/hat.h>
#include <sys/pci/pci_obj.h>

/*LINTLIBRARY*/

static struct dvma_ops fdvma_ops;

/*
 * The following routines are used to implement the sun4u fast dvma
 * routines on this bus.
 */

/*ARGSUSED*/
static void
pci_fdvma_load(ddi_dma_handle_t h, caddr_t a, uint_t len, uint_t index,
	ddi_dma_cookie_t *cp)
{
	ddi_dma_impl_t *mp = (ddi_dma_impl_t *)h;
	fdvma_t *fdvma_p = (fdvma_t *)mp->dmai_fdvma;
	pci_t *pci_p = (pci_t *)fdvma_p->softsp;
	iommu_t *iommu_p = pci_p->pci_iommu_p;
	dev_info_t *dip = pci_p->pci_dip;
	dvma_addr_t dvma_addr, dvma_pg;
	caddr_t baseaddr = (caddr_t)((uintptr_t)a & PAGEMASK);
	uint32_t offset;
	size_t npages, pg_index;
	pfn_t pfn;
	int i;
	uint64_t tte;

	offset = (uint32_t)(uintptr_t)a & IOMMU_PAGE_OFFSET;
	npages = IOMMU_BTOPR(len + offset);
	if (!npages)
		return;

	/* make sure we don't exceed reserved boundary */
	DEBUG3(DBG_FAST_DVMA, dip, "load index=%x: %p+%x ", index, a, len);
	if (index + npages > mp->dmai_ndvmapages) {
		cmn_err(pci_panic_on_fatal_errors ? CE_PANIC : CE_WARN,
			"%s%d: kaddr_load index(%x)+pgs(%lx) exceeds limit\n",
			ddi_driver_name(dip), ddi_get_instance(dip),
			index, npages);
		return;
	}

	/* better have not already loaded something at this address */
	ASSERT(fdvma_p->kvbase[index] == NULL);
	ASSERT(fdvma_p->pagecnt[index] == 0);

	dvma_addr = mp->dmai_mapping + IOMMU_PTOB(index);
	dvma_pg = IOMMU_BTOP(dvma_addr);
	pg_index = dvma_pg - iommu_p->dvma_base_pg;

	/* construct the dma cookie to be returned */
	MAKE_DMA_COOKIE(cp, dvma_addr | offset, len);
	DEBUG2(DBG_FAST_DVMA | DBG_CONT, dip, "cookie: %x+%x\n",
		cp->dmac_address, cp->dmac_size);

	for (i = 0, a = baseaddr; i < npages; i++, a += IOMMU_PAGE_SIZE) {
		if (pci_dvma_remap_enabled) {
			uint_t flags = HAC_NOSLEEP | HAC_PAGELOCK;

			(void) hat_add_callback(pci_fast_dvma_cbid, a,
			    IOMMU_PAGE_SIZE, flags, mp, &pfn,
			    &fdvma_p->cbcookie[index + i]);

			mp->dmai_flags |= DMAI_FLAGS_RELOC;
		} else {
			pfn = hat_getpfnum(kas.a_hat, a);
		}
		if (pfn == PFN_INVALID)
			goto bad_pfn;

		if (i == 0)	/* setup template, all bits except pfn value */
			tte = MAKE_TTE_TEMPLATE((iopfn_t)pfn, mp);

		/* XXX assumes iommu and mmu has same page size */
		iommu_p->iommu_tsb_vaddr[pg_index + i] = tte | IOMMU_PTOB(pfn);
		IOMMU_PAGE_FLUSH(iommu_p, (dvma_pg + i));
	}

	mp->dmai_flags |= DMAI_FLAGS_MAPPED;
	fdvma_p->kvbase[index] = baseaddr;
	fdvma_p->pagecnt[index] = npages;

	return;
bad_pfn:
	cmn_err(CE_WARN, "%s%d: kaddr_load can't get page frame for vaddr %x",
		ddi_driver_name(dip), ddi_get_instance(dip), (int)(uintptr_t)a);
}

/*ARGSUSED*/
static void
pci_fdvma_unload(ddi_dma_handle_t h, uint_t index, uint_t sync_flags)
{
	ddi_dma_impl_t *mp = (ddi_dma_impl_t *)h;
	fdvma_t *fdvma_p = (fdvma_t *)mp->dmai_fdvma;
	pci_t *pci_p = (pci_t *)fdvma_p->softsp;
	size_t npg = fdvma_p->pagecnt[index];

	dvma_addr_t dvma_pg = IOMMU_BTOP(mp->dmai_mapping + IOMMU_PTOB(index));

	DEBUG5(DBG_FAST_DVMA, pci_p->pci_dip,
		"unload index=%x flags=%x %x+%x+%x\n", index, sync_flags,
		mp->dmai_mapping, IOMMU_PTOB(index), IOMMU_PTOB(npg));

	if (!pci_dvma_sync_before_unmap) {
		if (PCI_DMA_CANRELOC(mp))
			pci_fdvma_unregister_callbacks(pci_p, fdvma_p, mp,
				index);
		fdvma_p->kvbase[index] = NULL;
		iommu_unmap_pages(pci_p->pci_iommu_p, dvma_pg, npg);
	}
	if (sync_flags != -1)
		pci_dma_sync(pci_p->pci_dip, mp->dmai_rdip, h,
			IOMMU_PTOB(index), IOMMU_PTOB(npg), sync_flags);
	if (pci_dvma_sync_before_unmap) {
		if (PCI_DMA_CANRELOC(mp))
			pci_fdvma_unregister_callbacks(pci_p, fdvma_p, mp,
				index);
		fdvma_p->kvbase[index] = NULL;
		iommu_unmap_pages(pci_p->pci_iommu_p, dvma_pg, npg);
	}
	fdvma_p->pagecnt[index] = 0;
}

/*ARGSUSED*/
static void
pci_fdvma_sync(ddi_dma_handle_t h, uint_t index, uint_t sync_flags)
{
	ddi_dma_impl_t *mp = (ddi_dma_impl_t *)h;
	fdvma_t *fdvma_p = (fdvma_t *)mp->dmai_fdvma;
	pci_t *pci_p = (pci_t *)fdvma_p->softsp;
	size_t npg = fdvma_p->pagecnt[index];

	DEBUG5(DBG_FAST_DVMA, pci_p->pci_dip,
		"sync index=%x flags=%x %x+%x+%x\n", index, sync_flags,
		mp->dmai_mapping, IOMMU_PTOB(index), IOMMU_PTOB(npg));
	pci_dma_sync(pci_p->pci_dip, mp->dmai_rdip, h, IOMMU_PTOB(index),
		IOMMU_PTOB(npg), sync_flags);
}

int
pci_fdvma_reserve(dev_info_t *dip, dev_info_t *rdip, pci_t *pci_p,
	ddi_dma_req_t *dmareq, ddi_dma_handle_t *handlep)
{
	fdvma_t *fdvma_p;
	dvma_addr_t dvma_pg;
	iommu_t *iommu_p = pci_p->pci_iommu_p;
	size_t npages;
	ddi_dma_impl_t *mp;
	ddi_dma_lim_t *lim_p = dmareq->dmar_limits;
	ulong_t hi = lim_p->dlim_addr_hi;
	ulong_t lo = lim_p->dlim_addr_lo;
	size_t counter_max = (lim_p->dlim_cntr_max + 1) & IOMMU_PAGE_MASK;

	if (pci_disable_fdvma)
		return (DDI_FAILURE);

	DEBUG2(DBG_DMA_CTL, dip, "DDI_DMA_RESERVE: rdip=%s%d\n",
		ddi_driver_name(rdip), ddi_get_instance(rdip));

	/*
	 * Check the limit structure.
	 */
	if ((lo >= hi) || (hi < iommu_p->iommu_dvma_base))
		return (DDI_DMA_BADLIMITS);

	/*
	 * Allocate DVMA space from reserve.
	 */
	npages = dmareq->dmar_object.dmao_size;
	if ((long)atomic_add_long_nv(&iommu_p->iommu_dvma_reserve,
	    -npages) < 0) {
		atomic_add_long(&iommu_p->iommu_dvma_reserve, npages);
		return (DDI_DMA_NORESOURCES);
	}

	/*
	 * Allocate the dma handle.
	 */
	mp = kmem_zalloc(sizeof (pci_dma_hdl_t), KM_SLEEP);

	/*
	 * Get entries from dvma space map.
	 * (vmem_t *vmp,
	 *	size_t size, size_t align, size_t phase,
	 *	size_t nocross, void *minaddr, void *maxaddr, int vmflag)
	 */
	dvma_pg = IOMMU_BTOP((ulong_t)vmem_xalloc(iommu_p->iommu_dvma_map,
		IOMMU_PTOB(npages), IOMMU_PAGE_SIZE, 0,
		counter_max, (void *)lo, (void *)(hi + 1),
		dmareq->dmar_fp == DDI_DMA_SLEEP ? VM_SLEEP : VM_NOSLEEP));
	if (dvma_pg == 0) {
		atomic_add_long(&iommu_p->iommu_dvma_reserve, npages);
		kmem_free(mp, sizeof (pci_dma_hdl_t));
		return (DDI_DMA_NOMAPPING);
	}

	/*
	 * Create the fast dvma request structure.
	 */
	fdvma_p = kmem_alloc(sizeof (fdvma_t), KM_SLEEP);
	fdvma_p->kvbase = kmem_zalloc(npages * sizeof (caddr_t), KM_SLEEP);
	fdvma_p->pagecnt = kmem_zalloc(npages * sizeof (uint_t), KM_SLEEP);
	fdvma_p->cbcookie = kmem_zalloc(npages * sizeof (void *), KM_SLEEP);
	fdvma_p->ops = &fdvma_ops;
	fdvma_p->softsp = (caddr_t)pci_p;
	fdvma_p->sync_flag = NULL;

	/*
	 * Initialize the handle.
	 */
	mp->dmai_rdip = rdip;
	mp->dmai_rflags = DMP_BYPASSNEXUS |
		pci_dma_consist_check(dmareq->dmar_flags, pci_p->pci_pbm_p);
	if (!(dmareq->dmar_flags & DDI_DMA_RDWR))
		mp->dmai_rflags |= DDI_DMA_READ;
	mp->dmai_flags = DMAI_FLAGS_INUSE |
		(mp->dmai_rflags & DMP_NOSYNC ? DMAI_FLAGS_NOSYNC : 0);
	mp->dmai_minxfer = dmareq->dmar_limits->dlim_minxfer;
	mp->dmai_burstsizes = dmareq->dmar_limits->dlim_burstsizes;
	mp->dmai_mapping = IOMMU_PTOB(dvma_pg);
	mp->dmai_ndvmapages = npages;
	mp->dmai_size = npages * IOMMU_PAGE_SIZE;
	mp->dmai_nwin = 0;
	mp->dmai_fdvma = (caddr_t)fdvma_p;

	DEBUG4(DBG_DMA_CTL, dip,
		"PCI_DVMA_RESERVE: mp=%p dvma=%x npages=%x private=%p\n",
		mp, mp->dmai_mapping, npages, fdvma_p);
	*handlep = (ddi_dma_handle_t)mp;
	return (DDI_SUCCESS);
}

int
pci_fdvma_release(dev_info_t *dip, pci_t *pci_p, ddi_dma_impl_t *mp)
{
	iommu_t *iommu_p = pci_p->pci_iommu_p;
	size_t npages;
	fdvma_t *fdvma_p = (fdvma_t *)mp->dmai_fdvma;

	if (pci_disable_fdvma)
		return (DDI_FAILURE);

	/* validate fdvma handle */
	if (!(mp->dmai_rflags & DMP_BYPASSNEXUS)) {
		DEBUG0(DBG_DMA_CTL, dip, "DDI_DMA_RELEASE: not fast dma\n");
		return (DDI_FAILURE);
	}

	/* flush all reserved dvma addresses from iommu */
	pci_dma_sync_unmap(dip, mp->dmai_rdip, mp);

	npages = mp->dmai_ndvmapages;
	pci_vmem_free(iommu_p, mp, (void *)mp->dmai_mapping, npages);

	atomic_add_long(&iommu_p->iommu_dvma_reserve, npages);
	mp->dmai_ndvmapages = 0;

	/* see if there is anyone waiting for dvma space */
	if (iommu_p->iommu_dvma_clid != 0) {
		DEBUG0(DBG_DMA_CTL, dip, "run dvma callback\n");
		ddi_run_callback(&iommu_p->iommu_dvma_clid);
	}

	/* free data structures */
	kmem_free(fdvma_p->kvbase, npages * sizeof (caddr_t));
	kmem_free(fdvma_p->pagecnt, npages * sizeof (uint_t));
	kmem_free(fdvma_p->cbcookie, npages * sizeof (void *));
	kmem_free(fdvma_p, sizeof (fdvma_t));
	kmem_free(mp, sizeof (pci_dma_hdl_t));

	/* see if there is anyone waiting for kmem */
	if (pci_kmem_clid != 0) {
		DEBUG0(DBG_DMA_CTL, dip, "run handle callback\n");
		ddi_run_callback(&pci_kmem_clid);
	}
	return (DDI_SUCCESS);
}

/*
 * fast dvma ops structure:
 */
static struct dvma_ops fdvma_ops = {
	DVMAO_REV,
	pci_fdvma_load,
	pci_fdvma_unload,
	pci_fdvma_sync
};
