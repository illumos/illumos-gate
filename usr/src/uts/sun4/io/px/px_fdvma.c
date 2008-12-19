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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
#include "px_obj.h"

/*LINTLIBRARY*/

static struct dvma_ops fdvma_ops;
typedef struct fast_dvma fdvma_t;

/*
 * The following routines are used to implement the sun4u fast dvma
 * routines on this bus.
 */

/*ARGSUSED*/
static void
px_fdvma_load(ddi_dma_handle_t h, caddr_t a, uint_t len, uint_t index,
	ddi_dma_cookie_t *cp)
{
	ddi_dma_impl_t *mp = (ddi_dma_impl_t *)h;
	fdvma_t *fdvma_p = (fdvma_t *)mp->dmai_fdvma;
	px_t *px_p = (px_t *)fdvma_p->softsp;
	px_mmu_t *mmu_p = px_p->px_mmu_p;
	dev_info_t *dip = px_p->px_dip;
	px_dvma_addr_t dvma_addr, dvma_pg;
	uint32_t offset;
	size_t npages, pg_index;
	uint64_t attr;

	offset = (uint32_t)(uintptr_t)a & MMU_PAGE_OFFSET;
	npages = MMU_BTOPR(len + offset);
	if (!npages)
		return;

	/* make sure we don't exceed reserved boundary */
	DBG(DBG_FAST_DVMA, dip, "load index=%x: %p+%x ", index, a, len);
	if (index + npages > mp->dmai_ndvmapages) {
		cmn_err(px_panic_on_fatal_errors ? CE_PANIC : CE_WARN,
		    "%s%d: kaddr_load index(%x)+pgs(%lx) exceeds limit\n",
		    ddi_driver_name(dip), ddi_get_instance(dip),
		    index, npages);
		return;
	}
	fdvma_p->pagecnt[index] = npages;

	dvma_addr = mp->dmai_mapping + MMU_PTOB(index);
	dvma_pg = MMU_BTOP(dvma_addr);
	pg_index = dvma_pg - mmu_p->dvma_base_pg;

	/* construct the dma cookie to be returned */
	MAKE_DMA_COOKIE(cp, dvma_addr | offset, len);
	DBG(DBG_FAST_DVMA | DBG_CONT, dip, "cookie: %x+%x\n",
	    cp->dmac_address, cp->dmac_size);

	attr = PX_GET_TTE_ATTR(mp->dmai_rflags, mp->dmai_attr.dma_attr_flags);

	if (px_lib_iommu_map(dip, PCI_TSBID(0, pg_index), npages,
	    PX_ADD_ATTR_EXTNS(attr, mp->dmai_bdf), (void *)a, 0,
	    MMU_MAP_BUF) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: kaddr_load can't get "
		    "page frame for vaddr %lx", ddi_driver_name(dip),
		    ddi_get_instance(dip), (uintptr_t)a);
	}
}

/*ARGSUSED*/
static void
px_fdvma_unload(ddi_dma_handle_t h, uint_t index, uint_t sync_flag)
{
	ddi_dma_impl_t *mp = (ddi_dma_impl_t *)h;
	fdvma_t *fdvma_p = (fdvma_t *)mp->dmai_fdvma;
	px_t *px_p = (px_t *)fdvma_p->softsp;
	size_t npages = fdvma_p->pagecnt[index];
	px_dvma_addr_t dvma_pg = MMU_BTOP(mp->dmai_mapping + MMU_PTOB(index));

	DBG(DBG_FAST_DVMA, px_p->px_dip,
	    "unload index=%x sync_flag=%x %x+%x+%x\n", index, sync_flag,
	    mp->dmai_mapping, MMU_PTOB(index), MMU_PTOB(npages));

	px_mmu_unmap_pages(px_p->px_mmu_p, mp, dvma_pg, npages);
	fdvma_p->pagecnt[index] = 0;
}

/*ARGSUSED*/
static void
px_fdvma_sync(ddi_dma_handle_t h, uint_t index, uint_t sync_flag)
{
	ddi_dma_impl_t *mp = (ddi_dma_impl_t *)h;
	fdvma_t *fdvma_p = (fdvma_t *)mp->dmai_fdvma;
	px_t *px_p = (px_t *)fdvma_p->softsp;
	size_t npg = fdvma_p->pagecnt[index];

	DBG(DBG_FAST_DVMA, px_p->px_dip,
	    "sync index=%x sync_flag=%x %x+%x+%x\n", index, sync_flag,
	    mp->dmai_mapping, MMU_PTOB(index), MMU_PTOB(npg));
}

int
px_fdvma_reserve(dev_info_t *dip, dev_info_t *rdip, px_t *px_p,
	ddi_dma_req_t *dmareq, ddi_dma_handle_t *handlep)
{
	fdvma_t *fdvma_p;
	px_dvma_addr_t dvma_pg;
	px_mmu_t *mmu_p = px_p->px_mmu_p;
	size_t npages;
	ddi_dma_impl_t *mp;
	ddi_dma_lim_t *lim_p = dmareq->dmar_limits;
	ulong_t hi = lim_p->dlim_addr_hi;
	ulong_t lo = lim_p->dlim_addr_lo;
	size_t counter_max = (lim_p->dlim_cntr_max + 1) & MMU_PAGE_MASK;

	if (px_disable_fdvma)
		return (DDI_FAILURE);

	DBG(DBG_DMA_CTL, dip, "DDI_DMA_RESERVE: rdip=%s%d\n",
	    ddi_driver_name(rdip), ddi_get_instance(rdip));

	/*
	 * Check the limit structure.
	 */
	if ((lo >= hi) || (hi < mmu_p->mmu_dvma_base))
		return (DDI_DMA_BADLIMITS);

	/*
	 * Check the size of the request.
	 */
	npages = dmareq->dmar_object.dmao_size;
	if (npages > mmu_p->mmu_dvma_reserve)
		return (DDI_DMA_NORESOURCES);

	/*
	 * Allocate the dma handle.
	 */
	mp = kmem_zalloc(sizeof (px_dma_hdl_t), KM_SLEEP);

	/*
	 * Get entries from dvma space map.
	 * (vmem_t *vmp,
	 *	size_t size, size_t align, size_t phase,
	 *	size_t nocross, void *minaddr, void *maxaddr, int vmflag)
	 */
	dvma_pg = MMU_BTOP((ulong_t)vmem_xalloc(mmu_p->mmu_dvma_map,
	    MMU_PTOB(npages), MMU_PAGE_SIZE, 0,
	    counter_max, (void *)lo, (void *)(hi + 1),
	    dmareq->dmar_fp == DDI_DMA_SLEEP ? VM_SLEEP : VM_NOSLEEP));
	if (dvma_pg == 0) {
		kmem_free(mp, sizeof (px_dma_hdl_t));
		return (DDI_DMA_NOMAPPING);
	}
	mmu_p->mmu_dvma_reserve -= npages;

	/*
	 * Create the fast dvma request structure.
	 */
	fdvma_p = kmem_alloc(sizeof (fdvma_t), KM_SLEEP);
	fdvma_p->pagecnt = kmem_alloc(npages * sizeof (uint_t), KM_SLEEP);
	fdvma_p->ops = &fdvma_ops;
	fdvma_p->softsp = (caddr_t)px_p;
	fdvma_p->sync_flag = NULL;

	/*
	 * Initialize the handle.
	 */
	mp->dmai_rdip = rdip;
	mp->dmai_rflags = DMP_BYPASSNEXUS | DDI_DMA_READ | DMP_NOSYNC;
	mp->dmai_burstsizes = dmareq->dmar_limits->dlim_burstsizes;
	mp->dmai_mapping = MMU_PTOB(dvma_pg);
	mp->dmai_ndvmapages = npages;
	mp->dmai_size = npages * MMU_PAGE_SIZE;
	mp->dmai_nwin = 0;
	mp->dmai_fdvma = (caddr_t)fdvma_p;

	/*
	 * The bdf protection value is set to immediate child
	 * at first. It gets modified by switch/bridge drivers
	 * as the code traverses down the fabric topology.
	 *
	 * XXX No IOMMU protection for broken devices.
	 */
	ASSERT((intptr_t)ddi_get_parent_data(rdip) >> 1 == 0);
	mp->dmai_bdf = ((intptr_t)ddi_get_parent_data(rdip) == 1) ? 0 :
	    pcie_get_bdf_for_dma_xfer(dip, rdip);

	DBG(DBG_DMA_CTL, dip,
	    "DDI_DMA_RESERVE: mp=%p dvma=%x npages=%x private=%p\n",
	    mp, mp->dmai_mapping, npages, fdvma_p);
	*handlep = (ddi_dma_handle_t)mp;
	return (DDI_SUCCESS);
}

int
px_fdvma_release(dev_info_t *dip, px_t *px_p, ddi_dma_impl_t *mp)
{
	px_mmu_t *mmu_p = px_p->px_mmu_p;
	size_t npages;
	fdvma_t *fdvma_p = (fdvma_t *)mp->dmai_fdvma;

	if (px_disable_fdvma)
		return (DDI_FAILURE);

	/* validate fdvma handle */
	if (!(mp->dmai_rflags & DMP_BYPASSNEXUS)) {
		DBG(DBG_DMA_CTL, dip, "DDI_DMA_RELEASE: not fast dma\n");
		return (DDI_FAILURE);
	}

	/* flush all reserved dvma addresses from mmu */
	px_mmu_unmap_window(mmu_p, mp);

	npages = mp->dmai_ndvmapages;
	vmem_xfree(mmu_p->mmu_dvma_map, (void *)mp->dmai_mapping,
	    MMU_PTOB(npages));

	mmu_p->mmu_dvma_reserve += npages;
	mp->dmai_ndvmapages = 0;

	/* see if there is anyone waiting for dvma space */
	if (mmu_p->mmu_dvma_clid != 0) {
		DBG(DBG_DMA_CTL, dip, "run dvma callback\n");
		ddi_run_callback(&mmu_p->mmu_dvma_clid);
	}

	/* free data structures */
	kmem_free(fdvma_p->pagecnt, npages * sizeof (uint_t));
	kmem_free(fdvma_p, sizeof (fdvma_t));
	kmem_free(mp, sizeof (px_dma_hdl_t));

	/* see if there is anyone waiting for kmem */
	if (px_kmem_clid != 0) {
		DBG(DBG_DMA_CTL, dip, "run handle callback\n");
		ddi_run_callback(&px_kmem_clid);
	}
	return (DDI_SUCCESS);
}

static struct dvma_ops fdvma_ops = {
	DVMAO_REV,
	px_fdvma_load,
	px_fdvma_unload,
	px_fdvma_sync
};
