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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * PX mmu initialization and configuration
 */
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/async.h>
#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/vmem.h>
#include <sys/machsystm.h>	/* lddphys() */
#include <sys/iommutsb.h>
#include "px_obj.h"

int
px_mmu_attach(px_t *px_p)
{
	dev_info_t		*dip = px_p->px_dip;
	px_mmu_t			*mmu_p;
	uint32_t		base_pg_index, i = 0;
	char			map_name[32];
	px_dvma_range_prop_t	*dvma_prop;
	int			dvma_prop_len;
	uint32_t		cache_size, tsb_entries;

	/*
	 * Allocate mmu state structure and link it to the
	 * px state structure.
	 */
	mmu_p = kmem_zalloc(sizeof (px_mmu_t), KM_SLEEP);
	if (mmu_p == NULL)
		return (DDI_FAILURE);

	px_p->px_mmu_p = mmu_p;
	mmu_p->mmu_px_p = px_p;
	mmu_p->mmu_inst = ddi_get_instance(dip);

	/*
	 * Check for "virtual-dma" property that specifies
	 * the DVMA range.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "virtual-dma", (caddr_t)&dvma_prop, &dvma_prop_len) !=
	    DDI_PROP_SUCCESS) {

		DBG(DBG_ATTACH, dip, "Getting virtual-dma failed\n");

		kmem_free(mmu_p, sizeof (px_mmu_t));
		px_p->px_mmu_p = NULL;

		return (DDI_FAILURE);
	}

	mmu_p->mmu_dvma_base = dvma_prop->dvma_base;
	mmu_p->mmu_dvma_end = dvma_prop->dvma_base +
	    (dvma_prop->dvma_len - 1);
	tsb_entries = MMU_BTOP(dvma_prop->dvma_len);

	kmem_free(dvma_prop, dvma_prop_len);

	/*
	 * Setup base and bounds for DVMA and bypass mappings.
	 */
	mmu_p->mmu_dvma_cache_locks =
		kmem_zalloc(px_dvma_page_cache_entries, KM_SLEEP);

	mmu_p->dvma_base_pg = MMU_BTOP(mmu_p->mmu_dvma_base);
	mmu_p->mmu_dvma_reserve = tsb_entries >> 1;
	mmu_p->dvma_end_pg = MMU_BTOP(mmu_p->mmu_dvma_end);

	/*
	 * Create a virtual memory map for dvma address space.
	 * Reserve 'size' bytes of low dvma space for fast track cache.
	 */
	(void) snprintf(map_name, sizeof (map_name), "%s%d_dvma",
	    ddi_driver_name(dip), ddi_get_instance(dip));

	cache_size = MMU_PTOB(px_dvma_page_cache_entries *
		px_dvma_page_cache_clustsz);
	mmu_p->mmu_dvma_fast_end = mmu_p->mmu_dvma_base +
		cache_size - 1;

	mmu_p->mmu_dvma_map = vmem_create(map_name,
	    (void *)(mmu_p->mmu_dvma_fast_end + 1),
	    MMU_PTOB(tsb_entries) - cache_size, MMU_PAGE_SIZE,
	    NULL, NULL, NULL, MMU_PAGE_SIZE, VM_SLEEP);

	mutex_init(&mmu_p->dvma_debug_lock, NULL, MUTEX_DRIVER, NULL);

	base_pg_index = MMU_BTOP(mmu_p->mmu_dvma_end) - tsb_entries + 1;

	for (i = 0; i < tsb_entries; i++) {
		r_addr_t ra = 0;
		io_attributes_t attr;
		caddr_t va;

		if (px_lib_iommu_getmap(px_p->px_dip, PCI_TSBID(0, i),
		    &attr, &ra) == DDI_SUCCESS) {
			va = (caddr_t)(MMU_PTOB(base_pg_index + i));
			(void) vmem_xalloc(mmu_p->mmu_dvma_map, MMU_PAGE_SIZE,
			    MMU_PAGE_SIZE, 0, 0, va, va + MMU_PAGE_SIZE,
			    VM_NOSLEEP | VM_BESTFIT | VM_PANIC);
		}
	}

	return (DDI_SUCCESS);
}

void
px_mmu_detach(px_t *px_p)
{
	px_mmu_t *mmu_p = px_p->px_mmu_p;

	/*
	 * Free the dvma resource map.
	 */
	vmem_destroy(mmu_p->mmu_dvma_map);

	kmem_free(mmu_p->mmu_dvma_cache_locks,
	    px_dvma_page_cache_entries);

	if (DVMA_DBG_ON(mmu_p))
		px_dvma_debug_fini(mmu_p);

	mutex_destroy(&mmu_p->dvma_debug_lock);

	/*
	 * Free the mmu state structure.
	 */
	kmem_free(mmu_p, sizeof (px_mmu_t));
	px_p->px_mmu_p = NULL;
}

px_mmu_map_pages(px_mmu_t *mmu_p, ddi_dma_impl_t *mp, px_dvma_addr_t dvma_pg,
    size_t npages, size_t pfn_index)
{
	dev_info_t	*dip = mmu_p->mmu_px_p->px_dip;
	px_dvma_addr_t	pg_index = MMU_PAGE_INDEX(mmu_p, dvma_pg);
	io_attributes_t	attr = PX_GET_MP_TTE(mp->dmai_tte);
	int		ret;

	ASSERT(npages <= mp->dmai_ndvmapages);
	DBG(DBG_MAP_WIN, mmu_p->mmu_px_p->px_dip,
		"px_mmu_map_pages:%x+%x=%x npages=0x%x pfn_index=0x%x\n",
		(uint_t)mmu_p->dvma_base_pg, (uint_t)pg_index, dvma_pg,
		(uint_t)npages, (uint_t)pfn_index);

	if ((ret = px_lib_iommu_map(dip, PCI_TSBID(0, pg_index), npages,
	    attr, (void *)mp, pfn_index, MMU_MAP_MP)) != DDI_SUCCESS) {
		DBG(DBG_MAP_WIN, mmu_p->mmu_px_p->px_dip,
		    "px_mmu_map_pages: px_iommu_map failed, ret %x\n", ret);

		return (ret);
	}

	if (DVMA_DBG_ON(mmu_p))
		px_dvma_alloc_debug(mmu_p, (char *)mp->dmai_mapping,
		    mp->dmai_size, mp);

	return (ret);
}

void
px_mmu_unmap_pages(px_mmu_t *mmu_p, px_dvma_addr_t dvma_pg, uint_t npages)
{
	px_dvma_addr_t	pg_index = MMU_PAGE_INDEX(mmu_p, dvma_pg);

	DBG(DBG_UNMAP_WIN, mmu_p->mmu_px_p->px_dip,
		"px_mmu_unmap_pages:%x+%x=%x npages=0x%x\n",
		(uint_t)mmu_p->dvma_base_pg, (uint_t)pg_index, dvma_pg,
		(uint_t)npages);

	(void) px_lib_iommu_demap(mmu_p->mmu_px_p->px_dip,
	    PCI_TSBID(0, pg_index), npages);
}

/*
 * px_mmu_map_window - map a dvma window into the mmu
 * used by: px_dma_win(), px_dma_ctlops() - DDI_DMA_MOVWIN, DDI_DMA_NEXTWIN
 * return value: none
 */
/*ARGSUSED*/
int
px_mmu_map_window(px_mmu_t *mmu_p, ddi_dma_impl_t *mp, px_window_t win_no)
{
	uint32_t obj_pg0_off = mp->dmai_roffset;
	uint32_t win_pg0_off = win_no ? 0 : obj_pg0_off;
	size_t win_size = mp->dmai_winsize;
	size_t pfn_index = win_size * win_no;			/* temp value */
	size_t obj_off = win_no ? pfn_index - obj_pg0_off : 0;	/* xferred sz */
	px_dvma_addr_t dvma_pg = MMU_BTOP(mp->dmai_mapping);
	size_t res_size = mp->dmai_object.dmao_size - obj_off + win_pg0_off;
	int ret = DDI_SUCCESS;

	ASSERT(!(win_size & MMU_PAGE_OFFSET));
	if (win_no >= mp->dmai_nwin)
		return (ret);
	if (res_size < win_size)		/* last window */
		win_size = res_size;		/* mp->dmai_winsize unchanged */

	mp->dmai_mapping = MMU_PTOB(dvma_pg) | win_pg0_off;
	mp->dmai_size = win_size - win_pg0_off;	/* cur win xferrable size */
	mp->dmai_offset = obj_off;		/* win offset into object */
	pfn_index = MMU_BTOP(pfn_index);	/* index into pfnlist */
	ret = px_mmu_map_pages(mmu_p, mp, dvma_pg, MMU_BTOPR(win_size),
	    pfn_index);

	return (ret);
}

/*
 * px_mmu_unmap_window
 * This routine is called to break down the mmu mappings to a dvma window.
 * Non partial mappings are viewed as single window mapping.
 * used by: px_dma_unbindhdl(), px_dma_window(),
 *	and px_dma_ctlops() - DDI_DMA_FREE, DDI_DMA_MOVWIN, DDI_DMA_NEXTWIN
 * return value: none
 */
/*ARGSUSED*/
void
px_mmu_unmap_window(px_mmu_t *mmu_p, ddi_dma_impl_t *mp)
{
	px_dvma_addr_t dvma_pg = MMU_BTOP(mp->dmai_mapping);
	uint_t npages = MMU_BTOP(mp->dmai_winsize);

	px_mmu_unmap_pages(mmu_p, dvma_pg, npages);

	if (DVMA_DBG_ON(mmu_p))
		px_dvma_free_debug(mmu_p, (char *)mp->dmai_mapping,
		    mp->dmai_size, mp);
}


#if 0
/*
 * The following table is for reference only. It denotes the
 * the TSB table size measured in number of 8 byte entries.
 * It is represented by bits 3:0 in the MMU TSB CTRL REG.
 */
static int px_mmu_tsb_sizes[] = {
	0x0,		/* 1K */
	0x1,		/* 2K */
	0x2,		/* 4K */
	0x3,		/* 8K */
	0x4,		/* 16K */
	0x5,		/* 32K */
	0x6,		/* 64K */
	0x7,		/* 128K */
	0x8		/* 256K */
};
#endif

static char *px_mmu_errsts[] = {
	"Protection Error", "Invalid Error", "Timeout", "ECC Error(UE)"
};

/*ARGSUSED*/
static int
px_log_mmu_err(px_t *px_p)
{
	/*
	 * Place holder, the correct eror bits need tobe logged.
	 */
	return (0);
}
