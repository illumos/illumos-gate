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

#ifndef	_SYS_PX_MMU_H
#define	_SYS_PX_MMU_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/vmem.h>

typedef uint64_t px_dvma_addr_t;
typedef uint64_t px_dma_bypass_addr_t;
typedef uint64_t px_dma_peer_addr_t;
typedef uint16_t px_dvma_context_t;
typedef uint64_t px_window_t;

/*
 * boiler plate for tte (everything except the pfn)
 */
#define	PX_GET_TTE_ATTR(flags, attr)\
	(((flags & DDI_DMA_READ) ? PCI_MAP_ATTR_WRITE : 0) | \
	((flags & DDI_DMA_WRITE) ? PCI_MAP_ATTR_READ : 0) | \
	((attr & DDI_DMA_RELAXED_ORDERING) ? PCI_MAP_ATTR_RO : 0))

/*
 * mmu block soft state structure:
 *
 * Each px node may share an mmu block structure with its peer
 * node of have its own private mmu block structure.
 */
typedef struct px_mmu {
	px_t *mmu_px_p;	/* link back to px soft state */
	int mmu_inst;

	/*
	 * address ranges of dvma space:
	 */
	px_dvma_addr_t mmu_dvma_base;
	px_dvma_addr_t mmu_dvma_end;
	px_dvma_addr_t mmu_dvma_fast_end;
	px_dvma_addr_t dvma_base_pg;	/* = MMU_BTOP(mmu_dvma_base) */
	px_dvma_addr_t dvma_end_pg;	/* = MMU_BTOP(mmu_dvma_end) */

	/*
	 * virtual memory map and callback id for dvma space:
	 */
	vmem_t *mmu_dvma_map;
	uintptr_t mmu_dvma_clid;

	/*
	 * fields for fast dvma interfaces:
	 */
	ulong_t mmu_dvma_reserve;

	/*
	 * dvma fast track page cache byte map
	 */
	uint8_t *mmu_dvma_cache_locks;
	uint_t mmu_dvma_addr_scan_start;

	/* dvma debug */
	kmutex_t dvma_debug_lock;
	uint32_t dvma_alloc_rec_index;
	uint32_t dvma_free_rec_index;
	uint32_t dvma_active_count;

	struct px_dvma_rec *dvma_alloc_rec;
	struct px_dvma_rec *dvma_free_rec;
	struct px_dvma_rec *dvma_active_list;
} px_mmu_t;

typedef struct px_dvma_range_prop {
	uint32_t dvma_base;
	uint32_t dvma_len;
} px_dvma_range_prop_t;

#define	MMU_PAGE_INDEX(mmu_p, dvma_pg) ((dvma_pg) - (mmu_p)->dvma_base_pg)

/* dvma debug */
#define	PX_DVMA_DBG_ON(mmu_p)  \
	((1ull << (mmu_p)->mmu_inst) & px_dvma_debug_on)
#define	PX_DVMA_DBG_OFF(mmu_p) \
	((1ull << (mmu_p)->mmu_inst) & px_dvma_debug_off)

extern	void px_dvma_debug_fini(px_mmu_t *mmu_p);
extern	void px_dvma_alloc_debug(px_mmu_t *mmu_p, char *address, uint_t len,
	ddi_dma_impl_t *mp);
extern	void px_dvma_free_debug(px_mmu_t *mmu_p, char *address, uint_t len,
	ddi_dma_impl_t *mp);

/* DVMA routines */
extern int px_mmu_map_pages(px_mmu_t *mmu_p, ddi_dma_impl_t *mp,
    px_dvma_addr_t dvma_pg, size_t npages, size_t pfn_index);
extern int px_mmu_map_window(px_mmu_t *mmu_p, ddi_dma_impl_t *mp,
    px_window_t window);
extern void px_mmu_unmap_pages(px_mmu_t *mmu_p, ddi_dma_impl_t *mp,
    px_dvma_addr_t dvma_pg, uint_t npages);
extern void px_mmu_unmap_window(px_mmu_t *mmu_p, ddi_dma_impl_t *mp);

/* MMU initialization routines */
extern int px_mmu_attach(px_t *px_p);
extern void px_mmu_detach(px_t *px_p);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PX_MMU_H */
