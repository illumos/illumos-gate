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

#ifndef _SYS_PCI_IOMMU_H
#define	_SYS_PCI_IOMMU_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/vmem.h>

typedef uint64_t dvma_addr_t;
typedef uint64_t dma_bypass_addr_t;
typedef uint64_t dma_peer_addr_t;
typedef uint16_t dvma_context_t;
typedef uint64_t window_t;

/*
 * The following typedef's represents the types for DMA transactions
 * and corresponding DMA addresses supported by psycho/schizo.
 */
typedef enum { IOMMU_XLATE, IOMMU_BYPASS, PCI_PEER_TO_PEER } iommu_dma_t;

/*
 * The following macros define the iommu page size and related operations.
 */
#define	IOMMU_PAGE_SHIFT	13
#define	IOMMU_PAGE_SIZE		(1 << IOMMU_PAGE_SHIFT)
#define	IOMMU_PAGE_MASK		~(IOMMU_PAGE_SIZE - 1)
#define	IOMMU_PAGE_OFFSET	(IOMMU_PAGE_SIZE - 1)
#define	IOMMU_PTOB(x)		(((uint64_t)(x)) << IOMMU_PAGE_SHIFT)
#define	IOMMU_BTOP(x)		((x) >> IOMMU_PAGE_SHIFT)
#define	IOMMU_BTOPR(x)		IOMMU_BTOP((x) + IOMMU_PAGE_OFFSET)

/*
 * control register decoding
 */
/* tsb size: 0=1k 1=2k 2=4k 3=8k 4=16k 5=32k 6=64k 7=128k */
#define	IOMMU_CTL_TO_TSBSIZE(ctl)	((ctl) >> 16)
#define	IOMMU_TSBSIZE_TO_TSBENTRIES(s)	((1 << (s)) << (13 - 3))
#define	IOMMU_DARWIN_BOGUS_TSBSIZE	7

/*
 * boiler plate for tte (everything except the pfn)
 */
#define	MAKE_TTE_TEMPLATE(pfn, mp) (COMMON_IOMMU_TTE_V | \
	(pf_is_memory(pfn) ? COMMON_IOMMU_TTE_C : 0) | \
	((mp->dmai_rflags & DDI_DMA_READ) ? COMMON_IOMMU_TTE_W : 0) | \
	((mp->dmai_rflags & DDI_DMA_CONSISTENT) ? 0 : COMMON_IOMMU_TTE_S))
#define	TTE_IS_INVALID(tte)	(((tte) & COMMON_IOMMU_TTE_V) == 0x0ull)

/*
 * The following macros define the address ranges supported for DVMA
 * and iommu bypass transfers.
 */
#define	COMMON_IOMMU_BYPASS_BASE	0xFFFC000000000000ull

/*
 * The IOMMU_BYPASS_END is ASIC dependent and so defined in the appropriate
 * header file.
 */

/*
 * For iommu bypass addresses, bit 43 specifies cacheability.
 */
#define	COMMON_IOMMU_BYPASS_NONCACHE	0x0000080000000000ull

/*
 * Generic iommu definitions and types:
 */
#define	IOMMU_TLB_ENTRIES		16

/*
 * The following macros are for loading and unloading iotte
 * entries.
 */
#define	COMMON_IOMMU_TTE_SIZE		8
#define	COMMON_IOMMU_TTE_V		0x8000000000000000ull
#define	COMMON_IOMMU_TTE_S		0x1000000000000000ull
#define	COMMON_IOMMU_TTE_C		0x0000000000000010ull
#define	COMMON_IOMMU_TTE_W		0x0000000000000002ull
#define	COMMON_IOMMU_INVALID_TTE	0x0000000000000000ull

/*
 * Tomatillo's micro TLB bug. errata #82
 */
typedef struct dvma_unbind_req {
	uint32_t	dur_base;
	uint_t		dur_npg;
	uint_t		dur_flags; /* = dmai_flags & DMAI_FLAGS_VMEMCACHE */
} dvma_unbind_req_t;

/*
 * iommu block soft state structure:
 *
 * Each pci node may share an iommu block structure with its peer
 * node of have its own private iommu block structure.
 */
typedef struct iommu iommu_t;
struct iommu {

	pci_t *iommu_pci_p;	/* link back to pci soft state */
	int iommu_inst;		/* ddi_get_instance(iommu_pci_p->pci_dip) */

	volatile uint64_t *iommu_ctrl_reg;
	volatile uint64_t *iommu_tsb_base_addr_reg;
	volatile uint64_t *iommu_flush_page_reg;
	volatile uint64_t *iommu_flush_ctx_reg;	/* schizo only */
	volatile uint64_t *iommu_tfar_reg; /* tomatillo only */

	/*
	 * virtual and physical addresses and size of the iommu tsb:
	 */
	uint64_t *iommu_tsb_vaddr;
	uint64_t iommu_tsb_paddr;
	uint_t iommu_tsb_entries;
	uint_t iommu_tsb_size;

	/*
	 * address ranges of dvma space:
	 */
	dvma_addr_t iommu_dvma_base;
	dvma_addr_t iommu_dvma_end;
	dvma_addr_t iommu_dvma_fast_end;
	dvma_addr_t dvma_base_pg;	/* = IOMMU_BTOP(iommu_dvma_base) */
	dvma_addr_t dvma_end_pg;	/* = IOMMU_BTOP(iommu_dvma_end) */

	/*
	 * address ranges of dma bypass space:
	 */
	dma_bypass_addr_t iommu_dma_bypass_base;
	dma_bypass_addr_t iommu_dma_bypass_end;

	/*
	 * virtual memory map and callback id for dvma space:
	 */
	vmem_t *iommu_dvma_map;
	uintptr_t iommu_dvma_clid;

	/*
	 * fields for fast dvma interfaces:
	 */
	ulong_t iommu_dvma_reserve;

	/*
	 * dvma fast track page cache byte map
	 */
	uint8_t *iommu_dvma_cache_locks;
	uint_t iommu_dvma_addr_scan_start;

	/*
	 * dvma context bitmap
	 */
	uint64_t *iommu_ctx_bitmap;

	/*
	 * dvma debug
	 */
	kmutex_t dvma_debug_lock;
	uint32_t dvma_alloc_rec_index;
	uint32_t dvma_free_rec_index;
	uint32_t dvma_active_count;

	struct dvma_rec *dvma_alloc_rec;
	struct dvma_rec *dvma_free_rec;
	struct dvma_rec *dvma_active_list;

	/*
	 * tomatillo's micro TLB bug. errata #82
	 */
	dvma_unbind_req_t *iommu_mtlb_req_p;	/* unbind requests */
	uint32_t	iommu_mtlb_maxpgs;	/* GC threshold */
	uint32_t	iommu_mtlb_npgs;	/* total page count */
	uint32_t	iommu_mtlb_nreq;	/* total request count */
	kmutex_t	iommu_mtlb_lock;
};

typedef struct pci_dvma_range_prop {
	uint32_t dvma_base;
	uint32_t dvma_len;
} pci_dvma_range_prop_t;

#define	IOMMU_PAGE_INDEX(iommu_p, dvma_pg) ((dvma_pg) - (iommu_p)->dvma_base_pg)
#define	IOMMU_PAGE_FLUSH(iommu_p, dvma_pg) \
	*(iommu_p)->iommu_flush_page_reg = IOMMU_PTOB(dvma_pg)
#define	IOMMU_UNLOAD_TTE(iommu_p, pg_index) \
	(iommu_p)->iommu_tsb_vaddr[pg_index] = COMMON_IOMMU_INVALID_TTE
#define	IOMMU_PAGE_TTEPA(iommu_p, dvma_pg) \
	((iommu_p)->iommu_tsb_paddr + (IOMMU_PAGE_INDEX(iommu_p, dvma_pg) << 3))

#define	IOMMU_CONTEXT_BITS 12
#define	IOMMU_CTX_MASK		((1 << IOMMU_CONTEXT_BITS) - 1)
#define	IOMMU_TTE_CTX_SHIFT	47
#define	IOMMU_CTX2TTE(ctx) (((uint64_t)(ctx)) << IOMMU_TTE_CTX_SHIFT)
#define	IOMMU_TTE2CTX(tte) \
		(((tte) >> (IOMMU_TTE_CTX_SHIFT - 32)) & IOMMU_CTX_MASK)
#define	MP2CTX(mp)	IOMMU_TTE2CTX((uint32_t)(uintptr_t)(mp)->dmai_tte)

/* dvma debug */
#define	DVMA_DBG_ON(iommu_p)  \
	((1ull << (iommu_p)->iommu_inst) & pci_dvma_debug_on)
#define	DVMA_DBG_OFF(iommu_p) \
	((1ull << (iommu_p)->iommu_inst) & pci_dvma_debug_off)

extern void pci_dvma_debug_fini(iommu_t *iommu_p);
extern void pci_dvma_alloc_debug(iommu_t *iommu_p, char *address, uint_t len,
	ddi_dma_impl_t *mp);
extern void pci_dvma_free_debug(iommu_t *iommu_p, char *address, uint_t len,
	ddi_dma_impl_t *mp);

/* dvma routines */
extern void iommu_map_pages(iommu_t *iommu_p, ddi_dma_impl_t *mp,
			dvma_addr_t dvma_pg, size_t npages, size_t pfn_index);
extern void iommu_unmap_pages(iommu_t *iommu_p, dvma_addr_t dvma_pg,
			uint_t npages);
extern void iommu_remap_pages(iommu_t *iommu_p, ddi_dma_impl_t *mp,
			dvma_addr_t dvma_pg, size_t npages, size_t pfn_index);
extern void iommu_map_window(iommu_t *iommu_p,
			ddi_dma_impl_t *mp, window_t window);
extern void iommu_unmap_window(iommu_t *iommu_p, ddi_dma_impl_t *mp);

/* iommu initialization routines */
extern void iommu_configure(iommu_t *iommu_p);
extern void iommu_create(pci_t *pci_p);
extern void iommu_destroy(pci_t *pci_p);
extern uint_t iommu_tsb_size_encode(uint_t tsb_bytes);

/* TSB allocate/free */
extern int pci_alloc_tsb(pci_t *pci_p);
extern void pci_free_tsb(pci_t *pci_p);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCI_IOMMU_H */
