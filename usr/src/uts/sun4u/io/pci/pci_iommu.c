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
/*
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>.  All rights reserved.
 */

/*
 * PCI iommu initialization and configuration
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
#include <sys/pci/pci_obj.h>

/*LINTLIBRARY*/

static void iommu_tlb_flushall(iommu_t *iommu_p);
static void iommu_preserve_tsb(iommu_t *iommu_p);

void
iommu_create(pci_t *pci_p)
{
	dev_info_t *dip = pci_p->pci_dip;
	iommu_t *iommu_p;
	uintptr_t a;
	size_t cache_size;
	uint32_t tsb_entries;

	char map_name[32];
	extern uint64_t va_to_pa(void *);

	pci_dvma_range_prop_t	pci_dvma_range;

	/*
	 * Allocate iommu state structure and link it to the
	 * pci state structure.
	 */
	iommu_p = (iommu_t *)kmem_zalloc(sizeof (iommu_t), KM_SLEEP);
	pci_p->pci_iommu_p = iommu_p;
	iommu_p->iommu_pci_p = pci_p;
	iommu_p->iommu_inst = ddi_get_instance(dip);

	/*
	 * chip specific dvma_end, tsb_size & context support
	 */
	iommu_p->iommu_dvma_end = pci_iommu_dvma_end;
	a = pci_iommu_setup(iommu_p);

	/*
	 * Determine the virtual address of iommu registers.
	 */
	iommu_p->iommu_ctrl_reg =
	    (uint64_t *)(a + COMMON_IOMMU_CTRL_REG_OFFSET);
	iommu_p->iommu_tsb_base_addr_reg =
	    (uint64_t *)(a + COMMON_IOMMU_TSB_BASE_ADDR_REG_OFFSET);
	iommu_p->iommu_flush_page_reg =
	    (uint64_t *)(a + COMMON_IOMMU_FLUSH_PAGE_REG_OFFSET);

	/*
	 * Configure the rest of the iommu parameters according to:
	 * tsb_size and dvma_end
	 */
	iommu_p->iommu_tsb_vaddr = /* retrieve TSB VA reserved by system */
	    iommu_tsb_cookie_to_va(pci_p->pci_tsb_cookie);
	iommu_p->iommu_tsb_entries = tsb_entries =
	    IOMMU_TSBSIZE_TO_TSBENTRIES(iommu_p->iommu_tsb_size);
	iommu_p->iommu_tsb_paddr = va_to_pa((caddr_t)iommu_p->iommu_tsb_vaddr);
	iommu_p->iommu_dvma_cache_locks =
	    kmem_zalloc(pci_dvma_page_cache_entries, KM_SLEEP);

	iommu_p->iommu_dvma_base = iommu_p->iommu_dvma_end + 1
	    - (tsb_entries * IOMMU_PAGE_SIZE);
	iommu_p->dvma_base_pg = IOMMU_BTOP(iommu_p->iommu_dvma_base);
	iommu_p->iommu_dvma_reserve = tsb_entries >> 1;
	iommu_p->dvma_end_pg = IOMMU_BTOP(iommu_p->iommu_dvma_end);
	iommu_p->iommu_dma_bypass_base = COMMON_IOMMU_BYPASS_BASE;
	iommu_p->iommu_dma_bypass_end = pci_iommu_bypass_end_configure();

	/*
	 * export "virtual-dma" software property to support
	 * child devices needing to know DVMA range
	 */
	pci_dvma_range.dvma_base = (uint32_t)iommu_p->iommu_dvma_base;
	pci_dvma_range.dvma_len = (uint32_t)
	    iommu_p->iommu_dvma_end - iommu_p->iommu_dvma_base + 1;
	(void) ddi_prop_create(DDI_DEV_T_NONE, dip, DDI_PROP_CANSLEEP,
	    "virtual-dma", (caddr_t)&pci_dvma_range,
	    sizeof (pci_dvma_range));

	DEBUG2(DBG_ATTACH, dip, "iommu_create: ctrl=%p, tsb=%p\n",
	    iommu_p->iommu_ctrl_reg, iommu_p->iommu_tsb_base_addr_reg);
	DEBUG2(DBG_ATTACH, dip, "iommu_create: page_flush=%p, ctx_flush=%p\n",
	    iommu_p->iommu_flush_page_reg, iommu_p->iommu_flush_ctx_reg);
	DEBUG2(DBG_ATTACH, dip, "iommu_create: tsb vaddr=%p tsb_paddr=%p\n",
	    iommu_p->iommu_tsb_vaddr, iommu_p->iommu_tsb_paddr);
	DEBUG1(DBG_ATTACH, dip, "iommu_create: allocated size=%x\n",
	    iommu_tsb_cookie_to_size(pci_p->pci_tsb_cookie));
	DEBUG2(DBG_ATTACH, dip, "iommu_create: fast tsb tte addr: %x + %x\n",
	    iommu_p->iommu_tsb_vaddr,
	    pci_dvma_page_cache_entries * pci_dvma_page_cache_clustsz);
	DEBUG3(DBG_ATTACH, dip,
	    "iommu_create: tsb size=%x, tsb entries=%x, dvma base=%x\n",
	    iommu_p->iommu_tsb_size, iommu_p->iommu_tsb_entries,
	    iommu_p->iommu_dvma_base);
	DEBUG2(DBG_ATTACH, dip,
	    "iommu_create: dvma_cache_locks=%x cache_entries=%x\n",
	    iommu_p->iommu_dvma_cache_locks, pci_dvma_page_cache_entries);

	/*
	 * zero out the area to be used for iommu tsb
	 */
	bzero(iommu_p->iommu_tsb_vaddr, tsb_entries << 3);

	/*
	 * Create a virtual memory map for dvma address space.
	 * Reserve 'size' bytes of low dvma space for fast track cache.
	 */
	(void) snprintf(map_name, sizeof (map_name), "%s%d_dvma",
	    ddi_driver_name(dip), ddi_get_instance(dip));

	cache_size = IOMMU_PTOB(pci_dvma_page_cache_entries *
	    pci_dvma_page_cache_clustsz);
	iommu_p->iommu_dvma_fast_end = iommu_p->iommu_dvma_base +
	    cache_size - 1;
	iommu_p->iommu_dvma_map = vmem_create(map_name,
	    (void *)(iommu_p->iommu_dvma_fast_end + 1),
	    IOMMU_PTOB(tsb_entries) - cache_size, IOMMU_PAGE_SIZE,
	    NULL, NULL, NULL, IOMMU_PAGE_SIZE, VM_SLEEP);

	mutex_init(&iommu_p->dvma_debug_lock, NULL, MUTEX_DRIVER, NULL);

	/*
	 * On detach, the TSB Base Address Register gets set to zero,
	 * so if its zero here, there is no need to preserve TTEs.
	 */
	if (pci_preserve_iommu_tsb && *iommu_p->iommu_tsb_base_addr_reg)
		iommu_preserve_tsb(iommu_p);

	iommu_configure(iommu_p);
}

void
iommu_destroy(pci_t *pci_p)
{
#ifdef DEBUG
	dev_info_t *dip = pci_p->pci_dip;
#endif
	iommu_t *iommu_p = pci_p->pci_iommu_p;
	volatile uint64_t ctl_val = *iommu_p->iommu_ctrl_reg;

	DEBUG0(DBG_DETACH, dip, "iommu_destroy:\n");

	/*
	 * Disable the IOMMU by setting the TSB Base Address to zero
	 * and the TSB Table size to the smallest possible.
	 */
	ctl_val = ctl_val & ~(7 << COMMON_IOMMU_CTRL_TSB_SZ_SHIFT);

	*iommu_p->iommu_ctrl_reg = ctl_val;
	*iommu_p->iommu_tsb_base_addr_reg = 0;

	/*
	 * Return the boot time allocated tsb.
	 */
	iommu_tsb_free(pci_p->pci_tsb_cookie);

	/*
	 * Teardown any implementation-specific structures set up in
	 * pci_iommu_setup.
	 */
	pci_iommu_teardown(iommu_p);

	if (DVMA_DBG_ON(iommu_p))
		pci_dvma_debug_fini(iommu_p);
	mutex_destroy(&iommu_p->dvma_debug_lock);

	/*
	 * Free the dvma resource map.
	 */
	vmem_destroy(iommu_p->iommu_dvma_map);

	kmem_free(iommu_p->iommu_dvma_cache_locks,
	    pci_dvma_page_cache_entries);

	/*
	 * Free the iommu state structure.
	 */
	kmem_free(iommu_p, sizeof (iommu_t));
	pci_p->pci_iommu_p = NULL;
}

/*
 * re-program iommu on the fly while preserving on-going dma
 * transactions on the PCI bus.
 */
void
iommu_configure(iommu_t *iommu_p)
{
	pci_t *pci_p = iommu_p->iommu_pci_p;
	uint64_t cfgpa = pci_get_cfg_pabase(pci_p);
	dev_info_t *dip = iommu_p->iommu_pci_p->pci_dip;
	dev_info_t *cdip = NULL;
	volatile uint64_t ctl_val = (uint64_t)
	    ((iommu_p->iommu_tsb_size << COMMON_IOMMU_CTRL_TSB_SZ_SHIFT) |
	    (0 /* 8k page */ << COMMON_IOMMU_CTRL_TBW_SZ_SHIFT) |
	    COMMON_IOMMU_CTRL_ENABLE | COMMON_IOMMU_CTRL_DIAG_ENABLE |
	    (pci_lock_tlb ? COMMON_IOMMU_CTRL_LCK_ENABLE : 0));

	DEBUG2(DBG_ATTACH, dip, "iommu_configure: iommu_ctl=%08x.%08x\n",
	    HI32(ctl_val), LO32(ctl_val));
	if (!pci_preserve_iommu_tsb || !(*iommu_p->iommu_tsb_base_addr_reg)) {
		*iommu_p->iommu_ctrl_reg = COMMON_IOMMU_CTRL_DIAG_ENABLE;
		iommu_tlb_flushall(iommu_p);
		goto config;
	}
	cdip = ddi_get_child(dip);
	for (; cdip; cdip = ddi_get_next_sibling(cdip)) {
		uint32_t *reg_p;
		int reg_len;
		if (ddi_getlongprop(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS,
		    "reg", (caddr_t)&reg_p, &reg_len) != DDI_PROP_SUCCESS)
			continue;
		cfgpa += (*reg_p) & (PCI_CONF_ADDR_MASK ^ PCI_REG_REG_M);
		kmem_free(reg_p, reg_len);
		break;
	}

config:
	pci_iommu_config(iommu_p, ctl_val, cdip ? cfgpa : 0);
}

void
iommu_map_pages(iommu_t *iommu_p, ddi_dma_impl_t *mp,
		dvma_addr_t dvma_pg, size_t npages, size_t pfn_index)
{
	int i;
	dvma_addr_t pg_index = dvma_pg - iommu_p->dvma_base_pg;
	uint64_t *tte_addr = iommu_p->iommu_tsb_vaddr + pg_index;
	size_t pfn_last = pfn_index + npages;
	uint64_t tte = PCI_GET_MP_TTE(mp->dmai_tte);
#ifdef DEBUG
	dev_info_t *dip = iommu_p->iommu_pci_p->pci_dip;
#endif

	ASSERT(pfn_last <= mp->dmai_ndvmapages);

	DEBUG5(DBG_MAP_WIN, dip,
	    "iommu_map_pages:%x+%x=%x npages=0x%x pfn_index=0x%x\n",
	    (uint_t)iommu_p->dvma_base_pg, (uint_t)pg_index, dvma_pg,
	    (uint_t)npages, (uint_t)pfn_index);

	for (i = pfn_index; i < pfn_last; i++, pg_index++, tte_addr++) {
		iopfn_t pfn = PCI_GET_MP_PFN(mp, i);
		volatile uint64_t cur_tte = IOMMU_PTOB(pfn) | tte;

		DEBUG3(DBG_MAP_WIN, dip, "iommu_map_pages: mp=%p pg[%x]=%x\n",
		    mp, i, (uint_t)pfn);
		DEBUG3(DBG_MAP_WIN, dip,
		    "iommu_map_pages: pg_index=%x tte=%08x.%08x\n",
		    pg_index, HI32(cur_tte), LO32(cur_tte));
		ASSERT(TTE_IS_INVALID(*tte_addr));
		*tte_addr = cur_tte;
#ifdef DEBUG
		if (pfn == 0 && pci_warn_pp0)
			cmn_err(CE_WARN, "%s%d <%p> doing DMA to pp0\n",
			    ddi_driver_name(mp->dmai_rdip),
			    ddi_get_instance(mp->dmai_rdip), mp);
#endif
	}
	ASSERT(tte_addr == iommu_p->iommu_tsb_vaddr + pg_index);
#ifdef DEBUG
	if (HAS_REDZONE(mp)) {
		DEBUG1(DBG_MAP_WIN, dip, "iommu_map_pages: redzone pg=%x\n",
		    pg_index);
		ASSERT(TTE_IS_INVALID(iommu_p->iommu_tsb_vaddr[pg_index]));
	}
#endif
	if (DVMA_DBG_ON(iommu_p))
		pci_dvma_alloc_debug(iommu_p, (char *)mp->dmai_mapping,
		    mp->dmai_size, mp);
}

/*
 * iommu_map_window - map a dvma window into the iommu
 *
 * used by: pci_dma_win(), pci_dma_ctlops() - DDI_DMA_MOVWIN
 *
 * return value: none
 */
/*ARGSUSED*/
void
iommu_map_window(iommu_t *iommu_p, ddi_dma_impl_t *mp, window_t win_no)
{
	uint32_t obj_pg0_off = mp->dmai_roffset;
	uint32_t win_pg0_off = win_no ? 0 : obj_pg0_off;
	size_t win_size = mp->dmai_winsize;
	size_t pfn_index = win_size * win_no;			/* temp value */
	size_t obj_off = win_no ? pfn_index - obj_pg0_off : 0;	/* xferred sz */
	dvma_addr_t dvma_pg = IOMMU_BTOP(mp->dmai_mapping);
	size_t res_size = mp->dmai_object.dmao_size - obj_off + win_pg0_off;

	ASSERT(!(win_size & IOMMU_PAGE_OFFSET));
	if (win_no >= mp->dmai_nwin)
		return;
	if (res_size < win_size)		/* last window */
		win_size = res_size;		/* mp->dmai_winsize unchanged */

	mp->dmai_mapping = IOMMU_PTOB(dvma_pg) | win_pg0_off;
	mp->dmai_size = win_size - win_pg0_off;	/* cur win xferrable size */
	mp->dmai_offset = obj_off;		/* win offset into object */
	pfn_index = IOMMU_BTOP(pfn_index);	/* index into pfnlist */
	iommu_map_pages(iommu_p, mp, dvma_pg, IOMMU_BTOPR(win_size), pfn_index);
}

void
iommu_unmap_pages(iommu_t *iommu_p, dvma_addr_t dvma_pg, uint_t npages)
{
	dvma_addr_t pg_index = IOMMU_PAGE_INDEX(iommu_p, dvma_pg);

	for (; npages; npages--, dvma_pg++, pg_index++) {
		DEBUG1(DBG_UNMAP_WIN|DBG_CONT, 0, " %x", dvma_pg);
		IOMMU_UNLOAD_TTE(iommu_p, pg_index);

		if (!tm_mtlb_gc)
			IOMMU_PAGE_FLUSH(iommu_p, dvma_pg);
	}
}

void
iommu_remap_pages(iommu_t *iommu_p, ddi_dma_impl_t *mp, dvma_addr_t dvma_pg,
	size_t npages, size_t pfn_index)
{
	iommu_unmap_pages(iommu_p, dvma_pg, npages);
	iommu_map_pages(iommu_p, mp, dvma_pg, npages, pfn_index);
}

/*
 * iommu_unmap_window
 *
 * This routine is called to break down the iommu mappings to a dvma window.
 * Non partial mappings are viewed as single window mapping.
 *
 * used by: pci_dma_unbindhdl(), pci_dma_window(),
 *	and pci_dma_ctlops() - DDI_DMA_FREE, DDI_DMA_MOVWIN, DDI_DMA_NEXTWIN
 *
 * return value: none
 */
/*ARGSUSED*/
void
iommu_unmap_window(iommu_t *iommu_p, ddi_dma_impl_t *mp)
{
	dvma_addr_t dvma_pg = IOMMU_BTOP(mp->dmai_mapping);
	dvma_addr_t pg_index = IOMMU_PAGE_INDEX(iommu_p, dvma_pg);
	uint_t npages = IOMMU_BTOP(mp->dmai_winsize);
#ifdef DEBUG
	dev_info_t *dip = iommu_p->iommu_pci_p->pci_dip;
#endif
	/*
	 * Invalidate each page of the mapping in the tsb and flush
	 * it from the tlb.
	 */
	DEBUG2(DBG_UNMAP_WIN, dip, "mp=%p %x pfns:", mp, npages);
	if (mp->dmai_flags & DMAI_FLAGS_CONTEXT) {
		dvma_context_t ctx = MP2CTX(mp);
		for (; npages; npages--, pg_index++) {
			DEBUG1(DBG_UNMAP_WIN|DBG_CONT, dip, " %x", pg_index);
			IOMMU_UNLOAD_TTE(iommu_p, pg_index);
		}
		DEBUG1(DBG_UNMAP_WIN|DBG_CONT, dip, " (context %x)", ctx);
		*iommu_p->iommu_flush_ctx_reg = ctx;
	} else
		iommu_unmap_pages(iommu_p, dvma_pg, npages);

	DEBUG0(DBG_UNMAP_WIN|DBG_CONT, dip, "\n");

	if (DVMA_DBG_ON(iommu_p))
		pci_dvma_free_debug(iommu_p, (char *)mp->dmai_mapping,
		    mp->dmai_size, mp);
}

int
pci_alloc_tsb(pci_t *pci_p)
{
	uint16_t tsbc;

	if ((tsbc = iommu_tsb_alloc(pci_p->pci_id)) == IOMMU_TSB_COOKIE_NONE) {
		cmn_err(CE_WARN, "%s%d: Unable to allocate IOMMU TSB.",
		    ddi_driver_name(pci_p->pci_dip),
		    ddi_get_instance(pci_p->pci_dip));
		return (DDI_FAILURE);
	}
	pci_p->pci_tsb_cookie = tsbc;
	return (DDI_SUCCESS);
}

void
pci_free_tsb(pci_t *pci_p)
{
	iommu_tsb_free(pci_p->pci_tsb_cookie);
}

#if 0
/*
 * The following data structure is used to map a tsb size
 * to a tsb size configuration parameter in the iommu
 * control register.
 * This is a hardware table. It is here for reference only.
 */
static int pci_iommu_tsb_sizes[] = {
	0x2000,		/* 0 - 8 mb */
	0x4000,		/* 1 - 16 mb */
	0x8000,		/* 2 - 32 mb */
	0x10000,	/* 3 - 64 mb */
	0x20000,	/* 4 - 128 mb */
	0x40000,	/* 5 - 256 mb */
	0x80000,	/* 6 - 512 mb */
	0x100000	/* 7 - 1 gb */
};
#endif

uint_t
iommu_tsb_size_encode(uint_t tsb_bytes)
{
	uint_t i;

	for (i = 7; i && (tsb_bytes < (0x2000 << i)); i--)
		/* empty */;
	return (i);
}

/*
 * invalidate IOMMU TLB entries through diagnostic registers.
 */
static void
iommu_tlb_flushall(iommu_t *iommu_p)
{
	int i;
	uint64_t base = (uint64_t)(iommu_p->iommu_ctrl_reg) -
	    COMMON_IOMMU_CTRL_REG_OFFSET;
	volatile uint64_t *tlb_tag = (volatile uint64_t *)
	    (base + COMMON_IOMMU_TLB_TAG_DIAG_ACC_OFFSET);
	volatile uint64_t *tlb_data = (volatile uint64_t *)
	    (base + COMMON_IOMMU_TLB_DATA_DIAG_ACC_OFFSET);
	for (i = 0; i < IOMMU_TLB_ENTRIES; i++)
		tlb_tag[i] = tlb_data[i] = 0ull;
}

static void
iommu_preserve_tsb(iommu_t *iommu_p)
{
#ifdef DEBUG
	dev_info_t *dip = iommu_p->iommu_pci_p->pci_dip;
#endif
	uint_t i, obp_tsb_entries, obp_tsb_size, base_pg_index;
	uint64_t ctl = *iommu_p->iommu_ctrl_reg;
	uint64_t obp_tsb_pa = *iommu_p->iommu_tsb_base_addr_reg;
	uint64_t *base_tte_addr;

	DEBUG3(DBG_ATTACH, dip,
	    "iommu_tsb_base_addr_reg=0x%08x (0x%08x.0x%08x)\n",
	    iommu_p->iommu_tsb_base_addr_reg,
	    (uint32_t)(*iommu_p->iommu_tsb_base_addr_reg >> 32),
	    (uint32_t)(*iommu_p->iommu_tsb_base_addr_reg & 0xffffffff));

	obp_tsb_size = IOMMU_CTL_TO_TSBSIZE(ctl);
	obp_tsb_entries = IOMMU_TSBSIZE_TO_TSBENTRIES(obp_tsb_size);
	base_pg_index = iommu_p->dvma_end_pg - obp_tsb_entries + 1;
	base_tte_addr = iommu_p->iommu_tsb_vaddr +
	    (iommu_p->iommu_tsb_entries - obp_tsb_entries);

	/*
	 * old darwin prom does not set tsb size correctly, bail out.
	 */
	if ((obp_tsb_size == IOMMU_DARWIN_BOGUS_TSBSIZE) &&
	    (CHIP_TYPE(iommu_p->iommu_pci_p) == PCI_CHIP_SABRE))
		return;

	DEBUG3(DBG_ATTACH, dip, "iommu_preserve_tsb: kernel info\n"
	    "iommu_tsb_vaddr=%08x copy to base_tte_addr=%08x "
	    "base_pg_index=%x\n", iommu_p->iommu_tsb_vaddr,
	    base_tte_addr, base_pg_index);

	DEBUG3(DBG_ATTACH | DBG_CONT, dip, "iommu_preserve_tsb: obp info "
	    "obp_tsb_entries=0x%x obp_tsb_pa=%08x.%08x\n", obp_tsb_entries,
	    (uint32_t)(obp_tsb_pa >> 32), (uint32_t)obp_tsb_pa);

	for (i = 0; i < obp_tsb_entries; i++) {
		uint64_t tte = lddphys(obp_tsb_pa + i * 8);
		caddr_t va;

		if (TTE_IS_INVALID(tte)) {
			DEBUG0(DBG_ATTACH | DBG_CONT, dip, ".");
			continue;
		}

		base_tte_addr[i] = tte;
		DEBUG3(DBG_ATTACH | DBG_CONT, dip,
		    "\npreserve_tsb: (%x)=%08x.%08x\n", base_tte_addr + i,
		    (uint_t)(tte >> 32), (uint_t)(tte & 0xffffffff));

		/*
		 * permanantly reserve this page from dvma address space
		 * resource map
		 */

		va = (caddr_t)(IOMMU_PTOB(base_pg_index + i));
		(void) vmem_xalloc(iommu_p->iommu_dvma_map, IOMMU_PAGE_SIZE,
		    IOMMU_PAGE_SIZE, 0, 0, va, va + IOMMU_PAGE_SIZE,
		    VM_NOSLEEP | VM_BESTFIT | VM_PANIC);
	}
}
