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
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/vmem.h>
#include <sys/sysmacros.h>

#include <sys/ddidmareq.h>
#include <sys/sysiosbus.h>
#include <sys/iommu.h>
#include <sys/iocache.h>
#include <sys/dvma.h>

#include <vm/as.h>
#include <vm/hat.h>
#include <vm/page.h>
#include <vm/hat_sfmmu.h>
#include <sys/machparam.h>
#include <sys/machsystm.h>
#include <sys/vmsystm.h>
#include <sys/iommutsb.h>

/* Useful debugging Stuff */
#include <sys/nexusdebug.h>
#include <sys/debug.h>
/* Bitfield debugging definitions for this file */
#define	IOMMU_GETDVMAPAGES_DEBUG	0x1
#define	IOMMU_DMAMAP_DEBUG		0x2
#define	IOMMU_DMAMCTL_DEBUG		0x4
#define	IOMMU_DMAMCTL_SYNC_DEBUG	0x8
#define	IOMMU_DMAMCTL_HTOC_DEBUG	0x10
#define	IOMMU_DMAMCTL_KVADDR_DEBUG	0x20
#define	IOMMU_DMAMCTL_GETERR_DEBUG	0x400
#define	IOMMU_DMAMCTL_DMA_FREE_DEBUG	0x1000
#define	IOMMU_REGISTERS_DEBUG		0x2000
#define	IOMMU_DMA_SETUP_DEBUG		0x4000
#define	IOMMU_DMA_UNBINDHDL_DEBUG	0x8000
#define	IOMMU_DMA_BINDHDL_DEBUG		0x10000
#define	IOMMU_DMA_WIN_DEBUG		0x20000
#define	IOMMU_DMA_ALLOCHDL_DEBUG	0x40000
#define	IOMMU_DMA_LIM_SETUP_DEBUG	0x80000
#define	IOMMU_FASTDMA_RESERVE		0x100000
#define	IOMMU_FASTDMA_LOAD		0x200000
#define	IOMMU_INTER_INTRA_XFER		0x400000
#define	IOMMU_TTE			0x800000
#define	IOMMU_TLB			0x1000000
#define	IOMMU_FASTDMA_SYNC		0x2000000

/* Turn on if you need to keep track of outstanding IOMMU usage */
/* #define	IO_MEMUSAGE */
/* Turn on to debug IOMMU unmapping code */
/* #define	IO_MEMDEBUG */

static struct dvma_ops iommu_dvma_ops = {
	DVMAO_REV,
	iommu_dvma_kaddr_load,
	iommu_dvma_unload,
	iommu_dvma_sync
};

extern void *sbusp;		/* sbus soft state hook */

#define	DVMA_MAX_CACHE	65536

/*
 * This is the number of pages that a mapping request needs before we force
 * the TLB flush code to use diagnostic registers.  This value was determined
 * through a series of test runs measuring dma mapping settup performance.
 */
int tlb_flush_using_diag = 16;

int sysio_iommu_tsb_sizes[] = {
	IOMMU_TSB_SIZE_8M,
	IOMMU_TSB_SIZE_16M,
	IOMMU_TSB_SIZE_32M,
	IOMMU_TSB_SIZE_64M,
	IOMMU_TSB_SIZE_128M,
	IOMMU_TSB_SIZE_256M,
	IOMMU_TSB_SIZE_512M,
	IOMMU_TSB_SIZE_1G
};

static int iommu_map_window(ddi_dma_impl_t *, off_t, size_t);

int
iommu_init(struct sbus_soft_state *softsp, caddr_t address)
{
	int i;
	char name[40];

#ifdef DEBUG
	debug_info = 1;
#endif

	/*
	 * Simply add each registers offset to the base address
	 * to calculate the already mapped virtual address of
	 * the device register...
	 *
	 * define a macro for the pointer arithmetic; all registers
	 * are 64 bits wide and are defined as uint64_t's.
	 */

#define	REG_ADDR(b, o)	(uint64_t *)((caddr_t)(b) + (o))

	softsp->iommu_ctrl_reg = REG_ADDR(address, OFF_IOMMU_CTRL_REG);
	softsp->tsb_base_addr = REG_ADDR(address, OFF_TSB_BASE_ADDR);
	softsp->iommu_flush_reg = REG_ADDR(address, OFF_IOMMU_FLUSH_REG);
	softsp->iommu_tlb_tag = REG_ADDR(address, OFF_IOMMU_TLB_TAG);
	softsp->iommu_tlb_data = REG_ADDR(address, OFF_IOMMU_TLB_DATA);

#undef REG_ADDR

	mutex_init(&softsp->dma_pool_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&softsp->intr_poll_list_lock, NULL, MUTEX_DEFAULT, NULL);

	/* Set up the DVMA resource sizes */
	if ((softsp->iommu_tsb_cookie = iommu_tsb_alloc(softsp->upa_id)) ==
	    IOMMU_TSB_COOKIE_NONE) {
		cmn_err(CE_WARN, "%s%d: Unable to retrieve IOMMU array.",
		    ddi_driver_name(softsp->dip),
		    ddi_get_instance(softsp->dip));
		return (DDI_FAILURE);
	}
	softsp->soft_tsb_base_addr =
	    iommu_tsb_cookie_to_va(softsp->iommu_tsb_cookie);
	softsp->iommu_dvma_size =
	    iommu_tsb_cookie_to_size(softsp->iommu_tsb_cookie) <<
	    IOMMU_TSB_TO_RNG;
	softsp->iommu_dvma_base = (ioaddr_t)
	    (0 - (ioaddr_t)softsp->iommu_dvma_size);

	(void) snprintf(name, sizeof (name), "%s%d_dvma",
	    ddi_driver_name(softsp->dip), ddi_get_instance(softsp->dip));

	/*
	 * Initialize the DVMA vmem arena.
	 */
	softsp->dvma_arena = vmem_create(name,
	    (void *)(uintptr_t)softsp->iommu_dvma_base,
	    softsp->iommu_dvma_size, PAGESIZE, NULL, NULL, NULL,
	    DVMA_MAX_CACHE, VM_SLEEP);

	/* Set the limit for dvma_reserve() to 1/2 of the total dvma space */
	softsp->dma_reserve = iommu_btop(softsp->iommu_dvma_size >> 1);

#if defined(DEBUG) && defined(IO_MEMUSAGE)
	mutex_init(&softsp->iomemlock, NULL, MUTEX_DEFAULT, NULL);
	softsp->iomem = (struct io_mem_list *)0;
#endif /* DEBUG && IO_MEMUSAGE */
	/*
	 * Get the base address of the TSB table and store it in the hardware
	 */

	/*
	 * We plan on the PROM flushing all TLB entries.  If this is not the
	 * case, this is where we should flush the hardware TLB.
	 */

	/* Set the IOMMU registers */
	(void) iommu_resume_init(softsp);

	/* check the convenient copy of TSB base, and flush write buffers */
	if (*softsp->tsb_base_addr !=
	    va_to_pa((caddr_t)softsp->soft_tsb_base_addr)) {
		iommu_tsb_free(softsp->iommu_tsb_cookie);
		return (DDI_FAILURE);
	}

	softsp->sbus_io_lo_pfn = UINT32_MAX;
	softsp->sbus_io_hi_pfn = 0;
	for (i = 0; i < sysio_pd_getnrng(softsp->dip); i++) {
		struct rangespec *rangep;
		uint64_t addr;
		pfn_t hipfn, lopfn;

		rangep = sysio_pd_getrng(softsp->dip, i);
		addr = (uint64_t)((uint64_t)rangep->rng_bustype << 32);
		addr |= (uint64_t)rangep->rng_offset;
		lopfn = (pfn_t)(addr >> MMU_PAGESHIFT);
		addr += (uint64_t)(rangep->rng_size - 1);
		hipfn = (pfn_t)(addr >> MMU_PAGESHIFT);

		softsp->sbus_io_lo_pfn = (lopfn < softsp->sbus_io_lo_pfn) ?
		    lopfn : softsp->sbus_io_lo_pfn;

		softsp->sbus_io_hi_pfn = (hipfn > softsp->sbus_io_hi_pfn) ?
		    hipfn : softsp->sbus_io_hi_pfn;
	}

	DPRINTF(IOMMU_REGISTERS_DEBUG, ("IOMMU Control reg: %p IOMMU TSB "
	    "base reg: %p IOMMU flush reg: %p TSB base addr %p\n",
	    (void *)softsp->iommu_ctrl_reg, (void *)softsp->tsb_base_addr,
	    (void *)softsp->iommu_flush_reg,
	    (void *)softsp->soft_tsb_base_addr));

	return (DDI_SUCCESS);
}

/*
 * function to uninitialize the iommu and release the tsb back to
 * the spare pool.  See startup.c for tsb spare management.
 */

int
iommu_uninit(struct sbus_soft_state *softsp)
{
	vmem_destroy(softsp->dvma_arena);

	/* flip off the IOMMU enable switch */
	*softsp->iommu_ctrl_reg &=
	    (TSB_SIZE << TSB_SIZE_SHIFT | IOMMU_DISABLE);

	iommu_tsb_free(softsp->iommu_tsb_cookie);

	return (DDI_SUCCESS);
}

/*
 * Initialize iommu hardware registers when the system is being resumed.
 * (Subset of iommu_init())
 */
int
iommu_resume_init(struct sbus_soft_state *softsp)
{
	int i;
	uint_t tsb_size;
	uint_t tsb_bytes;

	/*
	 * Reset the base address of the TSB table in the hardware
	 */
	*softsp->tsb_base_addr = va_to_pa((caddr_t)softsp->soft_tsb_base_addr);

	/*
	 * Figure out the correct size of the IOMMU TSB entries.  If we
	 * end up with a size smaller than that needed for 8M of IOMMU
	 * space, default the size to 8M.  XXX We could probably panic here
	 */
	i = sizeof (sysio_iommu_tsb_sizes) / sizeof (sysio_iommu_tsb_sizes[0])
	    - 1;

	tsb_bytes = iommu_tsb_cookie_to_size(softsp->iommu_tsb_cookie);

	while (i > 0) {
		if (tsb_bytes >= sysio_iommu_tsb_sizes[i])
			break;
		i--;
	}

	tsb_size = i;

	/* OK, lets flip the "on" switch of the IOMMU */
	*softsp->iommu_ctrl_reg = (uint64_t)(tsb_size << TSB_SIZE_SHIFT
	    | IOMMU_ENABLE | IOMMU_DIAG_ENABLE);

	return (DDI_SUCCESS);
}

void
iommu_tlb_flush(struct sbus_soft_state *softsp, ioaddr_t addr, pgcnt_t npages)
{
	volatile uint64_t tmpreg;
	volatile uint64_t *vaddr_reg, *valid_bit_reg;
	ioaddr_t hiaddr, ioaddr;
	int i, do_flush = 0;

	if (npages == 1) {
		*softsp->iommu_flush_reg = (uint64_t)addr;
		tmpreg = *softsp->sbus_ctrl_reg;
		return;
	}

	hiaddr = addr + (ioaddr_t)(npages * IOMMU_PAGESIZE);
	for (i = 0, vaddr_reg = softsp->iommu_tlb_tag,
	    valid_bit_reg = softsp->iommu_tlb_data;
	    i < IOMMU_TLB_ENTRIES; i++, vaddr_reg++, valid_bit_reg++) {
		tmpreg = *vaddr_reg;
		ioaddr = (ioaddr_t)((tmpreg & IOMMU_TLBTAG_VA_MASK) <<
		    IOMMU_TLBTAG_VA_SHIFT);

		DPRINTF(IOMMU_TLB, ("Vaddr reg 0x%p, "
		    "TLB vaddr reg %lx, IO addr 0x%x "
		    "Base addr 0x%x, Hi addr 0x%x\n",
		    (void *)vaddr_reg, tmpreg, ioaddr, addr, hiaddr));

		if (ioaddr >= addr && ioaddr <= hiaddr) {
			tmpreg = *valid_bit_reg;

			DPRINTF(IOMMU_TLB, ("Valid reg addr 0x%p, "
			    "TLB valid reg %lx\n",
			    (void *)valid_bit_reg, tmpreg));

			if (tmpreg & IOMMU_TLB_VALID) {
				*softsp->iommu_flush_reg = (uint64_t)ioaddr;
				do_flush = 1;
			}
		}
	}

	if (do_flush)
		tmpreg = *softsp->sbus_ctrl_reg;
}


/*
 * Shorthand defines
 */

#define	ALO		dma_lim->dlim_addr_lo
#define	AHI		dma_lim->dlim_addr_hi
#define	OBJSIZE		dmareq->dmar_object.dmao_size
#define	IOTTE_NDX(vaddr, base) (base + \
		(int)(iommu_btop((vaddr & ~IOMMU_PAGEMASK) - \
		softsp->iommu_dvma_base)))
/*
 * If DDI_DMA_PARTIAL flag is set and the request is for
 * less than MIN_DVMA_WIN_SIZE, it's not worth the hassle so
 * we turn off the DDI_DMA_PARTIAL flag
 */
#define	MIN_DVMA_WIN_SIZE	(128)

/* ARGSUSED */
void
iommu_remove_mappings(ddi_dma_impl_t *mp)
{
#if defined(DEBUG) && defined(IO_MEMDEBUG)
	pgcnt_t npages;
	ioaddr_t ioaddr;
	volatile uint64_t *iotte_ptr;
	ioaddr_t ioaddr = mp->dmai_mapping & ~IOMMU_PAGEOFFSET;
	pgcnt_t npages = mp->dmai_ndvmapages;
	struct dma_impl_priv *mppriv = (struct dma_impl_priv *)mp;
	struct sbus_soft_state *softsp = mppriv->softsp;

#if defined(IO_MEMUSAGE)
	struct io_mem_list **prevp, *walk;
#endif /* DEBUG && IO_MEMUSAGE */

	ASSERT(softsp != NULL);
	/*
	 * Run thru the mapped entries and free 'em
	 */

	ioaddr = mp->dmai_mapping & ~IOMMU_PAGEOFFSET;
	npages = mp->dmai_ndvmapages;

#if defined(IO_MEMUSAGE)
	mutex_enter(&softsp->iomemlock);
	prevp = &softsp->iomem;
	walk = softsp->iomem;

	while (walk) {
		if (walk->ioaddr == ioaddr) {
			*prevp = walk->next;
			break;
		}

		prevp = &walk->next;
		walk = walk->next;
	}
	mutex_exit(&softsp->iomemlock);

	kmem_free(walk->pfn, sizeof (pfn_t) * (npages + 1));
	kmem_free(walk, sizeof (struct io_mem_list));
#endif /* IO_MEMUSAGE */

	iotte_ptr = IOTTE_NDX(ioaddr, softsp->soft_tsb_base_addr);

	while (npages) {
		DPRINTF(IOMMU_DMAMCTL_DEBUG,
		    ("dma_mctl: freeing ioaddr %x iotte %p\n",
		    ioaddr, iotte_ptr));
		*iotte_ptr = (uint64_t)0;	/* unload tte */
		iommu_tlb_flush(softsp, ioaddr, 1);
		npages--;
		ioaddr += IOMMU_PAGESIZE;
		iotte_ptr++;
	}
#endif /* DEBUG && IO_MEMDEBUG */
}


int
iommu_create_vaddr_mappings(ddi_dma_impl_t *mp, uintptr_t addr)
{
	pfn_t pfn;
	struct as *as = NULL;
	pgcnt_t npages;
	ioaddr_t ioaddr;
	uint_t offset;
	volatile uint64_t *iotte_ptr;
	uint64_t tmp_iotte_flag;
	int rval = DDI_DMA_MAPPED;
	struct dma_impl_priv *mppriv = (struct dma_impl_priv *)mp;
	struct sbus_soft_state *softsp = mppriv->softsp;
	int diag_tlb_flush;
#if defined(DEBUG) && defined(IO_MEMUSAGE)
	struct io_mem_list *iomemp;
	pfn_t *pfnp;
#endif /* DEBUG && IO_MEMUSAGE */

	ASSERT(softsp != NULL);

	/* Set Valid and Cache for mem xfer */
	tmp_iotte_flag = IOTTE_VALID | IOTTE_CACHE | IOTTE_WRITE | IOTTE_STREAM;

	offset = (uint_t)(mp->dmai_mapping & IOMMU_PAGEOFFSET);
	npages = iommu_btopr(mp->dmai_size + offset);
	ioaddr = (ioaddr_t)(mp->dmai_mapping & ~IOMMU_PAGEOFFSET);
	iotte_ptr = IOTTE_NDX(ioaddr, softsp->soft_tsb_base_addr);
	diag_tlb_flush = npages > tlb_flush_using_diag ? 1 : 0;

	as = mp->dmai_object.dmao_obj.virt_obj.v_as;
	if (as == NULL)
		as = &kas;

	/*
	 * Set the per object bits of the TTE here. We optimize this for
	 * the memory case so that the while loop overhead is minimal.
	 */
	/* Turn on NOSYNC if we need consistent mem */
	if (mp->dmai_rflags & DDI_DMA_CONSISTENT) {
		mp->dmai_rflags |= DMP_NOSYNC;
		tmp_iotte_flag ^= IOTTE_STREAM;
	/* Set streaming mode if not consistent mem */
	} else if (softsp->stream_buf_off) {
		tmp_iotte_flag ^= IOTTE_STREAM;
	}

#if defined(DEBUG) && defined(IO_MEMUSAGE)
	iomemp = kmem_alloc(sizeof (struct io_mem_list), KM_SLEEP);
	iomemp->rdip = mp->dmai_rdip;
	iomemp->ioaddr = ioaddr;
	iomemp->addr = addr;
	iomemp->npages = npages;
	pfnp = iomemp->pfn = kmem_zalloc(sizeof (*pfnp) * (npages + 1),
	    KM_SLEEP);
#endif /* DEBUG && IO_MEMUSAGE */
	/*
	 * Grab the mappings from the dmmu and stick 'em into the
	 * iommu.
	 */
	ASSERT(npages != 0);

	/* If we're going to flush the TLB using diag mode, do it now. */
	if (diag_tlb_flush)
		iommu_tlb_flush(softsp, ioaddr, npages);

	do {
		uint64_t iotte_flag = tmp_iotte_flag;

		/*
		 * Fetch the pfn for the DMA object
		 */

		ASSERT(as);
		pfn = hat_getpfnum(as->a_hat, (caddr_t)addr);
		ASSERT(pfn != PFN_INVALID);

		if (!pf_is_memory(pfn)) {
			/* DVMA'ing to IO space */

			/* Turn off cache bit if set */
			if (iotte_flag & IOTTE_CACHE)
				iotte_flag ^= IOTTE_CACHE;

			/* Turn off stream bit if set */
			if (iotte_flag & IOTTE_STREAM)
				iotte_flag ^= IOTTE_STREAM;

			if (IS_INTRA_SBUS(softsp, pfn)) {
				/* Intra sbus transfer */

				/* Turn on intra flag */
				iotte_flag |= IOTTE_INTRA;

				DPRINTF(IOMMU_INTER_INTRA_XFER, (
				    "Intra xfer pfnum %lx TTE %lx\n",
				    pfn, iotte_flag));
			} else {
				if (pf_is_dmacapable(pfn) == 1) {
					/*EMPTY*/
					DPRINTF(IOMMU_INTER_INTRA_XFER,
					    ("Inter xfer pfnum %lx "
					    "tte hi %lx\n",
					    pfn, iotte_flag));
				} else {
					rval = DDI_DMA_NOMAPPING;
#if defined(DEBUG) && defined(IO_MEMDEBUG)
					goto bad;
#endif /* DEBUG && IO_MEMDEBUG */
				}
			}
		}
		addr += IOMMU_PAGESIZE;

		DPRINTF(IOMMU_TTE, ("vaddr mapping: tte index %p pfn %lx "
		    "tte flag %lx addr %lx ioaddr %x\n",
		    (void *)iotte_ptr, pfn, iotte_flag, addr, ioaddr));

		/* Flush the IOMMU TLB before loading a new mapping */
		if (!diag_tlb_flush)
			iommu_tlb_flush(softsp, ioaddr, 1);

		/* Set the hardware IO TTE */
		*iotte_ptr = ((uint64_t)pfn << IOMMU_PAGESHIFT) | iotte_flag;

		ioaddr += IOMMU_PAGESIZE;
		npages--;
		iotte_ptr++;
#if defined(DEBUG) && defined(IO_MEMUSAGE)
		*pfnp = pfn;
		pfnp++;
#endif /* DEBUG && IO_MEMUSAGE */
	} while (npages != 0);

#if defined(DEBUG) && defined(IO_MEMUSAGE)
	mutex_enter(&softsp->iomemlock);
	iomemp->next = softsp->iomem;
	softsp->iomem = iomemp;
	mutex_exit(&softsp->iomemlock);
#endif /* DEBUG && IO_MEMUSAGE */

	return (rval);

#if defined(DEBUG) && defined(IO_MEMDEBUG)
bad:
	/* If we fail a mapping, free up any mapping resources used */
	iommu_remove_mappings(mp);
	return (rval);
#endif /* DEBUG && IO_MEMDEBUG */
}


int
iommu_create_pp_mappings(ddi_dma_impl_t *mp, page_t *pp, page_t **pplist)
{
	pfn_t pfn;
	pgcnt_t npages;
	ioaddr_t ioaddr;
	uint_t offset;
	volatile uint64_t *iotte_ptr;
	uint64_t tmp_iotte_flag;
	struct dma_impl_priv *mppriv = (struct dma_impl_priv *)mp;
	struct sbus_soft_state *softsp = mppriv->softsp;
	int diag_tlb_flush;
#if defined(DEBUG) && defined(IO_MEMUSAGE)
	struct io_mem_list *iomemp;
	pfn_t *pfnp;
#endif /* DEBUG && IO_MEMUSAGE */
	int rval = DDI_DMA_MAPPED;

	/* Set Valid and Cache for mem xfer */
	tmp_iotte_flag = IOTTE_VALID | IOTTE_CACHE | IOTTE_WRITE | IOTTE_STREAM;

	ASSERT(softsp != NULL);

	offset = (uint_t)(mp->dmai_mapping & IOMMU_PAGEOFFSET);
	npages = iommu_btopr(mp->dmai_size + offset);
	ioaddr = (ioaddr_t)(mp->dmai_mapping & ~IOMMU_PAGEOFFSET);
	iotte_ptr = IOTTE_NDX(ioaddr, softsp->soft_tsb_base_addr);
	diag_tlb_flush = npages > tlb_flush_using_diag ? 1 : 0;

	/*
	 * Set the per object bits of the TTE here. We optimize this for
	 * the memory case so that the while loop overhead is minimal.
	 */
	if (mp->dmai_rflags & DDI_DMA_CONSISTENT) {
		/* Turn on NOSYNC if we need consistent mem */
		mp->dmai_rflags |= DMP_NOSYNC;
		tmp_iotte_flag ^= IOTTE_STREAM;
	} else if (softsp->stream_buf_off) {
		/* Set streaming mode if not consistent mem */
		tmp_iotte_flag ^= IOTTE_STREAM;
	}

#if defined(DEBUG) && defined(IO_MEMUSAGE)
	iomemp = kmem_alloc(sizeof (struct io_mem_list), KM_SLEEP);
	iomemp->rdip = mp->dmai_rdip;
	iomemp->ioaddr = ioaddr;
	iomemp->npages = npages;
	pfnp = iomemp->pfn = kmem_zalloc(sizeof (*pfnp) * (npages + 1),
	    KM_SLEEP);
#endif /* DEBUG && IO_MEMUSAGE */
	/*
	 * Grab the mappings from the dmmu and stick 'em into the
	 * iommu.
	 */
	ASSERT(npages != 0);

	/* If we're going to flush the TLB using diag mode, do it now. */
	if (diag_tlb_flush)
		iommu_tlb_flush(softsp, ioaddr, npages);

	do {
		uint64_t iotte_flag;

		iotte_flag = tmp_iotte_flag;

		if (pp != NULL) {
			pfn = pp->p_pagenum;
			pp = pp->p_next;
		} else {
			pfn = (*pplist)->p_pagenum;
			pplist++;
		}

		DPRINTF(IOMMU_TTE, ("pp mapping TTE index %p pfn %lx "
		    "tte flag %lx ioaddr %x\n", (void *)iotte_ptr,
		    pfn, iotte_flag, ioaddr));

		/* Flush the IOMMU TLB before loading a new mapping */
		if (!diag_tlb_flush)
			iommu_tlb_flush(softsp, ioaddr, 1);

		/* Set the hardware IO TTE */
		*iotte_ptr = ((uint64_t)pfn << IOMMU_PAGESHIFT) | iotte_flag;

		ioaddr += IOMMU_PAGESIZE;
		npages--;
		iotte_ptr++;

#if defined(DEBUG) && defined(IO_MEMUSAGE)
		*pfnp = pfn;
		pfnp++;
#endif /* DEBUG && IO_MEMUSAGE */

	} while (npages != 0);

#if defined(DEBUG) && defined(IO_MEMUSAGE)
	mutex_enter(&softsp->iomemlock);
	iomemp->next = softsp->iomem;
	softsp->iomem = iomemp;
	mutex_exit(&softsp->iomemlock);
#endif /* DEBUG && IO_MEMUSAGE */

	return (rval);
}


int
iommu_dma_lim_setup(dev_info_t *dip, dev_info_t *rdip,
    struct sbus_soft_state *softsp, uint_t *burstsizep, uint_t burstsize64,
    uint_t *minxferp, uint_t dma_flags)
{
	struct regspec *rp;

	/* Take care of 64 bit limits. */
	if (!(dma_flags & DDI_DMA_SBUS_64BIT)) {
		/*
		 * return burst size for 32-bit mode
		 */
		*burstsizep &= softsp->sbus_burst_sizes;
		return (DDI_FAILURE);
	}

	/*
	 * check if SBus supports 64 bit and if caller
	 * is child of SBus. No support through bridges
	 */
	if (!softsp->sbus64_burst_sizes || (ddi_get_parent(rdip) != dip)) {
		/*
		 * SBus doesn't support it or bridge. Do 32-bit
		 * xfers
		 */
		*burstsizep &= softsp->sbus_burst_sizes;
		return (DDI_FAILURE);
	}

	rp = ddi_rnumber_to_regspec(rdip, 0);
	if (rp == NULL) {
		*burstsizep &= softsp->sbus_burst_sizes;
		return (DDI_FAILURE);
	}

	/* Check for old-style 64 bit burstsizes */
	if (burstsize64 & SYSIO64_BURST_MASK) {
		/* Scale back burstsizes if Necessary */
		*burstsizep &= (softsp->sbus64_burst_sizes |
		    softsp->sbus_burst_sizes);
	} else {
		/* Get the 64 bit burstsizes. */
		*burstsizep = burstsize64;

		/* Scale back burstsizes if Necessary */
		*burstsizep &= (softsp->sbus64_burst_sizes >>
		    SYSIO64_BURST_SHIFT);
	}

	/*
	 * Set the largest value of the smallest burstsize that the
	 * device or the bus can manage.
	 */
	*minxferp = MAX(*minxferp,
	    (1 << (ddi_ffs(softsp->sbus64_burst_sizes) - 1)));

	return (DDI_SUCCESS);
}


int
iommu_dma_allochdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_attr_t *dma_attr, int (*waitfp)(caddr_t), caddr_t arg,
    ddi_dma_handle_t *handlep)
{
	ioaddr_t addrlow, addrhigh, segalign;
	ddi_dma_impl_t *mp;
	struct dma_impl_priv *mppriv;
	struct sbus_soft_state *softsp = (struct sbus_soft_state *)
	    ddi_get_soft_state(sbusp, ddi_get_instance(dip));

	/*
	 * Setup dma burstsizes and min-xfer counts.
	 */
	(void) iommu_dma_lim_setup(dip, rdip, softsp,
	    &dma_attr->dma_attr_burstsizes,
	    dma_attr->dma_attr_burstsizes, &dma_attr->dma_attr_minxfer,
	    dma_attr->dma_attr_flags);

	if (dma_attr->dma_attr_burstsizes == 0)
		return (DDI_DMA_BADATTR);

	addrlow = (ioaddr_t)dma_attr->dma_attr_addr_lo;
	addrhigh = (ioaddr_t)dma_attr->dma_attr_addr_hi;
	segalign = (ioaddr_t)dma_attr->dma_attr_seg;

	/*
	 * Check sanity for hi and lo address limits
	 */
	if ((addrhigh <= addrlow) ||
	    (addrhigh < (ioaddr_t)softsp->iommu_dvma_base)) {
		return (DDI_DMA_BADATTR);
	}
	if (dma_attr->dma_attr_flags & DDI_DMA_FORCE_PHYSICAL)
		return (DDI_DMA_BADATTR);

	mppriv = kmem_zalloc(sizeof (*mppriv),
	    (waitfp == DDI_DMA_SLEEP) ? KM_SLEEP : KM_NOSLEEP);

	if (mppriv == NULL) {
		if (waitfp != DDI_DMA_DONTWAIT) {
			ddi_set_callback(waitfp, arg,
			    &softsp->dvma_call_list_id);
		}
		return (DDI_DMA_NORESOURCES);
	}
	mp = (ddi_dma_impl_t *)mppriv;

	DPRINTF(IOMMU_DMA_ALLOCHDL_DEBUG, ("dma_allochdl: (%s) handle %p "
	    "hi %x lo %x min %x burst %x\n",
	    ddi_get_name(dip), (void *)mp, addrhigh, addrlow,
	    dma_attr->dma_attr_minxfer, dma_attr->dma_attr_burstsizes));

	mp->dmai_rdip = rdip;
	mp->dmai_minxfer = (uint_t)dma_attr->dma_attr_minxfer;
	mp->dmai_burstsizes = (uint_t)dma_attr->dma_attr_burstsizes;
	mp->dmai_attr = *dma_attr;
	/* See if the DMA engine has any limit restrictions. */
	if (segalign == (ioaddr_t)UINT32_MAX &&
	    addrhigh == (ioaddr_t)UINT32_MAX &&
	    (dma_attr->dma_attr_align <= IOMMU_PAGESIZE) && addrlow == 0) {
		mp->dmai_rflags |= DMP_NOLIMIT;
	}
	mppriv->softsp = softsp;
	mppriv->phys_sync_flag = va_to_pa((caddr_t)&mppriv->sync_flag);

	*handlep = (ddi_dma_handle_t)mp;
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
iommu_dma_freehdl(dev_info_t *dip, dev_info_t *rdip, ddi_dma_handle_t handle)
{
	struct dma_impl_priv *mppriv = (struct dma_impl_priv *)handle;
	struct sbus_soft_state *softsp = mppriv->softsp;
	ASSERT(softsp != NULL);

	kmem_free(mppriv, sizeof (*mppriv));

	if (softsp->dvma_call_list_id != 0) {
		ddi_run_callback(&softsp->dvma_call_list_id);
	}
	return (DDI_SUCCESS);
}

static int
check_dma_attr(struct ddi_dma_req *dmareq, ddi_dma_attr_t *dma_attr,
    uint32_t *size)
{
	ioaddr_t addrlow;
	ioaddr_t addrhigh;
	uint32_t segalign;
	uint32_t smask;

	smask = *size - 1;
	segalign = dma_attr->dma_attr_seg;
	if (smask > segalign) {
		if ((dmareq->dmar_flags & DDI_DMA_PARTIAL) == 0)
			return (DDI_DMA_TOOBIG);
		*size = segalign + 1;
	}
	addrlow = (ioaddr_t)dma_attr->dma_attr_addr_lo;
	addrhigh = (ioaddr_t)dma_attr->dma_attr_addr_hi;
	if (addrlow + smask > addrhigh || addrlow + smask < addrlow) {
		if (!((addrlow + dmareq->dmar_object.dmao_size == 0) &&
		    (addrhigh == (ioaddr_t)-1))) {
			if ((dmareq->dmar_flags & DDI_DMA_PARTIAL) == 0)
				return (DDI_DMA_TOOBIG);
			*size = MIN(addrhigh - addrlow + 1, *size);
		}
	}
	return (DDI_DMA_MAPOK);
}

int
iommu_dma_bindhdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, struct ddi_dma_req *dmareq,
    ddi_dma_cookie_t *cp, uint_t *ccountp)
{
	page_t *pp;
	uint32_t size;
	ioaddr_t ioaddr;
	uint_t offset;
	uintptr_t addr = 0;
	pgcnt_t npages;
	int rval;
	ddi_dma_attr_t *dma_attr;
	struct sbus_soft_state *softsp;
	struct page **pplist = NULL;
	ddi_dma_impl_t *mp = (ddi_dma_impl_t *)handle;
	struct dma_impl_priv *mppriv = (struct dma_impl_priv *)mp;

#ifdef lint
	dip = dip;
	rdip = rdip;
#endif

	if (mp->dmai_inuse)
		return (DDI_DMA_INUSE);

	dma_attr = &mp->dmai_attr;
	size = (uint32_t)dmareq->dmar_object.dmao_size;
	if (!(mp->dmai_rflags & DMP_NOLIMIT)) {
		rval = check_dma_attr(dmareq, dma_attr, &size);
		if (rval != DDI_DMA_MAPOK)
			return (rval);
	}
	mp->dmai_inuse = 1;
	mp->dmai_offset = 0;
	mp->dmai_rflags = (dmareq->dmar_flags & DMP_DDIFLAGS) |
	    (mp->dmai_rflags & DMP_NOLIMIT);

	switch (dmareq->dmar_object.dmao_type) {
	case DMA_OTYP_VADDR:
	case DMA_OTYP_BUFVADDR:
		addr = (uintptr_t)dmareq->dmar_object.dmao_obj.virt_obj.v_addr;
		offset = addr & IOMMU_PAGEOFFSET;
		pplist = dmareq->dmar_object.dmao_obj.virt_obj.v_priv;
		npages = iommu_btopr(OBJSIZE + offset);

		DPRINTF(IOMMU_DMAMAP_DEBUG, ("dma_map vaddr: %lx pages "
		    "req addr %lx off %x OBJSIZE %x\n",
		    npages, addr, offset, OBJSIZE));

		/* We don't need the addr anymore if we have a shadow list */
		if (pplist != NULL)
			addr = NULL;
		pp = NULL;
		break;

	case DMA_OTYP_PAGES:
		pp = dmareq->dmar_object.dmao_obj.pp_obj.pp_pp;
		offset = dmareq->dmar_object.dmao_obj.pp_obj.pp_offset;
		npages = iommu_btopr(OBJSIZE + offset);
		break;

	case DMA_OTYP_PADDR:
	default:
		/*
		 * Not a supported type for this implementation
		 */
		rval = DDI_DMA_NOMAPPING;
		goto bad;
	}

	/* Get our soft state once we know we're mapping an object. */
	softsp = mppriv->softsp;
	ASSERT(softsp != NULL);

	if (mp->dmai_rflags & DDI_DMA_PARTIAL) {
		if (size != OBJSIZE) {
			/*
			 * If the request is for partial mapping arrangement,
			 * the device has to be able to address at least the
			 * size of the window we are establishing.
			 */
			if (size < iommu_ptob(MIN_DVMA_WIN_SIZE)) {
				rval = DDI_DMA_NOMAPPING;
				goto bad;
			}
			npages = iommu_btopr(size + offset);
		}
		/*
		 * If the size requested is less than a moderate amt,
		 * skip the partial mapping stuff- it's not worth the
		 * effort.
		 */
		if (npages > MIN_DVMA_WIN_SIZE) {
			npages = MIN_DVMA_WIN_SIZE + iommu_btopr(offset);
			size = iommu_ptob(MIN_DVMA_WIN_SIZE);
			DPRINTF(IOMMU_DMA_SETUP_DEBUG, ("dma_setup: SZ %x pg "
			    "%lx sz %x\n", OBJSIZE, npages, size));
			if (pplist != NULL) {
				mp->dmai_minfo = (void *)pplist;
				mp->dmai_rflags |= DMP_SHADOW;
			}
		} else {
			mp->dmai_rflags ^= DDI_DMA_PARTIAL;
		}
	} else {
		if (npages >= iommu_btop(softsp->iommu_dvma_size) -
		    MIN_DVMA_WIN_SIZE) {
			rval = DDI_DMA_TOOBIG;
			goto bad;
		}
	}

	/*
	 * save dmareq-object, size and npages into mp
	 */
	mp->dmai_object = dmareq->dmar_object;
	mp->dmai_size = size;
	mp->dmai_ndvmapages = npages;

	if (mp->dmai_rflags & DMP_NOLIMIT) {
		ioaddr = (ioaddr_t)(uintptr_t)vmem_alloc(softsp->dvma_arena,
		    iommu_ptob(npages),
		    dmareq->dmar_fp == DDI_DMA_SLEEP ? VM_SLEEP : VM_NOSLEEP);
		if (ioaddr == 0) {
			rval = DDI_DMA_NORESOURCES;
			goto bad;
		}

		/*
		 * If we have a 1 page request and we're working with a page
		 * list, we're going to speed load an IOMMU entry.
		 */
		if (npages == 1 && !addr) {
			uint64_t iotte_flag = IOTTE_VALID | IOTTE_CACHE |
			    IOTTE_WRITE | IOTTE_STREAM;
			volatile uint64_t *iotte_ptr;
			pfn_t pfn;
#if defined(DEBUG) && defined(IO_MEMUSAGE)
			struct io_mem_list *iomemp;
			pfn_t *pfnp;
#endif /* DEBUG && IO_MEMUSAGE */

			iotte_ptr = IOTTE_NDX(ioaddr,
			    softsp->soft_tsb_base_addr);

			if (mp->dmai_rflags & DDI_DMA_CONSISTENT) {
				mp->dmai_rflags |= DMP_NOSYNC;
				iotte_flag ^= IOTTE_STREAM;
			} else if (softsp->stream_buf_off)
				iotte_flag ^= IOTTE_STREAM;

			mp->dmai_rflags ^= DDI_DMA_PARTIAL;

			if (pp != NULL)
				pfn = pp->p_pagenum;
			else
				pfn = (*pplist)->p_pagenum;

			iommu_tlb_flush(softsp, ioaddr, 1);

			*iotte_ptr =
			    ((uint64_t)pfn << IOMMU_PAGESHIFT) | iotte_flag;

			mp->dmai_mapping = (ioaddr_t)(ioaddr + offset);
			mp->dmai_nwin = 0;
			if (cp != NULL) {
				cp->dmac_notused = 0;
				cp->dmac_address = (ioaddr_t)mp->dmai_mapping;
				cp->dmac_size = mp->dmai_size;
				cp->dmac_type = 0;
				*ccountp = 1;
			}

			DPRINTF(IOMMU_TTE, ("speed loading: TTE index %p "
			    "pfn %lx tte flag %lx addr %lx ioaddr %x\n",
			    (void *)iotte_ptr, pfn, iotte_flag, addr, ioaddr));

#if defined(DEBUG) && defined(IO_MEMUSAGE)
			iomemp = kmem_alloc(sizeof (struct io_mem_list),
			    KM_SLEEP);
			iomemp->rdip = mp->dmai_rdip;
			iomemp->ioaddr = ioaddr;
			iomemp->addr = addr;
			iomemp->npages = npages;
			pfnp = iomemp->pfn = kmem_zalloc(sizeof (*pfnp) *
			    (npages + 1), KM_SLEEP);
			*pfnp = pfn;
			mutex_enter(&softsp->iomemlock);
			iomemp->next = softsp->iomem;
			softsp->iomem = iomemp;
			mutex_exit(&softsp->iomemlock);
#endif /* DEBUG && IO_MEMUSAGE */

			return (DDI_DMA_MAPPED);
		}
	} else {
		ioaddr = (ioaddr_t)(uintptr_t)vmem_xalloc(softsp->dvma_arena,
		    iommu_ptob(npages),
		    MAX((uint_t)dma_attr->dma_attr_align, IOMMU_PAGESIZE), 0,
		    (uint_t)dma_attr->dma_attr_seg + 1,
		    (void *)(uintptr_t)(ioaddr_t)dma_attr->dma_attr_addr_lo,
		    (void *)(uintptr_t)
		    ((ioaddr_t)dma_attr->dma_attr_addr_hi + 1),
		    dmareq->dmar_fp == DDI_DMA_SLEEP ? VM_SLEEP : VM_NOSLEEP);
	}

	if (ioaddr == 0) {
		if (dmareq->dmar_fp == DDI_DMA_SLEEP)
			rval = DDI_DMA_NOMAPPING;
		else
			rval = DDI_DMA_NORESOURCES;
		goto bad;
	}

	mp->dmai_mapping = ioaddr + offset;
	ASSERT(mp->dmai_mapping >= softsp->iommu_dvma_base);

	/*
	 * At this point we have a range of virtual address allocated
	 * with which we now have to map to the requested object.
	 */
	if (addr) {
		rval = iommu_create_vaddr_mappings(mp,
		    addr & ~IOMMU_PAGEOFFSET);
		if (rval == DDI_DMA_NOMAPPING)
			goto bad_nomap;
	} else {
		rval = iommu_create_pp_mappings(mp, pp, pplist);
		if (rval == DDI_DMA_NOMAPPING)
			goto bad_nomap;
	}

	if (cp) {
		cp->dmac_notused = 0;
		cp->dmac_address = (ioaddr_t)mp->dmai_mapping;
		cp->dmac_size = mp->dmai_size;
		cp->dmac_type = 0;
		*ccountp = 1;
	}
	if (mp->dmai_rflags & DDI_DMA_PARTIAL) {
		size = iommu_ptob(mp->dmai_ndvmapages - iommu_btopr(offset));
		mp->dmai_nwin =
		    (dmareq->dmar_object.dmao_size + (size - 1)) / size;
		return (DDI_DMA_PARTIAL_MAP);
	} else {
		mp->dmai_nwin = 0;
		return (DDI_DMA_MAPPED);
	}

bad_nomap:
	/*
	 * Could not create mmu mappings.
	 */
	if (mp->dmai_rflags & DMP_NOLIMIT) {
		vmem_free(softsp->dvma_arena, (void *)(uintptr_t)ioaddr,
		    iommu_ptob(npages));
	} else {
		vmem_xfree(softsp->dvma_arena, (void *)(uintptr_t)ioaddr,
		    iommu_ptob(npages));
	}

bad:
	if (rval == DDI_DMA_NORESOURCES &&
	    dmareq->dmar_fp != DDI_DMA_DONTWAIT) {
		ddi_set_callback(dmareq->dmar_fp,
		    dmareq->dmar_arg, &softsp->dvma_call_list_id);
	}
	mp->dmai_inuse = 0;
	return (rval);
}

/* ARGSUSED */
int
iommu_dma_unbindhdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle)
{
	ioaddr_t addr;
	uint_t npages;
	size_t size;
	ddi_dma_impl_t *mp = (ddi_dma_impl_t *)handle;
	struct dma_impl_priv *mppriv = (struct dma_impl_priv *)mp;
	struct sbus_soft_state *softsp = mppriv->softsp;
	ASSERT(softsp != NULL);

	addr = (ioaddr_t)(mp->dmai_mapping & ~IOMMU_PAGEOFFSET);
	npages = mp->dmai_ndvmapages;
	size = iommu_ptob(npages);

	DPRINTF(IOMMU_DMA_UNBINDHDL_DEBUG, ("iommu_dma_unbindhdl: "
	    "unbinding addr %x for %x pages\n", addr, mp->dmai_ndvmapages));

	/* sync the entire object */
	if (!(mp->dmai_rflags & DDI_DMA_CONSISTENT)) {
		/* flush stream write buffers */
		sync_stream_buf(softsp, addr, npages, (int *)&mppriv->sync_flag,
		    mppriv->phys_sync_flag);
	}

#if defined(DEBUG) && defined(IO_MEMDEBUG)
	/*
	 * 'Free' the dma mappings.
	 */
	iommu_remove_mappings(mp);
#endif /* DEBUG && IO_MEMDEBUG */

	ASSERT(npages > (uint_t)0);
	if (mp->dmai_rflags & DMP_NOLIMIT)
		vmem_free(softsp->dvma_arena, (void *)(uintptr_t)addr, size);
	else
		vmem_xfree(softsp->dvma_arena, (void *)(uintptr_t)addr, size);

	mp->dmai_ndvmapages = 0;
	mp->dmai_inuse = 0;
	mp->dmai_minfo = NULL;

	if (softsp->dvma_call_list_id != 0)
		ddi_run_callback(&softsp->dvma_call_list_id);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
iommu_dma_flush(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, off_t off, size_t len,
    uint_t cache_flags)
{
	ddi_dma_impl_t *mp = (ddi_dma_impl_t *)handle;
	struct dma_impl_priv *mppriv = (struct dma_impl_priv *)mp;

	if (!(mp->dmai_rflags & DDI_DMA_CONSISTENT)) {
		sync_stream_buf(mppriv->softsp, mp->dmai_mapping,
		    mp->dmai_ndvmapages, (int *)&mppriv->sync_flag,
		    mppriv->phys_sync_flag);
	}
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
int
iommu_dma_win(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, uint_t win, off_t *offp,
    size_t *lenp, ddi_dma_cookie_t *cookiep, uint_t *ccountp)
{
	ddi_dma_impl_t *mp = (ddi_dma_impl_t *)handle;
	off_t offset;
	uint_t winsize;
	uint_t newoff;
	int rval;

	offset = mp->dmai_mapping & IOMMU_PAGEOFFSET;
	winsize = iommu_ptob(mp->dmai_ndvmapages - iommu_btopr(offset));

	DPRINTF(IOMMU_DMA_WIN_DEBUG, ("getwin win %d winsize %x\n", win,
	    winsize));

	/*
	 * win is in the range [0 .. dmai_nwin-1]
	 */
	if (win >= mp->dmai_nwin)
		return (DDI_FAILURE);

	newoff = win * winsize;
	if (newoff > mp->dmai_object.dmao_size - mp->dmai_minxfer)
		return (DDI_FAILURE);

	ASSERT(cookiep);
	cookiep->dmac_notused = 0;
	cookiep->dmac_type = 0;
	cookiep->dmac_address = (ioaddr_t)mp->dmai_mapping;
	cookiep->dmac_size = mp->dmai_size;
	*ccountp = 1;
	*offp = (off_t)newoff;
	*lenp = (uint_t)winsize;

	if (newoff == mp->dmai_offset) {
		/*
		 * Nothing to do...
		 */
		return (DDI_SUCCESS);
	}

	if ((rval = iommu_map_window(mp, newoff, winsize)) != DDI_SUCCESS)
		return (rval);

	/*
	 * Set this again in case iommu_map_window() has changed it
	 */
	cookiep->dmac_size = mp->dmai_size;

	return (DDI_SUCCESS);
}

static int
iommu_map_window(ddi_dma_impl_t *mp, off_t newoff, size_t winsize)
{
	uintptr_t addr = 0;
	page_t *pp;
	uint_t flags;
	struct page **pplist = NULL;

#if defined(DEBUG) && defined(IO_MEMDEBUG)
	/* Free mappings for current window */
	iommu_remove_mappings(mp);
#endif /* DEBUG && IO_MEMDEBUG */

	mp->dmai_offset = newoff;
	mp->dmai_size = mp->dmai_object.dmao_size - newoff;
	mp->dmai_size = MIN(mp->dmai_size, winsize);

	if (mp->dmai_object.dmao_type == DMA_OTYP_VADDR ||
	    mp->dmai_object.dmao_type == DMA_OTYP_BUFVADDR) {
		if (mp->dmai_rflags & DMP_SHADOW) {
			pplist = (struct page **)mp->dmai_minfo;
			ASSERT(pplist != NULL);
			pplist = pplist + (newoff >> MMU_PAGESHIFT);
		} else {
			addr = (uintptr_t)
			    mp->dmai_object.dmao_obj.virt_obj.v_addr;
			addr = (addr + newoff) & ~IOMMU_PAGEOFFSET;
		}
		pp = NULL;
	} else {
		pp = mp->dmai_object.dmao_obj.pp_obj.pp_pp;
		flags = 0;
		while (flags < newoff) {
			pp = pp->p_next;
			flags += MMU_PAGESIZE;
		}
	}

	/* Set up mappings for next window */
	if (addr) {
		if (iommu_create_vaddr_mappings(mp, addr) < 0)
			return (DDI_FAILURE);
	} else {
		if (iommu_create_pp_mappings(mp, pp, pplist) < 0)
			return (DDI_FAILURE);
	}

	/*
	 * also invalidate read stream buffer
	 */
	if (!(mp->dmai_rflags & DDI_DMA_CONSISTENT)) {
		struct dma_impl_priv *mppriv = (struct dma_impl_priv *)mp;

		sync_stream_buf(mppriv->softsp, mp->dmai_mapping,
		    mp->dmai_ndvmapages, (int *)&mppriv->sync_flag,
		    mppriv->phys_sync_flag);
	}

	return (DDI_SUCCESS);

}


/*ARGSUSED*/
int
iommu_dma_mctl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, enum ddi_dma_ctlops request,
    off_t *offp, size_t *lenp, caddr_t *objp, uint_t cache_flags)
{
	pgcnt_t npages;
	ddi_dma_impl_t *mp = (ddi_dma_impl_t *)handle;

	DPRINTF(IOMMU_DMAMCTL_DEBUG, ("dma_mctl: handle %p ", (void *)mp));
	switch (request) {

	case DDI_DMA_SET_SBUS64:
	{
		struct dma_impl_priv *mppriv = (struct dma_impl_priv *)mp;

		return (iommu_dma_lim_setup(dip, rdip, mppriv->softsp,
		    &mp->dmai_burstsizes, (uint_t)*lenp, &mp->dmai_minxfer,
		    DDI_DMA_SBUS_64BIT));
	}

	case DDI_DMA_RESERVE:
	{
		struct ddi_dma_req *dmareq = (struct ddi_dma_req *)offp;
		ddi_dma_lim_t *dma_lim;
		ddi_dma_handle_t *handlep;
		uint_t np;
		ioaddr_t ioaddr;
		int i;
		struct fast_dvma *iommu_fast_dvma;
		struct sbus_soft_state *softsp =
		    (struct sbus_soft_state *)ddi_get_soft_state(sbusp,
		    ddi_get_instance(dip));

		/* Some simple sanity checks */
		dma_lim = dmareq->dmar_limits;
		if (dma_lim->dlim_burstsizes == 0) {
			DPRINTF(IOMMU_FASTDMA_RESERVE,
			    ("Reserve: bad burstsizes\n"));
			return (DDI_DMA_BADLIMITS);
		}
		if ((AHI <= ALO) || (AHI < softsp->iommu_dvma_base)) {
			DPRINTF(IOMMU_FASTDMA_RESERVE,
			    ("Reserve: bad limits\n"));
			return (DDI_DMA_BADLIMITS);
		}

		np = dmareq->dmar_object.dmao_size;
		mutex_enter(&softsp->dma_pool_lock);
		if (np > softsp->dma_reserve) {
			mutex_exit(&softsp->dma_pool_lock);
			DPRINTF(IOMMU_FASTDMA_RESERVE,
			    ("Reserve: dma_reserve is exhausted\n"));
			return (DDI_DMA_NORESOURCES);
		}

		softsp->dma_reserve -= np;
		mutex_exit(&softsp->dma_pool_lock);
		mp = kmem_zalloc(sizeof (*mp), KM_SLEEP);
		mp->dmai_rflags = DMP_BYPASSNEXUS;
		mp->dmai_rdip = rdip;
		mp->dmai_minxfer = dma_lim->dlim_minxfer;
		mp->dmai_burstsizes = dma_lim->dlim_burstsizes;

		ioaddr = (ioaddr_t)(uintptr_t)vmem_xalloc(softsp->dvma_arena,
		    iommu_ptob(np), IOMMU_PAGESIZE, 0,
		    dma_lim->dlim_cntr_max + 1,
		    (void *)(uintptr_t)ALO, (void *)(uintptr_t)(AHI + 1),
		    dmareq->dmar_fp == DDI_DMA_SLEEP ? VM_SLEEP : VM_NOSLEEP);

		if (ioaddr == 0) {
			mutex_enter(&softsp->dma_pool_lock);
			softsp->dma_reserve += np;
			mutex_exit(&softsp->dma_pool_lock);
			kmem_free(mp, sizeof (*mp));
			DPRINTF(IOMMU_FASTDMA_RESERVE,
			    ("Reserve: No dvma resources available\n"));
			return (DDI_DMA_NOMAPPING);
		}

		/* create a per request structure */
		iommu_fast_dvma = kmem_alloc(sizeof (struct fast_dvma),
		    KM_SLEEP);

		/*
		 * We need to remember the size of the transfer so that
		 * we can figure the virtual pages to sync when the transfer
		 * is complete.
		 */
		iommu_fast_dvma->pagecnt = kmem_zalloc(np *
		    sizeof (uint_t), KM_SLEEP);

		/* Allocate a streaming cache sync flag for each index */
		iommu_fast_dvma->sync_flag = kmem_zalloc(np *
		    sizeof (int), KM_SLEEP);

		/* Allocate a physical sync flag for each index */
		iommu_fast_dvma->phys_sync_flag =
		    kmem_zalloc(np * sizeof (uint64_t), KM_SLEEP);

		for (i = 0; i < np; i++)
			iommu_fast_dvma->phys_sync_flag[i] = va_to_pa((caddr_t)
			    &iommu_fast_dvma->sync_flag[i]);

		mp->dmai_mapping = ioaddr;
		mp->dmai_ndvmapages = np;
		iommu_fast_dvma->ops = &iommu_dvma_ops;
		iommu_fast_dvma->softsp = (caddr_t)softsp;
		mp->dmai_nexus_private = (caddr_t)iommu_fast_dvma;
		handlep = (ddi_dma_handle_t *)objp;
		*handlep = (ddi_dma_handle_t)mp;

		DPRINTF(IOMMU_FASTDMA_RESERVE,
		    ("Reserve: mapping object %p base addr %lx size %x\n",
		    (void *)mp, mp->dmai_mapping, mp->dmai_ndvmapages));

		break;
	}

	case DDI_DMA_RELEASE:
	{
		ddi_dma_impl_t *mp = (ddi_dma_impl_t *)handle;
		uint_t np = npages = mp->dmai_ndvmapages;
		ioaddr_t ioaddr = mp->dmai_mapping;
		volatile uint64_t *iotte_ptr;
		struct fast_dvma *iommu_fast_dvma = (struct fast_dvma *)
		    mp->dmai_nexus_private;
		struct sbus_soft_state *softsp = (struct sbus_soft_state *)
		    iommu_fast_dvma->softsp;

		ASSERT(softsp != NULL);

		/* Unload stale mappings and flush stale tlb's */
		iotte_ptr = IOTTE_NDX(ioaddr, softsp->soft_tsb_base_addr);

		while (npages > (uint_t)0) {
			*iotte_ptr = (uint64_t)0;	/* unload tte */
			iommu_tlb_flush(softsp, ioaddr, 1);

			npages--;
			iotte_ptr++;
			ioaddr += IOMMU_PAGESIZE;
		}

		ioaddr = (ioaddr_t)mp->dmai_mapping;
		mutex_enter(&softsp->dma_pool_lock);
		softsp->dma_reserve += np;
		mutex_exit(&softsp->dma_pool_lock);

		if (mp->dmai_rflags & DMP_NOLIMIT)
			vmem_free(softsp->dvma_arena,
			    (void *)(uintptr_t)ioaddr, iommu_ptob(np));
		else
			vmem_xfree(softsp->dvma_arena,
			    (void *)(uintptr_t)ioaddr, iommu_ptob(np));

		kmem_free(mp, sizeof (*mp));
		kmem_free(iommu_fast_dvma->pagecnt, np * sizeof (uint_t));
		kmem_free(iommu_fast_dvma->sync_flag, np * sizeof (int));
		kmem_free(iommu_fast_dvma->phys_sync_flag, np *
		    sizeof (uint64_t));
		kmem_free(iommu_fast_dvma, sizeof (struct fast_dvma));


		DPRINTF(IOMMU_FASTDMA_RESERVE,
		    ("Release: Base addr %x size %x\n", ioaddr, np));
		/*
		 * Now that we've freed some resource,
		 * if there is anybody waiting for it
		 * try and get them going.
		 */
		if (softsp->dvma_call_list_id != 0)
			ddi_run_callback(&softsp->dvma_call_list_id);

		break;
	}

	default:
		DPRINTF(IOMMU_DMAMCTL_DEBUG, ("iommu_dma_mctl: unknown option "
		    "0%x\n", request));

		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
void
iommu_dvma_kaddr_load(ddi_dma_handle_t h, caddr_t a, uint_t len, uint_t index,
    ddi_dma_cookie_t *cp)
{
	uintptr_t addr;
	ioaddr_t ioaddr;
	uint_t offset;
	pfn_t pfn;
	int npages;
	volatile uint64_t *iotte_ptr;
	uint64_t iotte_flag = 0;
	struct as *as = NULL;
	extern struct as kas;
	ddi_dma_impl_t *mp = (ddi_dma_impl_t *)h;
	struct fast_dvma *iommu_fast_dvma =
	    (struct fast_dvma *)mp->dmai_nexus_private;
	struct sbus_soft_state *softsp = (struct sbus_soft_state *)
	    iommu_fast_dvma->softsp;
#if defined(DEBUG) && defined(IO_MEMUSAGE)
	struct io_mem_list *iomemp;
	pfn_t *pfnp;
#endif /* DEBUG && IO_MEMUSAGE */

	ASSERT(softsp != NULL);

	addr = (uintptr_t)a;
	ioaddr = (ioaddr_t)(mp->dmai_mapping + iommu_ptob(index));
	offset = (uint_t)(addr & IOMMU_PAGEOFFSET);
	iommu_fast_dvma->pagecnt[index] = iommu_btopr(len + offset);
	as = &kas;
	addr &= ~IOMMU_PAGEOFFSET;
	npages = iommu_btopr(len + offset);

#if defined(DEBUG) && defined(IO_MEMUSAGE)
	iomemp = kmem_alloc(sizeof (struct io_mem_list), KM_SLEEP);
	iomemp->rdip = mp->dmai_rdip;
	iomemp->ioaddr = ioaddr;
	iomemp->addr = addr;
	iomemp->npages = npages;
	pfnp = iomemp->pfn = kmem_zalloc(sizeof (*pfnp) * (npages + 1),
	    KM_SLEEP);
#endif /* DEBUG && IO_MEMUSAGE */

	cp->dmac_address = ioaddr | offset;
	cp->dmac_size = len;

	iotte_ptr = IOTTE_NDX(ioaddr, softsp->soft_tsb_base_addr);
	/* read/write and streaming io on */
	iotte_flag = IOTTE_VALID | IOTTE_WRITE | IOTTE_CACHE;

	if (mp->dmai_rflags & DDI_DMA_CONSISTENT)
		mp->dmai_rflags |= DMP_NOSYNC;
	else if (!softsp->stream_buf_off)
		iotte_flag |= IOTTE_STREAM;

	DPRINTF(IOMMU_FASTDMA_LOAD, ("kaddr_load: ioaddr %x "
	    "size %x offset %x index %x kaddr %lx\n",
	    ioaddr, len, offset, index, addr));
	ASSERT(npages > 0);
	do {
		pfn = hat_getpfnum(as->a_hat, (caddr_t)addr);
		if (pfn == PFN_INVALID) {
			DPRINTF(IOMMU_FASTDMA_LOAD, ("kaddr_load: invalid pfn "
			    "from hat_getpfnum()\n"));
		}

		iommu_tlb_flush(softsp, ioaddr, 1);

		/* load tte */
		*iotte_ptr = ((uint64_t)pfn << IOMMU_PAGESHIFT) | iotte_flag;

		npages--;
		iotte_ptr++;

		addr += IOMMU_PAGESIZE;
		ioaddr += IOMMU_PAGESIZE;

#if defined(DEBUG) && defined(IO_MEMUSAGE)
		*pfnp = pfn;
		pfnp++;
#endif /* DEBUG && IO_MEMUSAGE */

	} while (npages > 0);

#if defined(DEBUG) && defined(IO_MEMUSAGE)
	mutex_enter(&softsp->iomemlock);
	iomemp->next = softsp->iomem;
	softsp->iomem = iomemp;
	mutex_exit(&softsp->iomemlock);
#endif /* DEBUG && IO_MEMUSAGE */
}

/*ARGSUSED*/
void
iommu_dvma_unload(ddi_dma_handle_t h, uint_t index, uint_t view)
{
	ddi_dma_impl_t *mp = (ddi_dma_impl_t *)h;
	ioaddr_t ioaddr;
	pgcnt_t npages;
	struct fast_dvma *iommu_fast_dvma =
	    (struct fast_dvma *)mp->dmai_nexus_private;
	struct sbus_soft_state *softsp = (struct sbus_soft_state *)
	    iommu_fast_dvma->softsp;
#if defined(DEBUG) && defined(IO_MEMUSAGE)
	struct io_mem_list **prevp, *walk;
#endif /* DEBUG && IO_MEMUSAGE */

	ASSERT(softsp != NULL);

	ioaddr = (ioaddr_t)(mp->dmai_mapping + iommu_ptob(index));
	npages = iommu_fast_dvma->pagecnt[index];

#if defined(DEBUG) && defined(IO_MEMUSAGE)
	mutex_enter(&softsp->iomemlock);
	prevp = &softsp->iomem;
	walk = softsp->iomem;

	while (walk != NULL) {
		if (walk->ioaddr == ioaddr) {
			*prevp = walk->next;
			break;
		}
		prevp = &walk->next;
		walk = walk->next;
	}
	mutex_exit(&softsp->iomemlock);

	kmem_free(walk->pfn, sizeof (pfn_t) * (npages + 1));
	kmem_free(walk, sizeof (struct io_mem_list));
#endif /* DEBUG && IO_MEMUSAGE */

	DPRINTF(IOMMU_FASTDMA_SYNC, ("kaddr_unload: handle %p sync flag "
	    "addr %p sync flag pfn %llx index %x page count %lx\n", (void *)mp,
	    (void *)&iommu_fast_dvma->sync_flag[index],
	    iommu_fast_dvma->phys_sync_flag[index],
	    index, npages));

	if ((mp->dmai_rflags & DMP_NOSYNC) != DMP_NOSYNC) {
		sync_stream_buf(softsp, ioaddr, npages,
		    (int *)&iommu_fast_dvma->sync_flag[index],
		    iommu_fast_dvma->phys_sync_flag[index]);
	}
}

/*ARGSUSED*/
void
iommu_dvma_sync(ddi_dma_handle_t h, uint_t index, uint_t view)
{
	ddi_dma_impl_t *mp = (ddi_dma_impl_t *)h;
	ioaddr_t ioaddr;
	uint_t npages;
	struct fast_dvma *iommu_fast_dvma =
	    (struct fast_dvma *)mp->dmai_nexus_private;
	struct sbus_soft_state *softsp = (struct sbus_soft_state *)
	    iommu_fast_dvma->softsp;

	if ((mp->dmai_rflags & DMP_NOSYNC) == DMP_NOSYNC)
		return;

	ASSERT(softsp != NULL);
	ioaddr = (ioaddr_t)(mp->dmai_mapping + iommu_ptob(index));
	npages = iommu_fast_dvma->pagecnt[index];

	DPRINTF(IOMMU_FASTDMA_SYNC, ("kaddr_sync: handle %p, "
	    "sync flag addr %p, sync flag pfn %llx\n", (void *)mp,
	    (void *)&iommu_fast_dvma->sync_flag[index],
	    iommu_fast_dvma->phys_sync_flag[index]));

	sync_stream_buf(softsp, ioaddr, npages,
	    (int *)&iommu_fast_dvma->sync_flag[index],
	    iommu_fast_dvma->phys_sync_flag[index]);
}
