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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>.  All rights reserved.
 */

/*
 * PCI nexus DVMA and DMA core routines:
 *	dma_map/dma_bind_handle implementation
 *	bypass and peer-to-peer support
 *	fast track DVMA space allocation
 *	runtime DVMA debug
 */
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/async.h>
#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/machsystm.h>	/* lddphys() */
#include <sys/ddi_impldefs.h>
#include <vm/hat.h>
#include <sys/pci/pci_obj.h>

/*LINTLIBRARY*/

static void
pci_sc_pg_inv(dev_info_t *dip, sc_t *sc_p, ddi_dma_impl_t *mp, off_t off,
	size_t len)
{
	dvma_addr_t dvma_addr, pg_off;
	volatile uint64_t *invl_va = sc_p->sc_invl_reg;

	if (!len)
		len = mp->dmai_size;

	pg_off = mp->dmai_offset;			/* start min */
	dvma_addr = MAX(off, pg_off);			/* lo */
	pg_off += mp->dmai_size;			/* end max */
	pg_off = MIN(off + len, pg_off);		/* hi */
	if (dvma_addr >= pg_off) {			/* lo >= hi ? */
		DEBUG4(DBG_SC, dip, "%x+%x out of window [%x,%x)\n",
		    off, len, mp->dmai_offset,
		    mp->dmai_offset + mp->dmai_size);
		return;
	}

	len = pg_off - dvma_addr;			/* sz = hi - lo */
	dvma_addr += mp->dmai_mapping;			/* start addr */
	pg_off = dvma_addr & IOMMU_PAGE_OFFSET;		/* offset in 1st pg */
	len = IOMMU_BTOPR(len + pg_off);		/* # of pages */
	dvma_addr ^= pg_off;

	DEBUG2(DBG_SC, dip, "addr=%x+%x pages: \n", dvma_addr, len);
	for (; len; len--, dvma_addr += IOMMU_PAGE_SIZE) {
		DEBUG1(DBG_SC|DBG_CONT, dip, " %x", dvma_addr);
		*invl_va = (uint64_t)dvma_addr;
	}
	DEBUG0(DBG_SC|DBG_CONT, dip, "\n");
}

static void
pci_dma_sync_flag_wait(ddi_dma_impl_t *mp, sc_t *sc_p, uint32_t onstack)
{
	hrtime_t start_time;
	uint64_t loops = 0;
	uint64_t sync_flag_pa = SYNC_BUF_PA(mp);
	uint64_t sync_reg_pa = sc_p->sc_sync_reg_pa;
	uint8_t stack_buf[128];

	stack_buf[0] = DDI_SUCCESS;

	/* check for handle specific sync flag */
	if (sync_flag_pa)
		goto start;

	sync_flag_pa = sc_p->sc_sync_flag_pa;

	if (onstack) {
		sync_flag_pa = va_to_pa(stack_buf);
		sync_flag_pa += PCI_SYNC_FLAG_SIZE;
		sync_flag_pa >>= PCI_SYNC_FLAG_SZSHIFT;
		sync_flag_pa <<= PCI_SYNC_FLAG_SZSHIFT;
		goto start;
	}
	stack_buf[0] |= PCI_SYNC_FLAG_LOCKED;
	mutex_enter(&sc_p->sc_sync_mutex);
start:
	ASSERT(!(sync_flag_pa & PCI_SYNC_FLAG_SIZE - 1));
	stdphys(sync_flag_pa, 0);	/* reset sync flag to 0 */
					/* membar  #LoadStore|#StoreStore */
	stdphysio(sync_reg_pa, sync_flag_pa);
	start_time = gethrtime();

	for (; gethrtime() - start_time < pci_sync_buf_timeout; loops++)
		if (lddphys(sync_flag_pa))
			goto done;

	if (!lddphys(sync_flag_pa))
		stack_buf[0] |= PCI_SYNC_FLAG_FAILED;
done:
	DEBUG3(DBG_SC|DBG_CONT, 0, "flag wait loops=%lu ticks=%lu status=%x\n",
	    loops, gethrtime() - start_time, stack_buf[0]);

	if (stack_buf[0] & PCI_SYNC_FLAG_LOCKED)
		mutex_exit(&sc_p->sc_sync_mutex);

	if (stack_buf[0] & PCI_SYNC_FLAG_FAILED)
		cmn_err(CE_PANIC, "%p pci dma sync %lx %lx timeout!",
		    mp, sync_flag_pa, loops);
}

/*
 * Cache	RW	Before	During		After
 *
 * STREAMING	read	no/no	pg/no		ctx,pg/no
 * STREAMING	write	no/no	pg/yes		ctx,pg/yes
 * CONSISTENT	read	no/no	yes,no/no	yes,no/no
 * CONSISTENT	write	no/no	yes,yes/yes	yes,yes/yes
 *
 * STREAMING	read	ctx,pg/no
 * STREAMING	write	ctx,pg/yes
 * CONSISTENT	read	yes,no/no
 * CONSISTENT	write	yes,yes/yes
 */
int
pci_dma_sync(dev_info_t *dip, dev_info_t *rdip, ddi_dma_handle_t handle,
	off_t off, size_t len, uint32_t sync_flag)
{
	ddi_dma_impl_t *mp = (ddi_dma_impl_t *)handle;
	int ret = ddi_get_instance(dip);
	pci_t *pci_p = get_pci_soft_state(ret);
	pbm_t *pbm_p = pci_p->pci_pbm_p;
	uint32_t dev_flag = mp->dmai_rflags;
	sc_t *sc_p;

	DEBUG4(DBG_DMA_SYNC, dip, "%s%d flags=%x,%x\n", ddi_driver_name(rdip),
	    ddi_get_instance(rdip), dev_flag, sync_flag);
	DEBUG4(DBG_SC, dip, "dmai_mapping=%x, dmai_sz=%x off=%x len=%x\n",
	    mp->dmai_mapping, mp->dmai_size, off, len);
	DEBUG2(DBG_SC, dip, "mp=%p, ctx=%x\n", mp, MP2CTX(mp));

	if (!(mp->dmai_flags & DMAI_FLAGS_INUSE)) {
		cmn_err(CE_WARN, "Unbound dma handle %p from %s%d", mp,
		    ddi_driver_name(rdip), ddi_get_instance(rdip));
		return (DDI_FAILURE);
	}

	if (mp->dmai_flags & DMAI_FLAGS_NOSYNC)
		return (DDI_SUCCESS);

	if (!(dev_flag & DDI_DMA_CONSISTENT))
		goto streaming;

	if (sync_flag & PCI_DMA_SYNC_EXT) {
		if (sync_flag & (PCI_DMA_SYNC_BEFORE | PCI_DMA_SYNC_POST) ||
		    !(sync_flag & PCI_DMA_SYNC_WRITE))
			return (DDI_SUCCESS);
	} else {
		if (!(dev_flag & DDI_DMA_READ) ||
		    ((sync_flag & PCI_DMA_SYNC_DDI_FLAGS) ==
		    DDI_DMA_SYNC_FORDEV))
			return (DDI_SUCCESS);
	}

	pci_pbm_dma_sync(pbm_p, pbm_p->pbm_sync_ino);
	return (DDI_SUCCESS);

streaming:
	ASSERT(pci_stream_buf_exists && (pci_stream_buf_enable & 1 << ret));
	sc_p = pci_p->pci_sc_p;
	ret = DDI_FAILURE;

	if (sync_flag & PCI_DMA_SYNC_EXT)
		goto ext;

	if (mp->dmai_flags & DMAI_FLAGS_CONTEXT && pci_sc_use_contexts)
		ret = pci_sc_ctx_inv(dip, sc_p, mp);
	if (ret)
		pci_sc_pg_inv(dip, sc_p, mp, off, len);

	if ((dev_flag & DDI_DMA_READ) &&
	    ((sync_flag & PCI_DMA_SYNC_DDI_FLAGS) != DDI_DMA_SYNC_FORDEV))
		goto wait;

	return (DDI_SUCCESS);
ext:
	if (sync_flag & PCI_DMA_SYNC_BEFORE)
		return (DDI_SUCCESS);
	if (sync_flag & PCI_DMA_SYNC_BAR)
		goto wait_check;
	if (sync_flag & PCI_DMA_SYNC_AFTER &&
	    mp->dmai_flags & DMAI_FLAGS_CONTEXT && pci_sc_use_contexts)
		ret = pci_sc_ctx_inv(dip, sc_p, mp);
	if (ret)
		pci_sc_pg_inv(dip, sc_p, mp, off, len);
wait_check:
	if (sync_flag & PCI_DMA_SYNC_POST || !(sync_flag & PCI_DMA_SYNC_WRITE))
		return (DDI_SUCCESS);
wait:
	pci_dma_sync_flag_wait(mp, sc_p, sync_flag & PCI_DMA_SYNC_PRIVATE);
	return (DDI_SUCCESS);
}

int
pci_dma_handle_clean(dev_info_t *rdip, ddi_dma_handle_t h)
{
	ddi_dma_impl_t *mp = (ddi_dma_impl_t *)h;
	if ((mp->dmai_flags & DMAI_FLAGS_INUSE) == 0)
		return (DDI_FAILURE);
	mp->dmai_rflags |= DMP_NOSYNC;
	mp->dmai_flags |= DMAI_FLAGS_NOSYNC;
	return (DDI_SUCCESS);
}

/*
 * pci_dma_allocmp - Allocate a pci dma implementation structure
 *
 * An extra ddi_dma_attr structure is bundled with the usual ddi_dma_impl
 * to hold unmodified device limits. The ddi_dma_attr inside the
 * ddi_dma_impl structure is augumented with system limits to enhance
 * DVMA performance at runtime. The unaugumented device limits saved
 * right after (accessed through the DEV_ATTR macro) is used
 * strictly for peer-to-peer transfers which do not obey system limits.
 *
 * return: DDI_SUCCESS DDI_DMA_NORESOURCES
 */
ddi_dma_impl_t *
pci_dma_allocmp(dev_info_t *dip, dev_info_t *rdip, int (*waitfp)(caddr_t),
	caddr_t arg)
{
	ddi_dma_impl_t *mp;
	int sleep = (waitfp == DDI_DMA_SLEEP) ? KM_SLEEP : KM_NOSLEEP;

	/* Caution: we don't use zalloc to enhance performance! */
	if ((mp = kmem_alloc(sizeof (pci_dma_hdl_t), sleep)) == 0) {
		DEBUG0(DBG_DMA_MAP, dip, "can't alloc dma_handle\n");
		if (waitfp != DDI_DMA_DONTWAIT) {
			DEBUG0(DBG_DMA_MAP, dip, "alloc_mp kmem cb\n");
			ddi_set_callback(waitfp, arg, &pci_kmem_clid);
		}
		return (mp);
	}

	mp->dmai_rdip = rdip;
	mp->dmai_flags = 0;
	mp->dmai_pfnlst = NULL;
	mp->dmai_winlst = NULL;
	mp->dmai_ncookies = 0;
	mp->dmai_curcookie = 0;

	/*
	 * kmem_alloc debug: the following fields are not zero-ed
	 * mp->dmai_mapping = 0;
	 * mp->dmai_size = 0;
	 * mp->dmai_offset = 0;
	 * mp->dmai_minxfer = 0;
	 * mp->dmai_burstsizes = 0;
	 * mp->dmai_ndvmapages = 0;
	 * mp->dmai_pool/roffset = 0;
	 * mp->dmai_rflags = 0;
	 * mp->dmai_inuse/flags
	 * mp->dmai_nwin = 0;
	 * mp->dmai_winsize = 0;
	 * mp->dmai_nexus_private/tte = 0;
	 * mp->dmai_iopte/pfnlst
	 * mp->dmai_sbi/pfn0 = 0;
	 * mp->dmai_minfo/winlst/fdvma
	 * mp->dmai_rdip
	 * bzero(&mp->dmai_object, sizeof (ddi_dma_obj_t));
	 * mp->dmai_cookie = 0;
	 */

	mp->dmai_attr.dma_attr_version = (uint_t)DMA_ATTR_VERSION;
	mp->dmai_attr.dma_attr_flags = (uint_t)0;
	mp->dmai_fault = 0;
	mp->dmai_fault_check = NULL;
	mp->dmai_fault_notify = NULL;

	mp->dmai_error.err_ena = 0;
	mp->dmai_error.err_status = DDI_FM_OK;
	mp->dmai_error.err_expected = DDI_FM_ERR_UNEXPECTED;
	mp->dmai_error.err_ontrap = NULL;
	mp->dmai_error.err_fep = NULL;
	mp->dmai_error.err_cf = NULL;
	ndi_fmc_insert(rdip, DMA_HANDLE, mp, NULL);

	SYNC_BUF_PA(mp) = 0ull;
	return (mp);
}

void
pci_dma_freemp(ddi_dma_impl_t *mp)
{
	ndi_fmc_remove(mp->dmai_rdip, DMA_HANDLE, mp);
	if (mp->dmai_ndvmapages > 1)
		pci_dma_freepfn(mp);
	if (mp->dmai_winlst)
		pci_dma_freewin(mp);
	kmem_free(mp, sizeof (pci_dma_hdl_t));
}

void
pci_dma_freepfn(ddi_dma_impl_t *mp)
{
	void *addr = mp->dmai_pfnlst;
	ASSERT(!PCI_DMA_CANRELOC(mp));
	if (addr) {
		size_t npages = mp->dmai_ndvmapages;
		if (npages > 1)
			kmem_free(addr, npages * sizeof (iopfn_t));
		mp->dmai_pfnlst = NULL;
	}
	mp->dmai_ndvmapages = 0;
}

/*
 * pci_dma_lmts2hdl - alloate a ddi_dma_impl_t, validate practical limits
 *			and convert dmareq->dmar_limits to mp->dmai_attr
 *
 * ddi_dma_impl_t member modified     input
 * ------------------------------------------------------------------------
 * mp->dmai_minxfer		    - dev
 * mp->dmai_burstsizes		    - dev
 * mp->dmai_flags		    - no limit? peer-to-peer only?
 *
 * ddi_dma_attr member modified       input
 * ------------------------------------------------------------------------
 * mp->dmai_attr.dma_attr_addr_lo   - dev lo, sys lo
 * mp->dmai_attr.dma_attr_addr_hi   - dev hi, sys hi
 * mp->dmai_attr.dma_attr_count_max - dev count max, dev/sys lo/hi delta
 * mp->dmai_attr.dma_attr_seg       - 0         (no nocross   restriction)
 * mp->dmai_attr.dma_attr_align     - 1		(no alignment restriction)
 *
 * The dlim_dmaspeed member of dmareq->dmar_limits is ignored.
 */
ddi_dma_impl_t *
pci_dma_lmts2hdl(dev_info_t *dip, dev_info_t *rdip, iommu_t *iommu_p,
	ddi_dma_req_t *dmareq)
{
	ddi_dma_impl_t *mp;
	ddi_dma_attr_t *attr_p;
	uint64_t syslo		= iommu_p->iommu_dvma_base;
	uint64_t syshi		= iommu_p->iommu_dvma_end;
	uint64_t fasthi		= iommu_p->iommu_dvma_fast_end;
	ddi_dma_lim_t *lim_p	= dmareq->dmar_limits;
	uint32_t count_max	= lim_p->dlim_cntr_max;
	uint64_t lo		= lim_p->dlim_addr_lo;
	uint64_t hi		= lim_p->dlim_addr_hi;
	if (hi <= lo) {
		DEBUG0(DBG_DMA_MAP, dip, "Bad limits\n");
		return ((ddi_dma_impl_t *)DDI_DMA_NOMAPPING);
	}
	if (!count_max)
		count_max--;

	if (!(mp = pci_dma_allocmp(dip, rdip, dmareq->dmar_fp,
	    dmareq->dmar_arg)))
		return (NULL);

	/* store original dev input at the 2nd ddi_dma_attr */
	attr_p = DEV_ATTR(mp);
	SET_DMAATTR(attr_p, lo, hi, -1, count_max);
	SET_DMAALIGN(attr_p, 1);

	lo = MAX(lo, syslo);
	hi = MIN(hi, syshi);
	if (hi <= lo)
		mp->dmai_flags |= DMAI_FLAGS_PEER_ONLY;
	count_max = MIN(count_max, hi - lo);

	if (DEV_NOSYSLIMIT(lo, hi, syslo, fasthi, 1))
		mp->dmai_flags |= DMAI_FLAGS_NOFASTLIMIT |
		    DMAI_FLAGS_NOSYSLIMIT;
	else {
		if (DEV_NOFASTLIMIT(lo, hi, syslo, syshi, 1))
			mp->dmai_flags |= DMAI_FLAGS_NOFASTLIMIT;
	}
	if (PCI_DMA_NOCTX(rdip))
		mp->dmai_flags |= DMAI_FLAGS_NOCTX;

	/* store augumented dev input to mp->dmai_attr */
	mp->dmai_minxfer	= lim_p->dlim_minxfer;
	mp->dmai_burstsizes	= lim_p->dlim_burstsizes;
	attr_p = &mp->dmai_attr;
	SET_DMAATTR(attr_p, lo, hi, -1, count_max);
	SET_DMAALIGN(attr_p, 1);
	return (mp);
}

/*
 * pci_dma_attr2hdl
 *
 * This routine is called from the alloc handle entry point to sanity check the
 * dma attribute structure.
 *
 * use by: pci_dma_allochdl()
 *
 * return value:
 *
 *	DDI_SUCCESS		- on success
 *	DDI_DMA_BADATTR		- attribute has invalid version number
 *				  or address limits exclude dvma space
 */
int
pci_dma_attr2hdl(pci_t *pci_p, ddi_dma_impl_t *mp)
{
	iommu_t *iommu_p = pci_p->pci_iommu_p;
	uint64_t syslo, syshi;
	ddi_dma_attr_t *attrp		= DEV_ATTR(mp);
	uint64_t hi		= attrp->dma_attr_addr_hi;
	uint64_t lo		= attrp->dma_attr_addr_lo;
	uint64_t align		= attrp->dma_attr_align;
	uint64_t nocross	= attrp->dma_attr_seg;
	uint64_t count_max	= attrp->dma_attr_count_max;

	DEBUG3(DBG_DMA_ALLOCH, pci_p->pci_dip, "attrp=%p cntr_max=%x.%08x\n",
	    attrp, HI32(count_max), LO32(count_max));
	DEBUG4(DBG_DMA_ALLOCH, pci_p->pci_dip, "hi=%x.%08x lo=%x.%08x\n",
	    HI32(hi), LO32(hi), HI32(lo), LO32(lo));
	DEBUG4(DBG_DMA_ALLOCH, pci_p->pci_dip, "seg=%x.%08x align=%x.%08x\n",
	    HI32(nocross), LO32(nocross), HI32(align), LO32(align));

	if (!nocross)
		nocross--;
	if (attrp->dma_attr_flags & DDI_DMA_FORCE_PHYSICAL) { /* BYPASS */

		DEBUG0(DBG_DMA_ALLOCH, pci_p->pci_dip, "bypass mode\n");
		/* if tomatillo ver <= 2.3 don't allow bypass */
		if (tomatillo_disallow_bypass)
			return (DDI_DMA_BADATTR);

		mp->dmai_flags |= DMAI_FLAGS_BYPASSREQ;
		if (nocross != UINT64_MAX)
			return (DDI_DMA_BADATTR);
		if (align && (align > IOMMU_PAGE_SIZE))
			return (DDI_DMA_BADATTR);
		align = 1; /* align on 1 page boundary */
		syslo = iommu_p->iommu_dma_bypass_base;
		syshi = iommu_p->iommu_dma_bypass_end;

	} else { /* IOMMU_XLATE or PEER_TO_PEER */
		align = MAX(align, IOMMU_PAGE_SIZE) - 1;
		if ((align & nocross) != align) {
			dev_info_t *rdip = mp->dmai_rdip;
			cmn_err(CE_WARN, "%s%d dma_attr_seg not aligned",
			    NAMEINST(rdip));
			return (DDI_DMA_BADATTR);
		}
		align = IOMMU_BTOP(align + 1);
		syslo = iommu_p->iommu_dvma_base;
		syshi = iommu_p->iommu_dvma_end;
	}
	if (hi <= lo) {
		dev_info_t *rdip = mp->dmai_rdip;
		cmn_err(CE_WARN, "%s%d limits out of range", NAMEINST(rdip));
		return (DDI_DMA_BADATTR);
	}
	lo = MAX(lo, syslo);
	hi = MIN(hi, syshi);
	if (!count_max)
		count_max--;

	DEBUG4(DBG_DMA_ALLOCH, pci_p->pci_dip, "hi=%x.%08x, lo=%x.%08x\n",
	    HI32(hi), LO32(hi), HI32(lo), LO32(lo));
	if (hi <= lo) { /* peer transfers cannot have alignment & nocross */
		dev_info_t *rdip = mp->dmai_rdip;
		cmn_err(CE_WARN, "%s%d peer only dev %p", NAMEINST(rdip), mp);
		if ((nocross < UINT32_MAX) || (align > 1)) {
			cmn_err(CE_WARN, "%s%d peer only device bad attr",
			    NAMEINST(rdip));
			return (DDI_DMA_BADATTR);
		}
		mp->dmai_flags |= DMAI_FLAGS_PEER_ONLY;
	} else /* set practical counter_max value */
		count_max = MIN(count_max, hi - lo);

	if (DEV_NOSYSLIMIT(lo, hi, syslo, syshi, align))
		mp->dmai_flags |= DMAI_FLAGS_NOSYSLIMIT |
		    DMAI_FLAGS_NOFASTLIMIT;
	else {
		syshi = iommu_p->iommu_dvma_fast_end;
		if (DEV_NOFASTLIMIT(lo, hi, syslo, syshi, align))
			mp->dmai_flags |= DMAI_FLAGS_NOFASTLIMIT;
	}
	if (PCI_DMA_NOCTX(mp->dmai_rdip))
		mp->dmai_flags |= DMAI_FLAGS_NOCTX;

	mp->dmai_minxfer	= attrp->dma_attr_minxfer;
	mp->dmai_burstsizes	= attrp->dma_attr_burstsizes;
	attrp = &mp->dmai_attr;
	SET_DMAATTR(attrp, lo, hi, nocross, count_max);
	return (DDI_SUCCESS);
}

/*
 * set up consistent dma flags according to hardware capability
 */
uint32_t
pci_dma_consist_check(uint32_t req_flags, pbm_t *pbm_p)
{
	if (!pci_stream_buf_enable || !pci_stream_buf_exists)
		req_flags |= DDI_DMA_CONSISTENT;
	if (req_flags & DDI_DMA_CONSISTENT && !pbm_p->pbm_sync_reg_pa)
		req_flags |= DMP_NOSYNC;
	return (req_flags);
}

#define	TGT_PFN_INBETWEEN(pfn, bgn, end) ((pfn >= bgn) && (pfn <= end))

/*
 * pci_dma_type - determine which of the three types DMA (peer-to-peer,
 *		iommu bypass, or iommu translate) we are asked to do.
 *		Also checks pfn0 and rejects any non-peer-to-peer
 *		requests for peer-only devices.
 *
 *	return values:
 *		DDI_DMA_NOMAPPING - can't get valid pfn0, or bad dma type
 *		DDI_SUCCESS
 *
 *	dma handle members affected (set on exit):
 *	mp->dmai_object		- dmareq->dmar_object
 *	mp->dmai_rflags		- consistent?, nosync?, dmareq->dmar_flags
 *	mp->dmai_flags   	- DMA type
 *	mp->dmai_pfn0   	- 1st page pfn (if va/size pair and not shadow)
 *	mp->dmai_roffset 	- initialized to starting IOMMU page offset
 *	mp->dmai_ndvmapages	- # of total IOMMU pages of entire object
 *	mp->pdh_sync_buf_pa	- dma sync buffer PA is DMA flow is supported
 */
int
pci_dma_type(pci_t *pci_p, ddi_dma_req_t *dmareq, ddi_dma_impl_t *mp)
{
	dev_info_t *dip = pci_p->pci_dip;
	ddi_dma_obj_t *dobj_p = &dmareq->dmar_object;
	pbm_t *pbm_p = pci_p->pci_pbm_p;
	page_t **pplist;
	struct as *as_p;
	uint32_t offset;
	caddr_t vaddr;
	pfn_t pfn0;

	mp->dmai_rflags = pci_dma_consist_check(dmareq->dmar_flags, pbm_p);
	mp->dmai_flags |= mp->dmai_rflags & DMP_NOSYNC ? DMAI_FLAGS_NOSYNC : 0;

	switch (dobj_p->dmao_type) {
	case DMA_OTYP_BUFVADDR:
	case DMA_OTYP_VADDR: {
		vaddr = dobj_p->dmao_obj.virt_obj.v_addr;
		pplist = dobj_p->dmao_obj.virt_obj.v_priv;
		as_p = dobj_p->dmao_obj.virt_obj.v_as;
		if (as_p == NULL)
			as_p = &kas;

		DEBUG2(DBG_DMA_MAP, dip, "vaddr=%p pplist=%p\n", vaddr, pplist);
		offset = (ulong_t)vaddr & IOMMU_PAGE_OFFSET;

		if (pplist) {				/* shadow list */
			mp->dmai_flags |= DMAI_FLAGS_PGPFN;
			ASSERT(PAGE_LOCKED(*pplist));
			pfn0 = page_pptonum(*pplist);
		} else if (pci_dvma_remap_enabled && as_p == &kas &&
		    dobj_p->dmao_type != DMA_OTYP_BUFVADDR) {
			int (*waitfp)(caddr_t) = dmareq->dmar_fp;
			uint_t flags = ((waitfp == DDI_DMA_SLEEP)?
			    HAC_SLEEP : HAC_NOSLEEP) | HAC_PAGELOCK;
			int ret;

			ret = hat_add_callback(pci_dvma_cbid, vaddr,
			    IOMMU_PAGE_SIZE - offset, flags, mp, &pfn0,
			    MP_HAT_CB_COOKIE_PTR(mp, 0));

			if (pfn0 == PFN_INVALID && ret == ENOMEM) {
				ASSERT(waitfp != DDI_DMA_SLEEP);
				if (waitfp != DDI_DMA_DONTWAIT) {
					ddi_set_callback(waitfp,
					    dmareq->dmar_arg,
					    &pci_kmem_clid);
					return (DDI_DMA_NORESOURCES);
					}
			}
			mp->dmai_flags |= DMAI_FLAGS_RELOC;
		} else
			pfn0 = hat_getpfnum(as_p->a_hat, vaddr);
		}
		break;

	case DMA_OTYP_PAGES:
		offset = dobj_p->dmao_obj.pp_obj.pp_offset;
		mp->dmai_flags |= DMAI_FLAGS_PGPFN;
		pfn0 = page_pptonum(dobj_p->dmao_obj.pp_obj.pp_pp);
		ASSERT(PAGE_LOCKED(dobj_p->dmao_obj.pp_obj.pp_pp));
		break;

	case DMA_OTYP_PADDR:
	default:
		cmn_err(CE_WARN, "%s%d requested unsupported dma type %x",
		    NAMEINST(mp->dmai_rdip), dobj_p->dmao_type);
		return (DDI_DMA_NOMAPPING);
	}
	if (pfn0 == PFN_INVALID) {
		cmn_err(CE_WARN, "%s%d: invalid pfn0 for DMA object %p",
		    NAMEINST(dip), dobj_p);
		return (DDI_DMA_NOMAPPING);
	}
	if (TGT_PFN_INBETWEEN(pfn0, pbm_p->pbm_base_pfn, pbm_p->pbm_last_pfn)) {
		mp->dmai_flags |= DMAI_FLAGS_PEER_TO_PEER;
		goto done;	/* leave bypass and dvma flag as 0 */
	}
	if (PCI_DMA_ISPEERONLY(mp)) {
		dev_info_t *rdip = mp->dmai_rdip;
		cmn_err(CE_WARN, "Bad peer-to-peer req %s%d", NAMEINST(rdip));
		return (DDI_DMA_NOMAPPING);
	}
	mp->dmai_flags |= (mp->dmai_flags & DMAI_FLAGS_BYPASSREQ) ?
	    DMAI_FLAGS_BYPASS : DMAI_FLAGS_DVMA;
done:
	mp->dmai_object	 = *dobj_p;			/* whole object    */
	mp->dmai_pfn0	 = (void *)pfn0;		/* cache pfn0	   */
	mp->dmai_roffset = offset;			/* win0 pg0 offset */
	mp->dmai_ndvmapages = IOMMU_BTOPR(offset + mp->dmai_object.dmao_size);

	return (DDI_SUCCESS);
}

/*
 * pci_dma_pgpfn - set up pfnlst array according to pages
 *	VA/size pair: <shadow IO, bypass, peer-to-peer>, or OTYP_PAGES
 */
/*ARGSUSED*/
static int
pci_dma_pgpfn(pci_t *pci_p, ddi_dma_impl_t *mp, uint_t npages)
{
	int i;
#ifdef DEBUG
	dev_info_t *dip = pci_p->pci_dip;
#endif
	switch (mp->dmai_object.dmao_type) {
	case DMA_OTYP_BUFVADDR:
	case DMA_OTYP_VADDR: {
		page_t **pplist = mp->dmai_object.dmao_obj.virt_obj.v_priv;
		DEBUG2(DBG_DMA_MAP, dip, "shadow pplist=%p, %x pages, pfns=",
		    pplist, npages);
		for (i = 1; i < npages; i++) {
			iopfn_t pfn = page_pptonum(pplist[i]);
			ASSERT(PAGE_LOCKED(pplist[i]));
			PCI_SET_MP_PFN1(mp, i, pfn);
			DEBUG1(DBG_DMA_MAP|DBG_CONT, dip, "%x ", pfn);
		}
		DEBUG0(DBG_DMA_MAP|DBG_CONT, dip, "\n");
		}
		break;

	case DMA_OTYP_PAGES: {
		page_t *pp = mp->dmai_object.dmao_obj.pp_obj.pp_pp->p_next;
		DEBUG1(DBG_DMA_MAP, dip, "pp=%p pfns=", pp);
		for (i = 1; i < npages; i++, pp = pp->p_next) {
			iopfn_t pfn = page_pptonum(pp);
			ASSERT(PAGE_LOCKED(pp));
			PCI_SET_MP_PFN1(mp, i, pfn);
			DEBUG1(DBG_DMA_MAP|DBG_CONT, dip, "%x ", pfn);
		}
		DEBUG0(DBG_DMA_MAP|DBG_CONT, dip, "\n");
		}
		break;

	default:	/* check is already done by pci_dma_type */
		ASSERT(0);
		break;
	}
	return (DDI_SUCCESS);
}

/*
 * pci_dma_vapfn - set up pfnlst array according to VA
 *	VA/size pair: <normal, bypass, peer-to-peer>
 *	pfn0 is skipped as it is already done.
 *	In this case, the cached pfn0 is used to fill pfnlst[0]
 */
static int
pci_dma_vapfn(pci_t *pci_p, ddi_dma_req_t *dmareq, ddi_dma_impl_t *mp,
	uint_t npages)
{
	dev_info_t *dip = pci_p->pci_dip;
	int i;
	caddr_t vaddr = (caddr_t)mp->dmai_object.dmao_obj.virt_obj.v_as;
	struct hat *hat_p = vaddr ? ((struct as *)vaddr)->a_hat : kas.a_hat;
	caddr_t sva;
	int needcb = 0;

	sva = (caddr_t)(((uintptr_t)mp->dmai_object.dmao_obj.virt_obj.v_addr +
	    IOMMU_PAGE_SIZE) & IOMMU_PAGE_MASK);

	if (pci_dvma_remap_enabled && hat_p == kas.a_hat &&
	    mp->dmai_object.dmao_type != DMA_OTYP_BUFVADDR)
		needcb = 1;

	for (vaddr = sva, i = 1; i < npages; i++, vaddr += IOMMU_PAGE_SIZE) {
		pfn_t pfn;

		if (needcb) {
			int (*waitfp)(caddr_t) = dmareq->dmar_fp;
			uint_t flags = ((waitfp == DDI_DMA_SLEEP)?
			    HAC_SLEEP : HAC_NOSLEEP) | HAC_PAGELOCK;
			int ret;

			ret = hat_add_callback(pci_dvma_cbid, vaddr,
			    IOMMU_PAGE_SIZE, flags, mp, &pfn,
			    MP_HAT_CB_COOKIE_PTR(mp, i));

			if (pfn == PFN_INVALID && ret == ENOMEM) {
				ASSERT(waitfp != DDI_DMA_SLEEP);
				if (waitfp != DDI_DMA_DONTWAIT)
					ddi_set_callback(waitfp,
					    dmareq->dmar_arg, &pci_kmem_clid);
				return (DDI_DMA_NORESOURCES);
			}
		} else
			pfn = hat_getpfnum(hat_p, vaddr);
		if (pfn == PFN_INVALID)
			goto err_badpfn;
		PCI_SET_MP_PFN1(mp, i, (iopfn_t)pfn);
		DEBUG3(DBG_DMA_MAP, dip, "pci_dma_vapfn: mp=%p pfnlst[%x]=%x\n",
		    mp, i, (iopfn_t)pfn);
	}
	return (DDI_SUCCESS);
err_badpfn:
	cmn_err(CE_WARN, "%s%d: bad page frame vaddr=%p", NAMEINST(dip), vaddr);
	return (DDI_DMA_NOMAPPING);
}

/*
 * pci_dma_pfn - Fills pfn list for all pages being DMA-ed.
 *
 * dependencies:
 *	mp->dmai_ndvmapages	- set to total # of dma pages
 *
 * return value:
 *	DDI_SUCCESS
 *	DDI_DMA_NOMAPPING
 */
int
pci_dma_pfn(pci_t *pci_p, ddi_dma_req_t *dmareq, ddi_dma_impl_t *mp)
{
	uint32_t npages = mp->dmai_ndvmapages;
	int (*waitfp)(caddr_t) = dmareq->dmar_fp;
	int i, ret, peer = PCI_DMA_ISPTP(mp);

	pbm_t *pbm_p = pci_p->pci_pbm_p;
	iopfn_t pfn_base = pbm_p->pbm_base_pfn;
	iopfn_t pfn_last = pbm_p->pbm_last_pfn;
	iopfn_t pfn_adj = peer ? pfn_base : 0;

	DEBUG2(DBG_DMA_MAP, pci_p->pci_dip, "pci_dma_pfn: mp=%p pfn0=%x\n",
	    mp, MP_PFN0(mp) - pfn_adj);
	/* 1 page: no array alloc/fill, no mixed mode check */
	if (npages == 1) {
		PCI_SET_MP_PFN(mp, 0, MP_PFN0(mp) - pfn_adj);
		return (DDI_SUCCESS);
	}
	/* allocate pfn array */
	if (!(mp->dmai_pfnlst = kmem_alloc(npages * sizeof (iopfn_t),
	    waitfp == DDI_DMA_SLEEP ? KM_SLEEP : KM_NOSLEEP))) {
		if (waitfp != DDI_DMA_DONTWAIT)
			ddi_set_callback(waitfp, dmareq->dmar_arg,
			    &pci_kmem_clid);
		return (DDI_DMA_NORESOURCES);
	}
	/* fill pfn array */
	PCI_SET_MP_PFN(mp, 0, MP_PFN0(mp) - pfn_adj);	/* pfnlst[0] */
	if ((ret = PCI_DMA_ISPGPFN(mp) ? pci_dma_pgpfn(pci_p, mp, npages) :
	    pci_dma_vapfn(pci_p, dmareq, mp, npages)) != DDI_SUCCESS)
		goto err;

	/* skip pfn0, check mixed mode and adjust peer to peer pfn */
	for (i = 1; i < npages; i++) {
		iopfn_t pfn = PCI_GET_MP_PFN1(mp, i);
		if (peer ^ TGT_PFN_INBETWEEN(pfn, pfn_base, pfn_last)) {
			cmn_err(CE_WARN, "%s%d mixed mode DMA %lx %lx",
			    NAMEINST(mp->dmai_rdip), MP_PFN0(mp), pfn);
			ret = DDI_DMA_NOMAPPING;	/* mixed mode */
			goto err;
		}
		DEBUG3(DBG_DMA_MAP, pci_p->pci_dip,
		    "pci_dma_pfn: pfnlst[%x]=%x-%x\n", i, pfn, pfn_adj);
		if (pfn_adj)
			PCI_SET_MP_PFN1(mp, i, pfn - pfn_adj);
	}
	return (DDI_SUCCESS);
err:
	pci_dvma_unregister_callbacks(pci_p, mp);
	pci_dma_freepfn(mp);
	return (ret);
}

/*
 * pci_dvma_win() - trim requested DVMA size down to window size
 *	The 1st window starts from offset and ends at page-aligned boundary.
 *	From the 2nd window on, each window starts and ends at page-aligned
 *	boundary except the last window ends at wherever requested.
 *
 *	accesses the following mp-> members:
 *	mp->dmai_attr.dma_attr_count_max
 *	mp->dmai_attr.dma_attr_seg
 *	mp->dmai_roffset   - start offset of 1st window
 *	mp->dmai_rflags (redzone)
 *	mp->dmai_ndvmapages (for 1 page fast path)
 *
 *	sets the following mp-> members:
 *	mp->dmai_size	   - xfer size, != winsize if 1st/last win  (not fixed)
 *	mp->dmai_winsize   - window size (no redzone), n * page size    (fixed)
 *	mp->dmai_nwin	   - # of DMA windows of entire object		(fixed)
 *	mp->dmai_rflags	   - remove partial flag if nwin == 1		(fixed)
 *	mp->dmai_winlst	   - NULL, window objects not used for DVMA	(fixed)
 *
 *	fixed - not changed across different DMA windows
 */
/*ARGSUSED*/
int
pci_dvma_win(pci_t *pci_p, ddi_dma_req_t *dmareq, ddi_dma_impl_t *mp)
{
	uint32_t redzone_sz	= HAS_REDZONE(mp) ? IOMMU_PAGE_SIZE : 0;
	size_t obj_sz	= mp->dmai_object.dmao_size;
	size_t xfer_sz;
	ulong_t pg_off;

	if ((mp->dmai_ndvmapages == 1) && !redzone_sz) {
		mp->dmai_rflags &= ~DDI_DMA_PARTIAL;
		mp->dmai_size = obj_sz;
		mp->dmai_winsize = IOMMU_PAGE_SIZE;
		mp->dmai_nwin = 1;
		goto done;
	}

	pg_off	= mp->dmai_roffset;
	xfer_sz	= obj_sz + redzone_sz;

	/* include redzone in nocross check */
	{
		uint64_t nocross = mp->dmai_attr.dma_attr_seg;
		if (xfer_sz + pg_off - 1 > nocross)
			xfer_sz = nocross - pg_off + 1;
		if (redzone_sz && (xfer_sz <= redzone_sz)) {
			DEBUG5(DBG_DMA_MAP, pci_p->pci_dip,
			    "nocross too small %lx(%lx)+%lx+%x < %" PRIx64 "\n",
			    xfer_sz, obj_sz, pg_off, redzone_sz, nocross);
			return (DDI_DMA_TOOBIG);
		}
	}
	xfer_sz -= redzone_sz;	/* restore transfer size  */
	/* check counter max */
	{
		uint32_t count_max = mp->dmai_attr.dma_attr_count_max;
		if (xfer_sz - 1 > count_max)
			xfer_sz = count_max + 1;
	}
	if (xfer_sz >= obj_sz) {
		mp->dmai_rflags &= ~DDI_DMA_PARTIAL;
		mp->dmai_size = xfer_sz;
		mp->dmai_winsize = P2ROUNDUP(xfer_sz + pg_off, IOMMU_PAGE_SIZE);
		mp->dmai_nwin = 1;
		goto done;
	}
	if (!(dmareq->dmar_flags & DDI_DMA_PARTIAL)) {
		DEBUG4(DBG_DMA_MAP, pci_p->pci_dip,
		    "too big: %lx+%lx+%x > %lx\n",
		    obj_sz, pg_off, redzone_sz, xfer_sz);
		return (DDI_DMA_TOOBIG);
	}

	xfer_sz = IOMMU_PTOB(IOMMU_BTOP(xfer_sz + pg_off)); /* page align */
	mp->dmai_size = xfer_sz - pg_off;	/* 1st window xferrable size */
	mp->dmai_winsize = xfer_sz;		/* redzone not in winsize */
	mp->dmai_nwin = (obj_sz + pg_off + xfer_sz - 1) / xfer_sz;
done:
	mp->dmai_winlst = NULL;
	dump_dma_handle(DBG_DMA_MAP, pci_p->pci_dip, mp);
	return (DDI_SUCCESS);
}

/*
 * fast track cache entry to iommu context, inserts 3 0 bits between
 * upper 6-bits and lower 3-bits of the 9-bit cache entry
 */
#define	IOMMU_FCE_TO_CTX(i)	(((i) << 3) | ((i) & 0x7) | 0x38)

/*
 * pci_dvma_map_fast - attempts to map fast trackable DVMA
 */
int
pci_dvma_map_fast(iommu_t *iommu_p, ddi_dma_impl_t *mp)
{
	uint_t clustsz = pci_dvma_page_cache_clustsz;
	uint_t entries = pci_dvma_page_cache_entries;
	uint64_t *tte_addr;
	uint64_t tte = GET_TTE_TEMPLATE(mp);
	int i = iommu_p->iommu_dvma_addr_scan_start;
	uint8_t *lock_addr = iommu_p->iommu_dvma_cache_locks + i;
	iopfn_t *pfn_addr;
	dvma_addr_t dvma_pg;
	size_t npages = IOMMU_BTOP(mp->dmai_winsize);
#ifdef DEBUG
	dev_info_t *dip = mp->dmai_rdip;
#endif
	extern uint8_t ldstub(uint8_t *);
	ASSERT(IOMMU_PTOB(npages) == mp->dmai_winsize);
	ASSERT(npages + HAS_REDZONE(mp) <= clustsz);

	for (; i < entries && ldstub(lock_addr); i++, lock_addr++)
		;
	if (i >= entries) {
		lock_addr = iommu_p->iommu_dvma_cache_locks;
		i = 0;
		for (; i < entries && ldstub(lock_addr); i++, lock_addr++)
			;
		if (i >= entries) {
#ifdef PCI_DMA_PROF
			pci_dvmaft_exhaust++;
#endif
			return (DDI_DMA_NORESOURCES);
		}
	}
	iommu_p->iommu_dvma_addr_scan_start = (i + 1) & (entries - 1);
	if (PCI_DMA_USECTX(mp)) {
		dvma_context_t ctx = IOMMU_FCE_TO_CTX(i);
		tte |= IOMMU_CTX2TTE(ctx);
		mp->dmai_flags |= DMAI_FLAGS_CONTEXT;
		DEBUG1(DBG_DMA_MAP, dip, "fast: ctx=0x%x\n", ctx);
	}
	i *= clustsz;
	tte_addr = iommu_p->iommu_tsb_vaddr + i;
	dvma_pg = iommu_p->dvma_base_pg + i;
#ifdef DEBUG
	for (i = 0; i < clustsz; i++)
		ASSERT(TTE_IS_INVALID(tte_addr[i]));
#endif
	*tte_addr = tte | IOMMU_PTOB(MP_PFN0(mp)); /* map page 0 */
	DEBUG5(DBG_DMA_MAP, dip, "fast %p:dvma_pg=%x tte0(%p)=%08x.%08x\n", mp,
	    dvma_pg, tte_addr, HI32(*tte_addr), LO32(*tte_addr));
	if (npages == 1)
		goto tte_done;
	pfn_addr = PCI_GET_MP_PFN1_ADDR(mp); /* short iommu_map_pages() */
	for (tte_addr++, i = 1; i < npages; i++, tte_addr++, pfn_addr++) {
		*tte_addr = tte | IOMMU_PTOB(*pfn_addr);
		DEBUG5(DBG_DMA_MAP, dip, "fast %p:tte(%p, %p)=%08x.%08x\n", mp,
		    tte_addr, pfn_addr, HI32(*tte_addr), LO32(*tte_addr));
	}
tte_done:
#ifdef PCI_DMA_PROF
	pci_dvmaft_success++;
#endif
	mp->dmai_mapping = mp->dmai_roffset | IOMMU_PTOB(dvma_pg);
	mp->dmai_offset = 0;
	mp->dmai_flags |= DMAI_FLAGS_FASTTRACK;
	PCI_SAVE_MP_TTE(mp, tte);	/* save TTE template for unmapping */
	if (DVMA_DBG_ON(iommu_p))
		pci_dvma_alloc_debug(iommu_p, (char *)mp->dmai_mapping,
		    mp->dmai_size, mp);
	return (DDI_SUCCESS);
}

/*
 * pci_dvma_map: map non-fasttrack DMA
 *		Use quantum cache if single page DMA.
 */
int
pci_dvma_map(ddi_dma_impl_t *mp, ddi_dma_req_t *dmareq, iommu_t *iommu_p)
{
	uint_t npages = PCI_DMA_WINNPGS(mp);
	dvma_addr_t dvma_pg, dvma_pg_index;
	void *dvma_addr;
	uint64_t tte = GET_TTE_TEMPLATE(mp);
	int sleep = dmareq->dmar_fp == DDI_DMA_SLEEP ? VM_SLEEP : VM_NOSLEEP;
#ifdef DEBUG
	dev_info_t *dip = mp->dmai_rdip;
#endif
	/*
	 * allocate dvma space resource and map in the first window.
	 * (vmem_t *vmp, size_t size,
	 *	size_t align, size_t phase, size_t nocross,
	 *	void *minaddr, void *maxaddr, int vmflag)
	 */
	if ((npages == 1) && !HAS_REDZONE(mp) && HAS_NOSYSLIMIT(mp)) {
		dvma_addr = vmem_alloc(iommu_p->iommu_dvma_map,
		    IOMMU_PAGE_SIZE, sleep);
		mp->dmai_flags |= DMAI_FLAGS_VMEMCACHE;
#ifdef PCI_DMA_PROF
		pci_dvma_vmem_alloc++;
#endif
	} else {
		dvma_addr = vmem_xalloc(iommu_p->iommu_dvma_map,
		    IOMMU_PTOB(npages + HAS_REDZONE(mp)),
		    MAX(mp->dmai_attr.dma_attr_align, IOMMU_PAGE_SIZE),
		    0,
		    mp->dmai_attr.dma_attr_seg + 1,
		    (void *)mp->dmai_attr.dma_attr_addr_lo,
		    (void *)(mp->dmai_attr.dma_attr_addr_hi + 1),
		    sleep);
#ifdef PCI_DMA_PROF
		pci_dvma_vmem_xalloc++;
#endif
	}
	dvma_pg = IOMMU_BTOP((ulong_t)dvma_addr);
	dvma_pg_index = dvma_pg - iommu_p->dvma_base_pg;
	DEBUG2(DBG_DMA_MAP, dip, "fallback dvma_pages: dvma_pg=%x index=%x\n",
	    dvma_pg, dvma_pg_index);
	if (dvma_pg == 0)
		goto noresource;

	/* allocate DVMA context */
	if ((npages >= pci_context_minpages) && PCI_DMA_USECTX(mp)) {
		dvma_context_t ctx;
		if (ctx = pci_iommu_get_dvma_context(iommu_p, dvma_pg_index)) {
			tte |= IOMMU_CTX2TTE(ctx);
			mp->dmai_flags |= DMAI_FLAGS_CONTEXT;
		}
	}
	mp->dmai_mapping = mp->dmai_roffset | IOMMU_PTOB(dvma_pg);
	mp->dmai_offset = 0;
	PCI_SAVE_MP_TTE(mp, tte);	/* mp->dmai_tte = tte */
	iommu_map_pages(iommu_p, mp, dvma_pg, npages, 0);
	return (DDI_SUCCESS);
noresource:
	if (dmareq->dmar_fp != DDI_DMA_DONTWAIT) {
		DEBUG0(DBG_DMA_MAP, dip, "dvma_pg 0 - set callback\n");
		ddi_set_callback(dmareq->dmar_fp, dmareq->dmar_arg,
		    &iommu_p->iommu_dvma_clid);
	}
	DEBUG0(DBG_DMA_MAP, dip, "vmem_xalloc - DDI_DMA_NORESOURCES\n");
	return (DDI_DMA_NORESOURCES);
}

void
pci_dvma_unmap(iommu_t *iommu_p, ddi_dma_impl_t *mp)
{
	size_t npages;
	dvma_addr_t dvma_addr = (dvma_addr_t)mp->dmai_mapping;
	dvma_addr_t dvma_pg = IOMMU_BTOP(dvma_addr);
	dvma_addr = IOMMU_PTOB(dvma_pg);

	if (mp->dmai_flags & DMAI_FLAGS_FASTTRACK) {
		iopfn_t index = dvma_pg - iommu_p->dvma_base_pg;
		ASSERT(index % pci_dvma_page_cache_clustsz == 0);
		index /= pci_dvma_page_cache_clustsz;
		ASSERT(index < pci_dvma_page_cache_entries);
		iommu_p->iommu_dvma_cache_locks[index] = 0;
#ifdef PCI_DMA_PROF
		pci_dvmaft_free++;
#endif
		return;
	}
	npages = IOMMU_BTOP(mp->dmai_winsize) + HAS_REDZONE(mp);
	pci_vmem_free(iommu_p, mp, (void *)dvma_addr, npages);

	if (mp->dmai_flags & DMAI_FLAGS_CONTEXT)
		pci_iommu_free_dvma_context(iommu_p, MP2CTX(mp));
}

void
pci_dma_sync_unmap(dev_info_t *dip, dev_info_t *rdip, ddi_dma_impl_t *mp)
{
	pci_t *pci_p = get_pci_soft_state(ddi_get_instance(dip));
	iommu_t *iommu_p = pci_p->pci_iommu_p;
	uint64_t sync_buf_save = SYNC_BUF_PA(mp);
	uint32_t fast_track = mp->dmai_flags & DMAI_FLAGS_FASTTRACK;

	if (fast_track) {
		dvma_addr_t dvma_pg = IOMMU_BTOP(mp->dmai_mapping);

		SYNC_BUF_PA(mp) = IOMMU_PAGE_TTEPA(iommu_p, dvma_pg);
		ASSERT(!(SYNC_BUF_PA(mp) & PCI_SYNC_FLAG_SIZE - 1));
	}

	if (pci_dvma_sync_before_unmap) {
		pci_dma_sync(dip, rdip, (ddi_dma_handle_t)mp, 0, 0,
		    DDI_DMA_SYNC_FORCPU);
		iommu_unmap_window(iommu_p, mp);
	} else {
		iommu_unmap_window(iommu_p, mp);
		pci_dma_sync(dip, rdip, (ddi_dma_handle_t)mp, 0, 0,
		    DDI_DMA_SYNC_FORCPU);
	}

	if (fast_track)
		SYNC_BUF_PA(mp) = sync_buf_save;
}

/*
 * DVMA mappings may have multiple windows, but each window always have
 * one segment.
 */
int
pci_dvma_ctl(dev_info_t *dip, dev_info_t *rdip, ddi_dma_impl_t *mp,
	enum ddi_dma_ctlops cmd, off_t *offp, size_t *lenp, caddr_t *objp,
	uint_t cache_flags)
{
	switch (cmd) {

	case DDI_DMA_REMAP:
		if (pci_dvma_remap_enabled)
			return (pci_dvma_remap(dip, rdip, mp, *offp, *lenp));
		return (DDI_FAILURE);

	default:
		DEBUG3(DBG_DMA_CTL, dip, "unknown command (%x): rdip=%s%d\n",
		    cmd, ddi_driver_name(rdip), ddi_get_instance(rdip));
		break;
	}
	return (DDI_FAILURE);
}

void
pci_dma_freewin(ddi_dma_impl_t *mp)
{
	pci_dma_win_t *win_p = mp->dmai_winlst, *win2_p;
	for (win2_p = win_p; win_p; win2_p = win_p) {
		win_p = win2_p->win_next;
		kmem_free(win2_p, sizeof (pci_dma_win_t) +
		    sizeof (ddi_dma_cookie_t) * win2_p->win_ncookies);
	}
	mp->dmai_nwin = 0;
	mp->dmai_winlst = NULL;
}

/*
 * pci_dma_newwin - create a dma window object and cookies
 *
 *	After the initial scan in pci_dma_physwin(), which identifies
 *	a portion of the pfn array that belongs to a dma window,
 *	we are called to allocate and initialize representing memory
 *	resources. We know from the 1st scan the number of cookies
 *	or dma segment in this window so we can allocate a contiguous
 *	memory array for the dma cookies (The implementation of
 *	ddi_dma_nextcookie(9f) dictates dma cookies be contiguous).
 *
 *	A second round scan is done on the pfn array to identify
 *	each dma segment and initialize its corresponding dma cookie.
 *	We don't need to do all the safety checking and we know they
 *	all belong to the same dma window.
 *
 *	Input:	cookie_no - # of cookies identified by the 1st scan
 *		start_idx - subscript of the pfn array for the starting pfn
 *		end_idx   - subscript of the last pfn in dma window
 *		win_pp    - pointer to win_next member of previous window
 *	Return:	DDI_SUCCESS - with **win_pp as newly created window object
 *		DDI_DMA_NORESROUCE - caller frees all previous window objs
 *	Note:	Each cookie and window size are all initialized on page
 *		boundary. This is not true for the 1st cookie of the 1st
 *		window and the last cookie of the last window.
 *		We fix that later in upper layer which has access to size
 *		and offset info.
 *
 */
static int
pci_dma_newwin(ddi_dma_req_t *dmareq, ddi_dma_impl_t *mp, uint32_t cookie_no,
	uint32_t start_idx, uint32_t end_idx, pci_dma_win_t **win_pp,
	uint64_t count_max, uint64_t bypass_prefix)
{
	int (*waitfp)(caddr_t) = dmareq->dmar_fp;
	ddi_dma_cookie_t *cookie_p;
	uint32_t pfn_no = 1;
	iopfn_t pfn = PCI_GET_MP_PFN(mp, start_idx);
	iopfn_t prev_pfn = pfn;
	uint64_t seg_pfn0 = pfn;
	size_t sz = cookie_no * sizeof (ddi_dma_cookie_t);
	pci_dma_win_t *win_p = kmem_alloc(sizeof (pci_dma_win_t) + sz,
	    waitfp == DDI_DMA_SLEEP ? KM_SLEEP : KM_NOSLEEP);
	if (!win_p)
		goto noresource;

	win_p->win_next = NULL;
	win_p->win_ncookies = cookie_no;
	win_p->win_curseg = 0;	/* start from segment 0 */
	win_p->win_size = IOMMU_PTOB(end_idx - start_idx + 1);
	/* win_p->win_offset is left uninitialized */

	cookie_p = (ddi_dma_cookie_t *)(win_p + 1);
	start_idx++;
	for (; start_idx <= end_idx; start_idx++, prev_pfn = pfn, pfn_no++) {
		pfn = PCI_GET_MP_PFN1(mp, start_idx);
		if ((pfn == prev_pfn + 1) &&
		    (IOMMU_PTOB(pfn_no + 1) - 1 <= count_max))
			continue;

		/* close up the cookie up to (including) prev_pfn */
		MAKE_DMA_COOKIE(cookie_p, IOMMU_PTOB(seg_pfn0) | bypass_prefix,
		    IOMMU_PTOB(pfn_no));
		DEBUG2(DBG_BYPASS, mp->dmai_rdip, "cookie %p (%x pages)\n",
		    IOMMU_PTOB(seg_pfn0) | bypass_prefix, pfn_no);

		cookie_p++;	/* advance to next available cookie cell */
		pfn_no = 0;
		seg_pfn0 = pfn;	/* start a new segment from current pfn */
	}
	MAKE_DMA_COOKIE(cookie_p, IOMMU_PTOB(seg_pfn0) | bypass_prefix,
	    IOMMU_PTOB(pfn_no));
	DEBUG3(DBG_BYPASS, mp->dmai_rdip, "cookie %p (%x pages) of total %x\n",
	    IOMMU_PTOB(seg_pfn0) | bypass_prefix, pfn_no, cookie_no);
#ifdef DEBUG
	cookie_p++;
	ASSERT((cookie_p - (ddi_dma_cookie_t *)(win_p + 1)) == cookie_no);
#endif
	*win_pp = win_p;
	return (DDI_SUCCESS);
noresource:
	if (waitfp != DDI_DMA_DONTWAIT)
		ddi_set_callback(waitfp, dmareq->dmar_arg, &pci_kmem_clid);
	return (DDI_DMA_NORESOURCES);
}

/*
 * pci_dma_adjust - adjust 1st and last cookie and window sizes
 *	remove initial dma page offset from 1st cookie and window size
 *	remove last dma page remainder from last cookie and window size
 *	fill win_offset of each dma window according to just fixed up
 *		each window sizes
 *	pci_dma_win_t members modified:
 *	win_p->win_offset - this window's offset within entire DMA object
 *	win_p->win_size	  - xferrable size (in bytes) for this window
 *
 *	ddi_dma_impl_t members modified:
 *	mp->dmai_size	  - 1st window xferrable size
 *	mp->dmai_offset   - 0, which is the dma offset of the 1st window
 *
 *	ddi_dma_cookie_t members modified:
 *	cookie_p->dmac_size - 1st and last cookie remove offset or remainder
 *	cookie_p->dmac_laddress - 1st cookie add page offset
 */
static void
pci_dma_adjust(ddi_dma_req_t *dmareq, ddi_dma_impl_t *mp, pci_dma_win_t *win_p)
{
	ddi_dma_cookie_t *cookie_p = (ddi_dma_cookie_t *)(win_p + 1);
	size_t pg_offset = mp->dmai_roffset;
	size_t win_offset = 0;

	cookie_p->dmac_size -= pg_offset;
	cookie_p->dmac_laddress |= pg_offset;
	win_p->win_size -= pg_offset;
	DEBUG1(DBG_BYPASS, mp->dmai_rdip, "pg0 adjust %lx\n", pg_offset);

	mp->dmai_size = win_p->win_size;
	mp->dmai_offset = 0;

	pg_offset += mp->dmai_object.dmao_size;
	pg_offset &= IOMMU_PAGE_OFFSET;
	if (pg_offset)
		pg_offset = IOMMU_PAGE_SIZE - pg_offset;
	DEBUG1(DBG_BYPASS, mp->dmai_rdip, "last pg adjust %lx\n", pg_offset);

	for (; win_p->win_next; win_p = win_p->win_next) {
		DEBUG1(DBG_BYPASS, mp->dmai_rdip, "win off %p\n", win_offset);
		win_p->win_offset = win_offset;
		win_offset += win_p->win_size;
	}
	/* last window */
	win_p->win_offset = win_offset;
	cookie_p = (ddi_dma_cookie_t *)(win_p + 1);
	cookie_p[win_p->win_ncookies - 1].dmac_size -= pg_offset;
	win_p->win_size -= pg_offset;
	ASSERT((win_offset + win_p->win_size) == mp->dmai_object.dmao_size);
}

/*
 * pci_dma_physwin() - carve up dma windows using physical addresses.
 *	Called to handle iommu bypass and pci peer-to-peer transfers.
 *	Calls pci_dma_newwin() to allocate window objects.
 *
 * Dependency: mp->dmai_pfnlst points to an array of pfns
 *
 * 1. Each dma window is represented by a pci_dma_win_t object.
 *	The object will be casted to ddi_dma_win_t and returned
 *	to leaf driver through the DDI interface.
 * 2. Each dma window can have several dma segments with each
 *	segment representing a physically contiguous either memory
 *	space (if we are doing an iommu bypass transfer) or pci address
 *	space (if we are doing a peer-to-peer transfer).
 * 3. Each segment has a DMA cookie to program the DMA engine.
 *	The cookies within each DMA window must be located in a
 *	contiguous array per ddi_dma_nextcookie(9f).
 * 4. The number of DMA segments within each DMA window cannot exceed
 *	mp->dmai_attr.dma_attr_sgllen. If the transfer size is
 *	too large to fit in the sgllen, the rest needs to be
 *	relocated to the next dma window.
 * 5. Peer-to-peer DMA segment follows device hi, lo, count_max,
 *	and nocross restrictions while bypass DMA follows the set of
 *	restrictions with system limits factored in.
 *
 * Return:
 *	mp->dmai_winlst	 - points to a link list of pci_dma_win_t objects.
 *		Each pci_dma_win_t object on the link list contains
 *		infomation such as its window size (# of pages),
 *		starting offset (also see Restriction), an array of
 *		DMA cookies, and # of cookies in the array.
 *	mp->dmai_pfnlst	 - NULL, the pfn list is freed to conserve memory.
 *	mp->dmai_nwin	 - # of total DMA windows on mp->dmai_winlst.
 *	mp->dmai_mapping - starting cookie address
 *	mp->dmai_rflags	 - consistent, nosync, no redzone
 *	mp->dmai_cookie	 - start of cookie table of the 1st DMA window
 *
 * Restriction:
 *	Each pci_dma_win_t object can theoratically start from any offset
 *	since the iommu is not involved. However, this implementation
 *	always make windows start from page aligned offset (except
 *	the 1st window, which follows the requested offset) due to the
 *	fact that we are handed a pfn list. This does require device's
 *	count_max and attr_seg to be at least IOMMU_PAGE_SIZE aligned.
 */
int
pci_dma_physwin(pci_t *pci_p, ddi_dma_req_t *dmareq, ddi_dma_impl_t *mp)
{
	uint_t npages = mp->dmai_ndvmapages;
	int ret, sgllen = mp->dmai_attr.dma_attr_sgllen;
	iopfn_t pfn_lo, pfn_hi, prev_pfn, bypass_pfn;
	iopfn_t pfn = PCI_GET_MP_PFN(mp, 0);
	uint32_t i, win_no = 0, pfn_no = 1, win_pfn0_index = 0, cookie_no = 0;
	uint64_t count_max, bypass = PCI_DMA_BYPASS_PREFIX(mp, pfn);
	pci_dma_win_t **win_pp = (pci_dma_win_t **)&mp->dmai_winlst;
	ddi_dma_cookie_t *cookie0_p;

	if (PCI_DMA_ISPTP(mp)) { /* ignore sys limits for peer-to-peer */
		ddi_dma_attr_t *dev_attr_p = DEV_ATTR(mp);
		iopfn_t pfn_base = pci_p->pci_pbm_p->pbm_base_pfn;
		iopfn_t pfn_last = pci_p->pci_pbm_p->pbm_last_pfn - pfn_base;
		uint64_t nocross = dev_attr_p->dma_attr_seg;
		if (nocross && (nocross < UINT32_MAX))
			return (DDI_DMA_NOMAPPING);
		if (dev_attr_p->dma_attr_align > IOMMU_PAGE_SIZE)
			return (DDI_DMA_NOMAPPING);
		pfn_lo = IOMMU_BTOP(dev_attr_p->dma_attr_addr_lo);
		pfn_hi = IOMMU_BTOP(dev_attr_p->dma_attr_addr_hi);
		pfn_hi = MIN(pfn_hi, pfn_last);
		if ((pfn_lo > pfn_hi) || (pfn < pfn_lo))
			return (DDI_DMA_NOMAPPING);
		count_max = dev_attr_p->dma_attr_count_max;
		count_max = MIN(count_max, nocross);
		/*
		 * the following count_max trim is not done because we are
		 * making sure pfn_lo <= pfn <= pfn_hi inside the loop
		 * count_max=MIN(count_max, IOMMU_PTOB(pfn_hi - pfn_lo + 1)-1);
		 */
	} else { /* bypass hi/lo/count_max have been processed by attr2hdl() */
		count_max = mp->dmai_attr.dma_attr_count_max;
		pfn_lo = IOMMU_BTOP(mp->dmai_attr.dma_attr_addr_lo);
		pfn_hi = IOMMU_BTOP(mp->dmai_attr.dma_attr_addr_hi);
	}

	bypass_pfn = IOMMU_BTOP(bypass);

	for (prev_pfn = (bypass_pfn | pfn), i = 1; i < npages;
	    i++, prev_pfn = pfn, pfn_no++) {
		pfn = bypass_pfn | PCI_GET_MP_PFN1(mp, i);
		if ((pfn == prev_pfn + 1) &&
		    (IOMMU_PTOB(pfn_no + 1) - 1 <= count_max))
			continue;
		if ((pfn < pfn_lo) || (prev_pfn > pfn_hi)) {
			ret = DDI_DMA_NOMAPPING;
			goto err;
		}
		cookie_no++;
		pfn_no = 0;
		if (cookie_no < sgllen)
			continue;

		DEBUG3(DBG_BYPASS, mp->dmai_rdip, "newwin pfn[%x-%x] %x cks\n",
		    win_pfn0_index, i - 1, cookie_no);
		if (ret = pci_dma_newwin(dmareq, mp, cookie_no,
		    win_pfn0_index, i - 1, win_pp, count_max, bypass))
			goto err;

		win_pp = &(*win_pp)->win_next;	/* win_pp = *(win_pp) */
		win_no++;
		win_pfn0_index = i;
		cookie_no = 0;
	}
	if (pfn > pfn_hi) {
		ret = DDI_DMA_NOMAPPING;
		goto err;
	}
	cookie_no++;
	DEBUG3(DBG_BYPASS, mp->dmai_rdip, "newwin pfn[%x-%x] %x cks\n",
	    win_pfn0_index, i - 1, cookie_no);
	if (ret = pci_dma_newwin(dmareq, mp, cookie_no, win_pfn0_index,
	    i - 1, win_pp, count_max, bypass))
		goto err;
	win_no++;
	pci_dma_adjust(dmareq, mp, mp->dmai_winlst);
	mp->dmai_nwin = win_no;
	mp->dmai_rflags |= DDI_DMA_CONSISTENT;
	if (!pci_p->pci_pbm_p->pbm_sync_reg_pa) {
		mp->dmai_rflags |= DMP_NOSYNC;
		mp->dmai_flags |= DMAI_FLAGS_NOSYNC;
	}
	mp->dmai_rflags &= ~DDI_DMA_REDZONE;
	cookie0_p = (ddi_dma_cookie_t *)(WINLST(mp) + 1);
	mp->dmai_cookie = cookie0_p + 1;
	mp->dmai_mapping = cookie0_p->dmac_laddress;
	mp->dmai_ncookies = WINLST(mp)->win_ncookies;
	mp->dmai_curcookie = 1;

	pci_dma_freepfn(mp);
	return (DDI_DMA_MAPPED);
err:
	pci_dma_freewin(mp);
	return (ret);
}

/*ARGSUSED*/
int
pci_dma_ctl(dev_info_t *dip, dev_info_t *rdip, ddi_dma_impl_t *mp,
	enum ddi_dma_ctlops cmd, off_t *offp, size_t *lenp, caddr_t *objp,
	uint_t cache_flags)
{
	switch (cmd) {

	case DDI_DMA_HTOC: {
		off_t off = *offp;
		ddi_dma_cookie_t *loop_cp, *cp;
		pci_dma_win_t *win_p = mp->dmai_winlst;

		if (off >= mp->dmai_object.dmao_size)
			return (DDI_FAILURE);

		/* locate window */
		while (win_p->win_offset + win_p->win_size <= off)
			win_p = win_p->win_next;

		loop_cp = cp = (ddi_dma_cookie_t *)(win_p + 1);
		mp->dmai_offset = win_p->win_offset;
		mp->dmai_size   = win_p->win_size;
		mp->dmai_mapping = cp->dmac_laddress; /* cookie0 start addr */

		/* adjust cookie addr/len if we are not on cookie boundary */
		off -= win_p->win_offset;	   /* offset within window */
		for (; off >= loop_cp->dmac_size; loop_cp++)
			off -= loop_cp->dmac_size; /* offset within cookie */

		mp->dmai_cookie = loop_cp + 1;
		win_p->win_curseg = loop_cp - cp;
		cp = (ddi_dma_cookie_t *)objp;
		MAKE_DMA_COOKIE(cp, loop_cp->dmac_laddress + off,
		    loop_cp->dmac_size - off);

		DEBUG2(DBG_DMA_CTL, dip,
		    "HTOC: cookie - dmac_laddress=%p dmac_size=%x\n",
		    cp->dmac_laddress, cp->dmac_size);
		}
		return (DDI_SUCCESS);

	case DDI_DMA_COFF: {
		pci_dma_win_t *win_p;
		ddi_dma_cookie_t *cp;
		uint64_t addr, key = ((ddi_dma_cookie_t *)offp)->dmac_laddress;
		size_t win_off;

		for (win_p = mp->dmai_winlst; win_p; win_p = win_p->win_next) {
			int i;
			win_off = 0;
			cp = (ddi_dma_cookie_t *)(win_p + 1);
			for (i = 0; i < win_p->win_ncookies; i++, cp++) {
				size_t sz = cp->dmac_size;

				addr = cp->dmac_laddress;
				if ((addr <= key) && (addr + sz >= key))
					goto found;
				win_off += sz;
			}
		}
		return (DDI_FAILURE);
found:
		*objp = (caddr_t)(win_p->win_offset + win_off + (key - addr));
		return (DDI_SUCCESS);
		}

	case DDI_DMA_REMAP:
		return (DDI_FAILURE);

	default:
		DEBUG3(DBG_DMA_CTL, dip, "unknown command (%x): rdip=%s%d\n",
		    cmd, ddi_driver_name(rdip), ddi_get_instance(rdip));
		break;
	}
	return (DDI_FAILURE);
}

static void
pci_dvma_debug_init(iommu_t *iommu_p)
{
	size_t sz = sizeof (struct dvma_rec) * pci_dvma_debug_rec;
	ASSERT(MUTEX_HELD(&iommu_p->dvma_debug_lock));
	cmn_err(CE_NOTE, "PCI DVMA %p stat ON", iommu_p);

	iommu_p->dvma_alloc_rec = kmem_zalloc(sz, KM_SLEEP);
	iommu_p->dvma_free_rec = kmem_zalloc(sz, KM_SLEEP);

	iommu_p->dvma_active_list = NULL;
	iommu_p->dvma_alloc_rec_index = 0;
	iommu_p->dvma_free_rec_index = 0;
	iommu_p->dvma_active_count = 0;
}

void
pci_dvma_debug_fini(iommu_t *iommu_p)
{
	struct dvma_rec *prev, *ptr;
	size_t sz = sizeof (struct dvma_rec) * pci_dvma_debug_rec;
	uint64_t mask = ~(1ull << iommu_p->iommu_inst);
	cmn_err(CE_NOTE, "PCI DVMA %p stat OFF", iommu_p);

	kmem_free(iommu_p->dvma_alloc_rec, sz);
	kmem_free(iommu_p->dvma_free_rec, sz);
	iommu_p->dvma_alloc_rec = iommu_p->dvma_free_rec = NULL;

	prev = iommu_p->dvma_active_list;
	if (!prev)
		return;
	for (ptr = prev->next; ptr; prev = ptr, ptr = ptr->next)
		kmem_free(prev, sizeof (struct dvma_rec));
	kmem_free(prev, sizeof (struct dvma_rec));

	iommu_p->dvma_active_list = NULL;
	iommu_p->dvma_alloc_rec_index = 0;
	iommu_p->dvma_free_rec_index = 0;
	iommu_p->dvma_active_count = 0;

	pci_dvma_debug_on  &= mask;
	pci_dvma_debug_off &= mask;
}

void
pci_dvma_alloc_debug(iommu_t *iommu_p, char *address, uint_t len,
	ddi_dma_impl_t *mp)
{
	struct dvma_rec *ptr;
	mutex_enter(&iommu_p->dvma_debug_lock);

	if (!iommu_p->dvma_alloc_rec)
		pci_dvma_debug_init(iommu_p);
	if (DVMA_DBG_OFF(iommu_p)) {
		pci_dvma_debug_fini(iommu_p);
		goto done;
	}

	ptr = &iommu_p->dvma_alloc_rec[iommu_p->dvma_alloc_rec_index];
	ptr->dvma_addr = address;
	ptr->len = len;
	ptr->mp = mp;
	if (++iommu_p->dvma_alloc_rec_index == pci_dvma_debug_rec)
		iommu_p->dvma_alloc_rec_index = 0;

	ptr = kmem_alloc(sizeof (struct dvma_rec), KM_SLEEP);
	ptr->dvma_addr = address;
	ptr->len = len;
	ptr->mp = mp;

	ptr->next = iommu_p->dvma_active_list;
	iommu_p->dvma_active_list = ptr;
	iommu_p->dvma_active_count++;
done:
	mutex_exit(&iommu_p->dvma_debug_lock);
}

void
pci_dvma_free_debug(iommu_t *iommu_p, char *address, uint_t len,
	ddi_dma_impl_t *mp)
{
	struct dvma_rec *ptr, *ptr_save;
	mutex_enter(&iommu_p->dvma_debug_lock);

	if (!iommu_p->dvma_alloc_rec)
		pci_dvma_debug_init(iommu_p);
	if (DVMA_DBG_OFF(iommu_p)) {
		pci_dvma_debug_fini(iommu_p);
		goto done;
	}

	ptr = &iommu_p->dvma_free_rec[iommu_p->dvma_free_rec_index];
	ptr->dvma_addr = address;
	ptr->len = len;
	ptr->mp = mp;
	if (++iommu_p->dvma_free_rec_index == pci_dvma_debug_rec)
		iommu_p->dvma_free_rec_index = 0;

	ptr_save = iommu_p->dvma_active_list;
	for (ptr = ptr_save; ptr; ptr = ptr->next) {
		if ((ptr->dvma_addr == address) && (ptr->len = len))
			break;
		ptr_save = ptr;
	}
	if (!ptr) {
		cmn_err(CE_WARN, "bad dvma free addr=%lx len=%x",
		    (long)address, len);
		goto done;
	}
	if (ptr == iommu_p->dvma_active_list)
		iommu_p->dvma_active_list = ptr->next;
	else
		ptr_save->next = ptr->next;
	kmem_free(ptr, sizeof (struct dvma_rec));
	iommu_p->dvma_active_count--;
done:
	mutex_exit(&iommu_p->dvma_debug_lock);
}

#ifdef DEBUG
void
dump_dma_handle(uint64_t flag, dev_info_t *dip, ddi_dma_impl_t *hp)
{
	DEBUG4(flag, dip, "mp(%p): flags=%x mapping=%lx xfer_size=%x\n",
	    hp, hp->dmai_inuse, hp->dmai_mapping, hp->dmai_size);
	DEBUG4(flag|DBG_CONT, dip, "\tnpages=%x roffset=%x rflags=%x nwin=%x\n",
	    hp->dmai_ndvmapages, hp->dmai_roffset, hp->dmai_rflags,
	    hp->dmai_nwin);
	DEBUG4(flag|DBG_CONT, dip, "\twinsize=%x tte=%p pfnlst=%p pfn0=%p\n",
	    hp->dmai_winsize, hp->dmai_tte, hp->dmai_pfnlst, hp->dmai_pfn0);
	DEBUG4(flag|DBG_CONT, dip, "\twinlst=%x obj=%p attr=%p ckp=%p\n",
	    hp->dmai_winlst, &hp->dmai_object, &hp->dmai_attr,
	    hp->dmai_cookie);
}
#endif

void
pci_vmem_do_free(iommu_t *iommu_p, void *base_addr, size_t npages,
    int vmemcache)
{
	vmem_t *map_p = iommu_p->iommu_dvma_map;

	if (vmemcache) {
		vmem_free(map_p, base_addr, IOMMU_PAGE_SIZE);
#ifdef PCI_DMA_PROF
		pci_dvma_vmem_free++;
#endif
		return;
	}

	vmem_xfree(map_p, base_addr, IOMMU_PTOB(npages));
#ifdef PCI_DMA_PROF
		pci_dvma_vmem_xfree++;
#endif
}
