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
 * PCI Express nexus DVMA and DMA core routines:
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
#include <sys/ddi_impldefs.h>
#include "px_obj.h"

/*LINTLIBRARY*/

/*
 * px_dma_allocmp - Allocate a pci dma implementation structure
 *
 * An extra ddi_dma_attr structure is bundled with the usual ddi_dma_impl
 * to hold unmodified device limits. The ddi_dma_attr inside the
 * ddi_dma_impl structure is augumented with system limits to enhance
 * DVMA performance at runtime. The unaugumented device limits saved
 * right after (accessed through (ddi_dma_attr_t *)(mp + 1)) is used
 * strictly for peer-to-peer transfers which do not obey system limits.
 *
 * return: DDI_SUCCESS DDI_DMA_NORESOURCES
 */
ddi_dma_impl_t *
px_dma_allocmp(dev_info_t *dip, dev_info_t *rdip, int (*waitfp)(caddr_t),
	caddr_t arg)
{
	register ddi_dma_impl_t *mp;
	int sleep = (waitfp == DDI_DMA_SLEEP) ? KM_SLEEP : KM_NOSLEEP;

	/* Caution: we don't use zalloc to enhance performance! */
	if ((mp = kmem_alloc(sizeof (px_dma_hdl_t), sleep)) == 0) {
		DBG(DBG_DMA_MAP, dip, "can't alloc dma_handle\n");
		if (waitfp != DDI_DMA_DONTWAIT) {
			DBG(DBG_DMA_MAP, dip, "alloc_mp kmem cb\n");
			ddi_set_callback(waitfp, arg, &px_kmem_clid);
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
	 * bzero(&mp->dmai_attr, sizeof (ddi_dma_attr_t));
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

	/*
	 * The bdf protection value is set to immediate child
	 * at first. It gets modified by switch/bridge drivers
	 * as the code traverses down the fabric topology.
	 *
	 * XXX No IOMMU protection for broken devices.
	 */
	ASSERT((intptr_t)ddi_get_parent_data(rdip) >> 1 == 0);
	mp->dmai_bdf = ((intptr_t)ddi_get_parent_data(rdip) == 1) ?
	    PCIE_INVALID_BDF : pcie_get_bdf_for_dma_xfer(dip, rdip);

	ndi_fmc_insert(rdip, DMA_HANDLE, mp, NULL);
	return (mp);
}

void
px_dma_freemp(ddi_dma_impl_t *mp)
{
	ndi_fmc_remove(mp->dmai_rdip, DMA_HANDLE, mp);
	if (mp->dmai_ndvmapages > 1)
		px_dma_freepfn(mp);
	if (mp->dmai_winlst)
		px_dma_freewin(mp);
	kmem_free(mp, sizeof (px_dma_hdl_t));
}

void
px_dma_freepfn(ddi_dma_impl_t *mp)
{
	void *addr = mp->dmai_pfnlst;
	if (addr) {
		size_t npages = mp->dmai_ndvmapages;
		if (npages > 1)
			kmem_free(addr, npages * sizeof (px_iopfn_t));
		mp->dmai_pfnlst = NULL;
	}
	mp->dmai_ndvmapages = 0;
}

/*
 * px_dma_lmts2hdl - alloate a ddi_dma_impl_t, validate practical limits
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
 * mp->dmai_attr.dma_attr_align     - 1         (no alignment restriction)
 *
 * The dlim_dmaspeed member of dmareq->dmar_limits is ignored.
 */
ddi_dma_impl_t *
px_dma_lmts2hdl(dev_info_t *dip, dev_info_t *rdip, px_mmu_t *mmu_p,
	ddi_dma_req_t *dmareq)
{
	ddi_dma_impl_t *mp;
	ddi_dma_attr_t *attr_p;
	uint64_t syslo		= mmu_p->mmu_dvma_base;
	uint64_t syshi		= mmu_p->mmu_dvma_end;
	uint64_t fasthi		= mmu_p->mmu_dvma_fast_end;
	ddi_dma_lim_t *lim_p	= dmareq->dmar_limits;
	uint32_t count_max	= lim_p->dlim_cntr_max;
	uint64_t lo		= lim_p->dlim_addr_lo;
	uint64_t hi		= lim_p->dlim_addr_hi;
	if (hi <= lo) {
		DBG(DBG_DMA_MAP, dip, "Bad limits\n");
		return ((ddi_dma_impl_t *)DDI_DMA_NOMAPPING);
	}
	if (!count_max)
		count_max--;

	if (!(mp = px_dma_allocmp(dip, rdip, dmareq->dmar_fp,
	    dmareq->dmar_arg)))
		return (NULL);

	/* store original dev input at the 2nd ddi_dma_attr */
	attr_p = PX_DEV_ATTR(mp);
	SET_DMAATTR(attr_p, lo, hi, -1, count_max);
	SET_DMAALIGN(attr_p, 1);

	lo = MAX(lo, syslo);
	hi = MIN(hi, syshi);
	if (hi <= lo)
		mp->dmai_flags |= PX_DMAI_FLAGS_PEER_ONLY;
	count_max = MIN(count_max, hi - lo);

	if (PX_DEV_NOSYSLIMIT(lo, hi, syslo, fasthi, 1))
		mp->dmai_flags |= PX_DMAI_FLAGS_NOFASTLIMIT |
		    PX_DMAI_FLAGS_NOSYSLIMIT;
	else {
		if (PX_DEV_NOFASTLIMIT(lo, hi, syslo, syshi, 1))
			mp->dmai_flags |= PX_DMAI_FLAGS_NOFASTLIMIT;
	}
	if (PX_DMA_NOCTX(rdip))
		mp->dmai_flags |= PX_DMAI_FLAGS_NOCTX;

	/* store augumented dev input to mp->dmai_attr */
	mp->dmai_burstsizes	= lim_p->dlim_burstsizes;
	attr_p = &mp->dmai_attr;
	SET_DMAATTR(attr_p, lo, hi, -1, count_max);
	SET_DMAALIGN(attr_p, 1);
	return (mp);
}

/*
 * Called from px_attach to check for bypass dma support and set
 * flags accordingly.
 */
int
px_dma_attach(px_t *px_p)
{
	uint64_t baddr;

	if (px_lib_iommu_getbypass(px_p->px_dip, 0ull,
	    PCI_MAP_ATTR_WRITE|PCI_MAP_ATTR_READ,
	    &baddr) != DDI_ENOTSUP)
		/* ignore all other errors */
		px_p->px_dev_caps |= PX_BYPASS_DMA_ALLOWED;

	px_p->px_dma_sync_opt = ddi_prop_get_int(DDI_DEV_T_ANY,
	    px_p->px_dip, DDI_PROP_DONTPASS, "dma-sync-options", 0);

	if (px_p->px_dma_sync_opt != 0)
		px_p->px_dev_caps |= PX_DMA_SYNC_REQUIRED;

	return (DDI_SUCCESS);
}

/*
 * px_dma_attr2hdl
 *
 * This routine is called from the alloc handle entry point to sanity check the
 * dma attribute structure.
 *
 * use by: px_dma_allochdl()
 *
 * return value:
 *
 *	DDI_SUCCESS		- on success
 *	DDI_DMA_BADATTR		- attribute has invalid version number
 *				  or address limits exclude dvma space
 */
int
px_dma_attr2hdl(px_t *px_p, ddi_dma_impl_t *mp)
{
	px_mmu_t *mmu_p = px_p->px_mmu_p;
	uint64_t syslo, syshi;
	int	ret;
	ddi_dma_attr_t *attrp		= PX_DEV_ATTR(mp);
	uint64_t hi			= attrp->dma_attr_addr_hi;
	uint64_t lo			= attrp->dma_attr_addr_lo;
	uint64_t align			= attrp->dma_attr_align;
	uint64_t nocross		= attrp->dma_attr_seg;
	uint64_t count_max		= attrp->dma_attr_count_max;

	DBG(DBG_DMA_ALLOCH, px_p->px_dip, "attrp=%p cntr_max=%x.%08x\n",
	    attrp, HI32(count_max), LO32(count_max));
	DBG(DBG_DMA_ALLOCH, px_p->px_dip, "hi=%x.%08x lo=%x.%08x\n",
	    HI32(hi), LO32(hi), HI32(lo), LO32(lo));
	DBG(DBG_DMA_ALLOCH, px_p->px_dip, "seg=%x.%08x align=%x.%08x\n",
	    HI32(nocross), LO32(nocross), HI32(align), LO32(align));

	if (!nocross)
		nocross--;
	if (attrp->dma_attr_flags & DDI_DMA_FORCE_PHYSICAL) { /* BYPASS */

		DBG(DBG_DMA_ALLOCH, px_p->px_dip, "bypass mode\n");
		/*
		 * If Bypass DMA is not supported, return error so that
		 * target driver can fall back to dvma mode of operation
		 */
		if (!(px_p->px_dev_caps & PX_BYPASS_DMA_ALLOWED))
			return (DDI_DMA_BADATTR);
		mp->dmai_flags |= PX_DMAI_FLAGS_BYPASSREQ;
		if (nocross != UINT64_MAX)
			return (DDI_DMA_BADATTR);
		if (align && (align > MMU_PAGE_SIZE))
			return (DDI_DMA_BADATTR);
		align = 1; /* align on 1 page boundary */

		/* do a range check and get the limits */
		ret = px_lib_dma_bypass_rngchk(px_p->px_dip, attrp,
		    &syslo, &syshi);
		if (ret != DDI_SUCCESS)
			return (ret);
	} else { /* MMU_XLATE or PEER_TO_PEER */
		align = MAX(align, MMU_PAGE_SIZE) - 1;
		if ((align & nocross) != align) {
			dev_info_t *rdip = mp->dmai_rdip;
			cmn_err(CE_WARN, "%s%d dma_attr_seg not aligned",
			    NAMEINST(rdip));
			return (DDI_DMA_BADATTR);
		}
		align = MMU_BTOP(align + 1);
		syslo = mmu_p->mmu_dvma_base;
		syshi = mmu_p->mmu_dvma_end;
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

	DBG(DBG_DMA_ALLOCH, px_p->px_dip, "hi=%x.%08x, lo=%x.%08x\n",
	    HI32(hi), LO32(hi), HI32(lo), LO32(lo));
	if (hi <= lo) {
		/*
		 * If this is an IOMMU bypass access, the caller can't use
		 * the required addresses, so fail it.  Otherwise, it's
		 * peer-to-peer; ensure that the caller has no alignment or
		 * segment size restrictions.
		 */
		if ((mp->dmai_flags & PX_DMAI_FLAGS_BYPASSREQ) ||
		    (nocross < UINT32_MAX) || (align > 1))
			return (DDI_DMA_BADATTR);

		mp->dmai_flags |= PX_DMAI_FLAGS_PEER_ONLY;
	} else /* set practical counter_max value */
		count_max = MIN(count_max, hi - lo);

	if (PX_DEV_NOSYSLIMIT(lo, hi, syslo, syshi, align))
		mp->dmai_flags |= PX_DMAI_FLAGS_NOSYSLIMIT |
		    PX_DMAI_FLAGS_NOFASTLIMIT;
	else {
		syshi = mmu_p->mmu_dvma_fast_end;
		if (PX_DEV_NOFASTLIMIT(lo, hi, syslo, syshi, align))
			mp->dmai_flags |= PX_DMAI_FLAGS_NOFASTLIMIT;
	}
	if (PX_DMA_NOCTX(mp->dmai_rdip))
		mp->dmai_flags |= PX_DMAI_FLAGS_NOCTX;

	mp->dmai_burstsizes	= attrp->dma_attr_burstsizes;
	attrp = &mp->dmai_attr;
	SET_DMAATTR(attrp, lo, hi, nocross, count_max);
	return (DDI_SUCCESS);
}

#define	TGT_PFN_INBETWEEN(pfn, bgn, end) ((pfn >= bgn) && (pfn <= end))

/*
 * px_dma_type - determine which of the three types DMA (peer-to-peer,
 *		mmu bypass, or mmu translate) we are asked to do.
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
 *	mp->dmai_roffset 	- initialized to starting MMU page offset
 *	mp->dmai_ndvmapages	- # of total MMU pages of entire object
 */
int
px_dma_type(px_t *px_p, ddi_dma_req_t *dmareq, ddi_dma_impl_t *mp)
{
	dev_info_t *dip = px_p->px_dip;
	ddi_dma_obj_t *dobj_p = &dmareq->dmar_object;
	px_pec_t *pec_p = px_p->px_pec_p;
	uint32_t offset;
	pfn_t pfn0;
	uint_t redzone;

	mp->dmai_rflags = dmareq->dmar_flags & DMP_DDIFLAGS;

	if (!(px_p->px_dev_caps & PX_DMA_SYNC_REQUIRED))
		mp->dmai_rflags |= DMP_NOSYNC;

	switch (dobj_p->dmao_type) {
	case DMA_OTYP_BUFVADDR:
	case DMA_OTYP_VADDR: {
		page_t **pplist = dobj_p->dmao_obj.virt_obj.v_priv;
		caddr_t vaddr = dobj_p->dmao_obj.virt_obj.v_addr;

		DBG(DBG_DMA_MAP, dip, "vaddr=%p pplist=%p\n", vaddr, pplist);
		offset = (ulong_t)vaddr & MMU_PAGE_OFFSET;
		if (pplist) {				/* shadow list */
			mp->dmai_flags |= PX_DMAI_FLAGS_PGPFN;
			pfn0 = page_pptonum(*pplist);
		} else {
			struct as *as_p = dobj_p->dmao_obj.virt_obj.v_as;
			struct hat *hat_p = as_p ? as_p->a_hat : kas.a_hat;
			pfn0 = hat_getpfnum(hat_p, vaddr);
		}
		}
		break;

	case DMA_OTYP_PAGES:
		offset = dobj_p->dmao_obj.pp_obj.pp_offset;
		mp->dmai_flags |= PX_DMAI_FLAGS_PGPFN;
		pfn0 = page_pptonum(dobj_p->dmao_obj.pp_obj.pp_pp);
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
	if (TGT_PFN_INBETWEEN(pfn0, pec_p->pec_base32_pfn,
	    pec_p->pec_last32_pfn)) {
		mp->dmai_flags |= PX_DMAI_FLAGS_PTP|PX_DMAI_FLAGS_PTP32;
		goto done;	/* leave bypass and dvma flag as 0 */
	} else if (TGT_PFN_INBETWEEN(pfn0, pec_p->pec_base64_pfn,
	    pec_p->pec_last64_pfn)) {
		mp->dmai_flags |= PX_DMAI_FLAGS_PTP|PX_DMAI_FLAGS_PTP64;
		goto done;	/* leave bypass and dvma flag as 0 */
	}
	if (PX_DMA_ISPEERONLY(mp)) {
		dev_info_t *rdip = mp->dmai_rdip;
		cmn_err(CE_WARN, "Bad peer-to-peer req %s%d", NAMEINST(rdip));
		return (DDI_DMA_NOMAPPING);
	}

	redzone = (mp->dmai_rflags & DDI_DMA_REDZONE) ||
	    (mp->dmai_flags & PX_DMAI_FLAGS_MAP_BUFZONE) ?
	    PX_DMAI_FLAGS_REDZONE : 0;

	mp->dmai_flags |= (mp->dmai_flags & PX_DMAI_FLAGS_BYPASSREQ) ?
	    PX_DMAI_FLAGS_BYPASS : (PX_DMAI_FLAGS_DVMA | redzone);
done:
	mp->dmai_object	 = *dobj_p;			/* whole object    */
	mp->dmai_pfn0	 = (void *)pfn0;		/* cache pfn0	   */
	mp->dmai_roffset = offset;			/* win0 pg0 offset */
	mp->dmai_ndvmapages = MMU_BTOPR(offset + mp->dmai_object.dmao_size);
	return (DDI_SUCCESS);
}

/*
 * px_dma_pgpfn - set up pfnlst array according to pages
 *	VA/size pair: <shadow IO, bypass, peer-to-peer>, or OTYP_PAGES
 */
/*ARGSUSED*/
static int
px_dma_pgpfn(px_t *px_p, ddi_dma_impl_t *mp, uint_t npages)
{
	int i;
	dev_info_t *dip = px_p->px_dip;

	switch (mp->dmai_object.dmao_type) {
	case DMA_OTYP_BUFVADDR:
	case DMA_OTYP_VADDR: {
		page_t **pplist = mp->dmai_object.dmao_obj.virt_obj.v_priv;
		DBG(DBG_DMA_MAP, dip, "shadow pplist=%p, %x pages, pfns=",
		    pplist, npages);
		for (i = 1; i < npages; i++) {
			px_iopfn_t pfn = page_pptonum(pplist[i]);
			PX_SET_MP_PFN1(mp, i, pfn);
			DBG(DBG_DMA_MAP|DBG_CONT, dip, "%x ", pfn);
		}
		DBG(DBG_DMA_MAP|DBG_CONT, dip, "\n");
		}
		break;

	case DMA_OTYP_PAGES: {
		page_t *pp = mp->dmai_object.dmao_obj.pp_obj.pp_pp->p_next;
		DBG(DBG_DMA_MAP, dip, "pp=%p pfns=", pp);
		for (i = 1; i < npages; i++, pp = pp->p_next) {
			px_iopfn_t pfn = page_pptonum(pp);
			PX_SET_MP_PFN1(mp, i, pfn);
			DBG(DBG_DMA_MAP|DBG_CONT, dip, "%x ", pfn);
		}
		DBG(DBG_DMA_MAP|DBG_CONT, dip, "\n");
		}
		break;

	default:	/* check is already done by px_dma_type */
		ASSERT(0);
		break;
	}
	return (DDI_SUCCESS);
}

/*
 * px_dma_vapfn - set up pfnlst array according to VA
 *	VA/size pair: <normal, bypass, peer-to-peer>
 *	pfn0 is skipped as it is already done.
 *	In this case, the cached pfn0 is used to fill pfnlst[0]
 */
static int
px_dma_vapfn(px_t *px_p, ddi_dma_impl_t *mp, uint_t npages)
{
	dev_info_t *dip = px_p->px_dip;
	int i;
	caddr_t vaddr = (caddr_t)mp->dmai_object.dmao_obj.virt_obj.v_as;
	struct hat *hat_p = vaddr ? ((struct as *)vaddr)->a_hat : kas.a_hat;

	vaddr = mp->dmai_object.dmao_obj.virt_obj.v_addr + MMU_PAGE_SIZE;
	for (i = 1; i < npages; i++, vaddr += MMU_PAGE_SIZE) {
		px_iopfn_t pfn = hat_getpfnum(hat_p, vaddr);
		if (pfn == PFN_INVALID)
			goto err_badpfn;
		PX_SET_MP_PFN1(mp, i, pfn);
		DBG(DBG_DMA_BINDH, dip, "px_dma_vapfn: mp=%p pfnlst[%x]=%x\n",
		    mp, i, pfn);
	}
	return (DDI_SUCCESS);
err_badpfn:
	cmn_err(CE_WARN, "%s%d: bad page frame vaddr=%p", NAMEINST(dip), vaddr);
	return (DDI_DMA_NOMAPPING);
}

/*
 * px_dma_pfn - Fills pfn list for all pages being DMA-ed.
 *
 * dependencies:
 *	mp->dmai_ndvmapages	- set to total # of dma pages
 *
 * return value:
 *	DDI_SUCCESS
 *	DDI_DMA_NOMAPPING
 */
int
px_dma_pfn(px_t *px_p, ddi_dma_req_t *dmareq, ddi_dma_impl_t *mp)
{
	uint32_t npages = mp->dmai_ndvmapages;
	int (*waitfp)(caddr_t) = dmareq->dmar_fp;
	int i, ret, peer = PX_DMA_ISPTP(mp);
	int peer32 = PX_DMA_ISPTP32(mp);
	dev_info_t *dip = px_p->px_dip;

	px_pec_t *pec_p = px_p->px_pec_p;
	px_iopfn_t pfn_base = peer32 ? pec_p->pec_base32_pfn :
	    pec_p->pec_base64_pfn;
	px_iopfn_t pfn_last = peer32 ? pec_p->pec_last32_pfn :
	    pec_p->pec_last64_pfn;
	px_iopfn_t pfn_adj = peer ? pfn_base : 0;

	DBG(DBG_DMA_BINDH, dip, "px_dma_pfn: mp=%p pfn0=%x\n",
	    mp, PX_MP_PFN0(mp) - pfn_adj);
	/* 1 page: no array alloc/fill, no mixed mode check */
	if (npages == 1) {
		PX_SET_MP_PFN(mp, 0, PX_MP_PFN0(mp) - pfn_adj);
		return (DDI_SUCCESS);
	}
	/* allocate pfn array */
	if (!(mp->dmai_pfnlst = kmem_alloc(npages * sizeof (px_iopfn_t),
	    waitfp == DDI_DMA_SLEEP ? KM_SLEEP : KM_NOSLEEP))) {
		if (waitfp != DDI_DMA_DONTWAIT)
			ddi_set_callback(waitfp, dmareq->dmar_arg,
			    &px_kmem_clid);
		return (DDI_DMA_NORESOURCES);
	}
	/* fill pfn array */
	PX_SET_MP_PFN(mp, 0, PX_MP_PFN0(mp) - pfn_adj);	/* pfnlst[0] */
	if ((ret = PX_DMA_ISPGPFN(mp) ? px_dma_pgpfn(px_p, mp, npages) :
	    px_dma_vapfn(px_p, mp, npages)) != DDI_SUCCESS)
		goto err;

	/* skip pfn0, check mixed mode and adjust peer to peer pfn */
	for (i = 1; i < npages; i++) {
		px_iopfn_t pfn = PX_GET_MP_PFN1(mp, i);
		if (peer ^ TGT_PFN_INBETWEEN(pfn, pfn_base, pfn_last)) {
			cmn_err(CE_WARN, "%s%d mixed mode DMA %lx %lx",
			    NAMEINST(mp->dmai_rdip), PX_MP_PFN0(mp), pfn);
			ret = DDI_DMA_NOMAPPING;	/* mixed mode */
			goto err;
		}
		DBG(DBG_DMA_MAP, dip,
		    "px_dma_pfn: pfnlst[%x]=%x-%x\n", i, pfn, pfn_adj);
		if (pfn_adj)
			PX_SET_MP_PFN1(mp, i, pfn - pfn_adj);
	}
	return (DDI_SUCCESS);
err:
	px_dma_freepfn(mp);
	return (ret);
}

/*
 * px_dvma_win() - trim requested DVMA size down to window size
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
px_dvma_win(px_t *px_p, ddi_dma_req_t *dmareq, ddi_dma_impl_t *mp)
{
	uint32_t redzone_sz	= PX_HAS_REDZONE(mp) ? MMU_PAGE_SIZE : 0;
	size_t obj_sz		= mp->dmai_object.dmao_size;
	size_t xfer_sz;
	ulong_t pg_off;

	if ((mp->dmai_ndvmapages == 1) && !redzone_sz) {
		mp->dmai_rflags &= ~DDI_DMA_PARTIAL;
		mp->dmai_size = obj_sz;
		mp->dmai_winsize = MMU_PAGE_SIZE;
		mp->dmai_nwin = 1;
		goto done;
	}

	pg_off	= mp->dmai_roffset;
	xfer_sz	= obj_sz + redzone_sz;

	/* include redzone in nocross check */	{
		uint64_t nocross = mp->dmai_attr.dma_attr_seg;
		if (xfer_sz + pg_off - 1 > nocross)
			xfer_sz = nocross - pg_off + 1;
		if (redzone_sz && (xfer_sz <= redzone_sz)) {
			DBG(DBG_DMA_MAP, px_p->px_dip,
			    "nocross too small: "
			    "%lx(%lx)+%lx+%lx < %llx\n",
			    xfer_sz, obj_sz, pg_off, redzone_sz, nocross);
			return (DDI_DMA_TOOBIG);
		}
	}
	xfer_sz -= redzone_sz;		/* restore transfer size  */
	/* check counter max */	{
		uint32_t count_max = mp->dmai_attr.dma_attr_count_max;
		if (xfer_sz - 1 > count_max)
			xfer_sz = count_max + 1;
	}
	if (xfer_sz >= obj_sz) {
		mp->dmai_rflags &= ~DDI_DMA_PARTIAL;
		mp->dmai_size = xfer_sz;
		mp->dmai_winsize = P2ROUNDUP(xfer_sz + pg_off, MMU_PAGE_SIZE);
		mp->dmai_nwin = 1;
		goto done;
	}
	if (!(dmareq->dmar_flags & DDI_DMA_PARTIAL)) {
		DBG(DBG_DMA_MAP, px_p->px_dip, "too big: %lx+%lx+%lx > %lx\n",
		    obj_sz, pg_off, redzone_sz, xfer_sz);
		return (DDI_DMA_TOOBIG);
	}

	xfer_sz = MMU_PTOB(MMU_BTOP(xfer_sz + pg_off)); /* page align */
	mp->dmai_size = xfer_sz - pg_off;	/* 1st window xferrable size */
	mp->dmai_winsize = xfer_sz;		/* redzone not in winsize */
	mp->dmai_nwin = (obj_sz + pg_off + xfer_sz - 1) / xfer_sz;
done:
	mp->dmai_winlst = NULL;
	px_dump_dma_handle(DBG_DMA_MAP, px_p->px_dip, mp);
	return (DDI_SUCCESS);
}

/*
 * fast track cache entry to mmu context, inserts 3 0 bits between
 * upper 6-bits and lower 3-bits of the 9-bit cache entry
 */
#define	MMU_FCE_TO_CTX(i)	(((i) << 3) | ((i) & 0x7) | 0x38)

/*
 * px_dvma_map_fast - attempts to map fast trackable DVMA
 */
/*ARGSUSED*/
int
px_dvma_map_fast(px_mmu_t *mmu_p, ddi_dma_impl_t *mp)
{
	uint_t clustsz = px_dvma_page_cache_clustsz;
	uint_t entries = px_dvma_page_cache_entries;
	io_attributes_t attr = PX_GET_TTE_ATTR(mp->dmai_rflags,
	    mp->dmai_attr.dma_attr_flags);
	int i = mmu_p->mmu_dvma_addr_scan_start;
	uint8_t *lock_addr = mmu_p->mmu_dvma_cache_locks + i;
	px_dvma_addr_t dvma_pg;
	size_t npages = MMU_BTOP(mp->dmai_winsize);
	dev_info_t *dip = mmu_p->mmu_px_p->px_dip;

	extern uint8_t ldstub(uint8_t *);
	ASSERT(MMU_PTOB(npages) == mp->dmai_winsize);
	ASSERT(npages + PX_HAS_REDZONE(mp) <= clustsz);

	for (; i < entries && ldstub(lock_addr); i++, lock_addr++)
		;
	if (i >= entries) {
		lock_addr = mmu_p->mmu_dvma_cache_locks;
		i = 0;
		for (; i < entries && ldstub(lock_addr); i++, lock_addr++)
			;
		if (i >= entries) {
#ifdef	PX_DMA_PROF
			px_dvmaft_exhaust++;
#endif	/* PX_DMA_PROF */
			return (DDI_DMA_NORESOURCES);
		}
	}
	mmu_p->mmu_dvma_addr_scan_start = (i + 1) & (entries - 1);

	i *= clustsz;
	dvma_pg = mmu_p->dvma_base_pg + i;

	if (px_lib_iommu_map(dip, PCI_TSBID(0, i), npages,
	    PX_ADD_ATTR_EXTNS(attr, mp->dmai_bdf), (void *)mp, 0,
	    MMU_MAP_PFN) != DDI_SUCCESS) {
		DBG(DBG_MAP_WIN, dip, "px_dvma_map_fast: "
		    "px_lib_iommu_map failed\n");
		return (DDI_FAILURE);
	}

	if (!PX_MAP_BUFZONE(mp))
		goto done;

	DBG(DBG_MAP_WIN, dip, "px_dvma_map_fast: redzone pg=%x\n", i + npages);

	ASSERT(PX_HAS_REDZONE(mp));

	if (px_lib_iommu_map(dip, PCI_TSBID(0, i + npages), 1,
	    PX_ADD_ATTR_EXTNS(attr, mp->dmai_bdf), (void *)mp, npages - 1,
	    MMU_MAP_PFN) != DDI_SUCCESS) {
		DBG(DBG_MAP_WIN, dip, "px_dvma_map_fast: "
		    "mapping REDZONE page failed\n");

		(void) px_lib_iommu_demap(dip, PCI_TSBID(0, i), npages);
		return (DDI_FAILURE);
	}

done:
#ifdef PX_DMA_PROF
	px_dvmaft_success++;
#endif
	mp->dmai_mapping = mp->dmai_roffset | MMU_PTOB(dvma_pg);
	mp->dmai_offset = 0;
	mp->dmai_flags |= PX_DMAI_FLAGS_FASTTRACK;
	PX_SAVE_MP_TTE(mp, attr);	/* save TTE template for unmapping */
	if (PX_DVMA_DBG_ON(mmu_p))
		px_dvma_alloc_debug(mmu_p, (char *)mp->dmai_mapping,
		    mp->dmai_size, mp);
	return (DDI_SUCCESS);
}

/*
 * px_dvma_map: map non-fasttrack DMA
 *		Use quantum cache if single page DMA.
 */
int
px_dvma_map(ddi_dma_impl_t *mp, ddi_dma_req_t *dmareq, px_mmu_t *mmu_p)
{
	uint_t npages = PX_DMA_WINNPGS(mp);
	px_dvma_addr_t dvma_pg, dvma_pg_index;
	void *dvma_addr;
	io_attributes_t attr = PX_GET_TTE_ATTR(mp->dmai_rflags,
	    mp->dmai_attr.dma_attr_flags);
	int sleep = dmareq->dmar_fp == DDI_DMA_SLEEP ? VM_SLEEP : VM_NOSLEEP;
	dev_info_t *dip = mp->dmai_rdip;
	int	ret = DDI_SUCCESS;

	/*
	 * allocate dvma space resource and map in the first window.
	 * (vmem_t *vmp, size_t size,
	 *	size_t align, size_t phase, size_t nocross,
	 *	void *minaddr, void *maxaddr, int vmflag)
	 */
	if ((npages == 1) && !PX_HAS_REDZONE(mp) && PX_HAS_NOSYSLIMIT(mp)) {
		dvma_addr = vmem_alloc(mmu_p->mmu_dvma_map,
		    MMU_PAGE_SIZE, sleep);
		mp->dmai_flags |= PX_DMAI_FLAGS_VMEMCACHE;
#ifdef	PX_DMA_PROF
		px_dvma_vmem_alloc++;
#endif	/* PX_DMA_PROF */
	} else {
		dvma_addr = vmem_xalloc(mmu_p->mmu_dvma_map,
		    MMU_PTOB(npages + PX_HAS_REDZONE(mp)),
		    MAX(mp->dmai_attr.dma_attr_align, MMU_PAGE_SIZE),
		    0,
		    mp->dmai_attr.dma_attr_seg + 1,
		    (void *)mp->dmai_attr.dma_attr_addr_lo,
		    (void *)(mp->dmai_attr.dma_attr_addr_hi + 1),
		    sleep);
#ifdef	PX_DMA_PROF
		px_dvma_vmem_xalloc++;
#endif	/* PX_DMA_PROF */
	}
	dvma_pg = MMU_BTOP((ulong_t)dvma_addr);
	dvma_pg_index = dvma_pg - mmu_p->dvma_base_pg;
	DBG(DBG_DMA_MAP, dip, "fallback dvma_pages: dvma_pg=%x index=%x\n",
	    dvma_pg, dvma_pg_index);
	if (dvma_pg == 0)
		goto noresource;

	mp->dmai_mapping = mp->dmai_roffset | MMU_PTOB(dvma_pg);
	mp->dmai_offset = 0;
	PX_SAVE_MP_TTE(mp, attr);	/* mp->dmai_tte = tte */

	if ((ret = px_mmu_map_pages(mmu_p,
	    mp, dvma_pg, npages, 0)) != DDI_SUCCESS) {
		if (mp->dmai_flags & PX_DMAI_FLAGS_VMEMCACHE) {
			vmem_free(mmu_p->mmu_dvma_map, (void *)dvma_addr,
			    MMU_PAGE_SIZE);
#ifdef PX_DMA_PROF
			px_dvma_vmem_free++;
#endif /* PX_DMA_PROF */
		} else {
			vmem_xfree(mmu_p->mmu_dvma_map, (void *)dvma_addr,
			    MMU_PTOB(npages + PX_HAS_REDZONE(mp)));
#ifdef PX_DMA_PROF
			px_dvma_vmem_xfree++;
#endif /* PX_DMA_PROF */
		}
	}

	return (ret);
noresource:
	if (dmareq->dmar_fp != DDI_DMA_DONTWAIT) {
		DBG(DBG_DMA_MAP, dip, "dvma_pg 0 - set callback\n");
		ddi_set_callback(dmareq->dmar_fp, dmareq->dmar_arg,
		    &mmu_p->mmu_dvma_clid);
	}
	DBG(DBG_DMA_MAP, dip, "vmem_xalloc - DDI_DMA_NORESOURCES\n");
	return (DDI_DMA_NORESOURCES);
}

void
px_dvma_unmap(px_mmu_t *mmu_p, ddi_dma_impl_t *mp)
{
	px_dvma_addr_t dvma_addr = (px_dvma_addr_t)mp->dmai_mapping;
	px_dvma_addr_t dvma_pg = MMU_BTOP(dvma_addr);
	dvma_addr = MMU_PTOB(dvma_pg);

	if (mp->dmai_flags & PX_DMAI_FLAGS_FASTTRACK) {
		px_iopfn_t index = dvma_pg - mmu_p->dvma_base_pg;
		ASSERT(index % px_dvma_page_cache_clustsz == 0);
		index /= px_dvma_page_cache_clustsz;
		ASSERT(index < px_dvma_page_cache_entries);
		mmu_p->mmu_dvma_cache_locks[index] = 0;
#ifdef	PX_DMA_PROF
		px_dvmaft_free++;
#endif	/* PX_DMA_PROF */
		return;
	}

	if (mp->dmai_flags & PX_DMAI_FLAGS_VMEMCACHE) {
		vmem_free(mmu_p->mmu_dvma_map, (void *)dvma_addr,
		    MMU_PAGE_SIZE);
#ifdef PX_DMA_PROF
		px_dvma_vmem_free++;
#endif /* PX_DMA_PROF */
	} else {
		size_t npages = MMU_BTOP(mp->dmai_winsize) + PX_HAS_REDZONE(mp);
		vmem_xfree(mmu_p->mmu_dvma_map, (void *)dvma_addr,
		    MMU_PTOB(npages));
#ifdef PX_DMA_PROF
		px_dvma_vmem_xfree++;
#endif /* PX_DMA_PROF */
	}
}

/*
 * DVMA mappings may have multiple windows, but each window always have
 * one segment.
 */
int
px_dvma_ctl(dev_info_t *dip, dev_info_t *rdip, ddi_dma_impl_t *mp,
	enum ddi_dma_ctlops cmd, off_t *offp, size_t *lenp, caddr_t *objp,
	uint_t cache_flags)
{
	switch (cmd) {
	default:
		DBG(DBG_DMA_CTL, dip, "unknown command (%x): rdip=%s%d\n",
		    cmd, ddi_driver_name(rdip), ddi_get_instance(rdip));
		break;
	}
	return (DDI_FAILURE);
}

void
px_dma_freewin(ddi_dma_impl_t *mp)
{
	px_dma_win_t *win_p = mp->dmai_winlst, *win2_p;
	for (win2_p = win_p; win_p; win2_p = win_p) {
		win_p = win2_p->win_next;
		kmem_free(win2_p, sizeof (px_dma_win_t) +
		    sizeof (ddi_dma_cookie_t) * win2_p->win_ncookies);
	}
	mp->dmai_nwin = 0;
	mp->dmai_winlst = NULL;
}

/*
 * px_dma_newwin - create a dma window object and cookies
 *
 *	After the initial scan in px_dma_physwin(), which identifies
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
/*ARGSUSED*/
static int
px_dma_newwin(dev_info_t *dip, ddi_dma_req_t *dmareq, ddi_dma_impl_t *mp,
	uint32_t cookie_no, uint32_t start_idx, uint32_t end_idx,
	px_dma_win_t **win_pp, uint64_t count_max, uint64_t bypass)
{
	int (*waitfp)(caddr_t) = dmareq->dmar_fp;
	ddi_dma_cookie_t *cookie_p;
	uint32_t pfn_no = 1;
	px_iopfn_t pfn = PX_GET_MP_PFN(mp, start_idx);
	px_iopfn_t prev_pfn = pfn;
	uint64_t baddr, seg_pfn0 = pfn;
	size_t sz = cookie_no * sizeof (ddi_dma_cookie_t);
	px_dma_win_t *win_p = kmem_zalloc(sizeof (px_dma_win_t) + sz,
	    waitfp == DDI_DMA_SLEEP ? KM_SLEEP : KM_NOSLEEP);
	io_attributes_t	attr = PX_GET_TTE_ATTR(mp->dmai_rflags,
	    mp->dmai_attr.dma_attr_flags);

	if (!win_p)
		goto noresource;

	win_p->win_next = NULL;
	win_p->win_ncookies = cookie_no;
	win_p->win_curseg = 0;	/* start from segment 0 */
	win_p->win_size = MMU_PTOB(end_idx - start_idx + 1);
	/* win_p->win_offset is left uninitialized */

	cookie_p = (ddi_dma_cookie_t *)(win_p + 1);
	start_idx++;
	for (; start_idx <= end_idx; start_idx++, prev_pfn = pfn, pfn_no++) {
		pfn = PX_GET_MP_PFN1(mp, start_idx);
		if ((pfn == prev_pfn + 1) &&
		    (MMU_PTOB(pfn_no + 1) - 1 <= count_max))
			continue;

		/* close up the cookie up to (including) prev_pfn */
		baddr = MMU_PTOB(seg_pfn0);
		if (bypass) {
			if (px_lib_iommu_getbypass(dip, baddr, attr, &baddr)
			    == DDI_SUCCESS)
				baddr = px_lib_ro_bypass(dip, attr, baddr);
			else
				return (DDI_FAILURE);
		}

		MAKE_DMA_COOKIE(cookie_p, baddr, MMU_PTOB(pfn_no));
		DBG(DBG_BYPASS, mp->dmai_rdip, "cookie %p (%x pages)\n",
		    MMU_PTOB(seg_pfn0), pfn_no);

		cookie_p++;	/* advance to next available cookie cell */
		pfn_no = 0;
		seg_pfn0 = pfn;	/* start a new segment from current pfn */
	}

	baddr = MMU_PTOB(seg_pfn0);
	if (bypass) {
		if (px_lib_iommu_getbypass(dip, baddr, attr, &baddr)
		    == DDI_SUCCESS)
			baddr = px_lib_ro_bypass(dip, attr, baddr);
		else
			return (DDI_FAILURE);
	}

	MAKE_DMA_COOKIE(cookie_p, baddr, MMU_PTOB(pfn_no));
	DBG(DBG_BYPASS, mp->dmai_rdip, "cookie %p (%x pages) of total %x\n",
	    MMU_PTOB(seg_pfn0), pfn_no, cookie_no);
#ifdef	DEBUG
	cookie_p++;
	ASSERT((cookie_p - (ddi_dma_cookie_t *)(win_p + 1)) == cookie_no);
#endif	/* DEBUG */
	*win_pp = win_p;
	return (DDI_SUCCESS);
noresource:
	if (waitfp != DDI_DMA_DONTWAIT)
		ddi_set_callback(waitfp, dmareq->dmar_arg, &px_kmem_clid);
	return (DDI_DMA_NORESOURCES);
}

/*
 * px_dma_adjust - adjust 1st and last cookie and window sizes
 *	remove initial dma page offset from 1st cookie and window size
 *	remove last dma page remainder from last cookie and window size
 *	fill win_offset of each dma window according to just fixed up
 *		each window sizes
 *	px_dma_win_t members modified:
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
px_dma_adjust(ddi_dma_req_t *dmareq, ddi_dma_impl_t *mp, px_dma_win_t *win_p)
{
	ddi_dma_cookie_t *cookie_p = (ddi_dma_cookie_t *)(win_p + 1);
	size_t pg_offset = mp->dmai_roffset;
	size_t win_offset = 0;

	cookie_p->dmac_size -= pg_offset;
	cookie_p->dmac_laddress |= pg_offset;
	win_p->win_size -= pg_offset;
	DBG(DBG_BYPASS, mp->dmai_rdip, "pg0 adjust %lx\n", pg_offset);

	mp->dmai_size = win_p->win_size;
	mp->dmai_offset = 0;

	pg_offset += mp->dmai_object.dmao_size;
	pg_offset &= MMU_PAGE_OFFSET;
	if (pg_offset)
		pg_offset = MMU_PAGE_SIZE - pg_offset;
	DBG(DBG_BYPASS, mp->dmai_rdip, "last pg adjust %lx\n", pg_offset);

	for (; win_p->win_next; win_p = win_p->win_next) {
		DBG(DBG_BYPASS, mp->dmai_rdip, "win off %p\n", win_offset);
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
 * px_dma_physwin() - carve up dma windows using physical addresses.
 *	Called to handle mmu bypass and pci peer-to-peer transfers.
 *	Calls px_dma_newwin() to allocate window objects.
 *
 * Dependency: mp->dmai_pfnlst points to an array of pfns
 *
 * 1. Each dma window is represented by a px_dma_win_t object.
 *	The object will be casted to ddi_dma_win_t and returned
 *	to leaf driver through the DDI interface.
 * 2. Each dma window can have several dma segments with each
 *	segment representing a physically contiguous either memory
 *	space (if we are doing an mmu bypass transfer) or pci address
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
 *	mp->dmai_winlst	 - points to a link list of px_dma_win_t objects.
 *		Each px_dma_win_t object on the link list contains
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
 *	Each px_dma_win_t object can theoratically start from any offset
 *	since the mmu is not involved. However, this implementation
 *	always make windows start from page aligned offset (except
 *	the 1st window, which follows the requested offset) due to the
 *	fact that we are handed a pfn list. This does require device's
 *	count_max and attr_seg to be at least MMU_PAGE_SIZE aligned.
 */
int
px_dma_physwin(px_t *px_p, ddi_dma_req_t *dmareq, ddi_dma_impl_t *mp)
{
	uint_t npages = mp->dmai_ndvmapages;
	int ret, sgllen = mp->dmai_attr.dma_attr_sgllen;
	px_iopfn_t pfn_lo, pfn_hi, prev_pfn;
	px_iopfn_t pfn = PX_GET_MP_PFN(mp, 0);
	uint32_t i, win_no = 0, pfn_no = 1, win_pfn0_index = 0, cookie_no = 0;
	uint64_t count_max, bypass_addr = 0;
	px_dma_win_t **win_pp = (px_dma_win_t **)&mp->dmai_winlst;
	ddi_dma_cookie_t *cookie0_p;
	io_attributes_t attr = PX_GET_TTE_ATTR(mp->dmai_rflags,
	    mp->dmai_attr.dma_attr_flags);
	dev_info_t *dip = px_p->px_dip;

	ASSERT(PX_DMA_ISPTP(mp) || PX_DMA_ISBYPASS(mp));
	if (PX_DMA_ISPTP(mp)) { /* ignore sys limits for peer-to-peer */
		ddi_dma_attr_t *dev_attr_p = PX_DEV_ATTR(mp);
		uint64_t nocross = dev_attr_p->dma_attr_seg;
		px_pec_t *pec_p = px_p->px_pec_p;
		px_iopfn_t pfn_last = PX_DMA_ISPTP32(mp) ?
		    pec_p->pec_last32_pfn - pec_p->pec_base32_pfn :
		    pec_p->pec_last64_pfn - pec_p->pec_base64_pfn;

		if (nocross && (nocross < UINT32_MAX))
			return (DDI_DMA_NOMAPPING);
		if (dev_attr_p->dma_attr_align > MMU_PAGE_SIZE)
			return (DDI_DMA_NOMAPPING);
		pfn_lo = MMU_BTOP(dev_attr_p->dma_attr_addr_lo);
		pfn_hi = MMU_BTOP(dev_attr_p->dma_attr_addr_hi);
		pfn_hi = MIN(pfn_hi, pfn_last);
		if ((pfn_lo > pfn_hi) || (pfn < pfn_lo))
			return (DDI_DMA_NOMAPPING);

		count_max = dev_attr_p->dma_attr_count_max;
		count_max = MIN(count_max, nocross);
		/*
		 * the following count_max trim is not done because we are
		 * making sure pfn_lo <= pfn <= pfn_hi inside the loop
		 * count_max=MIN(count_max, MMU_PTOB(pfn_hi - pfn_lo + 1)-1);
		 */
	} else { /* bypass hi/lo/count_max have been processed by attr2hdl() */
		count_max = mp->dmai_attr.dma_attr_count_max;
		pfn_lo = MMU_BTOP(mp->dmai_attr.dma_attr_addr_lo);
		pfn_hi = MMU_BTOP(mp->dmai_attr.dma_attr_addr_hi);

		if (px_lib_iommu_getbypass(dip, MMU_PTOB(pfn),
		    attr, &bypass_addr) != DDI_SUCCESS) {
			DBG(DBG_BYPASS, mp->dmai_rdip,
			    "bypass cookie failure %lx\n", pfn);
			return (DDI_DMA_NOMAPPING);
		}
		pfn = MMU_BTOP(bypass_addr);
	}

	/* pfn: absolute (bypass mode) or relative (p2p mode) */
	for (prev_pfn = pfn, i = 1; i < npages;
	    i++, prev_pfn = pfn, pfn_no++) {
		pfn = PX_GET_MP_PFN1(mp, i);
		if (bypass_addr) {
			if (px_lib_iommu_getbypass(dip, MMU_PTOB(pfn), attr,
			    &bypass_addr) != DDI_SUCCESS) {
				ret = DDI_DMA_NOMAPPING;
				goto err;
			}
			pfn = MMU_BTOP(bypass_addr);
		}
		if ((pfn == prev_pfn + 1) &&
		    (MMU_PTOB(pfn_no + 1) - 1 <= count_max))
			continue;
		if ((pfn < pfn_lo) || (prev_pfn > pfn_hi)) {
			ret = DDI_DMA_NOMAPPING;
			goto err;
		}
		cookie_no++;
		pfn_no = 0;
		if (cookie_no < sgllen)
			continue;

		DBG(DBG_BYPASS, mp->dmai_rdip, "newwin pfn[%x-%x] %x cks\n",
		    win_pfn0_index, i - 1, cookie_no);
		if (ret = px_dma_newwin(dip, dmareq, mp, cookie_no,
		    win_pfn0_index, i - 1, win_pp, count_max, bypass_addr))
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
	DBG(DBG_BYPASS, mp->dmai_rdip, "newwin pfn[%x-%x] %x cks\n",
	    win_pfn0_index, i - 1, cookie_no);
	if (ret = px_dma_newwin(dip, dmareq, mp, cookie_no, win_pfn0_index,
	    i - 1, win_pp, count_max, bypass_addr))
		goto err;
	win_no++;
	px_dma_adjust(dmareq, mp, mp->dmai_winlst);
	mp->dmai_nwin = win_no;
	mp->dmai_rflags |= DDI_DMA_CONSISTENT | DMP_NOSYNC;
	mp->dmai_rflags &= ~DDI_DMA_REDZONE;
	mp->dmai_flags |= PX_DMAI_FLAGS_NOSYNC;
	cookie0_p = (ddi_dma_cookie_t *)(PX_WINLST(mp) + 1);
	mp->dmai_cookie = cookie0_p + 1;
	mp->dmai_curcookie = 1;
	mp->dmai_ncookies = PX_WINLST(mp)->win_ncookies;
	mp->dmai_mapping = cookie0_p->dmac_laddress;

	px_dma_freepfn(mp);
	return (DDI_DMA_MAPPED);
err:
	px_dma_freewin(mp);
	return (ret);
}

int
px_dma_ctl(dev_info_t *dip, dev_info_t *rdip, ddi_dma_impl_t *mp,
	enum ddi_dma_ctlops cmd, off_t *offp, size_t *lenp, caddr_t *objp,
	uint_t cache_flags)
{
	switch (cmd) {
	default:
		DBG(DBG_DMA_CTL, dip, "unknown command (%x): rdip=%s%d\n",
		    cmd, ddi_driver_name(rdip), ddi_get_instance(rdip));
		break;
	}
	return (DDI_FAILURE);
}

static void
px_dvma_debug_init(px_mmu_t *mmu_p)
{
	size_t sz = sizeof (struct px_dvma_rec) * px_dvma_debug_rec;
	ASSERT(MUTEX_HELD(&mmu_p->dvma_debug_lock));
	cmn_err(CE_NOTE, "PCI Express DVMA %p stat ON", mmu_p);

	mmu_p->dvma_alloc_rec = kmem_alloc(sz, KM_SLEEP);
	mmu_p->dvma_free_rec = kmem_alloc(sz, KM_SLEEP);

	mmu_p->dvma_active_list = NULL;
	mmu_p->dvma_alloc_rec_index = 0;
	mmu_p->dvma_free_rec_index = 0;
	mmu_p->dvma_active_count = 0;
}

void
px_dvma_debug_fini(px_mmu_t *mmu_p)
{
	struct px_dvma_rec *prev, *ptr;
	size_t sz = sizeof (struct px_dvma_rec) * px_dvma_debug_rec;
	uint64_t mask = ~(1ull << mmu_p->mmu_inst);
	cmn_err(CE_NOTE, "PCI Express DVMA %p stat OFF", mmu_p);

	if (mmu_p->dvma_alloc_rec) {
		kmem_free(mmu_p->dvma_alloc_rec, sz);
		mmu_p->dvma_alloc_rec = NULL;
	}
	if (mmu_p->dvma_free_rec) {
		kmem_free(mmu_p->dvma_free_rec, sz);
		mmu_p->dvma_free_rec = NULL;
	}

	prev = mmu_p->dvma_active_list;
	if (!prev)
		return;
	for (ptr = prev->next; ptr; prev = ptr, ptr = ptr->next)
		kmem_free(prev, sizeof (struct px_dvma_rec));
	kmem_free(prev, sizeof (struct px_dvma_rec));

	mmu_p->dvma_active_list = NULL;
	mmu_p->dvma_alloc_rec_index = 0;
	mmu_p->dvma_free_rec_index = 0;
	mmu_p->dvma_active_count = 0;

	px_dvma_debug_off &= mask;
	px_dvma_debug_on &= mask;
}

void
px_dvma_alloc_debug(px_mmu_t *mmu_p, char *address, uint_t len,
	ddi_dma_impl_t *mp)
{
	struct px_dvma_rec *ptr;
	mutex_enter(&mmu_p->dvma_debug_lock);

	if (!mmu_p->dvma_alloc_rec)
		px_dvma_debug_init(mmu_p);
	if (PX_DVMA_DBG_OFF(mmu_p)) {
		px_dvma_debug_fini(mmu_p);
		goto done;
	}

	ptr = &mmu_p->dvma_alloc_rec[mmu_p->dvma_alloc_rec_index];
	ptr->dvma_addr = address;
	ptr->len = len;
	ptr->mp = mp;
	if (++mmu_p->dvma_alloc_rec_index == px_dvma_debug_rec)
		mmu_p->dvma_alloc_rec_index = 0;

	ptr = kmem_alloc(sizeof (struct px_dvma_rec), KM_SLEEP);
	ptr->dvma_addr = address;
	ptr->len = len;
	ptr->mp = mp;

	ptr->next = mmu_p->dvma_active_list;
	mmu_p->dvma_active_list = ptr;
	mmu_p->dvma_active_count++;
done:
	mutex_exit(&mmu_p->dvma_debug_lock);
}

void
px_dvma_free_debug(px_mmu_t *mmu_p, char *address, uint_t len,
    ddi_dma_impl_t *mp)
{
	struct px_dvma_rec *ptr, *ptr_save;
	mutex_enter(&mmu_p->dvma_debug_lock);

	if (!mmu_p->dvma_alloc_rec)
		px_dvma_debug_init(mmu_p);
	if (PX_DVMA_DBG_OFF(mmu_p)) {
		px_dvma_debug_fini(mmu_p);
		goto done;
	}

	ptr = &mmu_p->dvma_free_rec[mmu_p->dvma_free_rec_index];
	ptr->dvma_addr = address;
	ptr->len = len;
	ptr->mp = mp;
	if (++mmu_p->dvma_free_rec_index == px_dvma_debug_rec)
		mmu_p->dvma_free_rec_index = 0;

	ptr_save = mmu_p->dvma_active_list;
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
	if (ptr == mmu_p->dvma_active_list)
		mmu_p->dvma_active_list = ptr->next;
	else
		ptr_save->next = ptr->next;
	kmem_free(ptr, sizeof (struct px_dvma_rec));
	mmu_p->dvma_active_count--;
done:
	mutex_exit(&mmu_p->dvma_debug_lock);
}

#ifdef	DEBUG
void
px_dump_dma_handle(uint64_t flag, dev_info_t *dip, ddi_dma_impl_t *hp)
{
	DBG(flag, dip, "mp(%p): flags=%x mapping=%lx xfer_size=%x\n",
	    hp, hp->dmai_inuse, hp->dmai_mapping, hp->dmai_size);
	DBG(flag|DBG_CONT, dip, "\tnpages=%x roffset=%x rflags=%x nwin=%x\n",
	    hp->dmai_ndvmapages, hp->dmai_roffset, hp->dmai_rflags,
	    hp->dmai_nwin);
	DBG(flag|DBG_CONT, dip, "\twinsize=%x tte=%p pfnlst=%p pfn0=%p\n",
	    hp->dmai_winsize, hp->dmai_tte, hp->dmai_pfnlst, hp->dmai_pfn0);
	DBG(flag|DBG_CONT, dip, "\twinlst=%x obj=%p attr=%p ckp=%p\n",
	    hp->dmai_winlst, &hp->dmai_object, &hp->dmai_attr,
	    hp->dmai_cookie);
}
#endif	/* DEBUG */
