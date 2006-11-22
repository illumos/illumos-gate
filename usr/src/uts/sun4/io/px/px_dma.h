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

#ifndef	_SYS_PX_DMA_H
#define	_SYS_PX_DMA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

typedef	pfn_t px_iopfn_t;

#define	MAKE_DMA_COOKIE(cp, address, size)	\
	{					\
		(cp)->dmac_notused = 0;		\
		(cp)->dmac_type = 0;		\
		(cp)->dmac_laddress = (address);	\
		(cp)->dmac_size = (size);	\
	}

#define	PX_HAS_REDZONE(mp)	\
	(((mp)->dmai_flags & PX_DMAI_FLAGS_REDZONE) ? 1 : 0)
#define	PX_MAP_BUFZONE(mp)	\
	(((mp)->dmai_flags & PX_DMAI_FLAGS_MAP_BUFZONE) ? 1 :0)

typedef struct px_dma_hdl {
	ddi_dma_impl_t	pdh_ddi_hdl;
	ddi_dma_attr_t	pdh_attr_dev;
} px_dma_hdl_t;

struct px_dma_impl { /* forthdebug only, keep in sync with ddi_dma_impl_t */
	ulong_t		dmai_mapping;
	uint_t		dmai_size;
	off_t		dmai_offset;
	uint_t		dmai_minxfer;
	uint_t		dmai_burstsizes;
	uint_t		dmai_ndvmapages;
	uint_t		dmai_roffset;
	uint_t		dmai_rflags;
	uint_t		dmai_flags;
	uint_t		dmai_nwin;
	uint_t		dmai_winsize;
	caddr_t		dmai_tte;
	void		*dmai_pfnlst;
	uint_t		*dmai_pfn0;
	void		*dmai_winlst;
	dev_info_t	*dmai_rdip;
	ddi_dma_obj_t	dmai_object;
	ddi_dma_attr_t	dmai_attr_aug;
	ddi_dma_cookie_t *dmai_cookie;

	int		(*dmai_fault_check)(struct ddi_dma_impl *handle);
	void		(*dmai_fault_notify)(struct ddi_dma_impl *handle);
	int		dmai_fault;

	ddi_dma_attr_t	dmai_attr_dev;
};

/* Included in case other px-specific flags are added later. */
#define	PX_DMA_SYNC_DDI_FLAGS	((1 << 16) - 1)	/* Look for only DDI flags */

/*
 * flags for overloading dmai_inuse field of the dma request
 * structure:
 */
#define	dmai_flags		dmai_inuse
#define	dmai_tte		dmai_nexus_private
#define	dmai_fdvma		dmai_nexus_private
#define	dmai_pfnlst		dmai_iopte
#define	dmai_winlst		dmai_minfo
#define	dmai_pfn0		dmai_sbi
#define	dmai_roffset		dmai_pool
#define	dmai_bdf		dmai_minxfer
#define	PX_MP_PFN0(mp)		((px_iopfn_t)(mp)->dmai_pfn0)
#define	PX_WINLST(mp)		((px_dma_win_t *)(mp)->dmai_winlst)
#define	PX_DEV_ATTR(mp)		((ddi_dma_attr_t *)(mp + 1))
#define	SET_DMAATTR(p, lo, hi, nocross, cntmax)	\
	(p)->dma_attr_addr_lo	= (lo); \
	(p)->dma_attr_addr_hi	= (hi); \
	(p)->dma_attr_seg	= (nocross); \
	(p)->dma_attr_count_max	= (cntmax);

#define	SET_DMAALIGN(p, align)	\
	(p)->dma_attr_align = (align);

#define	PX_DMAI_FLAGS_INUSE		0x1
#define	PX_DMAI_FLAGS_BYPASSREQ		0x2
#define	PX_DMAI_FLAGS_PEER_ONLY		0x4
#define	PX_DMAI_FLAGS_NOCTX		0x8
#define	PX_DMAI_FLAGS_DVMA		0x10
#define	PX_DMAI_FLAGS_BYPASS		0x20
#define	PX_DMAI_FLAGS_PTP		0x40
#define	PX_DMAI_FLAGS_DMA	(PX_DMAI_FLAGS_BYPASS | PX_DMAI_FLAGS_PTP)
#define	PX_DMAI_FLAGS_DMA_TYPE	(PX_DMAI_FLAGS_DMA | PX_DMAI_FLAGS_DVMA)
#define	PX_DMAI_FLAGS_CONTEXT		0x100
#define	PX_DMAI_FLAGS_FASTTRACK		0x200
#define	PX_DMAI_FLAGS_VMEMCACHE		0x400
#define	PX_DMAI_FLAGS_PGPFN		0x800
#define	PX_DMAI_FLAGS_NOSYSLIMIT	0x1000
#define	PX_DMAI_FLAGS_NOFASTLIMIT	0x2000
#define	PX_DMAI_FLAGS_NOSYNC		0x4000
#define	PX_DMAI_FLAGS_PTP32		0x10000
#define	PX_DMAI_FLAGS_PTP64		0x20000
/*
 * #define PX_DMAI_FLAGS_MAP_BUFZONE	0x40000
 * See pcie_impl.h
 */
#define	PX_DMAI_FLAGS_REDZONE		0x80000
#define	PX_DMAI_FLAGS_PRESERVE	(PX_DMAI_FLAGS_PEER_ONLY | \
	PX_DMAI_FLAGS_BYPASSREQ | PX_DMAI_FLAGS_NOSYSLIMIT | \
	PX_DMAI_FLAGS_NOFASTLIMIT | PX_DMAI_FLAGS_NOCTX | \
	PX_DMAI_FLAGS_MAP_BUFZONE | PX_DMAI_FLAGS_REDZONE)

#define	PX_HAS_NOFASTLIMIT(mp)	((mp)->dmai_flags & PX_DMAI_FLAGS_NOFASTLIMIT)
#define	PX_HAS_NOSYSLIMIT(mp)	((mp)->dmai_flags & PX_DMAI_FLAGS_NOSYSLIMIT)
#define	PX_DMA_ISPEERONLY(mp)	((mp)->dmai_flags & PX_DMAI_FLAGS_PEER_ONLY)
#define	PX_DMA_ISPGPFN(mp)	((mp)->dmai_flags & PX_DMAI_FLAGS_PGPFN)
#define	PX_DMA_TYPE(mp)	((mp)->dmai_flags & PX_DMAI_FLAGS_DMA_TYPE)
#define	PX_DMA_ISDVMA(mp)	(PX_DMA_TYPE(mp) == PX_DMAI_FLAGS_DVMA)
#define	PX_DMA_ISBYPASS(mp)	(PX_DMA_TYPE(mp) == PX_DMAI_FLAGS_BYPASS)
#define	PX_DMA_ISPTP(mp)	(PX_DMA_TYPE(mp) == PX_DMAI_FLAGS_PTP)
#define	PX_DMA_ISPTP32(mp)	((mp)->dmai_flags & PX_DMAI_FLAGS_PTP32)
#define	PX_DMA_ISPTP64(mp)	((mp)->dmai_flags & PX_DMAI_FLAGS_PTP64)
#define	PX_DMA_CANFAST(mp)	(((mp)->dmai_ndvmapages + PX_HAS_REDZONE(mp) \
		<= px_dvma_page_cache_clustsz) && PX_HAS_NOFASTLIMIT(mp))
#define	PX_DMA_WINNPGS(mp)	MMU_BTOP((mp)->dmai_winsize)
#define	PX_DMA_CANCACHE(mp)	(!PX_HAS_REDZONE(mp) && \
		(PX_DMA_WINNPGS(mp) == 1) && PX_HAS_NOSYSLIMIT(mp))

#define	PX_DEV_NOFASTLIMIT(lo, hi, fastlo, fasthi, align_pg) \
	(((lo) <= (fastlo)) && ((hi) >= (fasthi)) && \
	((align_pg) <= px_dvma_page_cache_clustsz))

#define	PX_DEV_NOSYSLIMIT(lo, hi, syslo, syshi, align_pg) \
	(((lo) <= (syslo)) && ((hi) >= (syshi)) && (align_pg == 1))

#define	PX_DMA_NOCTX(rdip) (!px_use_contexts || (px_ctx_no_active_flush && \
	ddi_prop_exists(DDI_DEV_T_ANY, rdip, \
		DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "active-dma-flush")))
#define	PX_DMA_USECTX(mp)	(!(mp->dmai_flags & DMAI_FLAGS_NOCTX))

#define	PX_DMA_BADPTP(pfn, attrp) \
	((IOMMU_PTOB(pfn) < attrp->dma_attr_addr_lo) || \
	(IOMMU_PTOB(pfn) > attrp->dma_attr_addr_hi))
#define	PX_DMA_CURWIN(mp) \
	(((mp)->dmai_offset + (mp)->dmai_roffset) / (mp)->dmai_winsize)

#ifdef PX_DMA_PROF

/* collect fast track failure statistics */
#define	PX_DVMA_FASTTRAK_PROF(mp) { \
if ((mp->dmai_ndvmapages + PX_HAS_REDZONE(mp)) > px_dvma_page_cache_clustsz) \
	px_dvmaft_npages++; \
else if (!PX_HAS_NOFASTLIMIT(mp)) \
	px_dvmaft_limit++; \
}

#else /* !PX_DMA_PROF */

#define	PX_DVMA_FASTTRAK_PROF(mp)

#endif	/* PX_DMA_PROF */

typedef struct px_dma_win {
	struct px_dma_win *win_next;
	uint32_t win_ncookies;
	uint32_t win_curseg;
	uint64_t win_size;
	uint64_t win_offset;
	/* cookie table: sizeof (ddi_dma_cookie_t) * win_ncookies */
} px_dma_win_t;

/* dvma debug records */
struct px_dvma_rec {
	char *dvma_addr;
	uint_t len;
	ddi_dma_impl_t *mp;
	struct px_dvma_rec *next;
};

extern int px_dma_attach(px_t *px_p);
extern int px_dma_win(dev_info_t *dip, dev_info_t *rdip,
	ddi_dma_handle_t handle, uint_t win, off_t *offp,
	size_t *lenp, ddi_dma_cookie_t *cookiep, uint_t *ccountp);

extern ddi_dma_impl_t *px_dma_allocmp(dev_info_t *dip, dev_info_t *rdip,
	int (*waitfp)(caddr_t), caddr_t arg);
extern void px_dma_freemp(ddi_dma_impl_t *mp);
extern void px_dma_freepfn(ddi_dma_impl_t *mp);
extern ddi_dma_impl_t *px_dma_lmts2hdl(dev_info_t *dip, dev_info_t *rdip,
	px_mmu_t *mmu_p, ddi_dma_req_t *dmareq);
extern int px_dma_attr2hdl(px_t *px_p, ddi_dma_impl_t *mp);
extern int px_dma_type(px_t *px_p, ddi_dma_req_t *req, ddi_dma_impl_t *mp);
extern int px_dma_pfn(px_t *px_p, ddi_dma_req_t *req, ddi_dma_impl_t *mp);
extern int px_dvma_win(px_t *px_p, ddi_dma_req_t *r, ddi_dma_impl_t *mp);
extern void px_dma_freewin(ddi_dma_impl_t *mp);
extern int px_dvma_map_fast(px_mmu_t *mmu_p, ddi_dma_impl_t *mp);
extern int px_dvma_map(ddi_dma_impl_t *mp, ddi_dma_req_t *dmareq,
	px_mmu_t *mmu_p);
extern void px_dvma_unmap(px_mmu_t *mmu_p, ddi_dma_impl_t *mp);
extern int px_dma_physwin(px_t *px_p, ddi_dma_req_t *dmareq,
	ddi_dma_impl_t *mp);
extern int px_dvma_ctl(dev_info_t *dip, dev_info_t *rdip,
	ddi_dma_impl_t *mp, enum ddi_dma_ctlops cmd, off_t *offp,
	size_t *lenp, caddr_t *objp, uint_t cache_flags);
extern int px_dma_ctl(dev_info_t *dip, dev_info_t *rdip,
	ddi_dma_impl_t *mp, enum ddi_dma_ctlops cmd, off_t *offp,
	size_t *lenp, caddr_t *objp, uint_t cache_flags);

#define	PX_GET_MP_NCOOKIES(mp)		((mp)->dmai_ncookies)
#define	PX_SET_MP_NCOOKIES(mp, nc)	((mp)->dmai_ncookies = (nc))
#define	PX_GET_MP_PFN1_ADDR(mp)	(((px_iopfn_t *)(mp)->dmai_pfnlst) + 1)

#define	PX_GET_MP_TTE(tte) \
	(((uint64_t)(uintptr_t)(tte) >> 5) << (32 + 5) | \
			((uint32_t)(uintptr_t)(tte)) & 0x16)
#define	PX_SAVE_MP_TTE(mp, tte)	\
	(mp)->dmai_tte = (caddr_t)((uintptr_t)HI32(tte) | ((tte) & 0x16))

#define	PX_GET_MP_PFN1(mp, page_no) \
	(((px_iopfn_t *)(mp)->dmai_pfnlst)[page_no])
#define	PX_GET_MP_PFN(mp, page_no)	((mp)->dmai_ndvmapages == 1 ? \
	(px_iopfn_t)(mp)->dmai_pfnlst : PX_GET_MP_PFN1(mp, page_no))

#define	PX_SET_MP_PFN(mp, page_no, pfn) { \
	if ((mp)->dmai_ndvmapages == 1) { \
		ASSERT(!((page_no) || (mp)->dmai_pfnlst)); \
		(mp)->dmai_pfnlst = (void *)(pfn); \
	} else \
		((px_iopfn_t *)(mp)->dmai_pfnlst)[page_no] = \
		    (px_iopfn_t)(pfn);			     \
}
#define	PX_SET_MP_PFN1(mp, page_no, pfn) { \
	((px_iopfn_t *)(mp)->dmai_pfnlst)[page_no] = (pfn); \
}

extern int px_dma_freehdl(dev_info_t *dip, dev_info_t *rdip,
	ddi_dma_handle_t handle);

#if defined(DEBUG)
extern void px_dump_dma_handle(uint64_t flag, dev_info_t *dip,
	ddi_dma_impl_t *hp);
#else
#define	px_dump_dma_handle(flag, dip, hp)
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PX_DMA_H */
