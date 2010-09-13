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

#ifndef	_SYS_PCI_DMA_H
#define	_SYS_PCI_DMA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

typedef	pfn_t iopfn_t;
#define	MAKE_DMA_COOKIE(cp, address, size)	\
	{					\
		(cp)->dmac_notused = 0;		\
		(cp)->dmac_type = 0;		\
		(cp)->dmac_laddress = (address);	\
		(cp)->dmac_size = (size);	\
	}

#define	HAS_REDZONE(mp)	(((mp)->dmai_rflags & DDI_DMA_REDZONE) ? 1 : 0)

#define	PCI_DMA_HAT_NUM_CB_COOKIES	5

typedef struct pci_dma_hdl {
	ddi_dma_impl_t	pdh_ddi_hdl;
	ddi_dma_attr_t	pdh_attr_dev;
	uint64_t	pdh_sync_buf_pa;
	void		*pdh_cbcookie[PCI_DMA_HAT_NUM_CB_COOKIES];
} pci_dma_hdl_t;

struct pci_dma_impl { /* forthdebug only, keep in sync with ddi_dma_impl_t */
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
	caddr_t		dmai_tte_fdvma;
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

	ddi_dma_attr_t	pdh_attr_dev;
	uint64_t	pdh_sync_buf_pa;
	void		*pdh_cbcookie[PCI_DMA_HAT_NUM_CB_COOKIES];
};

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

#define	MP_PFN0(mp)		((iopfn_t)(mp)->dmai_pfn0)
#define	MP_HAT_CB_COOKIE(mp, i)	((i < PCI_DMA_HAT_NUM_CB_COOKIES)? \
	(((pci_dma_hdl_t *)(mp))->pdh_cbcookie[i]) : NULL)
#define	MP_HAT_CB_COOKIE_PTR(mp, i) \
	((i < PCI_DMA_HAT_NUM_CB_COOKIES)? \
	&(((pci_dma_hdl_t *)(mp))->pdh_cbcookie[i]) : NULL)
#define	WINLST(mp)		((pci_dma_win_t *)(mp)->dmai_winlst)
#define	DEV_ATTR(mp)		(&((pci_dma_hdl_t *)(mp))->pdh_attr_dev)
#define	SYNC_BUF_PA(mp)		(((pci_dma_hdl_t *)(mp))->pdh_sync_buf_pa)
#define	SET_DMAATTR(p, lo, hi, nocross, cntmax)	\
	(p)->dma_attr_addr_lo	= (lo); \
	(p)->dma_attr_addr_hi	= (hi); \
	(p)->dma_attr_seg	= (nocross); \
	(p)->dma_attr_count_max	= (cntmax);

#define	SET_DMAALIGN(p, align) \
	(p)->dma_attr_align = (align);

#define	DMAI_FLAGS_INUSE	0x1
#define	DMAI_FLAGS_BYPASSREQ	0x2
#define	DMAI_FLAGS_PEER_ONLY	0x4
#define	DMAI_FLAGS_NOCTX	0x8
#define	DMAI_FLAGS_DVMA		0x10
#define	DMAI_FLAGS_BYPASS	0x20
#define	DMAI_FLAGS_PEER_TO_PEER	0x40
#define	DMAI_FLAGS_DMA		(DMAI_FLAGS_BYPASS | DMAI_FLAGS_PEER_TO_PEER)
#define	DMAI_FLAGS_DMA_TYPE	(DMAI_FLAGS_DMA | DMAI_FLAGS_DVMA)
#define	DMAI_FLAGS_CONTEXT	0x100
#define	DMAI_FLAGS_FASTTRACK	0x200
#define	DMAI_FLAGS_VMEMCACHE	0x400
#define	DMAI_FLAGS_PGPFN	0x800
#define	DMAI_FLAGS_NOSYSLIMIT	0x1000
#define	DMAI_FLAGS_NOFASTLIMIT	0x2000
#define	DMAI_FLAGS_NOSYNC	0x4000
#define	DMAI_FLAGS_RELOC	0x8000
#define	DMAI_FLAGS_MAPPED	0x10000
#define	DMAI_FLAGS_PRESERVE	(DMAI_FLAGS_PEER_ONLY | DMAI_FLAGS_BYPASSREQ | \
	DMAI_FLAGS_NOSYSLIMIT | DMAI_FLAGS_NOFASTLIMIT | DMAI_FLAGS_NOCTX)

#define	HAS_NOFASTLIMIT(mp)	((mp)->dmai_flags & DMAI_FLAGS_NOFASTLIMIT)
#define	HAS_NOSYSLIMIT(mp)	((mp)->dmai_flags & DMAI_FLAGS_NOSYSLIMIT)
#define	PCI_DMA_ISPEERONLY(mp)	((mp)->dmai_flags & DMAI_FLAGS_PEER_ONLY)
#define	PCI_DMA_ISPGPFN(mp)	((mp)->dmai_flags & DMAI_FLAGS_PGPFN)
#define	PCI_DMA_TYPE(mp)	((mp)->dmai_flags & DMAI_FLAGS_DMA_TYPE)
#define	PCI_DMA_ISDVMA(mp)	(PCI_DMA_TYPE(mp) == DMAI_FLAGS_DVMA)
#define	PCI_DMA_ISBYPASS(mp)	(PCI_DMA_TYPE(mp) == DMAI_FLAGS_BYPASS)
#define	PCI_DMA_ISPTP(mp)	(PCI_DMA_TYPE(mp) == DMAI_FLAGS_PEER_TO_PEER)
#define	PCI_DMA_CANFAST(mp)	(((mp)->dmai_ndvmapages + HAS_REDZONE(mp) \
		<= pci_dvma_page_cache_clustsz) && HAS_NOFASTLIMIT(mp))
#define	PCI_DMA_WINNPGS(mp)	IOMMU_BTOP((mp)->dmai_winsize)
#define	PCI_DMA_CANCACHE(mp)	(!HAS_REDZONE(mp) && \
		(PCI_DMA_WINNPGS(mp) == 1) && HAS_NOSYSLIMIT(mp))
#define	PCI_DMA_CANRELOC(mp)	((mp)->dmai_flags & DMAI_FLAGS_RELOC)
#define	PCI_DMA_ISMAPPED(mp)	((mp)->dmai_flags & DMAI_FLAGS_MAPPED)

#define	PCI_SYNC_FLAG_SZSHIFT	6
#define	PCI_SYNC_FLAG_SIZE	(1 << PCI_SYNC_FLAG_SZSHIFT)
#define	PCI_SYNC_FLAG_FAILED	1
#define	PCI_SYNC_FLAG_LOCKED	2

#define	PCI_DMA_SYNC_DDI_FLAGS	((1 << 16) - 1)	/* Look for only DDI flags  */
#define	PCI_DMA_SYNC_EXT	(1 << 30)	/* enable/disable extension */
#define	PCI_DMA_SYNC_UNBIND	(1 << 28)	/* internal: part of unbind */
#define	PCI_DMA_SYNC_BAR	(1 << 26)	/* wait for all posted sync  */
#define	PCI_DMA_SYNC_POST	(1 << 25)	/* post request and return   */
#define	PCI_DMA_SYNC_PRIVATE	(1 << 24)	/* alloc private sync buffer */
#define	PCI_DMA_SYNC_DURING	(1 << 22)	/* sync in-progress dma */
#define	PCI_DMA_SYNC_BEFORE	(1 << 21)	/* before read or write */
#define	PCI_DMA_SYNC_AFTER	(1 << 20)	/* after read or write  */
#define	PCI_DMA_SYNC_WRITE	(1 << 17)	/* data from device to mem */
#define	PCI_DMA_SYNC_READ	(1 << 16)	/* data from memory to dev */

#define	PCI_FLOW_ID_TO_PA(flow_p, flow_id) \
	((flow_p)->flow_buf_pa + ((flow_id) << PCI_SYNC_FLAG_SZSHIFT))

#define	DEV_NOFASTLIMIT(lo, hi, fastlo, fasthi, align_pg) \
	(((lo) <= (fastlo)) && ((hi) >= (fasthi)) && \
	((align_pg) <= pci_dvma_page_cache_clustsz))

#define	DEV_NOSYSLIMIT(lo, hi, syslo, syshi, align_pg) \
	(((lo) <= (syslo)) && ((hi) >= (syshi)) && (align_pg == 1))

#define	PCI_DMA_NOCTX(rdip) (!pci_use_contexts || (pci_ctx_no_active_flush && \
	ddi_prop_exists(DDI_DEV_T_ANY, rdip, \
		DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "active-dma-flush")))
#define	PCI_DMA_USECTX(mp)	(!(mp->dmai_flags & DMAI_FLAGS_NOCTX))

#define	PCI_DMA_BYPASS_PREFIX(mp, pfn) \
	(PCI_DMA_ISBYPASS(mp) ? COMMON_IOMMU_BYPASS_BASE | \
	(pf_is_memory(pfn) ? 0 : COMMON_IOMMU_BYPASS_NONCACHE) : 0)
#define	PCI_DMA_BADPTP(pfn, attrp) \
	((IOMMU_PTOB(pfn) < attrp->dma_attr_addr_lo) || \
	(IOMMU_PTOB(pfn) > attrp->dma_attr_addr_hi))
#define	PCI_DMA_CURWIN(mp) \
	(((mp)->dmai_offset + (mp)->dmai_roffset) / (mp)->dmai_winsize)

#ifdef PCI_DMA_PROF

/* collect fast track failure statistics */
#define	PCI_DVMA_FASTTRAK_PROF(mp) { \
if ((mp->dmai_ndvmapages + HAS_REDZONE(mp)) > pci_dvma_page_cache_clustsz) \
	pci_dvmaft_npages++; \
else if (!HAS_NOFASTLIMIT(mp)) \
	pci_dvmaft_limit++; \
}

#else /* !PCI_DMA_PROF */

#define	PCI_DVMA_FASTTRAK_PROF(mp)

#endif	/* PCI_DMA_PROF */

typedef struct pci_dma_win {
	struct pci_dma_win *win_next;
	uint32_t win_ncookies;
	uint32_t win_curseg;
	uint64_t win_size;
	uint64_t win_offset;
	/* cookie table: sizeof (ddi_dma_cookie_t) * win_ncookies */
} pci_dma_win_t;

/* dvma debug records */
struct dvma_rec {
	char *dvma_addr;
	uint_t len;
	ddi_dma_impl_t *mp;
	struct dvma_rec *next;
};

typedef struct pbm pbm_t;
extern int pci_dma_sync(dev_info_t *dip, dev_info_t *rdip,
	ddi_dma_handle_t handle, off_t off, size_t len, uint32_t sync_flags);

extern int pci_dma_win(dev_info_t *dip, dev_info_t *rdip,
	ddi_dma_handle_t handle, uint_t win, off_t *offp,
	size_t *lenp, ddi_dma_cookie_t *cookiep, uint_t *ccountp);

extern ddi_dma_impl_t *pci_dma_allocmp(dev_info_t *dip, dev_info_t *rdip,
	int (*waitfp)(caddr_t), caddr_t arg);
extern void pci_dma_freemp(ddi_dma_impl_t *mp);
extern void pci_dma_freepfn(ddi_dma_impl_t *mp);
extern ddi_dma_impl_t *pci_dma_lmts2hdl(dev_info_t *dip, dev_info_t *rdip,
	iommu_t *iommu_p, ddi_dma_req_t *dmareq);
extern int pci_dma_attr2hdl(pci_t *pci_p, ddi_dma_impl_t *mp);
extern uint32_t pci_dma_consist_check(uint32_t req_flags, pbm_t *pbm_p);
extern int pci_dma_type(pci_t *pci_p, ddi_dma_req_t *req, ddi_dma_impl_t *mp);
extern int pci_dma_pfn(pci_t *pci_p, ddi_dma_req_t *req, ddi_dma_impl_t *mp);
extern int pci_dvma_win(pci_t *pci_p, ddi_dma_req_t *r, ddi_dma_impl_t *mp);
extern void pci_dma_freewin(ddi_dma_impl_t *mp);
extern int pci_dvma_map_fast(iommu_t *iommu_p, ddi_dma_impl_t *mp);
extern int pci_dvma_map(ddi_dma_impl_t *mp, ddi_dma_req_t *dmareq,
	iommu_t *iommu_p);
extern void pci_dvma_unmap(iommu_t *iommu_p, ddi_dma_impl_t *mp);
extern void pci_dma_sync_unmap(dev_info_t *dip, dev_info_t *rdip,
	ddi_dma_impl_t *mp);
extern int pci_dma_physwin(pci_t *pci_p, ddi_dma_req_t *dmareq,
	ddi_dma_impl_t *mp);
extern int pci_dvma_ctl(dev_info_t *dip, dev_info_t *rdip,
	ddi_dma_impl_t *mp, enum ddi_dma_ctlops cmd, off_t *offp,
	size_t *lenp, caddr_t *objp, uint_t cache_flags);
extern int pci_dma_ctl(dev_info_t *dip, dev_info_t *rdip,
	ddi_dma_impl_t *mp, enum ddi_dma_ctlops cmd, off_t *offp,
	size_t *lenp, caddr_t *objp, uint_t cache_flags);
extern void pci_vmem_do_free(iommu_t *iommu_p, void *base_addr, size_t npages,
	int vmemcache);

#define	PCI_GET_MP_NCOOKIES(mp)		((mp)->dmai_ncookies)
#define	PCI_SET_MP_NCOOKIES(mp, nc)	((mp)->dmai_ncookies = (nc))
#define	PCI_GET_MP_PFN1_ADDR(mp)	(((iopfn_t *)(mp)->dmai_pfnlst) + 1)

#define	PCI_GET_MP_TTE(tte) \
	(((uint64_t)(uintptr_t)(tte) >> 5) << (32 + 5) | \
	    ((uint32_t)(uintptr_t)(tte)) & 0x12)
#define	PCI_SAVE_MP_TTE(mp, tte)	\
	(mp)->dmai_tte = (caddr_t)(HI32(tte) | ((tte) & 0x12))

#define	PCI_GET_MP_PFN1(mp, page_no) (((iopfn_t *)(mp)->dmai_pfnlst)[page_no])
#define	PCI_GET_MP_PFN(mp, page_no)	((mp)->dmai_ndvmapages == 1 ? \
	(iopfn_t)(mp)->dmai_pfnlst : PCI_GET_MP_PFN1(mp, page_no))

#define	PCI_SET_MP_PFN(mp, page_no, pfn) { \
	if ((mp)->dmai_ndvmapages == 1) { \
		ASSERT(!((page_no) || (mp)->dmai_pfnlst)); \
		(mp)->dmai_pfnlst = (void *)(pfn); \
	} else \
		((iopfn_t *)(mp)->dmai_pfnlst)[page_no] = (iopfn_t)(pfn); \
}
#define	PCI_SET_MP_PFN1(mp, page_no, pfn) { \
	((iopfn_t *)(mp)->dmai_pfnlst)[page_no] = (pfn); \
}

#define	GET_TTE_TEMPLATE(mp) MAKE_TTE_TEMPLATE(PCI_GET_MP_PFN((mp), 0), (mp))

extern int pci_dma_freehdl(dev_info_t *dip, dev_info_t *rdip,
	ddi_dma_handle_t handle);

int pci_dma_handle_clean(dev_info_t *rdip, ddi_dma_handle_t handle);

#if defined(DEBUG)
extern void dump_dma_handle(uint64_t flag, dev_info_t *dip, ddi_dma_impl_t *hp);
#else
#define	dump_dma_handle(flag, dip, hp)
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCI_DMA_H */
