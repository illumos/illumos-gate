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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/scsi/scsi.h>
#include <sys/vtrace.h>


#define	A_TO_TRAN(ap)	((ap)->a_hba_tran)
#define	P_TO_TRAN(pkt)	((pkt)->pkt_address.a_hba_tran)
#define	P_TO_ADDR(pkt)	(&((pkt)->pkt_address))

/*
 * Callback id
 */
uintptr_t scsi_callback_id = 0;

extern ddi_dma_attr_t scsi_alloc_attr;

struct buf *
scsi_alloc_consistent_buf(struct scsi_address *ap,
    struct buf *in_bp, size_t datalen, uint_t bflags,
    int (*callback)(caddr_t), caddr_t callback_arg)
{
	dev_info_t	*pdip;
	struct		buf *bp;
	int		kmflag;
	size_t		rlen;

	TRACE_0(TR_FAC_SCSI_RES, TR_SCSI_ALLOC_CONSISTENT_BUF_START,
	    "scsi_alloc_consistent_buf_start");

	if (!in_bp) {
		kmflag = (callback == SLEEP_FUNC) ? KM_SLEEP : KM_NOSLEEP;
		if ((bp = getrbuf(kmflag)) == NULL) {
			goto no_resource;
		}
	} else {
		bp = in_bp;

		/* we are establishing a new buffer memory association */
		bp->b_flags &= ~(B_PAGEIO | B_PHYS | B_REMAPPED | B_SHADOW);
		bp->b_proc = NULL;
		bp->b_pages = NULL;
		bp->b_shadow = NULL;
	}

	/* limit bits that can be set by bflags argument */
	ASSERT(!(bflags & ~(B_READ | B_WRITE)));
	bflags &= (B_READ | B_WRITE);
	bp->b_un.b_addr = 0;

	if (datalen) {
		pdip = (A_TO_TRAN(ap))->tran_hba_dip;

		/*
		 * use i_ddi_mem_alloc() for now until we have an interface to
		 * allocate memory for DMA which doesn't require a DMA handle.
		 */
		while (i_ddi_mem_alloc(pdip, &scsi_alloc_attr, datalen,
		    ((callback == SLEEP_FUNC) ? 1 : 0), 0, NULL,
		    &bp->b_un.b_addr, &rlen, NULL) != DDI_SUCCESS) {
			if (callback == SLEEP_FUNC) {
				delay(drv_usectohz(10000));
			} else {
				if (!in_bp)
					freerbuf(bp);
				goto no_resource;
			}
		}
		bp->b_flags |= bflags;
	}
	bp->b_bcount = datalen;
	bp->b_resid = 0;

	TRACE_0(TR_FAC_SCSI_RES, TR_SCSI_ALLOC_CONSISTENT_BUF_END,
	    "scsi_alloc_consistent_buf_end");
	return (bp);

no_resource:

	if (callback != NULL_FUNC && callback != SLEEP_FUNC) {
		ddi_set_callback(callback, callback_arg,
		    &scsi_callback_id);
	}
	TRACE_0(TR_FAC_SCSI_RES,
	    TR_SCSI_ALLOC_CONSISTENT_BUF_RETURN1_END,
	    "scsi_alloc_consistent_buf_end (return1)");
	return (NULL);
}

void
scsi_free_consistent_buf(struct buf *bp)
{
	TRACE_0(TR_FAC_SCSI_RES, TR_SCSI_FREE_CONSISTENT_BUF_START,
	    "scsi_free_consistent_buf_start");
	if (!bp)
		return;
	if (bp->b_un.b_addr)
		i_ddi_mem_free((caddr_t)bp->b_un.b_addr, NULL);
	freerbuf(bp);
	if (scsi_callback_id != 0) {
		ddi_run_callback(&scsi_callback_id);
	}
	TRACE_0(TR_FAC_SCSI_RES, TR_SCSI_FREE_CONSISTENT_BUF_END,
	    "scsi_free_consistent_buf_end");
}

void
scsi_dmafree_attr(struct scsi_pkt *pktp)
{
	struct scsi_pkt_cache_wrapper *pktw =
	    (struct scsi_pkt_cache_wrapper *)pktp;

	if (pktw->pcw_flags & PCW_BOUND) {
		if (ddi_dma_unbind_handle(pktp->pkt_handle) !=
		    DDI_SUCCESS)
			cmn_err(CE_WARN, "scsi_dmafree_attr: "
			    "unbind handle failed");
		pktw->pcw_flags &= ~PCW_BOUND;
	}
	pktp->pkt_numcookies = 0;
	pktw->pcw_totalwin = 0;
}

struct buf *
scsi_pkt2bp(struct scsi_pkt *pkt)
{
	return (((struct scsi_pkt_cache_wrapper *)pkt)->pcw_bp);
}

int
scsi_dma_buf_bind_attr(struct scsi_pkt_cache_wrapper *pktw,
			struct buf	*bp,
			int		 dma_flags,
			int		(*callback)(),
			caddr_t		 arg)
{
	struct scsi_pkt *pktp = &(pktw->pcw_pkt);
	int	 status;

	/*
	 * First time, need to establish the handle.
	 */

	ASSERT(pktp->pkt_numcookies == 0);
	ASSERT(pktw->pcw_totalwin == 0);

	status = ddi_dma_buf_bind_handle(pktp->pkt_handle, bp, dma_flags,
	    callback, arg, &pktw->pcw_cookie,
	    &pktp->pkt_numcookies);

	switch (status) {
	case DDI_DMA_MAPPED:
		pktw->pcw_totalwin = 1;
		break;

	case DDI_DMA_PARTIAL_MAP:
		/* enable first call to ddi_dma_getwin */
		if (ddi_dma_numwin(pktp->pkt_handle,
		    &pktw->pcw_totalwin) != DDI_SUCCESS) {
			bp->b_error = 0;
			return (0);
		}
		break;

	case DDI_DMA_NORESOURCES:
		bp->b_error = 0;
		return (0);

	case DDI_DMA_TOOBIG:
		bioerror(bp, EINVAL);
		return (0);

	case DDI_DMA_NOMAPPING:
	case DDI_DMA_INUSE:
	default:
		bioerror(bp, EFAULT);
		return (0);
	}

	/* initialize the loop controls for scsi_dmaget_attr() */
	pktw->pcw_curwin = 0;
	pktw->pcw_total_xfer = 0;
	pktp->pkt_dma_flags = dma_flags;
	return (1);
}

#if defined(_DMA_USES_PHYSADDR)
int
scsi_dmaget_attr(struct scsi_pkt_cache_wrapper *pktw)
{
	struct scsi_pkt *pktp = &(pktw->pcw_pkt);

	int		status;
	int		num_segs = 0;
	ddi_dma_impl_t	*hp = (ddi_dma_impl_t *)pktp->pkt_handle;
	ddi_dma_cookie_t *cp;

	if (pktw->pcw_curwin != 0) {
		ddi_dma_cookie_t	cookie;

		/*
		 * start the next window, and get its first cookie
		 */
		status = ddi_dma_getwin(pktp->pkt_handle,
		    pktw->pcw_curwin, &pktp->pkt_dma_offset,
		    &pktp->pkt_dma_len, &cookie,
		    &pktp->pkt_numcookies);
		if (status != DDI_SUCCESS)
			return (0);
	}

	/*
	 * start the Scatter/Gather loop
	 */
	cp = hp->dmai_cookie - 1;
	pktp->pkt_dma_len = 0;
	for (;;) {

		/* take care of the loop-bookkeeping */
		pktp->pkt_dma_len += cp->dmac_size;
		num_segs++;
		/*
		 * if this was the last cookie in the current window
		 * set the loop controls start the next window and
		 * exit so the HBA can do this partial transfer
		 */
		if (num_segs >= pktp->pkt_numcookies) {
			pktw->pcw_curwin++;
			break;
		}

		cp++;
	}
	pktw->pcw_total_xfer += pktp->pkt_dma_len;
	pktp->pkt_cookies = hp->dmai_cookie - 1;
	hp->dmai_cookie = cp;

	return (1);
}
#endif

void scsi_free_cache_pkt(struct scsi_address *, struct scsi_pkt *);

struct scsi_pkt *
scsi_init_cache_pkt(struct scsi_address *ap, struct scsi_pkt *in_pktp,
    struct buf *bp, int cmdlen, int statuslen, int pplen,
    int flags, int (*callback)(caddr_t), caddr_t callback_arg)
{
	struct scsi_pkt_cache_wrapper *pktw;
	scsi_hba_tran_t *tranp = ap->a_hba_tran;
	int		(*func)(caddr_t);

	func = (callback == SLEEP_FUNC) ? SLEEP_FUNC : NULL_FUNC;

	if (in_pktp == NULL) {
		int kf;

		if (callback == SLEEP_FUNC)
			kf = KM_SLEEP;
		else
			kf = KM_NOSLEEP;
		/*
		 * By using kmem_cache_alloc(), the layout of the
		 * scsi_pkt, scsi_pkt_cache_wrapper, hba private data,
		 * cdb, tgt driver private data, and status block is
		 * as below.
		 *
		 * This is a piece of contiguous memory starting from
		 * the first structure field scsi_pkt in the struct
		 * scsi_pkt_cache_wrapper, followed by the hba private
		 * data, pkt_cdbp, the tgt driver private data and
		 * pkt_scbp.
		 *
		 * |----------------------------|--------------------->
		 * |	struct scsi_pkt		|	struct
		 * |	......			|scsi_pkt_cache_wrapper
		 * |	pcw_flags		|
		 * |----------------------------|<---------------------
		 * |	hba private data	|tranp->tran_hba_len
		 * |----------------------------|
		 * |	pkt_cdbp		|DEFAULT_CDBLEN
		 * |----------------------------|
		 * |	tgt private data	|DEFAULT_PRIVLEN
		 * |----------------------------|
		 * |	pkt_scbp		|DEFAULT_SCBLEN
		 * |----------------------------|
		 *
		 * If the actual data length of the cdb, or the tgt
		 * driver private data, or the status block is bigger
		 * than the default data length, kmem_alloc() will be
		 * called to get extra space.
		 */
		pktw = kmem_cache_alloc(tranp->tran_pkt_cache_ptr,
		    kf);
		if (pktw == NULL)
			goto fail1;

		pktw->pcw_flags = 0;
		in_pktp = &(pktw->pcw_pkt);
		in_pktp->pkt_address = *ap;

		/*
		 * target drivers should initialize pkt_comp and
		 * pkt_time, but sometimes they don't so initialize
		 * them here to be safe.
		 */
		in_pktp->pkt_flags = 0;
		in_pktp->pkt_time = 0;
		in_pktp->pkt_resid = 0;
		in_pktp->pkt_state = 0;
		in_pktp->pkt_statistics = 0;
		in_pktp->pkt_reason = 0;
		in_pktp->pkt_dma_offset = 0;
		in_pktp->pkt_dma_len = 0;
		in_pktp->pkt_dma_flags = 0;
		in_pktp->pkt_path_instance = 0;
		ASSERT(in_pktp->pkt_numcookies == 0);
		pktw->pcw_curwin = 0;
		pktw->pcw_totalwin = 0;
		pktw->pcw_total_xfer = 0;

		in_pktp->pkt_cdblen = cmdlen;
		if ((tranp->tran_hba_flags & SCSI_HBA_TRAN_CDB) &&
		    (cmdlen > DEFAULT_CDBLEN)) {
			pktw->pcw_flags |= PCW_NEED_EXT_CDB;
			in_pktp->pkt_cdbp = kmem_alloc(cmdlen, kf);
			if (in_pktp->pkt_cdbp == NULL)
				goto fail2;
		}
		in_pktp->pkt_tgtlen = pplen;
		if (pplen > DEFAULT_PRIVLEN) {
			pktw->pcw_flags |= PCW_NEED_EXT_TGT;
			in_pktp->pkt_private = kmem_alloc(pplen, kf);
			if (in_pktp->pkt_private == NULL)
				goto fail3;
		}
		in_pktp->pkt_scblen = statuslen;
		if ((tranp->tran_hba_flags & SCSI_HBA_TRAN_SCB) &&
		    (statuslen > DEFAULT_SCBLEN)) {
			pktw->pcw_flags |= PCW_NEED_EXT_SCB;
			in_pktp->pkt_scbp = kmem_alloc(statuslen, kf);
			if (in_pktp->pkt_scbp == NULL)
				goto fail4;
		}
		if ((*tranp->tran_setup_pkt) (in_pktp,
		    func, NULL) == -1) {
				goto fail5;
		}
		if (cmdlen)
			bzero((void *)in_pktp->pkt_cdbp, cmdlen);
		if (pplen)
			bzero((void *)in_pktp->pkt_private, pplen);
		if (statuslen)
			bzero((void *)in_pktp->pkt_scbp, statuslen);
	} else
		pktw = (struct scsi_pkt_cache_wrapper *)in_pktp;

	if (bp && bp->b_bcount) {

		int dma_flags = 0;

		/*
		 * we need to transfer data, so we alloc dma resources
		 * for this packet
		 */
		/*CONSTCOND*/
		ASSERT(SLEEP_FUNC == DDI_DMA_SLEEP);
		/*CONSTCOND*/
		ASSERT(NULL_FUNC == DDI_DMA_DONTWAIT);

#if defined(_DMA_USES_PHYSADDR)
		/*
		 * with an IOMMU we map everything, so we don't
		 * need to bother with this
		 */
		if (tranp->tran_dma_attr.dma_attr_granular !=
		    pktw->pcw_granular) {

			ddi_dma_free_handle(&in_pktp->pkt_handle);
			if (ddi_dma_alloc_handle(tranp->tran_hba_dip,
			    &tranp->tran_dma_attr,
			    func, NULL,
			    &in_pktp->pkt_handle) != DDI_SUCCESS) {

				in_pktp->pkt_handle = NULL;
				return (NULL);
			}
			pktw->pcw_granular =
			    tranp->tran_dma_attr.dma_attr_granular;
		}
#endif

		if (in_pktp->pkt_numcookies == 0) {
			pktw->pcw_bp = bp;
			/*
			 * set dma flags; the "read" case must be first
			 * since B_WRITE isn't always be set for writes.
			 */
			if (bp->b_flags & B_READ) {
				dma_flags |= DDI_DMA_READ;
			} else {
				dma_flags |= DDI_DMA_WRITE;
			}
			if (flags & PKT_CONSISTENT)
				dma_flags |= DDI_DMA_CONSISTENT;
			if (flags & PKT_DMA_PARTIAL)
				dma_flags |= DDI_DMA_PARTIAL;

#if defined(__sparc)
			/*
			 * workaround for byte hole issue on psycho and
			 * schizo pre 2.1
			 */
			if ((bp->b_flags & B_READ) && ((bp->b_flags &
			    (B_PAGEIO|B_REMAPPED)) != B_PAGEIO) &&
			    (((uintptr_t)bp->b_un.b_addr & 0x7) ||
			    ((uintptr_t)bp->b_bcount & 0x7))) {
				dma_flags |= DDI_DMA_CONSISTENT;
			}
#endif
			if (!scsi_dma_buf_bind_attr(pktw, bp,
			    dma_flags, callback, callback_arg)) {
				return (NULL);
			} else {
				pktw->pcw_flags |= PCW_BOUND;
			}
		}

#if defined(_DMA_USES_PHYSADDR)
		if (!scsi_dmaget_attr(pktw)) {
			scsi_dmafree_attr(in_pktp);
			goto fail5;
		}
#else
		in_pktp->pkt_cookies = &pktw->pcw_cookie;
		in_pktp->pkt_dma_len = pktw->pcw_cookie.dmac_size;
		pktw->pcw_total_xfer += in_pktp->pkt_dma_len;
#endif
		ASSERT(in_pktp->pkt_numcookies <=
		    tranp->tran_dma_attr.dma_attr_sgllen);
		ASSERT(pktw->pcw_total_xfer <= bp->b_bcount);
		in_pktp->pkt_resid = bp->b_bcount -
		    pktw->pcw_total_xfer;

		ASSERT((in_pktp->pkt_resid % pktw->pcw_granular) ==
		    0);
	} else {
		/* !bp or no b_bcount */
		in_pktp->pkt_resid = 0;
	}
	return (in_pktp);

fail5:
	if (pktw->pcw_flags & PCW_NEED_EXT_SCB) {
		kmem_free(in_pktp->pkt_scbp, statuslen);
		in_pktp->pkt_scbp = (opaque_t)((char *)in_pktp +
		    tranp->tran_hba_len + DEFAULT_PRIVLEN +
		    sizeof (struct scsi_pkt_cache_wrapper));
		if ((A_TO_TRAN(ap))->tran_hba_flags & SCSI_HBA_TRAN_CDB)
			in_pktp->pkt_scbp = (opaque_t)((in_pktp->pkt_scbp) +
			    DEFAULT_CDBLEN);
		in_pktp->pkt_scblen = 0;
	}
fail4:
	if (pktw->pcw_flags & PCW_NEED_EXT_TGT) {
		kmem_free(in_pktp->pkt_private, pplen);
		in_pktp->pkt_tgtlen = 0;
		in_pktp->pkt_private = NULL;
	}
fail3:
	if (pktw->pcw_flags & PCW_NEED_EXT_CDB) {
		kmem_free(in_pktp->pkt_cdbp, cmdlen);
		in_pktp->pkt_cdbp = (opaque_t)((char *)in_pktp +
		    tranp->tran_hba_len +
		    sizeof (struct scsi_pkt_cache_wrapper));
		in_pktp->pkt_cdblen = 0;
	}
	pktw->pcw_flags &=
	    ~(PCW_NEED_EXT_CDB|PCW_NEED_EXT_TGT|PCW_NEED_EXT_SCB);
fail2:
	kmem_cache_free(tranp->tran_pkt_cache_ptr, pktw);
fail1:
	if (callback != NULL_FUNC && callback != SLEEP_FUNC) {
		ddi_set_callback(callback, callback_arg,
		    &scsi_callback_id);
	}

	return (NULL);
}

void
scsi_free_cache_pkt(struct scsi_address *ap, struct scsi_pkt *pktp)
{
	struct scsi_pkt_cache_wrapper *pktw;

	(*A_TO_TRAN(ap)->tran_teardown_pkt)(pktp);
	pktw = (struct scsi_pkt_cache_wrapper *)pktp;
	if (pktw->pcw_flags & PCW_BOUND)
		scsi_dmafree_attr(pktp);

	/*
	 * if we allocated memory for anything that wouldn't fit, free
	 * the memory and restore the pointers
	 */
	if (pktw->pcw_flags & PCW_NEED_EXT_SCB) {
		kmem_free(pktp->pkt_scbp, pktp->pkt_scblen);
		pktp->pkt_scbp = (opaque_t)((char *)pktp +
		    (A_TO_TRAN(ap))->tran_hba_len +
		    DEFAULT_PRIVLEN + sizeof (struct scsi_pkt_cache_wrapper));
		if ((A_TO_TRAN(ap))->tran_hba_flags & SCSI_HBA_TRAN_CDB)
			pktp->pkt_scbp = (opaque_t)((pktp->pkt_scbp) +
			    DEFAULT_CDBLEN);
		pktp->pkt_scblen = 0;
	}
	if (pktw->pcw_flags & PCW_NEED_EXT_TGT) {
		kmem_free(pktp->pkt_private, pktp->pkt_tgtlen);
		pktp->pkt_tgtlen = 0;
		pktp->pkt_private = NULL;
	}
	if (pktw->pcw_flags & PCW_NEED_EXT_CDB) {
		kmem_free(pktp->pkt_cdbp, pktp->pkt_cdblen);
		pktp->pkt_cdbp = (opaque_t)((char *)pktp +
		    (A_TO_TRAN(ap))->tran_hba_len +
		    sizeof (struct scsi_pkt_cache_wrapper));
		pktp->pkt_cdblen = 0;
	}
	pktw->pcw_flags &=
	    ~(PCW_NEED_EXT_CDB|PCW_NEED_EXT_TGT|PCW_NEED_EXT_SCB);
	kmem_cache_free(A_TO_TRAN(ap)->tran_pkt_cache_ptr, pktw);

	if (scsi_callback_id != 0) {
		ddi_run_callback(&scsi_callback_id);
	}

}


struct scsi_pkt *
scsi_init_pkt(struct scsi_address *ap, struct scsi_pkt *in_pktp,
    struct buf *bp, int cmdlen, int statuslen, int pplen,
    int flags, int (*callback)(caddr_t), caddr_t callback_arg)
{
	struct scsi_pkt *pktp;
	scsi_hba_tran_t *tranp = ap->a_hba_tran;
	int		(*func)(caddr_t);

	TRACE_5(TR_FAC_SCSI_RES, TR_SCSI_INIT_PKT_START,
"scsi_init_pkt_start: addr %p in_pktp %p cmdlen %d statuslen %d pplen %d",
	    ap, in_pktp, cmdlen, statuslen, pplen);

#if defined(__i386) || defined(__amd64)
	if (flags & PKT_CONSISTENT_OLD) {
		flags &= ~PKT_CONSISTENT_OLD;
		flags |= PKT_CONSISTENT;
	}
#endif

	func = (callback == SLEEP_FUNC) ? SLEEP_FUNC : NULL_FUNC;

	pktp = (*tranp->tran_init_pkt) (ap, in_pktp, bp, cmdlen,
	    statuslen, pplen, flags, func, NULL);
	if (pktp == NULL) {
		if (callback != NULL_FUNC && callback != SLEEP_FUNC) {
			ddi_set_callback(callback, callback_arg,
			    &scsi_callback_id);
		}
	}

	TRACE_1(TR_FAC_SCSI_RES, TR_SCSI_INIT_PKT_END,
	    "scsi_init_pkt_end: pktp %p", pktp);
	return (pktp);
}

void
scsi_destroy_pkt(struct scsi_pkt *pkt)
{
	struct scsi_address	*ap = P_TO_ADDR(pkt);

	TRACE_1(TR_FAC_SCSI_RES, TR_SCSI_DESTROY_PKT_START,
	    "scsi_destroy_pkt_start: pkt %p", pkt);

	(*A_TO_TRAN(ap)->tran_destroy_pkt)(ap, pkt);

	if (scsi_callback_id != 0) {
		ddi_run_callback(&scsi_callback_id);
	}

	TRACE_0(TR_FAC_SCSI_RES, TR_SCSI_DESTROY_PKT_END,
	    "scsi_destroy_pkt_end");
}


/*
 *	Generic Resource Allocation Routines
 */

struct scsi_pkt *
scsi_resalloc(struct scsi_address *ap, int cmdlen, int statuslen,
    opaque_t dmatoken, int (*callback)())
{
	register struct	scsi_pkt *pkt;
	register scsi_hba_tran_t *tranp = ap->a_hba_tran;
	register int			(*func)(caddr_t);

	func = (callback == SLEEP_FUNC) ? SLEEP_FUNC : NULL_FUNC;

	pkt = (*tranp->tran_init_pkt) (ap, NULL, (struct buf *)dmatoken,
	    cmdlen, statuslen, 0, 0, func, NULL);
	if (pkt == NULL) {
		if (callback != NULL_FUNC && callback != SLEEP_FUNC) {
			ddi_set_callback(callback, NULL, &scsi_callback_id);
		}
	}

	return (pkt);
}

struct scsi_pkt *
scsi_pktalloc(struct scsi_address *ap, int cmdlen, int statuslen,
    int (*callback)())
{
	struct scsi_pkt		*pkt;
	struct scsi_hba_tran	*tran = ap->a_hba_tran;
	register int			(*func)(caddr_t);

	func = (callback == SLEEP_FUNC) ? SLEEP_FUNC : NULL_FUNC;

	pkt = (*tran->tran_init_pkt) (ap, NULL, NULL, cmdlen,
	    statuslen, 0, 0, func, NULL);
	if (pkt == NULL) {
		if (callback != NULL_FUNC && callback != SLEEP_FUNC) {
			ddi_set_callback(callback, NULL, &scsi_callback_id);
		}
	}

	return (pkt);
}

struct scsi_pkt *
scsi_dmaget(struct scsi_pkt *pkt, opaque_t dmatoken, int (*callback)())
{
	struct scsi_pkt		*new_pkt;
	register int		(*func)(caddr_t);

	func = (callback == SLEEP_FUNC) ? SLEEP_FUNC : NULL_FUNC;

	new_pkt = (*P_TO_TRAN(pkt)->tran_init_pkt) (&pkt->pkt_address,
	    pkt, (struct buf *)dmatoken,
	    0, 0, 0, 0, func, NULL);
	ASSERT(new_pkt == pkt || new_pkt == NULL);
	if (new_pkt == NULL) {
		if (callback != NULL_FUNC && callback != SLEEP_FUNC) {
			ddi_set_callback(callback, NULL, &scsi_callback_id);
		}
	}

	return (new_pkt);
}


/*
 *	Generic Resource Deallocation Routines
 */

void
scsi_dmafree(struct scsi_pkt *pkt)
{
	register struct scsi_address	*ap = P_TO_ADDR(pkt);

	(*A_TO_TRAN(ap)->tran_dmafree)(ap, pkt);

	if (scsi_callback_id != 0) {
		ddi_run_callback(&scsi_callback_id);
	}
}

/*ARGSUSED*/
void
scsi_cache_dmafree(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	ASSERT(pkt->pkt_numcookies == 0 ||
	    ((struct scsi_pkt_cache_wrapper *)pkt)->pcw_flags & PCW_BOUND);
	ASSERT(pkt->pkt_handle != NULL);
	scsi_dmafree_attr(pkt);

	if (scsi_callback_id != 0) {
		ddi_run_callback(&scsi_callback_id);
	}
}

void
scsi_sync_pkt(struct scsi_pkt *pkt)
{
	register struct scsi_address	*ap = P_TO_ADDR(pkt);

	if (pkt->pkt_state & STATE_XFERRED_DATA)
		(*A_TO_TRAN(ap)->tran_sync_pkt)(ap, pkt);
}

/*ARGSUSED*/
void
scsi_sync_cache_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	if (pkt->pkt_handle &&
	    (pkt->pkt_dma_flags & (DDI_DMA_WRITE | DDI_DMA_READ))) {
		(void) ddi_dma_sync(pkt->pkt_handle,
		    pkt->pkt_dma_offset, pkt->pkt_dma_len,
		    (pkt->pkt_dma_flags & DDI_DMA_WRITE) ?
		    DDI_DMA_SYNC_FORDEV : DDI_DMA_SYNC_FORCPU);
	}
}

void
scsi_resfree(struct scsi_pkt *pkt)
{
	register struct scsi_address	*ap = P_TO_ADDR(pkt);
	(*A_TO_TRAN(ap)->tran_destroy_pkt)(ap, pkt);

	if (scsi_callback_id != 0) {
		ddi_run_callback(&scsi_callback_id);
	}
}
