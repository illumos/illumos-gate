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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
		 * ddi_iopb_alloc() is obsolete and we want more flexibility in
		 * controlling the DMA address constraints.
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
		i_ddi_mem_free((caddr_t)bp->b_un.b_addr, 0);
	freerbuf(bp);
	if (scsi_callback_id != 0) {
		ddi_run_callback(&scsi_callback_id);
	}
	TRACE_0(TR_FAC_SCSI_RES, TR_SCSI_FREE_CONSISTENT_BUF_END,
		"scsi_free_consistent_buf_end");
}

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
		pktw = kmem_cache_alloc(tranp->tran_pkt_cache_ptr,
			    kf);
		if (pktw == NULL)
			goto fail1;

		pktw->pcw_kmflags = 0;
		in_pktp = &(pktw->pcw_pkt);
		/*
		 * target drivers should initialize pkt_comp and
		 * pkt_time, but sometimes they don't so initialize
		 * them here to be safe.
		 */
		in_pktp->pkt_address = *ap;
		in_pktp->pkt_flags = 0;
		in_pktp->pkt_time = 0;
		in_pktp->pkt_resid = 0;
		in_pktp->pkt_state = 0;
		in_pktp->pkt_statistics = 0;
		in_pktp->pkt_reason = 0;

		in_pktp->pkt_cdblen = cmdlen;
		if ((tranp->tran_hba_flags & SCSI_HBA_TRAN_CDB) &&
		    (cmdlen > DEFAULT_CDBLEN)) {
			pktw->pcw_kmflags |= NEED_EXT_CDB;
			in_pktp->pkt_cdbp = kmem_alloc(cmdlen, kf);
			if (in_pktp->pkt_cdbp == NULL)
				goto fail2;
		}
		in_pktp->pkt_tgtlen = pplen;
		if (pplen > DEFAULT_PRIVLEN) {
			pktw->pcw_kmflags |= NEED_EXT_TGT;
			in_pktp->pkt_private = kmem_alloc(pplen, kf);
			if (in_pktp->pkt_private == NULL)
				goto fail3;
		}
		in_pktp->pkt_scblen = statuslen;
		if ((tranp->tran_hba_flags & SCSI_HBA_TRAN_SCB) &&
		    (statuslen > DEFAULT_SCBLEN)) {
			pktw->pcw_kmflags |= NEED_EXT_SCB;
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
	}
	if (bp && bp->b_bcount) {
		if ((*tranp->tran_setup_bp) (in_pktp, bp,
		    flags, func, NULL) == -1) {
			scsi_free_cache_pkt(ap, in_pktp);
			in_pktp = NULL;
		}
	}
	return (in_pktp);

fail5:
	if (pktw->pcw_kmflags & NEED_EXT_SCB) {
		kmem_free(in_pktp->pkt_scbp, statuslen);
		in_pktp->pkt_scbp = (opaque_t)((char *)in_pktp +
		    tranp->tran_hba_len + DEFAULT_PRIVLEN +
		    sizeof (struct scsi_pkt));
		if ((A_TO_TRAN(ap))->tran_hba_flags & SCSI_HBA_TRAN_CDB)
			in_pktp->pkt_scbp = (opaque_t)((in_pktp->pkt_scbp) +
				DEFAULT_CDBLEN);
		in_pktp->pkt_scblen = 0;
	}
fail4:
	if (pktw->pcw_kmflags & NEED_EXT_TGT) {
		kmem_free(in_pktp->pkt_private, pplen);
		in_pktp->pkt_tgtlen = 0;
		in_pktp->pkt_private = NULL;
	}
fail3:
	if (pktw->pcw_kmflags & NEED_EXT_CDB) {
		kmem_free(in_pktp->pkt_cdbp, cmdlen);
		in_pktp->pkt_cdbp = (opaque_t)((char *)in_pktp +
		    tranp->tran_hba_len +
		    sizeof (struct scsi_pkt));
		in_pktp->pkt_cdblen = 0;
	}
	pktw->pcw_kmflags &=
	    ~(NEED_EXT_CDB|NEED_EXT_TGT|NEED_EXT_SCB);
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

	/*
	 * if we allocated memory for anything that wouldn't fit, free
	 * the memory and restore the pointers
	 */
	if (pktw->pcw_kmflags & NEED_EXT_SCB) {
		kmem_free(pktp->pkt_scbp, pktp->pkt_scblen);
		pktp->pkt_scbp = (opaque_t)((char *)pktp +
		    (A_TO_TRAN(ap))->tran_hba_len +
		    DEFAULT_PRIVLEN + sizeof (struct scsi_pkt_cache_wrapper));
		if ((A_TO_TRAN(ap))->tran_hba_flags & SCSI_HBA_TRAN_CDB)
			pktp->pkt_scbp = (opaque_t)((pktp->pkt_scbp) +
				DEFAULT_CDBLEN);
		pktp->pkt_scblen = 0;
	}
	if (pktw->pcw_kmflags & NEED_EXT_TGT) {
		kmem_free(pktp->pkt_private, pktp->pkt_tgtlen);
		pktp->pkt_tgtlen = 0;
		pktp->pkt_private = NULL;
	}
	if (pktw->pcw_kmflags & NEED_EXT_CDB) {
		kmem_free(pktp->pkt_cdbp, pktp->pkt_cdblen);
		pktp->pkt_cdbp = (opaque_t)((char *)pktp +
		    (A_TO_TRAN(ap))->tran_hba_len +
		    sizeof (struct scsi_pkt_cache_wrapper));
		pktp->pkt_cdblen = 0;
	}
	pktw->pcw_kmflags &=
	    ~(NEED_EXT_CDB|NEED_EXT_TGT|NEED_EXT_SCB);
	ASSERT(pktw->pcw_kmflags == 0);
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

void
scsi_sync_pkt(struct scsi_pkt *pkt)
{
	register struct scsi_address	*ap = P_TO_ADDR(pkt);
	(*A_TO_TRAN(ap)->tran_sync_pkt)(ap, pkt);
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
