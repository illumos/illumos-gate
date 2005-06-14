/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/dada/dada.h>
#include <sys/vtrace.h>

#define	A_TO_TRAN(ap)	((ap)->a_hba_tran)
#define	P_TO_TRAN(pkt)	((pkt)->pkt_address.a_hba_tran)
#define	P_TO_ADDR(pkt)	(&((pkt)->pkt_address))

/*
 * Callback id
 */
uintptr_t	dcd_callback_id = 0L;


struct buf *
dcd_alloc_consistent_buf(struct dcd_address *ap,
	struct buf *in_bp, size_t datalen, uint_t bflags,
	int (*callback)(caddr_t), caddr_t callback_arg)
{

	dev_info_t	*pdip;
	struct	buf 	*bp;
	int		kmflag;


	if (!in_bp) {
		kmflag = (callback == SLEEP_FUNC) ? KM_SLEEP: KM_NOSLEEP;
		if ((bp = getrbuf(kmflag)) == NULL) {
			goto no_resource;
		}
	} else
		bp = in_bp;

	bp->b_un.b_addr = 0;
	if (datalen) {
		pdip = (A_TO_TRAN(ap))->tran_hba_dip;

		if (ddi_iopb_alloc(pdip, (ddi_dma_lim_t *)0, datalen,
			&bp->b_un.b_addr)) {
			if (!in_bp)
				freerbuf(bp);
			goto no_resource;
		}
		bp->b_flags |= bflags;
	}
	bp->b_bcount = datalen;
	bp->b_resid = 0;

	return (bp);

no_resource:
	if (callback != NULL_FUNC && callback != SLEEP_FUNC) {
		ddi_set_callback(callback, callback_arg, &dcd_callback_id);
	}

	return (NULL);
}


void
dcd_free_consistent_buf(struct buf *bp)
{

	if (!bp)
		return;

	if (bp->b_un.b_addr)
		ddi_iopb_free((caddr_t)bp->b_un.b_addr);
	freerbuf(bp);
	if (dcd_callback_id != 0L) {
		ddi_run_callback(&dcd_callback_id);
	}

}

struct dcd_pkt *
dcd_init_pkt(struct dcd_address *ap, struct dcd_pkt *in_pktp,
	struct buf *bp, int cmdlen, int statuslen, int pplen,
	int flags, int (*callback)(caddr_t), caddr_t callback_arg)
{
	struct dcd_pkt *pktp;
	dcd_hba_tran_t	*tranp = ap->a_hba_tran;
	int		(*func)(caddr_t);

#if defined(__i386) || defined(__amd64)
	if (flags & PKT_CONSISTENT_OLD) {
		flags &= ~PKT_CONSISTENT_OLD;
		flags |= PKT_CONSISTENT;
	}
#endif	/* __i386 || __amd64 */

	func = (callback == SLEEP_FUNC) ? SLEEP_FUNC : NULL_FUNC;

	pktp = (*tranp->tran_init_pkt)(ap, in_pktp, bp, cmdlen,
		statuslen, pplen, flags, func, NULL);

	if (pktp == NULL) {
		if (callback != NULL_FUNC && callback != SLEEP_FUNC) {
			ddi_set_callback(callback, callback_arg,
				&dcd_callback_id);
		}
	}

	return (pktp);
}

void
dcd_destroy_pkt(struct dcd_pkt *pkt)
{

	struct dcd_address *ap = P_TO_ADDR(pkt);

	(*A_TO_TRAN(ap)->tran_destroy_pkt)(ap, pkt);

	if (dcd_callback_id != 0L) {
		ddi_run_callback(&dcd_callback_id);
	}

}

struct dcd_pkt *
dcd_resalloc(struct dcd_address *ap, int cmdlen, int statuslen,
	ataopaque_t dmatoken, int (*callback)())
{

	register struct dcd_pkt *pkt;
	register dcd_hba_tran_t	*tranp = ap->a_hba_tran;
	register int		(*func)(caddr_t);


	func = (callback == SLEEP_FUNC) ? SLEEP_FUNC: NULL_FUNC;
	pkt = (*tranp->tran_init_pkt) (ap, NULL, (struct buf *)dmatoken,
		cmdlen, statuslen, 0, 0, func, NULL);

	if (pkt == NULL) {
		if (callback != NULL_FUNC && callback != SLEEP_FUNC) {
			ddi_set_callback(callback, NULL, &dcd_callback_id);
		}
	}
	return (pkt);
}


struct dcd_pkt *
dcd_pktalloc(struct dcd_address *ap, int cmdlen, int statuslen,
	int (*callback)())
{

	struct dcd_pkt 	*pkt;
	struct dcd_hba_tran	*tran = ap->a_hba_tran;
	register int 		(*func)(caddr_t);


	func = (callback == SLEEP_FUNC) ? SLEEP_FUNC: NULL_FUNC;

	pkt = (*tran->tran_init_pkt) (ap, NULL, NULL, cmdlen, statuslen,
		0, 0, func, NULL);
	if (pkt == NULL) {
		if (callback != NULL_FUNC && callback != SLEEP_FUNC) {
			ddi_set_callback(callback, NULL, &dcd_callback_id);
		}
	}
	return (pkt);
}


struct dcd_pkt *
dcd_dmaget(struct dcd_pkt *pkt, ataopaque_t dmatoken, int (*callback)())
{

	struct dcd_pkt *new_pkt;
	register	int	(*func)(caddr_t);

	func = (callback == SLEEP_FUNC) ? SLEEP_FUNC : NULL_FUNC;

	new_pkt = (*P_TO_TRAN(pkt)->tran_init_pkt) (&pkt->pkt_address,
		pkt, (struct buf *)dmatoken, 0, 0, 0, 0, func, NULL);

	ASSERT(new_pkt == pkt || new_pkt == NULL);
	if (new_pkt == NULL) {
		if (callback != NULL_FUNC && callback != SLEEP_FUNC) {
			ddi_set_callback(callback, NULL, &dcd_callback_id);
		}
	}

	return (pkt);
}


/*
 * Generic Resource Allocation Routines
 */

void
dcd_dmafree(struct dcd_pkt *pkt)
{

	register struct dcd_address *ap = P_TO_ADDR(pkt);

	(*A_TO_TRAN(ap)->tran_dmafree)(ap, pkt);

	if (dcd_callback_id != 0L) {
		ddi_run_callback(&dcd_callback_id);
	}

}

void
dcd_sync_pkt(struct dcd_pkt *pkt)
{
	register struct dcd_address *ap = P_TO_ADDR(pkt);

	(*A_TO_TRAN(ap)->tran_sync_pkt) (ap, pkt);
}

void
dcd_resfree(struct dcd_pkt *pkt)
{

	register struct dcd_address *ap = P_TO_ADDR(pkt);

	(*A_TO_TRAN(ap)->tran_destroy_pkt)(ap, pkt);

	if (dcd_callback_id != 0L) {
		ddi_run_callback(&dcd_callback_id);
	}
}
