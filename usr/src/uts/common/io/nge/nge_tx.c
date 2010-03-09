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

#include "nge.h"

#define	TXD_OWN		0x80000000
#define	TXD_ERR		0x40000000
#define	TXD_END		0x20000000
#define	TXD_BCNT_MSK	0x00003FFF


#undef	NGE_DBG
#define	NGE_DBG		NGE_DBG_SEND

#define	NGE_TXSWD_RECYCLE(sd)	{\
					(sd)->mp = NULL; \
					(sd)->frags = 0; \
					(sd)->mp_hndl.head = NULL; \
					(sd)->mp_hndl.tail = NULL; \
					(sd)->flags = HOST_OWN; \
				}


static size_t nge_tx_dmah_pop(nge_dmah_list_t *, nge_dmah_list_t *, size_t);
static void nge_tx_dmah_push(nge_dmah_list_t *, nge_dmah_list_t *);


void nge_tx_recycle_all(nge_t *ngep);
#pragma	no_inline(nge_tx_recycle_all)

void
nge_tx_recycle_all(nge_t *ngep)
{
	send_ring_t *srp;
	sw_tx_sbd_t *ssbdp;
	nge_dmah_node_t	*dmah;
	uint32_t slot;
	uint32_t nslots;

	srp = ngep->send;
	nslots = srp->desc.nslots;

	for (slot = 0; slot < nslots; ++slot) {

		ssbdp = srp->sw_sbds + slot;

		DMA_ZERO(ssbdp->desc);

		if (ssbdp->mp != NULL)	{

			for (dmah = ssbdp->mp_hndl.head; dmah != NULL;
			    dmah = dmah->next)
				(void) ddi_dma_unbind_handle(dmah->hndl);

			freemsg(ssbdp->mp);
		}

		NGE_TXSWD_RECYCLE(ssbdp);
	}
	if (ngep->nge_mac_state == NGE_MAC_STARTED &&
	    ngep->resched_needed == 1) {
			ngep->resched_needed = 0;
			mac_tx_update(ngep->mh);
	}

}

static size_t
nge_tx_dmah_pop(nge_dmah_list_t *src, nge_dmah_list_t *dst, size_t num)
{
	nge_dmah_node_t	*node;

	for (node = src->head; node != NULL && --num != 0; node = node->next)
		;

	if (num == 0)	{

		dst->head = src->head;
		dst->tail = node;

		if ((src->head = node->next) == NULL)
			src->tail = NULL;

		node->next = NULL;
	}

	return (num);
}

static void
nge_tx_dmah_push(nge_dmah_list_t *src, nge_dmah_list_t *dst)
{
	if (dst->tail != NULL)
		dst->tail->next = src->head;
	else
		dst->head = src->head;

	dst->tail = src->tail;
}

static void
nge_tx_desc_sync(nge_t *ngep, uint32_t start_index, uint32_t bds, uint_t type)
{
	send_ring_t *srp = ngep->send;
	const size_t txd_size = ngep->desc_attr.txd_size;
	const uint64_t end = srp->desc.nslots * txd_size;
	uint64_t start;
	uint64_t num;

	start = start_index * txd_size;
	num = bds * txd_size;

	if (start + num <= end)
		(void) ddi_dma_sync(srp->desc.dma_hdl, start, num, type);
	else	{

		(void) ddi_dma_sync(srp->desc.dma_hdl, start, 0, type);
		(void) ddi_dma_sync(srp->desc.dma_hdl, 0, start + num - end,
		    type);
	}
}

/*
 * Reclaim the resource after tx's completion
 */
void
nge_tx_recycle(nge_t *ngep, boolean_t is_intr)
{
	int resched;
	uint32_t stflg;
	uint32_t free;
	uint32_t slot;
	uint32_t used;
	uint32_t next;
	uint32_t nslots;
	mblk_t *mp;
	sw_tx_sbd_t *ssbdp;
	void *hw_sbd_p;
	send_ring_t *srp;
	nge_dmah_node_t *dme;
	nge_dmah_list_t dmah;

	srp = ngep->send;

	if (is_intr) {
		if (mutex_tryenter(srp->tc_lock) == 0)
			return;
	} else
		mutex_enter(srp->tc_lock);
	mutex_enter(srp->tx_lock);

	next = srp->tx_next;
	used = srp->tx_flow;
	free = srp->tx_free;

	mutex_exit(srp->tx_lock);

	slot = srp->tc_next;
	nslots = srp->desc.nslots;

	used = nslots - free - used;

	ASSERT(slot == NEXT_INDEX(next, free, nslots));
	if (used == 0) {
		ngep->watchdog = 0;
		mutex_exit(srp->tc_lock);
		return;
	}

	if (used > srp->tx_hwmark && ngep->resched_needed == 0)
		used = srp->tx_hwmark;

	nge_tx_desc_sync(ngep, slot, used, DDI_DMA_SYNC_FORKERNEL);

	/*
	 * Look through the send ring by bd's status part
	 * to find all the bds which has been transmitted sucessfully
	 * then reclaim all resouces associated with these bds
	 */

	mp = NULL;
	dmah.head = NULL;
	dmah.tail = NULL;

	for (free = 0; used-- != 0; slot = NEXT(slot, nslots), ++free)	{

		ssbdp = &srp->sw_sbds[slot];
		hw_sbd_p = DMA_VPTR(ssbdp->desc);

		if (ssbdp->flags == HOST_OWN)
			break;
		stflg = ngep->desc_attr.txd_check(hw_sbd_p);
		if ((stflg & TXD_OWN) != 0)
			break;
		DMA_ZERO(ssbdp->desc);
		if (ssbdp->mp != NULL)	{
			ssbdp->mp->b_next = mp;
			mp = ssbdp->mp;

			if (ssbdp->mp_hndl.head != NULL)
				nge_tx_dmah_push(&ssbdp->mp_hndl, &dmah);
		}

		NGE_TXSWD_RECYCLE(ssbdp);
	}

	/*
	 * We're about to release one or more places :-)
	 * These ASSERTions check that our invariants still hold:
	 * there must always be at least one free place
	 * at this point, there must be at least one place NOT free
	 * we're not about to free more places than were claimed!
	 */

	if (free == 0) {
		mutex_exit(srp->tc_lock);
		return;
	}

	mutex_enter(srp->tx_lock);

	srp->tx_free += free;
	ngep->watchdog = (srp->desc.nslots - srp->tx_free != 0);

	srp->tc_next = slot;

	ASSERT(srp->tx_free <= nslots);
	ASSERT(srp->tc_next == NEXT_INDEX(srp->tx_next, srp->tx_free, nslots));

	resched = (ngep->resched_needed != 0 && srp->tx_hwmark <= srp->tx_free);

	mutex_exit(srp->tx_lock);
	mutex_exit(srp->tc_lock);

	/* unbind/free mblks */

	for (dme = dmah.head; dme != NULL; dme = dme->next)
		(void) ddi_dma_unbind_handle(dme->hndl);
	if (dmah.head != NULL) {
		mutex_enter(&srp->dmah_lock);
		nge_tx_dmah_push(&dmah, &srp->dmah_free);
		mutex_exit(&srp->dmah_lock);
	}
	freemsgchain(mp);

	/*
	 * up to this place, we maybe have reclaim some resouce
	 * if there is a requirement to report to gld, report this.
	 */

	if (resched)
		(void) ddi_intr_trigger_softint(ngep->resched_hdl, NULL);
}

static uint32_t
nge_tx_alloc(nge_t *ngep, uint32_t num)
{
	uint32_t start;
	send_ring_t *srp;

	start = (uint32_t)-1;
	srp = ngep->send;

	mutex_enter(srp->tx_lock);

	if (srp->tx_free < srp->tx_lwmark)	{

		mutex_exit(srp->tx_lock);
		nge_tx_recycle(ngep, B_FALSE);
		mutex_enter(srp->tx_lock);
	}

	if (srp->tx_free >= num)	{

		start = srp->tx_next;

		srp->tx_next = NEXT_INDEX(start, num, srp->desc.nslots);
		srp->tx_free -= num;
		srp->tx_flow += num;
	}

	mutex_exit(srp->tx_lock);
	return (start);
}

static void
nge_tx_start(nge_t *ngep, uint32_t slotnum)
{
	nge_mode_cntl mode_cntl;
	send_ring_t *srp;

	srp = ngep->send;

	/*
	 * Because there can be multiple concurrent threads in
	 * transit through this code, we only want to notify the
	 * hardware once the last one is departing ...
	 */

	mutex_enter(srp->tx_lock);

	srp->tx_flow -= slotnum;
	if (srp->tx_flow == 0) {

		/*
		 * Bump the watchdog counter, thus guaranteeing that it's
		 * nonzero (watchdog activated).  Note that non-synchonised
		 * access here means we may race with the reclaim() code
		 * above, but the outcome will be harmless.  At worst, the
		 * counter may not get reset on a partial reclaim; but the
		 * large trigger threshold makes false positives unlikely
		 */
		if (ngep->watchdog == 0)
			ngep->watchdog = 1;

		mode_cntl.mode_val = nge_reg_get32(ngep, NGE_MODE_CNTL);
		mode_cntl.mode_bits.txdm = NGE_SET;
		mode_cntl.mode_bits.tx_rcom_en = NGE_SET;
		nge_reg_put32(ngep, NGE_MODE_CNTL, mode_cntl.mode_val);
	}
	mutex_exit(srp->tx_lock);
}

static enum send_status
nge_send_copy(nge_t *ngep, mblk_t *mp, send_ring_t *srp);
#pragma	inline(nge_send_copy)

static enum send_status
nge_send_copy(nge_t *ngep, mblk_t *mp, send_ring_t *srp)
{
	size_t totlen;
	size_t mblen;
	uint32_t flags;
	uint32_t bds;
	uint32_t start_index;
	char *txb;
	mblk_t *bp;
	void *hw_sbd_p;
	sw_tx_sbd_t *ssbdp;
	boolean_t tfint;

	mac_hcksum_get(mp, NULL, NULL, NULL, NULL, &flags);
	bds = 0x1;

	if ((uint32_t)-1 == (start_index = nge_tx_alloc(ngep, bds)))
		return (SEND_COPY_FAIL);

	ASSERT(start_index < srp->desc.nslots);

	/*
	 * up to this point, there's nothing that can fail,
	 * so we can go straight to claiming our
	 * already-reserved place son the train.
	 *
	 * This is the point of no return!
	 */

	tfint = ((start_index % ngep->tfint_threshold) == 0);
	bp = mp;
	totlen = 0;
	ssbdp = &srp->sw_sbds[start_index];
	ASSERT(ssbdp->flags == HOST_OWN);

	txb = DMA_VPTR(ssbdp->pbuf);
	totlen = 0;
	for (; bp != NULL; bp = bp->b_cont) {
		if ((mblen = MBLKL(bp)) == 0)
			continue;
		if ((totlen += mblen) <= ngep->max_sdu) {
			bcopy(bp->b_rptr, txb, mblen);
			txb += mblen;
		}
	}

	DMA_SYNC(ssbdp->pbuf, DDI_DMA_SYNC_FORDEV);

	/* Fill & sync hw desc */

	hw_sbd_p = DMA_VPTR(ssbdp->desc);

	ngep->desc_attr.txd_fill(hw_sbd_p, &ssbdp->pbuf.cookie, totlen,
	    flags, B_TRUE, tfint);
	nge_tx_desc_sync(ngep, start_index, bds, DDI_DMA_SYNC_FORDEV);

	ssbdp->flags = CONTROLER_OWN;

	nge_tx_start(ngep, bds);

	/*
	 * The return status indicates that the message can be freed
	 * right away, as we've already copied the contents ...
	 */

	freemsg(mp);
	return (SEND_COPY_SUCESS);
}

/*
 * static enum send_status
 * nge_send_mapped(nge_t *ngep, mblk_t *mp, size_t fragno);
 * #pragma	inline(nge_send_mapped)
 */

static enum send_status
nge_send_mapped(nge_t *ngep, mblk_t *mp, size_t fragno)
{
	int err;
	boolean_t end;
	uint32_t i;
	uint32_t j;
	uint32_t ncookies;
	uint32_t slot;
	uint32_t nslots;
	uint32_t mblen;
	uint32_t flags;
	uint32_t start_index;
	uint32_t end_index;
	mblk_t *bp;
	void *hw_sbd_p;
	send_ring_t *srp;
	nge_dmah_node_t *dmah;
	nge_dmah_node_t	*dmer;
	nge_dmah_list_t dmah_list;
	ddi_dma_cookie_t cookie[NGE_MAX_COOKIES * NGE_MAP_FRAGS];
	boolean_t tfint;

	srp = ngep->send;
	nslots = srp->desc.nslots;

	mutex_enter(&srp->dmah_lock);
	err = nge_tx_dmah_pop(&srp->dmah_free, &dmah_list, fragno);
	mutex_exit(&srp->dmah_lock);

	if (err != 0)	{

		return (SEND_MAP_FAIL);
	}

	/*
	 * Pre-scan the message chain, noting the total number of bytes,
	 * the number of fragments by pre-doing dma addr bind
	 * if the fragment is larger than NGE_COPY_SIZE.
	 * This way has the following advantages:
	 * 1. Acquire the detailed information of resouce
	 *	need to send the message
	 *
	 * 2. If can not pre-apply enough resouce, fails  at once
	 *	and the driver will chose copy way to send out the
	 *	message
	 */

	slot = 0;
	dmah = dmah_list.head;

	mac_hcksum_get(mp, NULL, NULL, NULL, NULL, &flags);

	for (bp = mp; bp != NULL; bp = bp->b_cont)	{

		mblen = MBLKL(bp);
		if (mblen == 0)
			continue;

		err = ddi_dma_addr_bind_handle(dmah->hndl,
		    NULL, (caddr_t)bp->b_rptr, mblen,
		    DDI_DMA_STREAMING | DDI_DMA_WRITE,
		    DDI_DMA_DONTWAIT, NULL, cookie + slot, &ncookies);

		/*
		 * If there can not map successfully, it is uncessary
		 * sending the message by map way. Sending the message
		 * by copy way.
		 *
		 * By referring to intel's suggestion, it is better
		 * the number of cookies should be less than 4.
		 */
		if (err != DDI_DMA_MAPPED || ncookies > NGE_MAX_COOKIES) {
			NGE_DEBUG(("err(%x) map tx bulk fails"
			    " cookie(%x), ncookies(%x)",
			    err, cookie[slot].dmac_laddress, ncookies));
			goto map_fail;
		}

		/*
		 * Check How many bds a cookie will consume
		 */
		for (end_index = slot + ncookies;
		    ++slot != end_index;
		    ddi_dma_nextcookie(dmah->hndl, cookie + slot))
			;

		dmah = dmah->next;
	}

	/*
	 * Now allocate tx descriptors and fill them
	 * IMPORTANT:
	 *	Up to the point where it claims a place, It is impossibel
	 * 	to fail.
	 *
	 * In this version, there's no setup to be done here, and there's
	 * nothing that can fail, so we can go straight to claiming our
	 * already-reserved places on the train.
	 *
	 * This is the point of no return!
	 */


	if ((uint32_t)-1 == (start_index = nge_tx_alloc(ngep, slot)))
		goto map_fail;

	ASSERT(start_index < nslots);

	/* fill&sync hw desc, going in reverse order */

	end = B_TRUE;
	end_index = NEXT_INDEX(start_index, slot - 1, nslots);

	for (i = slot - 1, j = end_index; start_index - j != 0;
	    j = PREV(j, nslots), --i)	{

		tfint = ((j % ngep->tfint_threshold) == 0);
		hw_sbd_p = DMA_VPTR(srp->sw_sbds[j].desc);
		ngep->desc_attr.txd_fill(hw_sbd_p, cookie + i,
		    cookie[i].dmac_size, 0, end, tfint);

		end = B_FALSE;
	}

	hw_sbd_p = DMA_VPTR(srp->sw_sbds[j].desc);
	tfint = ((j % ngep->tfint_threshold) == 0);
	ngep->desc_attr.txd_fill(hw_sbd_p, cookie + i, cookie[i].dmac_size,
	    flags, end, tfint);

	nge_tx_desc_sync(ngep, start_index, slot, DDI_DMA_SYNC_FORDEV);

	/* fill sw desc */

	for (j = start_index; end_index - j != 0; j = NEXT(j, nslots)) {

		srp->sw_sbds[j].flags = CONTROLER_OWN;
	}

	srp->sw_sbds[j].mp = mp;
	srp->sw_sbds[j].mp_hndl = dmah_list;
	srp->sw_sbds[j].frags = (uint32_t)fragno;
	srp->sw_sbds[j].flags = CONTROLER_OWN;

	nge_tx_start(ngep, slot);

	/*
	 * The return status indicates that the message can not be freed
	 * right away, until we can make assure the message has been sent
	 * out sucessfully.
	 */
	return (SEND_MAP_SUCCESS);

map_fail:
	for (dmer = dmah_list.head; dmah - dmer != 0; dmer = dmer->next)
		(void) ddi_dma_unbind_handle(dmer->hndl);

	mutex_enter(&srp->dmah_lock);
	nge_tx_dmah_push(&dmah_list, &srp->dmah_free);
	mutex_exit(&srp->dmah_lock);

	return (SEND_MAP_FAIL);
}

static boolean_t
nge_send(nge_t *ngep, mblk_t *mp)
{
	mblk_t *bp;
	send_ring_t *srp;
	enum send_status status;
	uint32_t mblen = 0;
	uint32_t frags = 0;
	nge_statistics_t *nstp = &ngep->statistics;
	nge_sw_statistics_t *sw_stp = &nstp->sw_statistics;

	ASSERT(mp != NULL);
	ASSERT(ngep->nge_mac_state == NGE_MAC_STARTED);

	srp = ngep->send;
	/*
	 * 1.Check the number of the fragments of the messages
	 * If the total number is larger than 3,
	 * Chose copy way
	 *
	 * 2. Check the length of the message whether is larger than
	 * NGE_TX_COPY_SIZE, if so, choose the map way.
	 */
	for (frags = 0, bp = mp; bp != NULL; bp = bp->b_cont) {
		if (MBLKL(bp) == 0)
			continue;
		frags++;
		mblen += MBLKL(bp);
	}
	if (mblen > (ngep->max_sdu) || mblen == 0) {
		freemsg(mp);
		return (B_TRUE);
	}
	if ((mblen > ngep->param_txbcopy_threshold) &&
	    (frags <= NGE_MAP_FRAGS) &&
	    (srp->tx_free > frags * NGE_MAX_COOKIES)) {
		status = nge_send_mapped(ngep, mp, frags);
		if (status == SEND_MAP_FAIL)
			status = nge_send_copy(ngep, mp, srp);
	} else {
		status = nge_send_copy(ngep, mp, srp);
	}
	if (status == SEND_COPY_FAIL) {
		nge_tx_recycle(ngep, B_FALSE);
		status = nge_send_copy(ngep, mp, srp);
		if (status == SEND_COPY_FAIL) {
			ngep->resched_needed = 1;
			NGE_DEBUG(("nge_send: send fail!"));
			return (B_FALSE);
		}
	}
	/* Update the software statistics */
	sw_stp->obytes += mblen + ETHERFCSL;
	sw_stp->xmit_count ++;

	return (B_TRUE);
}

/*
 * nge_m_tx : Send a chain of packets.
 */
mblk_t *
nge_m_tx(void *arg, mblk_t *mp)
{
	nge_t *ngep = arg;
	mblk_t *next;

	rw_enter(ngep->rwlock, RW_READER);
	ASSERT(mp != NULL);
	if (ngep->nge_chip_state != NGE_CHIP_RUNNING) {
		freemsgchain(mp);
		mp = NULL;
	}
	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;

		if (!nge_send(ngep, mp)) {
			mp->b_next = next;
			break;
		}

		mp = next;
	}
	rw_exit(ngep->rwlock);

	return (mp);
}

/* ARGSUSED */
uint_t
nge_reschedule(caddr_t args1, caddr_t args2)
{
	nge_t *ngep;
	uint_t rslt;

	ngep = (nge_t *)args1;
	rslt = DDI_INTR_UNCLAIMED;

	/*
	 * when softintr is trigged, checking whether this
	 * is caused by our expected interrupt
	 */
	if (ngep->nge_mac_state == NGE_MAC_STARTED &&
	    ngep->resched_needed == 1) {
		ngep->resched_needed = 0;
		++ngep->statistics.sw_statistics.tx_resched;
		mac_tx_update(ngep->mh);
		rslt = DDI_INTR_CLAIMED;
	}
	return (rslt);
}

uint32_t
nge_hot_txd_check(const void *hwd)
{
	uint32_t err_flag;
	const hot_tx_bd * htbdp;

	htbdp = hwd;
	err_flag = htbdp->control_status.cntl_val;
	return (err_flag);
}

uint32_t
nge_sum_txd_check(const void *hwd)
{
	uint32_t err_flag;
	const sum_tx_bd * htbdp;

	htbdp = hwd;
	err_flag = htbdp->control_status.cntl_val;
	return (err_flag);
}


/*
 * Filling the contents of Tx's data descriptor
 * before transmitting.
 */

void
nge_hot_txd_fill(void *hwdesc, const ddi_dma_cookie_t *cookie,
	size_t length, uint32_t sum_flag, boolean_t end, boolean_t tfint)
{
	hot_tx_bd * hw_sbd_p = hwdesc;

	hw_sbd_p->host_buf_addr_hi = cookie->dmac_laddress >> 32;
	hw_sbd_p->host_buf_addr_lo = cookie->dmac_laddress;

	/*
	 * Setting the length of the packet
	 * Note: the length filled in the part should be
	 * the original length subtract 1;
	 */

	hw_sbd_p->control_status.control_sum_bits.bcnt = length - 1;

	/* setting ip checksum */
	if (sum_flag & HCK_IPV4_HDRCKSUM)
		hw_sbd_p->control_status.control_sum_bits.ip_hsum
		    = NGE_SET;
	/* setting tcp checksum */
	if (sum_flag & HCK_FULLCKSUM)
		hw_sbd_p->control_status.control_sum_bits.tcp_hsum
		    = NGE_SET;
	/*
	 * indicating the end of BDs
	 */
	if (tfint)
		hw_sbd_p->control_status.control_sum_bits.inten = NGE_SET;
	if (end)
		hw_sbd_p->control_status.control_sum_bits.end = NGE_SET;

	membar_producer();

	/* pass desc to HW */
	hw_sbd_p->control_status.control_sum_bits.own = NGE_SET;
}

void
nge_sum_txd_fill(void *hwdesc, const ddi_dma_cookie_t *cookie,
	size_t length, uint32_t sum_flag, boolean_t end, boolean_t tfint)
{
	sum_tx_bd * hw_sbd_p = hwdesc;

	hw_sbd_p->host_buf_addr = cookie->dmac_address;

	/*
	 * Setting the length of the packet
	 * Note: the length filled in the part should be
	 * the original length subtract 1;
	 */

	hw_sbd_p->control_status.control_sum_bits.bcnt = length - 1;

	/* setting ip checksum */
	if (sum_flag & HCK_IPV4_HDRCKSUM)
		hw_sbd_p->control_status.control_sum_bits.ip_hsum
		    = NGE_SET;
	/* setting tcp checksum */
	if (sum_flag & HCK_FULLCKSUM)
		hw_sbd_p->control_status.control_sum_bits.tcp_hsum
		    = NGE_SET;
	/*
	 * indicating the end of BDs
	 */
	if (tfint)
		hw_sbd_p->control_status.control_sum_bits.inten = NGE_SET;
	if (end)
		hw_sbd_p->control_status.control_sum_bits.end = NGE_SET;

	membar_producer();

	/* pass desc to HW */
	hw_sbd_p->control_status.control_sum_bits.own = NGE_SET;
}
