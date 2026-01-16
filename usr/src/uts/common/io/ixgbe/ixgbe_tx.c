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
 * Copyright(c) 2007-2010 Intel Corporation. All rights reserved.
 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Nexenta Systems, Inc. All rights reserved.
 * Copyright 2016 OmniTI Computer Consulting, Inc. All rights reserved.
 * Copyright 2021 Joyent, Inc.
 * Copyright 2026 Oxide Computer Company
 */

#include "ixgbe_sw.h"

static int ixgbe_tx_copy(ixgbe_tx_ring_t *, tx_control_block_t **,
    link_list_t *, const void *, size_t);
static int ixgbe_tx_bind(ixgbe_tx_ring_t *, tx_control_block_t **,
    link_list_t *, uint8_t *, size_t);
static uint_t ixgbe_tcb_done(tx_control_block_t *);
static int ixgbe_tx_fill_ring(ixgbe_tx_ring_t *, link_list_t *,
    ixgbe_tx_context_t *, size_t);
static void ixgbe_save_desc(tx_control_block_t *, uint64_t, size_t);
static tx_control_block_t *ixgbe_get_free_list(ixgbe_tx_ring_t *,
    link_list_t *);

static int ixgbe_get_context(mblk_t *, ixgbe_tx_context_t *);
static boolean_t ixgbe_check_context(ixgbe_tx_ring_t *,
    ixgbe_tx_context_t *);
static void ixgbe_fill_context(struct ixgbe_adv_tx_context_desc *,
    ixgbe_tx_context_t *);

/*
 * ixgbe_ring_tx
 *
 * To transmit one mblk through one specified ring.
 *
 * One mblk can consist of several fragments, each fragment
 * will be processed with different methods based on the size.
 * For the fragments with size less than the bcopy threshold,
 * they will be processed by using bcopy; otherwise, they will
 * be processed by using DMA binding.
 *
 * To process the mblk, for each fragment, we pass a pointer to the location
 * of the current transmit control block (tcb) (initialized to NULL) to either
 * ixgbe_tx_copy() or ixgbe_tx_bind() (based on the size of the mblk fragment).
 * ixgbe_tx_copy() and ixgbe_tx_bind() will either continue to use the current
 * if possible, or close out the current tcb, allocate a new tcb, and update
 * the passed location (tx_control_block_t **) to reflect the new current tcb.
 *
 * Since bound mblk fragments require their own tcb, the close, allocate new,
 * and update steps occur on every call to ixgbe_tx_bind(), but since
 * consecutive small mblk fragments can be combined into a single tcb, the
 * close, allocate new, and update steps may not occur on every call to
 * ixgbe_tx_copy(). If the current tcb is already being used to copy data and
 * we call ixgbe_tx_copy(), if there is enough room in the current tcb for
 * the current mblk fragment, we append the data from the mblk fragment. If
 * we call ixgbe_tx_copy() and the current tcb isn't being used to copy (i.e.
 * the previous iteration of the loop called ixgbe_tx_bind()), or doesn't
 * have enough space for the mblk fragment, we close out the current tcb,
 * grab a new tcb from the free list, and update the current tcb to the
 * newly obtained tcb.
 *
 * When LSO (large segment offload) is enabled, we first copy the packet
 * headers (ethernet, IP, and TCP/UDP) into their own descriptor before
 * processing the remainder of the packet. The remaining bytes of the packet
 * are then copied or mapped based on the fragment size as described above.
 *
 * Through the entire processing of a packet, we keep track of the number of
 * DMA descriptors being used (either bound or pre-bound buffers used for
 * copying) by this packet. Each tcb requires at least one DMA descriptor, but
 * may require more than one. When a tcb is closed by ixgbe_tx_bind() or
 * ixgbe_tx_copy(), it does so by calling ixgbe_tcb_done() which returns the
 * number of DMA descriptors that are closed (ready for the HW). Since the
 * hardware limits the number of descriptors that can be used to transmit a
 * single packet, if the total number DMA descriptors required to transmit
 * this packet exceeds this limit, we perform a msgpullup() and try again.
 * Since our DMA attributes limit the number of DMA cookies allowed to
 * map a single span of memory to a value (MAX_COOKIE) less than the
 * maximum number of descriptors allowed for a packet (IXGBE_TX_DESC_LIMIT),
 * as long as sufficient tcbs are available, we should always be able to
 * process a packet that's contained in a single mblk_t (no additional
 * fragments).
 *
 * Once all of the tcbs have been setup, ixgbe_tx_fill_ring() is called to
 * setup the tx ring to transmit the tcbs and then tell the HW to start
 * transmitting. When transmission is complete, an interrupt is triggered
 * which calls the appropriate recycle routine to place the tcbs that were
 * used in transmission back in the free list. We also may also try to
 * recycle any available tcbs when the size of the tcb free list gets low
 * or if the watchdog timer triggers.
 *
 */
mblk_t *
ixgbe_ring_tx(void *arg, mblk_t *orig_mp)
{
	ixgbe_tx_ring_t *tx_ring = (ixgbe_tx_ring_t *)arg;
	ixgbe_t *ixgbe = tx_ring->ixgbe;
	mblk_t *mp = orig_mp;
	mblk_t *pull_mp = NULL;
	tx_control_block_t *tcb;
	size_t mbsize, offset, len;
	uint32_t desc_total;
	uint32_t copy_thresh;
	int desc_num;
	ixgbe_tx_context_t tx_context, *ctx = NULL;
	link_list_t pending_list;
	boolean_t limit_retry = B_FALSE;

	ASSERT(mp->b_next == NULL);

	if ((ixgbe->ixgbe_state & IXGBE_SUSPENDED) ||
	    (ixgbe->ixgbe_state & IXGBE_ERROR) ||
	    (ixgbe->ixgbe_state & IXGBE_OVERTEMP) ||
	    !(ixgbe->ixgbe_state & IXGBE_STARTED) ||
	    ixgbe->link_state != LINK_STATE_UP) {
		freemsg(mp);
		return (NULL);
	}

	copy_thresh = ixgbe->tx_copy_thresh;

	mbsize = msgsize(mp);

	if (ixgbe->tx_hcksum_enable) {
		/*
		 * Retrieve checksum context information from the mblk
		 * that will be used to decide whether/how to fill the
		 * context descriptor.
		 */
		ctx = &tx_context;
		if (ixgbe_get_context(mp, ctx) < 0) {
			freemsg(mp);
			return (NULL);
		}

		/*
		 * If the mblk size exceeds the max size ixgbe could
		 * process, then discard this mblk, and return NULL.
		 */
		if ((ctx->lso_flag &&
		    ((mbsize - ctx->mac_hdr_len) > IXGBE_LSO_MAXLEN)) ||
		    (!ctx->lso_flag &&
		    (mbsize > (ixgbe->max_frame_size - ETHERFCSL)))) {
			freemsg(mp);
			IXGBE_DEBUGLOG_0(ixgbe, "ixgbe_tx: packet oversize");
			return (NULL);
		}
	}

	/*
	 * If we use too many descriptors (see comments below), we may do
	 * pull_mp = msgpullup(orig_mp, -1), and jump back to here. As such,
	 * any time we error return past here, we should check and free
	 * pull_mp if != NULL.
	 */
retry:
	/*
	 * Check and recycle tx descriptors.
	 * The recycle threshold here should be selected carefully
	 */
	if (tx_ring->tbd_free < ixgbe->tx_recycle_thresh) {
		tx_ring->tx_recycle(tx_ring);
	}

	/*
	 * After the recycling, if the tbd_free is less than the
	 * overload_threshold, assert overload, return mp;
	 * and we need to re-schedule the tx again.
	 */
	if (tx_ring->tbd_free < ixgbe->tx_overload_thresh) {
		tx_ring->reschedule = B_TRUE;
		tx_ring->stat_overload++;
		if (pull_mp != NULL)
			freemsg(pull_mp);
		return (orig_mp);
	}

	/*
	 * The pending_list is a linked list that is used to save
	 * the tx control blocks that have packet data processed
	 * but have not put the data to the tx descriptor ring.
	 * It is used to reduce the lock contention of the tx_lock.
	 */
	LINK_LIST_INIT(&pending_list);

	tcb = NULL;
	desc_num = 0;
	desc_total = 0;
	offset = 0;

	/*
	 * For LSO, we always copy the packet header (Ethernet + IP + TCP/UDP)
	 * into a single descriptor separate from the remaining data.
	 */
	if ((ctx != NULL) && ctx->lso_flag) {
		size_t hdr_len;

		hdr_len = ctx->ip_hdr_len + ctx->mac_hdr_len + ctx->l4_hdr_len;

		/*
		 * copy the first hdr_len bytes of mp (i.e. the Ethernet, IP,
		 * and TCP/UDP headers) into tcb.
		 */
		for (len = hdr_len; mp != NULL && len > 0; mp = mp->b_cont) {
			size_t mlen = MBLKL(mp);
			size_t amt = MIN(mlen, len);
			int ret;

			ret = ixgbe_tx_copy(tx_ring, &tcb, &pending_list,
			    mp->b_rptr, amt);
			/*
			 * Since we're trying to copy all of the headers into
			 * a single buffer in a single tcb, if ixgbe_tx_copy()
			 * returns anything but 0, it means either no tcbs
			 * are available (< 0), or while copying, we spilled
			 * over and couldn't fit all the headers into a
			 * single tcb.
			 */
			if (ret != 0) {
				if (ret > 0)
					tx_ring->stat_lso_header_fail++;
				goto tx_failure;
			}

			len -= amt;

			/*
			 * If we copy less than the full amount of this
			 * mblk_t, we have some amount to copy below.
			 */
			if (amt < mlen) {
				offset = amt;
				break;
			}
		}

		ASSERT0(len);

		/*
		 * Finish off the header tcb, and start anew for the
		 * rest of the packet.
		 */
		desc_total += ixgbe_tcb_done(tcb);
		tcb = NULL;
	}

	/*
	 * Process each remaining segment in the packet -- either binding
	 * the dblk_t or copying the contents of the dblk_t to an already
	 * bound buffer. When we copy, we will accumulate consecutive small
	 * (less than copy_thresh bytes) segments into a single tcb buffer
	 * until no more can fit (or we encounter a segment larger than
	 * copy_thresh and bind the dblk_t).
	 *
	 * Both ixgbe_tx_bind() and ixgbe_tx_copy() will allocate new
	 * transmit control blocks (tcb)s as needed (and append them onto
	 * 'pending_list'). Both functions also replace 'tcb' with the new
	 * tcb when they allocate a new tcb.
	 *
	 * We stop trying to process the packet once the number of descriptors
	 * used equals IXGBE_TX_DESC_LIMIT. Even if we're copying into the
	 * IXGBE_TX_DESC_LIMIT-th descriptor, we won't have room to add a
	 * context descriptor (since we're already at the limit), so there's
	 * no point in continuing. We'll pull up the mblk_t (see below)
	 * and try again.
	 */
	while (mp != NULL && desc_total < IXGBE_TX_DESC_LIMIT) {
		uint8_t *rptr = mp->b_rptr + offset;
		int ret;

		len = MBLKL(mp) - offset;
		offset = 0;

		if (len > copy_thresh) {
			ret = ixgbe_tx_bind(tx_ring, &tcb, &pending_list, rptr,
			    len);
		} else {
			ret = ixgbe_tx_copy(tx_ring, &tcb, &pending_list, rptr,
			    len);
		}

		if (ret < 0)
			goto tx_failure;

		desc_total += ret;
		mp = mp->b_cont;
	}

	/* Finish off the last tcb */
	desc_total += ixgbe_tcb_done(tcb);

	/*
	 * 82598/82599 chipset has a limitation that no more than 32 tx
	 * descriptors can be transmited out at one time. As noted above,
	 * we need to include space for a context descriptor in case its
	 * necessary, so we do this even if desc_total == IXGBE_TX_DESC_LIMIT
	 * as well as when it exceeds the limit.
	 *
	 * If we exceed this limit, we take the hit, do a msgpullup(), and
	 * then try again. Our DMA attributes guarantee we should never use
	 * more than MAX_COOKIE (18) descriptors to map a single mblk_t, so we
	 * should only need to retry once.
	 */
	if (desc_total >= IXGBE_TX_DESC_LIMIT) {
		/* We shouldn't hit this path twice */
		VERIFY0(limit_retry);

		tx_ring->stat_break_tbd_limit++;

		/* Release all the tcbs we used previously */
		ixgbe_put_free_list(tx_ring, &pending_list);
		desc_total = 0;
		offset = 0;

		pull_mp = msgpullup(orig_mp, -1);
		if (pull_mp == NULL) {
			tx_ring->reschedule = B_TRUE;
			return (orig_mp);
		}

		mp = pull_mp;
		limit_retry = B_TRUE;
		goto retry;
	}

	/*
	 * Before filling the tx descriptor ring with the data, we need to
	 * ensure there are adequate free descriptors for transmit
	 * (including one context descriptor).
	 * Do not use up all the tx descriptors.
	 * Otherwise tx recycle will fail and cause false hang.
	 */
	if (tx_ring->tbd_free <= (desc_total + 1)) {
		tx_ring->tx_recycle(tx_ring);
	}

	mutex_enter(&tx_ring->tx_lock);
	/*
	 * If the number of free tx descriptors is not enough for transmit
	 * then return mp.
	 *
	 * Note: we must put this check under the mutex protection to
	 * ensure the correctness when multiple threads access it in
	 * parallel.
	 */
	if (tx_ring->tbd_free <= (desc_total + 1)) {
		tx_ring->stat_fail_no_tbd++;
		mutex_exit(&tx_ring->tx_lock);
		goto tx_failure;
	}

	/*
	 * Attach the mblk_t we've setup to the last control block.
	 * This is only done once we know there are enough free descriptors
	 * to transmit so that the cleanup in tx_failure doesn't try to
	 * call freemsg() on mp (since we will want to return it).
	 */
	tcb->mp = (pull_mp != NULL) ? pull_mp : orig_mp;

	desc_num = ixgbe_tx_fill_ring(tx_ring, &pending_list, ctx,
	    mbsize);

	ASSERT((desc_num == desc_total) || (desc_num == (desc_total + 1)));

	tx_ring->stat_obytes += mbsize;
	tx_ring->stat_opackets++;

	mutex_exit(&tx_ring->tx_lock);

	/*
	 * Now that tx is done, if we pulled up the original message, we
	 * can free the original message since it is no longer being
	 * used.
	 */
	if (pull_mp != NULL) {
		freemsg(orig_mp);
	}

	return (NULL);

tx_failure:
	/*
	 * If transmission fails, need to free the pulling up mblk.
	 */
	if (pull_mp) {
		freemsg(pull_mp);
	}

	/*
	 * Return the tx control blocks in the pending list to the free list.
	 */
	ixgbe_put_free_list(tx_ring, &pending_list);

	/* Transmit failed, do not drop the mblk, rechedule the transmit */
	tx_ring->reschedule = B_TRUE;

	return (orig_mp);
}

/*
 * ixgbe_tx_copy
 *
 * Copy the mblk fragment to the pre-allocated tx buffer. Return -1 on error,
 * otherwise return the number of descriptors we've completed in this call.
 */
static int
ixgbe_tx_copy(ixgbe_tx_ring_t *tx_ring, tx_control_block_t **tcbp,
    link_list_t *pending_list, const void *buf, size_t len)
{
	tx_control_block_t *tcb = *tcbp;
	dma_buffer_t *tx_buf;
	uint32_t desc_num = 0;

	/*
	 * We need a new tcb -- either the current one (tcb) is NULL because
	 * we just started, tcb is being used for DMA, or tcb isn't large enough
	 * to hold the contents we need to copy.
	 */
	if (tcb == NULL || tcb->tx_type == USE_DMA ||
	    tcb->tx_buf.len + len > tcb->tx_buf.size) {
		tx_control_block_t *newtcb;

		newtcb = ixgbe_get_free_list(tx_ring, pending_list);
		if (newtcb == NULL)
			return (-1);

		newtcb->tx_type = USE_COPY;

		if (tcb != NULL)
			desc_num += ixgbe_tcb_done(tcb);
		*tcbp = tcb = newtcb;
	}

	ASSERT3S(tcb->tx_type, ==, USE_COPY);
	tx_buf = &tcb->tx_buf;

	/*
	 * Copy the packet data of the mblk fragment into the
	 * pre-allocated tx buffer, which is maintained by the
	 * tx control block.
	 *
	 * Several mblk fragments can be copied into one tx buffer.
	 * The destination address of the current copied fragment in
	 * the tx buffer is next to the end of the previous copied
	 * fragment.
	 */
	if (len > 0) {
		bcopy(buf, tx_buf->address + tx_buf->len, len);

		tx_buf->len += len;
		tcb->frag_num++;
	}

	return (desc_num);
}

/*
 * ixgbe_tx_bind
 *
 * Bind the mblk fragment with DMA. Returns -1 on error, otherwise it
 * returns the number of descriptors completed in this call. This count
 * can include descriptors that weren't filled in by the current call to
 * ixgbe_tx_bind() but were being used (but not yet completed) in previous
 * calls to ixgbe_tx_bind() or ixgbe_tx_copy().
 */
static int
ixgbe_tx_bind(ixgbe_tx_ring_t *tx_ring, tx_control_block_t **tcbp,
    link_list_t *pending_list, uint8_t *buf, size_t len)
{
	tx_control_block_t *tcb = NULL;
	uint_t desc_num = 0;
	int status;

	tcb = ixgbe_get_free_list(tx_ring, pending_list);
	if (tcb == NULL)
		return (-1);

	/*
	 * Use DMA binding to process the mblk fragment
	 */
	status = ddi_dma_addr_bind_handle(tcb->tx_dma_handle, NULL,
	    (caddr_t)buf, len,
	    DDI_DMA_WRITE | DDI_DMA_STREAMING, DDI_DMA_DONTWAIT,
	    0, NULL, NULL);

	if (status != DDI_DMA_MAPPED) {
		tx_ring->stat_fail_dma_bind++;
		return (-1);
	}

	tcb->frag_num++;
	tcb->tx_type = USE_DMA;

	/*
	 * If there was an old tcb, we're about to replace it. Finish
	 * setting up the old tcb so we can replace it with the new one.
	 */
	if (*tcbp != NULL)
		desc_num += ixgbe_tcb_done(*tcbp);

	*tcbp = tcb;
	return (desc_num);
}

/*
 * Once we're done populating a tcb (either by binding or copying into
 * a buffer in the tcb), get it ready for tx and return the number of
 * descriptors used.
 */
static uint_t
ixgbe_tcb_done(tx_control_block_t *tcb)
{
	uint_t desc_num = 0;

	if (tcb->tx_type == USE_DMA) {
		const ddi_dma_cookie_t *c;

		for (c = ddi_dma_cookie_iter(tcb->tx_dma_handle, NULL);
		    c != NULL;
		    c = ddi_dma_cookie_iter(tcb->tx_dma_handle, c)) {
			/*
			 * Save the address and length to the private data
			 * structure of the tx control block, which will be
			 * used to fill the tx descriptor ring after all the
			 * fragments are processed.
			 */
			ixgbe_save_desc(tcb, c->dmac_laddress, c->dmac_size);
			desc_num++;
		}
	} else if (tcb->tx_type == USE_COPY) {
		dma_buffer_t *tx_buf = &tcb->tx_buf;

		DMA_SYNC(tx_buf, DDI_DMA_SYNC_FORDEV);
		ixgbe_save_desc(tcb, tx_buf->dma_address, tx_buf->len);
		desc_num++;
	} else {
		panic("invalid tcb type");
	}

	return (desc_num);
}

/*
 * ixgbe_get_context
 *
 * Get the context information from the mblk
 */
static int
ixgbe_get_context(mblk_t *mp, ixgbe_tx_context_t *ctx)
{
	uint32_t start;
	uint32_t hckflags;
	uint32_t lsoflags;
	uint32_t lsocksum;
	uint32_t mss;
	uint32_t len;
	uint32_t size;
	uint32_t offset;
	unsigned char *pos;
	ushort_t etype;
	uint32_t mac_hdr_len;
	uint32_t l4_proto;
	uint32_t l4_hdr_len;

	ASSERT(mp != NULL);

	mac_hcksum_get(mp, &start, NULL, NULL, NULL, &hckflags);
	bzero(ctx, sizeof (ixgbe_tx_context_t));

	if (hckflags == 0) {
		return (0);
	}

	ctx->hcksum_flags = hckflags;

	mac_lso_get(mp, &mss, &lsoflags);
	ctx->mss = mss;
	ctx->lso_flag = (lsoflags == HW_LSO);

	etype = 0;
	mac_hdr_len = 0;
	l4_proto = 0;

	/*
	 * Firstly get the position of the ether_type/ether_tpid.
	 * Here we don't assume the ether (VLAN) header is fully included
	 * in one mblk fragment, so we go thourgh the fragments to parse
	 * the ether type.
	 */
	size = len = MBLKL(mp);
	offset = offsetof(struct ether_header, ether_type);
	while (size <= offset) {
		mp = mp->b_cont;
		ASSERT(mp != NULL);
		len = MBLKL(mp);
		size += len;
	}
	pos = mp->b_rptr + offset + len - size;

	etype = ntohs(*(ushort_t *)(uintptr_t)pos);
	if (etype == ETHERTYPE_VLAN) {
		/*
		 * Get the position of the ether_type in VLAN header
		 */
		offset = offsetof(struct ether_vlan_header, ether_type);
		while (size <= offset) {
			mp = mp->b_cont;
			ASSERT(mp != NULL);
			len = MBLKL(mp);
			size += len;
		}
		pos = mp->b_rptr + offset + len - size;

		etype = ntohs(*(ushort_t *)(uintptr_t)pos);
		mac_hdr_len = sizeof (struct ether_vlan_header);
	} else {
		mac_hdr_len = sizeof (struct ether_header);
	}

	/*
	 * Here we don't assume the IP(V6) header is fully included in
	 * one mblk fragment.
	 */
	lsocksum = HCK_PARTIALCKSUM;
	ctx->l3_proto = etype;
	switch (etype) {
	case ETHERTYPE_IP:
		if (ctx->lso_flag) {
			offset = offsetof(ipha_t, ipha_length) + mac_hdr_len;
			while (size <= offset) {
				mp = mp->b_cont;
				ASSERT(mp != NULL);
				len = MBLKL(mp);
				size += len;
			}
			pos = mp->b_rptr + offset + len - size;
			*((uint16_t *)(uintptr_t)(pos)) = 0;

			offset = offsetof(ipha_t, ipha_hdr_checksum) +
			    mac_hdr_len;
			while (size <= offset) {
				mp = mp->b_cont;
				ASSERT(mp != NULL);
				len = MBLKL(mp);
				size += len;
			}
			pos = mp->b_rptr + offset + len - size;
			*((uint16_t *)(uintptr_t)(pos)) = 0;

			/*
			 * To perform ixgbe LSO, here also need to fill
			 * the tcp checksum field of the packet with the
			 * following pseudo-header checksum:
			 * (ip_source_addr, ip_destination_addr, l4_proto)
			 * Currently the tcp/ip stack has done it.
			 */
			lsocksum |= HCK_IPV4_HDRCKSUM;
		}

		offset = offsetof(ipha_t, ipha_protocol) + mac_hdr_len;
		while (size <= offset) {
			mp = mp->b_cont;
			ASSERT(mp != NULL);
			len = MBLKL(mp);
			size += len;
		}
		pos = mp->b_rptr + offset + len - size;

		l4_proto = *(uint8_t *)pos;
		break;
	case ETHERTYPE_IPV6:
		/*
		 * We need to zero out the length in the header.
		 */
		if (ctx->lso_flag) {
			offset = offsetof(ip6_t, ip6_plen) + mac_hdr_len;
			while (size <= offset) {
				mp = mp->b_cont;
				ASSERT(mp != NULL);
				len = MBLKL(mp);
				size += len;
			}
			pos = mp->b_rptr + offset + len - size;
			*((uint16_t *)(uintptr_t)(pos)) = 0;
		}

		offset = offsetof(ip6_t, ip6_nxt) + mac_hdr_len;
		while (size <= offset) {
			mp = mp->b_cont;
			ASSERT(mp != NULL);
			len = MBLKL(mp);
			size += len;
		}
		pos = mp->b_rptr + offset + len - size;

		l4_proto = *(uint8_t *)pos;
		break;
	default:
		/* Unrecoverable error */
		IXGBE_DEBUGLOG_0(NULL, "Ether type error with tx hcksum");
		return (-2);
	}

	if (ctx->lso_flag) {
		/*
		 * LSO relies on tx h/w checksum, so here will drop the packet
		 * if h/w checksum flag is not declared.
		 */
		if ((ctx->hcksum_flags & lsocksum) != lsocksum) {
			IXGBE_DEBUGLOG_2(NULL, "ixgbe_tx: h/w checksum flags "
			    "are not set for LSO, found 0x%x, needed bits 0x%x",
			    ctx->hcksum_flags, lsocksum);
			return (-1);
		}


		offset = mac_hdr_len + start;
		while (size <= offset) {
			mp = mp->b_cont;
			ASSERT(mp != NULL);
			len = MBLKL(mp);
			size += len;
		}
		pos = mp->b_rptr + offset + len - size;

		l4_hdr_len = TCP_HDR_LENGTH((tcph_t *)pos);
	} else {
		/*
		 * l4 header length is only required for LSO
		 */
		l4_hdr_len = 0;
	}

	ctx->mac_hdr_len = mac_hdr_len;
	ctx->ip_hdr_len = start;
	ctx->l4_proto = l4_proto;
	ctx->l4_hdr_len = l4_hdr_len;

	return (0);
}

/*
 * ixgbe_check_context
 *
 * Check if a new context descriptor is needed
 */
static boolean_t
ixgbe_check_context(ixgbe_tx_ring_t *tx_ring, ixgbe_tx_context_t *ctx)
{
	ixgbe_tx_context_t *last;

	if (ctx == NULL)
		return (B_FALSE);

	/*
	 * Compare the context data retrieved from the mblk and the
	 * stored data of the last context descriptor. The data need
	 * to be checked are:
	 *	hcksum_flags
	 *	l4_proto
	 *	mac_hdr_len
	 *	ip_hdr_len
	 *	lso_flag
	 *	mss (only checked for LSO)
	 *	l4_hr_len (only checked for LSO)
	 * Either one of the above data is changed, a new context descriptor
	 * will be needed.
	 */
	last = &tx_ring->tx_context;

	if ((ctx->hcksum_flags != last->hcksum_flags) ||
	    (ctx->l4_proto != last->l4_proto) ||
	    (ctx->l3_proto != last->l3_proto) ||
	    (ctx->mac_hdr_len != last->mac_hdr_len) ||
	    (ctx->ip_hdr_len != last->ip_hdr_len) ||
	    (ctx->lso_flag != last->lso_flag) ||
	    (ctx->lso_flag && ((ctx->mss != last->mss) ||
	    (ctx->l4_hdr_len != last->l4_hdr_len)))) {
		return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * ixgbe_fill_context
 *
 * Fill the context descriptor with hardware checksum informations
 */
static void
ixgbe_fill_context(struct ixgbe_adv_tx_context_desc *ctx_tbd,
    ixgbe_tx_context_t *ctx)
{
	/*
	 * Fill the context descriptor with the checksum
	 * context information we've got.
	 */
	ctx_tbd->vlan_macip_lens = ctx->ip_hdr_len;
	ctx_tbd->vlan_macip_lens |= ctx->mac_hdr_len <<
	    IXGBE_ADVTXD_MACLEN_SHIFT;

	ctx_tbd->type_tucmd_mlhl =
	    IXGBE_ADVTXD_DCMD_DEXT | IXGBE_ADVTXD_DTYP_CTXT;
	/*
	 * When we have a TX context set up, we enforce that the ethertype is
	 * either IPv4 or IPv6 in ixgbe_get_tx_context().
	 */
	if (ctx->lso_flag || ctx->hcksum_flags & HCK_IPV4_HDRCKSUM) {
		if (ctx->l3_proto == ETHERTYPE_IP) {
			ctx_tbd->type_tucmd_mlhl |= IXGBE_ADVTXD_TUCMD_IPV4;
		} else {
			ctx_tbd->type_tucmd_mlhl |= IXGBE_ADVTXD_TUCMD_IPV6;
		}
	}

	if (ctx->lso_flag || ctx->hcksum_flags & HCK_PARTIALCKSUM) {
		switch (ctx->l4_proto) {
		case IPPROTO_TCP:
			ctx_tbd->type_tucmd_mlhl |= IXGBE_ADVTXD_TUCMD_L4T_TCP;
			break;
		case IPPROTO_UDP:
			/*
			 * We don't have to explicitly set:
			 *	ctx_tbd->type_tucmd_mlhl |=
			 *	    IXGBE_ADVTXD_TUCMD_L4T_UDP;
			 * Because IXGBE_ADVTXD_TUCMD_L4T_UDP == 0b
			 */
			break;
		default:
			/* Unrecoverable error */
			IXGBE_DEBUGLOG_0(NULL, "L4 type error with tx hcksum");
			break;
		}
	}

	ctx_tbd->seqnum_seed = 0;

	if (ctx->lso_flag) {
		ctx_tbd->mss_l4len_idx =
		    (ctx->l4_hdr_len << IXGBE_ADVTXD_L4LEN_SHIFT) |
		    (ctx->mss << IXGBE_ADVTXD_MSS_SHIFT);
	} else {
		ctx_tbd->mss_l4len_idx = 0;
	}
}

/*
 * ixgbe_tx_fill_ring
 *
 * Fill the tx descriptor ring with the data
 */
static int
ixgbe_tx_fill_ring(ixgbe_tx_ring_t *tx_ring, link_list_t *pending_list,
    ixgbe_tx_context_t *ctx, size_t mbsize)
{
	struct ixgbe_hw *hw = &tx_ring->ixgbe->hw;
	boolean_t load_context;
	uint32_t index, tcb_index, desc_num;
	union ixgbe_adv_tx_desc *tbd, *first_tbd;
	tx_control_block_t *tcb, *first_tcb;
	uint32_t hcksum_flags;
	int i;

	ASSERT(mutex_owned(&tx_ring->tx_lock));

	tbd = NULL;
	first_tbd = NULL;
	first_tcb = NULL;
	desc_num = 0;
	hcksum_flags = 0;
	load_context = B_FALSE;

	/*
	 * Get the index of the first tx descriptor that will be filled,
	 * and the index of the first work list item that will be attached
	 * with the first used tx control block in the pending list.
	 * Note: the two indexes are the same.
	 */
	index = tx_ring->tbd_tail;
	tcb_index = tx_ring->tbd_tail;

	if (ctx != NULL) {
		hcksum_flags = ctx->hcksum_flags;

		/*
		 * Check if a new context descriptor is needed for this packet
		 */
		load_context = ixgbe_check_context(tx_ring, ctx);

		if (load_context) {
			tbd = &tx_ring->tbd_ring[index];

			/*
			 * Fill the context descriptor with the
			 * hardware checksum offload informations.
			 */
			ixgbe_fill_context(
			    (struct ixgbe_adv_tx_context_desc *)tbd, ctx);

			index = NEXT_INDEX(index, 1, tx_ring->ring_size);
			desc_num++;

			/*
			 * Store the checksum context data if
			 * a new context descriptor is added
			 */
			tx_ring->tx_context = *ctx;
		}
	}

	first_tbd = &tx_ring->tbd_ring[index];

	/*
	 * Fill tx data descriptors with the data saved in the pending list.
	 * The tx control blocks in the pending list are added to the work list
	 * at the same time.
	 *
	 * The work list is strictly 1:1 corresponding to the descriptor ring.
	 * One item of the work list corresponds to one tx descriptor. Because
	 * one tx control block can span multiple tx descriptors, the tx
	 * control block will be added to the first work list item that
	 * corresponds to the first tx descriptor generated from that tx
	 * control block.
	 */
	tcb = (tx_control_block_t *)LIST_POP_HEAD(pending_list);
	first_tcb = tcb;
	while (tcb != NULL) {

		for (i = 0; i < tcb->desc_num; i++) {
			tbd = &tx_ring->tbd_ring[index];

			tbd->read.buffer_addr = tcb->desc[i].address;
			tbd->read.cmd_type_len = tcb->desc[i].length;

			tbd->read.cmd_type_len |= IXGBE_ADVTXD_DCMD_DEXT
			    | IXGBE_ADVTXD_DTYP_DATA;

			tbd->read.olinfo_status = 0;

			index = NEXT_INDEX(index, 1, tx_ring->ring_size);
			desc_num++;
		}

		/*
		 * Add the tx control block to the work list
		 */
		ASSERT(tx_ring->work_list[tcb_index] == NULL);
		tx_ring->work_list[tcb_index] = tcb;

		tcb_index = index;
		tcb = (tx_control_block_t *)LIST_POP_HEAD(pending_list);
	}

	if (load_context) {
		/*
		 * Count the context descriptor for
		 * the first tx control block.
		 */
		first_tcb->desc_num++;
	}
	first_tcb->last_index = PREV_INDEX(index, 1, tx_ring->ring_size);

	/*
	 * The Insert Ethernet CRC (IFCS) bit and the checksum fields are only
	 * valid in the first descriptor of the packet.
	 * Setting paylen in every first_tbd for all parts.
	 * 82599, X540 and X550 require the packet length in paylen field
	 * with or without LSO and 82598 will ignore it in non-LSO mode.
	 */
	ASSERT(first_tbd != NULL);
	first_tbd->read.cmd_type_len |= IXGBE_ADVTXD_DCMD_IFCS;

	switch (hw->mac.type) {
	case ixgbe_mac_82598EB:
		if (ctx != NULL && ctx->lso_flag) {
			first_tbd->read.cmd_type_len |= IXGBE_ADVTXD_DCMD_TSE;
			first_tbd->read.olinfo_status |=
			    (mbsize - ctx->mac_hdr_len - ctx->ip_hdr_len
			    - ctx->l4_hdr_len) << IXGBE_ADVTXD_PAYLEN_SHIFT;
		}
		break;

	case ixgbe_mac_82599EB:
	case ixgbe_mac_X540:
	case ixgbe_mac_X550:
	case ixgbe_mac_X550EM_x:
	case ixgbe_mac_X550EM_a:
	case ixgbe_mac_E610:
		if (ctx != NULL && ctx->lso_flag) {
			first_tbd->read.cmd_type_len |= IXGBE_ADVTXD_DCMD_TSE;
			first_tbd->read.olinfo_status |=
			    (mbsize - ctx->mac_hdr_len - ctx->ip_hdr_len
			    - ctx->l4_hdr_len) << IXGBE_ADVTXD_PAYLEN_SHIFT;
		} else {
			first_tbd->read.olinfo_status |=
			    (mbsize << IXGBE_ADVTXD_PAYLEN_SHIFT);
		}
		break;

	default:
		break;
	}

	/* Set hardware checksum bits */
	if (hcksum_flags != 0) {
		if (hcksum_flags & HCK_IPV4_HDRCKSUM)
			first_tbd->read.olinfo_status |=
			    IXGBE_ADVTXD_POPTS_IXSM;
		if (hcksum_flags & HCK_PARTIALCKSUM)
			first_tbd->read.olinfo_status |=
			    IXGBE_ADVTXD_POPTS_TXSM;
	}

	/*
	 * The last descriptor of packet needs End Of Packet (EOP),
	 * and Report Status (RS) bits set
	 */
	ASSERT(tbd != NULL);
	tbd->read.cmd_type_len |=
	    IXGBE_ADVTXD_DCMD_EOP | IXGBE_ADVTXD_DCMD_RS;

	/*
	 * Sync the DMA buffer of the tx descriptor ring
	 */
	DMA_SYNC(&tx_ring->tbd_area, DDI_DMA_SYNC_FORDEV);

	/*
	 * Update the number of the free tx descriptors.
	 * The mutual exclusion between the transmission and the recycling
	 * (for the tx descriptor ring and the work list) is implemented
	 * with the atomic operation on the number of the free tx descriptors.
	 *
	 * Note: we should always decrement the counter tbd_free before
	 * advancing the hardware TDT pointer to avoid the race condition -
	 * before the counter tbd_free is decremented, the transmit of the
	 * tx descriptors has done and the counter tbd_free is increased by
	 * the tx recycling.
	 */
	i = ixgbe_atomic_reserve(&tx_ring->tbd_free, desc_num);
	ASSERT(i >= 0);

	tx_ring->tbd_tail = index;

	/*
	 * Advance the hardware TDT pointer of the tx descriptor ring
	 */
	IXGBE_WRITE_REG(hw, IXGBE_TDT(tx_ring->index), index);

	if (ixgbe_check_acc_handle(tx_ring->ixgbe->osdep.reg_handle) !=
	    DDI_FM_OK) {
		ddi_fm_service_impact(tx_ring->ixgbe->dip,
		    DDI_SERVICE_DEGRADED);
		atomic_or_32(&tx_ring->ixgbe->ixgbe_state, IXGBE_ERROR);
	}

	return (desc_num);
}

/*
 * ixgbe_save_desc
 *
 * Save the address/length pair to the private array
 * of the tx control block. The address/length pairs
 * will be filled into the tx descriptor ring later.
 */
static void
ixgbe_save_desc(tx_control_block_t *tcb, uint64_t address, size_t length)
{
	sw_desc_t *desc;

	desc = &tcb->desc[tcb->desc_num];
	desc->address = address;
	desc->length = length;

	tcb->desc_num++;
}

/*
 * ixgbe_tx_recycle_legacy
 *
 * Recycle the tx descriptors and tx control blocks.
 *
 * The work list is traversed to check if the corresponding
 * tx descriptors have been transmitted. If so, the resources
 * bound to the tx control blocks will be freed, and those
 * tx control blocks will be returned to the free list.
 */
uint32_t
ixgbe_tx_recycle_legacy(ixgbe_tx_ring_t *tx_ring)
{
	uint32_t index, last_index, prev_index;
	int desc_num;
	boolean_t desc_done;
	tx_control_block_t *tcb;
	link_list_t pending_list;
	ixgbe_t *ixgbe = tx_ring->ixgbe;

	mutex_enter(&tx_ring->recycle_lock);

	ASSERT(tx_ring->tbd_free <= tx_ring->ring_size);

	if (tx_ring->tbd_free == tx_ring->ring_size) {
		tx_ring->recycle_fail = 0;
		tx_ring->stall_watchdog = 0;
		if (tx_ring->reschedule) {
			tx_ring->reschedule = B_FALSE;
			mac_tx_ring_update(ixgbe->mac_hdl,
			    tx_ring->ring_handle);
		}
		mutex_exit(&tx_ring->recycle_lock);
		return (0);
	}

	/*
	 * Sync the DMA buffer of the tx descriptor ring
	 */
	DMA_SYNC(&tx_ring->tbd_area, DDI_DMA_SYNC_FORKERNEL);

	if (ixgbe_check_dma_handle(tx_ring->tbd_area.dma_handle) != DDI_FM_OK) {
		mutex_exit(&tx_ring->recycle_lock);
		ddi_fm_service_impact(ixgbe->dip, DDI_SERVICE_DEGRADED);
		atomic_or_32(&ixgbe->ixgbe_state, IXGBE_ERROR);
		return (0);
	}

	LINK_LIST_INIT(&pending_list);
	desc_num = 0;
	index = tx_ring->tbd_head;	/* Index of next tbd/tcb to recycle */

	tcb = tx_ring->work_list[index];
	ASSERT(tcb != NULL);

	while (tcb != NULL) {
		/*
		 * Get the last tx descriptor of this packet.
		 * If the last tx descriptor is done, then
		 * we can recycle all descriptors of a packet
		 * which usually includes several tx control blocks.
		 * For 82599, LSO descriptors can not be recycled
		 * unless the whole packet's transmission is done.
		 * That's why packet level recycling is used here.
		 * For 82598, there's not such limit.
		 */
		last_index = tcb->last_index;
		/*
		 * MAX_TX_RING_SIZE is used to judge whether
		 * the index is a valid value or not.
		 */
		if (last_index == MAX_TX_RING_SIZE)
			break;

		/*
		 * Check if the Descriptor Done bit is set
		 */
		desc_done = tx_ring->tbd_ring[last_index].wb.status &
		    IXGBE_TXD_STAT_DD;
		if (desc_done) {
			/*
			 * recycle all descriptors of the packet
			 */
			while (tcb != NULL) {
				/*
				 * Strip off the tx control block from
				 * the work list, and add it to the
				 * pending list.
				 */
				tx_ring->work_list[index] = NULL;
				LIST_PUSH_TAIL(&pending_list, &tcb->link);

				/*
				 * Count the total number of the tx
				 * descriptors recycled
				 */
				desc_num += tcb->desc_num;

				index = NEXT_INDEX(index, tcb->desc_num,
				    tx_ring->ring_size);

				tcb = tx_ring->work_list[index];

				prev_index = PREV_INDEX(index, 1,
				    tx_ring->ring_size);
				if (prev_index == last_index)
					break;
			}
		} else {
			break;
		}
	}

	/*
	 * If no tx descriptors are recycled, no need to do more processing
	 */
	if (desc_num == 0) {
		tx_ring->recycle_fail++;
		mutex_exit(&tx_ring->recycle_lock);
		return (0);
	}

	tx_ring->recycle_fail = 0;
	tx_ring->stall_watchdog = 0;

	/*
	 * Update the head index of the tx descriptor ring
	 */
	tx_ring->tbd_head = index;

	/*
	 * Update the number of the free tx descriptors with atomic operations
	 */
	atomic_add_32(&tx_ring->tbd_free, desc_num);

	if ((tx_ring->tbd_free >= ixgbe->tx_resched_thresh) &&
	    (tx_ring->reschedule)) {
		tx_ring->reschedule = B_FALSE;
		mac_tx_ring_update(ixgbe->mac_hdl,
		    tx_ring->ring_handle);
	}
	mutex_exit(&tx_ring->recycle_lock);

	/*
	 * Add the tx control blocks in the pending list to the free list.
	 */
	ixgbe_put_free_list(tx_ring, &pending_list);

	return (desc_num);
}

/*
 * ixgbe_tx_recycle_head_wb
 *
 * Check the head write-back, and recycle all the transmitted
 * tx descriptors and tx control blocks.
 */
uint32_t
ixgbe_tx_recycle_head_wb(ixgbe_tx_ring_t *tx_ring)
{
	uint32_t index;
	uint32_t head_wb;
	int desc_num;
	tx_control_block_t *tcb;
	link_list_t pending_list;
	ixgbe_t *ixgbe = tx_ring->ixgbe;

	mutex_enter(&tx_ring->recycle_lock);

	ASSERT(tx_ring->tbd_free <= tx_ring->ring_size);

	if (tx_ring->tbd_free == tx_ring->ring_size) {
		tx_ring->recycle_fail = 0;
		tx_ring->stall_watchdog = 0;
		if (tx_ring->reschedule) {
			tx_ring->reschedule = B_FALSE;
			mac_tx_ring_update(ixgbe->mac_hdl,
			    tx_ring->ring_handle);
		}
		mutex_exit(&tx_ring->recycle_lock);
		return (0);
	}

	/*
	 * Sync the DMA buffer of the tx descriptor ring
	 *
	 * Note: For head write-back mode, the tx descriptors will not
	 * be written back, but the head write-back value is stored at
	 * the last extra tbd at the end of the DMA area, we still need
	 * to sync the head write-back value for kernel.
	 *
	 * DMA_SYNC(&tx_ring->tbd_area, DDI_DMA_SYNC_FORKERNEL);
	 */
	(void) ddi_dma_sync(tx_ring->tbd_area.dma_handle,
	    sizeof (union ixgbe_adv_tx_desc) * tx_ring->ring_size,
	    sizeof (uint32_t),
	    DDI_DMA_SYNC_FORKERNEL);

	if (ixgbe_check_dma_handle(tx_ring->tbd_area.dma_handle) != DDI_FM_OK) {
		mutex_exit(&tx_ring->recycle_lock);
		ddi_fm_service_impact(ixgbe->dip,
		    DDI_SERVICE_DEGRADED);
		atomic_or_32(&ixgbe->ixgbe_state, IXGBE_ERROR);
		return (0);
	}

	LINK_LIST_INIT(&pending_list);
	desc_num = 0;
	index = tx_ring->tbd_head;	/* Next index to clean */

	/*
	 * Get the value of head write-back
	 */
	head_wb = *tx_ring->tbd_head_wb;
	while (index != head_wb) {
		tcb = tx_ring->work_list[index];
		ASSERT(tcb != NULL);

		if (OFFSET(index, head_wb, tx_ring->ring_size) <
		    tcb->desc_num) {
			/*
			 * The current tx control block is not
			 * completely transmitted, stop recycling
			 */
			break;
		}

		/*
		 * Strip off the tx control block from the work list,
		 * and add it to the pending list.
		 */
		tx_ring->work_list[index] = NULL;
		LIST_PUSH_TAIL(&pending_list, &tcb->link);

		/*
		 * Advance the index of the tx descriptor ring
		 */
		index = NEXT_INDEX(index, tcb->desc_num, tx_ring->ring_size);

		/*
		 * Count the total number of the tx descriptors recycled
		 */
		desc_num += tcb->desc_num;
	}

	/*
	 * If no tx descriptors are recycled, no need to do more processing
	 */
	if (desc_num == 0) {
		tx_ring->recycle_fail++;
		mutex_exit(&tx_ring->recycle_lock);
		return (0);
	}

	tx_ring->recycle_fail = 0;
	tx_ring->stall_watchdog = 0;

	/*
	 * Update the head index of the tx descriptor ring
	 */
	tx_ring->tbd_head = index;

	/*
	 * Update the number of the free tx descriptors with atomic operations
	 */
	atomic_add_32(&tx_ring->tbd_free, desc_num);

	if ((tx_ring->tbd_free >= ixgbe->tx_resched_thresh) &&
	    (tx_ring->reschedule)) {
		tx_ring->reschedule = B_FALSE;
		mac_tx_ring_update(ixgbe->mac_hdl,
		    tx_ring->ring_handle);
	}
	mutex_exit(&tx_ring->recycle_lock);

	/*
	 * Add the tx control blocks in the pending list to the free list.
	 */
	ixgbe_put_free_list(tx_ring, &pending_list);

	return (desc_num);
}

/*
 * ixgbe_free_tcb - free up the tx control block
 *
 * Free the resources of the tx control block, including
 * unbind the previously bound DMA handle, and reset other
 * control fields.
 */
void
ixgbe_free_tcb(tx_control_block_t *tcb)
{
	if (tcb == NULL)
		return;

	switch (tcb->tx_type) {
	case USE_COPY:
		/*
		 * Reset the buffer length that is used for copy
		 */
		tcb->tx_buf.len = 0;
		break;
	case USE_DMA:
		/*
		 * Release the DMA resource that is used for
		 * DMA binding.
		 */
		(void) ddi_dma_unbind_handle(tcb->tx_dma_handle);
		break;
	default:
		break;
	}

	/*
	 * Free the mblk
	 */
	if (tcb->mp != NULL) {
		freemsg(tcb->mp);
		tcb->mp = NULL;
	}

	tcb->tx_type = USE_NONE;
	tcb->last_index = MAX_TX_RING_SIZE;
	tcb->frag_num = 0;
	tcb->desc_num = 0;
}

/*
 * ixgbe_get_free_list - Get a free tx control block from the free list.
 * Returns the tx control block and appends it to list.
 *
 * The atomic operation on the number of the available tx control block
 * in the free list is used to keep this routine mutual exclusive with
 * the routine ixgbe_put_check_list.
 */
static tx_control_block_t *
ixgbe_get_free_list(ixgbe_tx_ring_t *tx_ring, link_list_t *list)
{
	tx_control_block_t *tcb;

	/*
	 * Check and update the number of the free tx control block
	 * in the free list.
	 */
	if (ixgbe_atomic_reserve(&tx_ring->tcb_free, 1) < 0) {
		tx_ring->stat_fail_no_tcb++;
		return (NULL);
	}

	mutex_enter(&tx_ring->tcb_head_lock);

	tcb = tx_ring->free_list[tx_ring->tcb_head];
	ASSERT(tcb != NULL);
	tx_ring->free_list[tx_ring->tcb_head] = NULL;
	tx_ring->tcb_head = NEXT_INDEX(tx_ring->tcb_head, 1,
	    tx_ring->free_list_size);

	mutex_exit(&tx_ring->tcb_head_lock);

	LIST_PUSH_TAIL(list, &tcb->link);
	return (tcb);
}

/*
 * ixgbe_put_free_list
 *
 * Put a list of used tx control blocks back to the free list
 *
 * A mutex is used here to ensure the serialization. The mutual exclusion
 * between ixgbe_get_free_list and ixgbe_put_free_list is implemented with
 * the atomic operation on the counter tcb_free.
 */
void
ixgbe_put_free_list(ixgbe_tx_ring_t *tx_ring, link_list_t *pending_list)
{
	uint32_t index;
	int tcb_num;
	tx_control_block_t *tcb;

	for (tcb = (tx_control_block_t *)LIST_GET_HEAD(pending_list);
	    tcb != NULL;
	    tcb = (tx_control_block_t *)LIST_GET_NEXT(pending_list, tcb)) {
		/*
		 * Despite the name, ixgbe_free_tcb() just releases the
		 * resources in tcb, but does not free tcb itself.
		 */
		ixgbe_free_tcb(tcb);
	}

	mutex_enter(&tx_ring->tcb_tail_lock);

	index = tx_ring->tcb_tail;

	tcb_num = 0;
	tcb = (tx_control_block_t *)LIST_POP_HEAD(pending_list);
	while (tcb != NULL) {
		ASSERT(tx_ring->free_list[index] == NULL);
		tx_ring->free_list[index] = tcb;

		tcb_num++;

		index = NEXT_INDEX(index, 1, tx_ring->free_list_size);

		tcb = (tx_control_block_t *)LIST_POP_HEAD(pending_list);
	}

	tx_ring->tcb_tail = index;

	/*
	 * Update the number of the free tx control block
	 * in the free list. This operation must be placed
	 * under the protection of the lock.
	 */
	atomic_add_32(&tx_ring->tcb_free, tcb_num);

	mutex_exit(&tx_ring->tcb_tail_lock);
}
