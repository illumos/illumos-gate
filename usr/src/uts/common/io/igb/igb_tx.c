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
 */

#include "igb_sw.h"

static boolean_t igb_tx(igb_tx_ring_t *, mblk_t *);
static int igb_tx_copy(igb_tx_ring_t *, tx_control_block_t *, mblk_t *,
    uint32_t, boolean_t);
static int igb_tx_bind(igb_tx_ring_t *, tx_control_block_t *, mblk_t *,
    uint32_t);
static int igb_tx_fill_ring(igb_tx_ring_t *, link_list_t *, tx_context_t *,
    size_t);
static void igb_save_desc(tx_control_block_t *, uint64_t, size_t);
static tx_control_block_t *igb_get_free_list(igb_tx_ring_t *);
static int igb_get_tx_context(mblk_t *, tx_context_t *);
static boolean_t igb_check_tx_context(igb_tx_ring_t *, tx_context_t *);
static void igb_fill_tx_context(struct e1000_adv_tx_context_desc *,
    tx_context_t *, uint32_t);

#ifndef IGB_DEBUG
#pragma inline(igb_save_desc)
#pragma inline(igb_get_tx_context)
#pragma inline(igb_check_tx_context)
#pragma inline(igb_fill_tx_context)
#endif

mblk_t *
igb_tx_ring_send(void *arg, mblk_t *mp)
{
	igb_tx_ring_t *tx_ring = (igb_tx_ring_t *)arg;
	igb_t *igb;

	ASSERT(tx_ring != NULL);

	igb = tx_ring->igb;

	if ((igb->igb_state & IGB_SUSPENDED) ||
	    (igb->igb_state & IGB_ERROR) ||
	    !(igb->igb_state & IGB_STARTED) ||
	    igb->link_state != LINK_STATE_UP) {
		freemsg(mp);
		return (NULL);
	}

	return ((igb_tx(tx_ring, mp)) ? NULL : mp);
}

/*
 * igb_tx - Main transmit processing
 *
 * Called from igb_m_tx with an mblk ready to transmit. this
 * routine sets up the transmit descriptors and sends data to
 * the wire.
 *
 * One mblk can consist of several fragments, each fragment
 * will be processed with different methods based on the size.
 * For the fragments with size less than the bcopy threshold,
 * they will be processed by using bcopy; otherwise, they will
 * be processed by using DMA binding.
 *
 * To process the mblk, a tx control block is got from the
 * free list. One tx control block contains one tx buffer, which
 * is used to copy mblk fragments' data; and one tx DMA handle,
 * which is used to bind a mblk fragment with DMA resource.
 *
 * Several small mblk fragments can be copied into one tx control
 * block's buffer, and then the buffer will be transmitted with
 * one tx descriptor.
 *
 * A large fragment only binds with one tx control block's DMA
 * handle, and it can span several tx descriptors for transmitting.
 *
 * So to transmit a packet (mblk), several tx control blocks can
 * be used. After the processing, those tx control blocks will
 * be put to the work list.
 */
static boolean_t
igb_tx(igb_tx_ring_t *tx_ring, mblk_t *mp)
{
	igb_t *igb = tx_ring->igb;
	tx_type_t current_flag, next_flag;
	uint32_t current_len, next_len;
	uint32_t desc_total;
	size_t mbsize;
	int desc_num;
	boolean_t copy_done, eop;
	mblk_t *current_mp, *next_mp, *nmp;
	tx_control_block_t *tcb;
	tx_context_t tx_context, *ctx;
	link_list_t pending_list;
	mblk_t *hdr_new_mp = NULL;
	mblk_t *hdr_previous_mp = NULL;
	mblk_t *hdr_current_mp = NULL;
	uint32_t hdr_frag_len;
	uint32_t hdr_len, len;
	uint32_t copy_thresh;

	copy_thresh = igb->tx_copy_thresh;

	/* Get the mblk size */
	mbsize = 0;
	for (nmp = mp; nmp != NULL; nmp = nmp->b_cont) {
		mbsize += MBLKL(nmp);
	}

	if (igb->tx_hcksum_enable) {
		ctx = &tx_context;
		/*
		 * Retrieve offloading context information from the mblk
		 * that will be used to decide whether/how to fill the
		 * context descriptor.
		 */
		if (igb_get_tx_context(mp, ctx) != TX_CXT_SUCCESS) {
			freemsg(mp);
			return (B_TRUE);
		}

		if ((ctx->lso_flag &&
		    (mbsize > (ctx->mac_hdr_len + IGB_LSO_MAXLEN))) ||
		    (!ctx->lso_flag &&
		    (mbsize > (igb->max_frame_size - ETHERFCSL)))) {
			freemsg(mp);
			igb_log(igb, IGB_LOG_INFO, "igb_tx: packet oversize");
			return (B_TRUE);
		}
	} else {
		ctx = NULL;
		if (mbsize > (igb->max_frame_size - ETHERFCSL)) {
			freemsg(mp);
			igb_log(igb, IGB_LOG_INFO, "igb_tx: packet oversize");
			return (B_TRUE);
		}
	}

	/*
	 * Check and recycle tx descriptors.
	 * The recycle threshold here should be selected carefully
	 */
	if (tx_ring->tbd_free < igb->tx_recycle_thresh)
		tx_ring->tx_recycle(tx_ring);

	/*
	 * After the recycling, if the tbd_free is less than the
	 * tx_overload_threshold, assert overload, return B_FALSE;
	 * and we need to re-schedule the tx again.
	 */
	if (tx_ring->tbd_free < igb->tx_overload_thresh) {
		tx_ring->reschedule = B_TRUE;
		IGB_DEBUG_STAT(tx_ring->stat_overload);
		return (B_FALSE);
	}

	/*
	 * The software should guarantee LSO packet header(MAC+IP+TCP)
	 * to be within one descriptor - this is required by h/w.
	 * Here will reallocate and refill the header if
	 * the headers(MAC+IP+TCP) is physical memory non-contiguous.
	 */
	if (ctx && ctx->lso_flag) {
		hdr_len = ctx->mac_hdr_len + ctx->ip_hdr_len + ctx->l4_hdr_len;
		len = MBLKL(mp);
		hdr_current_mp = mp;
		while (len < hdr_len) {
			hdr_previous_mp = hdr_current_mp;
			hdr_current_mp = hdr_current_mp->b_cont;
			len += MBLKL(hdr_current_mp);
		}
		/*
		 * If the header and the payload are in different mblks,
		 * we simply force the header to be copied into pre-allocated
		 * page-aligned buffer.
		 */
		if (len == hdr_len)
			goto adjust_threshold;

		hdr_frag_len = hdr_len - (len - MBLKL(hdr_current_mp));
		/*
		 * There are two cases we will reallocate
		 * a mblk for the last header fragment.
		 * 1. the header is in multiple mblks and
		 *    the last fragment shares the same mblk
		 *    with the payload
		 * 2. the header is in a single mblk shared
		 *    with the payload but the header crosses
		 *    a page.
		 */
		if ((hdr_current_mp != mp) ||
		    (P2NPHASE((uintptr_t)hdr_current_mp->b_rptr, igb->page_size)
		    < hdr_len)) {
			/*
			 * reallocate the mblk for the last header fragment,
			 * expect it to be copied into pre-allocated
			 * page-aligned buffer
			 */
			hdr_new_mp = allocb(hdr_frag_len, 0);
			if (!hdr_new_mp) {
				return (B_FALSE);
			}

			/* link the new header fragment with the other parts */
			bcopy(hdr_current_mp->b_rptr,
			    hdr_new_mp->b_rptr, hdr_frag_len);
			hdr_new_mp->b_wptr = hdr_new_mp->b_rptr + hdr_frag_len;
			hdr_new_mp->b_cont = hdr_current_mp;
			if (hdr_previous_mp)
				hdr_previous_mp->b_cont = hdr_new_mp;
			else
				mp = hdr_new_mp;
			hdr_current_mp->b_rptr += hdr_frag_len;
		}
adjust_threshold:
		/*
		 * adjust the bcopy threshhold to guarantee
		 * the header to use bcopy way
		 */
		if (copy_thresh < hdr_len)
			copy_thresh = hdr_len;
	}

	/*
	 * The pending_list is a linked list that is used to save
	 * the tx control blocks that have packet data processed
	 * but have not put the data to the tx descriptor ring.
	 * It is used to reduce the lock contention of the tx_lock.
	 */
	LINK_LIST_INIT(&pending_list);
	desc_num = 0;
	desc_total = 0;

	current_mp = mp;
	current_len = MBLKL(current_mp);
	/*
	 * Decide which method to use for the first fragment
	 */
	current_flag = (current_len <= copy_thresh) ?
	    USE_COPY : USE_DMA;
	/*
	 * If the mblk includes several contiguous small fragments,
	 * they may be copied into one buffer. This flag is used to
	 * indicate whether there are pending fragments that need to
	 * be copied to the current tx buffer.
	 *
	 * If this flag is B_TRUE, it indicates that a new tx control
	 * block is needed to process the next fragment using either
	 * copy or DMA binding.
	 *
	 * Otherwise, it indicates that the next fragment will be
	 * copied to the current tx buffer that is maintained by the
	 * current tx control block. No new tx control block is needed.
	 */
	copy_done = B_TRUE;
	while (current_mp) {
		next_mp = current_mp->b_cont;
		eop = (next_mp == NULL); /* Last fragment of the packet? */
		next_len = eop ? 0: MBLKL(next_mp);

		/*
		 * When the current fragment is an empty fragment, if
		 * the next fragment will still be copied to the current
		 * tx buffer, we cannot skip this fragment here. Because
		 * the copy processing is pending for completion. We have
		 * to process this empty fragment in the tx_copy routine.
		 *
		 * If the copy processing is completed or a DMA binding
		 * processing is just completed, we can just skip this
		 * empty fragment.
		 */
		if ((current_len == 0) && (copy_done)) {
			current_mp = next_mp;
			current_len = next_len;
			current_flag = (current_len <= copy_thresh) ?
			    USE_COPY : USE_DMA;
			continue;
		}

		if (copy_done) {
			/*
			 * Get a new tx control block from the free list
			 */
			tcb = igb_get_free_list(tx_ring);

			if (tcb == NULL) {
				IGB_DEBUG_STAT(tx_ring->stat_fail_no_tcb);
				goto tx_failure;
			}

			/*
			 * Push the tx control block to the pending list
			 * to avoid using lock too early
			 */
			LIST_PUSH_TAIL(&pending_list, &tcb->link);
		}

		if (current_flag == USE_COPY) {
			/*
			 * Check whether to use bcopy or DMA binding to process
			 * the next fragment, and if using bcopy, whether we
			 * need to continue copying the next fragment into the
			 * current tx buffer.
			 */
			ASSERT((tcb->tx_buf.len + current_len) <=
			    tcb->tx_buf.size);

			if (eop) {
				/*
				 * This is the last fragment of the packet, so
				 * the copy processing will be completed with
				 * this fragment.
				 */
				next_flag = USE_NONE;
				copy_done = B_TRUE;
			} else if ((tcb->tx_buf.len + current_len + next_len) >
			    tcb->tx_buf.size) {
				/*
				 * If the next fragment is too large to be
				 * copied to the current tx buffer, we need
				 * to complete the current copy processing.
				 */
				next_flag = (next_len > copy_thresh) ?
				    USE_DMA: USE_COPY;
				copy_done = B_TRUE;
			} else if (next_len > copy_thresh) {
				/*
				 * The next fragment needs to be processed with
				 * DMA binding. So the copy prcessing will be
				 * completed with the current fragment.
				 */
				next_flag = USE_DMA;
				copy_done = B_TRUE;
			} else {
				/*
				 * Continue to copy the next fragment to the
				 * current tx buffer.
				 */
				next_flag = USE_COPY;
				copy_done = B_FALSE;
			}

			desc_num = igb_tx_copy(tx_ring, tcb, current_mp,
			    current_len, copy_done);
		} else {
			/*
			 * Check whether to use bcopy or DMA binding to process
			 * the next fragment.
			 */
			next_flag = (next_len > copy_thresh) ?
			    USE_DMA: USE_COPY;
			ASSERT(copy_done == B_TRUE);

			desc_num = igb_tx_bind(tx_ring, tcb, current_mp,
			    current_len);
		}

		if (desc_num > 0)
			desc_total += desc_num;
		else if (desc_num < 0)
			goto tx_failure;

		current_mp = next_mp;
		current_len = next_len;
		current_flag = next_flag;
	}

	/*
	 * Attach the mblk to the last tx control block
	 */
	ASSERT(tcb);
	ASSERT(tcb->mp == NULL);
	tcb->mp = mp;

	/*
	 * Before fill the tx descriptor ring with the data, we need to
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
	 * then return failure.
	 *
	 * Note: we must put this check under the mutex protection to
	 * ensure the correctness when multiple threads access it in
	 * parallel.
	 */
	if (tx_ring->tbd_free <= (desc_total + 1)) {
		IGB_DEBUG_STAT(tx_ring->stat_fail_no_tbd);
		mutex_exit(&tx_ring->tx_lock);
		goto tx_failure;
	}

	desc_num = igb_tx_fill_ring(tx_ring, &pending_list, ctx, mbsize);

	ASSERT((desc_num == desc_total) || (desc_num == (desc_total + 1)));

	/* Update per-ring tx statistics */
	tx_ring->tx_pkts++;
	tx_ring->tx_bytes += mbsize;

	mutex_exit(&tx_ring->tx_lock);

	return (B_TRUE);

tx_failure:
	/*
	 * If new mblk has been allocted for the last header
	 * fragment of a LSO packet, we should restore the
	 * modified mp.
	 */
	if (hdr_new_mp) {
		hdr_new_mp->b_cont = NULL;
		freeb(hdr_new_mp);
		hdr_current_mp->b_rptr -= hdr_frag_len;
		if (hdr_previous_mp)
			hdr_previous_mp->b_cont = hdr_current_mp;
		else
			mp = hdr_current_mp;
	}

	/*
	 * Discard the mblk and free the used resources
	 */
	tcb = (tx_control_block_t *)LIST_GET_HEAD(&pending_list);
	while (tcb) {
		tcb->mp = NULL;

		igb_free_tcb(tcb);

		tcb = (tx_control_block_t *)
		    LIST_GET_NEXT(&pending_list, &tcb->link);
	}

	/*
	 * Return the tx control blocks in the pending list to the free list.
	 */
	igb_put_free_list(tx_ring, &pending_list);

	/* Transmit failed, do not drop the mblk, rechedule the transmit */
	tx_ring->reschedule = B_TRUE;

	return (B_FALSE);
}

/*
 * igb_tx_copy
 *
 * Copy the mblk fragment to the pre-allocated tx buffer
 */
static int
igb_tx_copy(igb_tx_ring_t *tx_ring, tx_control_block_t *tcb, mblk_t *mp,
    uint32_t len, boolean_t copy_done)
{
	dma_buffer_t *tx_buf;
	uint32_t desc_num;
	_NOTE(ARGUNUSED(tx_ring));

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
		bcopy(mp->b_rptr, tx_buf->address + tx_buf->len, len);

		tx_buf->len += len;
		tcb->frag_num++;
	}

	desc_num = 0;

	/*
	 * If it is the last fragment copied to the current tx buffer,
	 * in other words, if there's no remaining fragment or the remaining
	 * fragment requires a new tx control block to process, we need to
	 * complete the current copy processing by syncing up the current
	 * DMA buffer and saving the descriptor data.
	 */
	if (copy_done) {
		/*
		 * Sync the DMA buffer of the packet data
		 */
		DMA_SYNC(tx_buf, DDI_DMA_SYNC_FORDEV);

		tcb->tx_type = USE_COPY;

		/*
		 * Save the address and length to the private data structure
		 * of the tx control block, which will be used to fill the
		 * tx descriptor ring after all the fragments are processed.
		 */
		igb_save_desc(tcb, tx_buf->dma_address, tx_buf->len);
		desc_num++;
	}

	return (desc_num);
}

/*
 * igb_tx_bind
 *
 * Bind the mblk fragment with DMA
 */
static int
igb_tx_bind(igb_tx_ring_t *tx_ring, tx_control_block_t *tcb, mblk_t *mp,
    uint32_t len)
{
	int status, i;
	ddi_dma_cookie_t dma_cookie;
	uint_t ncookies;
	int desc_num;

	/*
	 * Use DMA binding to process the mblk fragment
	 */
	status = ddi_dma_addr_bind_handle(tcb->tx_dma_handle, NULL,
	    (caddr_t)mp->b_rptr, len,
	    DDI_DMA_WRITE | DDI_DMA_STREAMING, DDI_DMA_DONTWAIT,
	    0, &dma_cookie, &ncookies);

	if (status != DDI_DMA_MAPPED) {
		IGB_DEBUG_STAT(tx_ring->stat_fail_dma_bind);
		return (-1);
	}

	tcb->frag_num++;
	tcb->tx_type = USE_DMA;
	/*
	 * Each fragment can span several cookies. One cookie will have
	 * one tx descriptor to transmit.
	 */
	desc_num = 0;
	for (i = ncookies; i > 0; i--) {
		/*
		 * Save the address and length to the private data structure
		 * of the tx control block, which will be used to fill the
		 * tx descriptor ring after all the fragments are processed.
		 */
		igb_save_desc(tcb,
		    dma_cookie.dmac_laddress,
		    dma_cookie.dmac_size);

		desc_num++;

		if (i > 1)
			ddi_dma_nextcookie(tcb->tx_dma_handle, &dma_cookie);
	}

	return (desc_num);
}

/*
 * igb_get_tx_context
 *
 * Get the tx context information from the mblk
 */
static int
igb_get_tx_context(mblk_t *mp, tx_context_t *ctx)
{
	uint32_t start;
	uint32_t flags;
	uint32_t lso_flag;
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

	mac_hcksum_get(mp, &start, NULL, NULL, NULL, &flags);
	bzero(ctx, sizeof (tx_context_t));

	ctx->hcksum_flags = flags;

	if (flags == 0)
		return (TX_CXT_SUCCESS);

	mac_lso_get(mp, &mss, &lso_flag);
	ctx->mss = mss;
	ctx->lso_flag = (lso_flag == HW_LSO);

	/*
	 * LSO relies on tx h/w checksum, so here the packet will be
	 * dropped if the h/w checksum flags are not set.
	 */
	if (ctx->lso_flag) {
		if (!((ctx->hcksum_flags & HCK_PARTIALCKSUM) &&
		    (ctx->hcksum_flags & HCK_IPV4_HDRCKSUM))) {
			igb_log(NULL, IGB_LOG_INFO, "igb_tx: h/w "
			    "checksum flags are not set for LSO");
			return (TX_CXT_E_LSO_CSUM);
		}
	}

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
	 * Here we assume the IP(V6) header is fully included in one
	 * mblk fragment.
	 */
	switch (etype) {
	case ETHERTYPE_IP:
		offset = mac_hdr_len;
		while (size <= offset) {
			mp = mp->b_cont;
			ASSERT(mp != NULL);
			len = MBLKL(mp);
			size += len;
		}
		pos = mp->b_rptr + offset + len - size;

		if (ctx->lso_flag) {
			*((uint16_t *)(uintptr_t)(pos + offsetof(ipha_t,
			    ipha_length))) = 0;

			/*
			 * To utilize igb LSO, here need to fill
			 * the tcp checksum field of the packet with the
			 * following pseudo-header checksum:
			 * (ip_source_addr, ip_destination_addr, l4_proto)
			 * and also need to fill the ip header checksum
			 * with zero. Currently the tcp/ip stack has done
			 * these.
			 */
		}

		l4_proto = *(uint8_t *)(pos + offsetof(ipha_t, ipha_protocol));
		break;
	case ETHERTYPE_IPV6:
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
		igb_log(NULL, IGB_LOG_INFO, "Ethernet type field error with "
		    "tx hcksum flag set");
		return (TX_CXT_E_ETHER_TYPE);
	}

	if (ctx->lso_flag) {
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

	return (TX_CXT_SUCCESS);
}

/*
 * igb_check_tx_context
 *
 * Check if a new context descriptor is needed
 */
static boolean_t
igb_check_tx_context(igb_tx_ring_t *tx_ring, tx_context_t *ctx)
{
	tx_context_t *last;

	if (ctx == NULL)
		return (B_FALSE);

	/*
	 * Compare the context data retrieved from the mblk and the
	 * stored context data of the last context descriptor. The data
	 * need to be checked are:
	 *	hcksum_flags
	 *	l4_proto
	 *	mss (only check for LSO)
	 *	l4_hdr_len (only check for LSO)
	 *	ip_hdr_len
	 *	mac_hdr_len
	 * Either one of the above data is changed, a new context descriptor
	 * will be needed.
	 */
	last = &tx_ring->tx_context;

	if (ctx->hcksum_flags != 0) {
		if ((ctx->hcksum_flags != last->hcksum_flags) ||
		    (ctx->l4_proto != last->l4_proto) ||
		    (ctx->lso_flag && ((ctx->mss != last->mss) ||
		    (ctx->l4_hdr_len != last->l4_hdr_len))) ||
		    (ctx->ip_hdr_len != last->ip_hdr_len) ||
		    (ctx->mac_hdr_len != last->mac_hdr_len)) {
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

/*
 * igb_fill_tx_context
 *
 * Fill the context descriptor with hardware checksum informations
 */
static void
igb_fill_tx_context(struct e1000_adv_tx_context_desc *ctx_tbd,
    tx_context_t *ctx, uint32_t ring_index)
{
	/*
	 * Fill the context descriptor with the checksum
	 * context information we've got
	 */
	ctx_tbd->vlan_macip_lens = ctx->ip_hdr_len;
	ctx_tbd->vlan_macip_lens |= ctx->mac_hdr_len <<
	    E1000_ADVTXD_MACLEN_SHIFT;

	ctx_tbd->type_tucmd_mlhl =
	    E1000_ADVTXD_DCMD_DEXT | E1000_ADVTXD_DTYP_CTXT;

	if (ctx->hcksum_flags & HCK_IPV4_HDRCKSUM)
		ctx_tbd->type_tucmd_mlhl |= E1000_ADVTXD_TUCMD_IPV4;

	if (ctx->hcksum_flags & HCK_PARTIALCKSUM) {
		switch (ctx->l4_proto) {
		case IPPROTO_TCP:
			ctx_tbd->type_tucmd_mlhl |= E1000_ADVTXD_TUCMD_L4T_TCP;
			break;
		case IPPROTO_UDP:
			/*
			 * We don't have to explicitly set:
			 *	ctx_tbd->type_tucmd_mlhl |=
			 *	    E1000_ADVTXD_TUCMD_L4T_UDP;
			 * Because E1000_ADVTXD_TUCMD_L4T_UDP == 0b
			 */
			break;
		default:
			/* Unrecoverable error */
			igb_log(NULL, IGB_LOG_INFO,
			    "L4 type error with tx hcksum");
			break;
		}
	}

	ctx_tbd->seqnum_seed = 0;
	ctx_tbd->mss_l4len_idx = ring_index << 4;
	if (ctx->lso_flag) {
		ctx_tbd->mss_l4len_idx |=
		    (ctx->l4_hdr_len << E1000_ADVTXD_L4LEN_SHIFT) |
		    (ctx->mss << E1000_ADVTXD_MSS_SHIFT);
	}
}

/*
 * igb_tx_fill_ring
 *
 * Fill the tx descriptor ring with the data
 */
static int
igb_tx_fill_ring(igb_tx_ring_t *tx_ring, link_list_t *pending_list,
    tx_context_t *ctx, size_t mbsize)
{
	struct e1000_hw *hw = &tx_ring->igb->hw;
	boolean_t load_context;
	uint32_t index, tcb_index, desc_num;
	union e1000_adv_tx_desc *tbd, *first_tbd;
	tx_control_block_t *tcb, *first_tcb;
	uint32_t hcksum_flags;
	int i;
	igb_t *igb = tx_ring->igb;

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
		load_context = igb_check_tx_context(tx_ring, ctx);
		if (load_context) {
			tbd = &tx_ring->tbd_ring[index];

			/*
			 * Fill the context descriptor with the
			 * hardware checksum offload informations.
			 */
			igb_fill_tx_context(
			    (struct e1000_adv_tx_context_desc *)tbd,
			    ctx, tx_ring->index);

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

			tbd->read.cmd_type_len |= E1000_ADVTXD_DCMD_RS |
			    E1000_ADVTXD_DCMD_DEXT | E1000_ADVTXD_DTYP_DATA |
			    E1000_ADVTXD_DCMD_IFCS;

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
		 * Count the checksum context descriptor for
		 * the first tx control block.
		 */
		first_tcb->desc_num++;
	}
	first_tcb->last_index = PREV_INDEX(index, 1, tx_ring->ring_size);

	/*
	 * The Insert Ethernet CRC (IFCS) bit and the checksum fields are only
	 * valid in the first descriptor of the packet.
	 * 82576 also requires the payload length setting even without LSO
	 */
	ASSERT(first_tbd != NULL);
	first_tbd->read.cmd_type_len |= E1000_ADVTXD_DCMD_IFCS;
	if (ctx != NULL && ctx->lso_flag) {
		first_tbd->read.cmd_type_len |= E1000_ADVTXD_DCMD_TSE;
		first_tbd->read.olinfo_status |=
		    (mbsize - ctx->mac_hdr_len - ctx->ip_hdr_len
		    - ctx->l4_hdr_len) << E1000_ADVTXD_PAYLEN_SHIFT;
	} else {
		if (hw->mac.type >= e1000_82576) {
			first_tbd->read.olinfo_status |=
			    (mbsize << E1000_ADVTXD_PAYLEN_SHIFT);
		}
	}

	/* Set hardware checksum bits */
	if (hcksum_flags != 0) {
		if (hcksum_flags & HCK_IPV4_HDRCKSUM)
			first_tbd->read.olinfo_status |=
			    E1000_TXD_POPTS_IXSM << 8;
		if (hcksum_flags & HCK_PARTIALCKSUM)
			first_tbd->read.olinfo_status |=
			    E1000_TXD_POPTS_TXSM << 8;
		first_tbd->read.olinfo_status |= tx_ring->index << 4;
	}

	/*
	 * The last descriptor of packet needs End Of Packet (EOP),
	 * and Report Status (RS) bits set
	 */
	ASSERT(tbd != NULL);
	tbd->read.cmd_type_len |=
	    E1000_ADVTXD_DCMD_EOP | E1000_ADVTXD_DCMD_RS;

	IGB_DEBUG_STAT(tx_ring->stat_pkt_cnt);

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
	i = igb_atomic_reserve(&tx_ring->tbd_free, desc_num);
	ASSERT(i >= 0);

	tx_ring->tbd_tail = index;

	/*
	 * Advance the hardware TDT pointer of the tx descriptor ring
	 */
	E1000_WRITE_REG(hw, E1000_TDT(tx_ring->index), index);

	if (igb_check_acc_handle(igb->osdep.reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(igb->dip, DDI_SERVICE_DEGRADED);
		atomic_or_32(&igb->igb_state, IGB_ERROR);
	}

	return (desc_num);
}

/*
 * igb_save_desc
 *
 * Save the address/length pair to the private array
 * of the tx control block. The address/length pairs
 * will be filled into the tx descriptor ring later.
 */
static void
igb_save_desc(tx_control_block_t *tcb, uint64_t address, size_t length)
{
	sw_desc_t *desc;

	desc = &tcb->desc[tcb->desc_num];
	desc->address = address;
	desc->length = length;

	tcb->desc_num++;
}

/*
 * igb_tx_recycle_legacy
 *
 * Recycle the tx descriptors and tx control blocks.
 *
 * The work list is traversed to check if the corresponding
 * tx descriptors have been transmitted. If so, the resources
 * bound to the tx control blocks will be freed, and those
 * tx control blocks will be returned to the free list.
 */
uint32_t
igb_tx_recycle_legacy(igb_tx_ring_t *tx_ring)
{
	uint32_t index, last_index, next_index;
	int desc_num;
	boolean_t desc_done;
	tx_control_block_t *tcb;
	link_list_t pending_list;
	igb_t *igb = tx_ring->igb;

	/*
	 * The mutex_tryenter() is used to avoid unnecessary
	 * lock contention.
	 */
	if (mutex_tryenter(&tx_ring->recycle_lock) == 0)
		return (0);

	ASSERT(tx_ring->tbd_free <= tx_ring->ring_size);

	if (tx_ring->tbd_free == tx_ring->ring_size) {
		tx_ring->recycle_fail = 0;
		tx_ring->stall_watchdog = 0;
		mutex_exit(&tx_ring->recycle_lock);
		return (0);
	}

	/*
	 * Sync the DMA buffer of the tx descriptor ring
	 */
	DMA_SYNC(&tx_ring->tbd_area, DDI_DMA_SYNC_FORKERNEL);

	if (igb_check_dma_handle(
	    tx_ring->tbd_area.dma_handle) != DDI_FM_OK) {
		mutex_exit(&tx_ring->recycle_lock);
		ddi_fm_service_impact(igb->dip, DDI_SERVICE_DEGRADED);
		atomic_or_32(&igb->igb_state, IGB_ERROR);
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
		 * For some chips, LSO descriptors can not be recycled
		 * unless the whole packet's transmission is done.
		 * That's why packet level recycling is used here.
		 */
		last_index = tcb->last_index;
		/*
		 * MAX_TX_RING_SIZE is used to judge whether
		 * the index is a valid value or not.
		 */
		if (last_index == MAX_TX_RING_SIZE)
			break;

		next_index = NEXT_INDEX(last_index, 1, tx_ring->ring_size);

		/*
		 * Check if the Descriptor Done bit is set
		 */
		desc_done = tx_ring->tbd_ring[last_index].wb.status &
		    E1000_TXD_STAT_DD;
		if (desc_done) {
			while (tcb != NULL) {
				/*
				 * Strip off the tx control block from the work
				 * list, and add it to the pending list.
				 */
				tx_ring->work_list[index] = NULL;
				LIST_PUSH_TAIL(&pending_list, &tcb->link);

				/*
				 * Count the total number of the tx descriptors
				 * recycled.
				 */
				desc_num += tcb->desc_num;

				/*
				 * Advance the index of the tx descriptor ring
				 */
				index = NEXT_INDEX(index, tcb->desc_num,
				    tx_ring->ring_size);

				tcb = tx_ring->work_list[index];
				if (index == next_index)
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

	mutex_exit(&tx_ring->recycle_lock);

	/*
	 * Free the resources used by the tx control blocks
	 * in the pending list
	 */
	tcb = (tx_control_block_t *)LIST_GET_HEAD(&pending_list);
	while (tcb != NULL) {
		/*
		 * Release the resources occupied by the tx control block
		 */
		igb_free_tcb(tcb);

		tcb = (tx_control_block_t *)
		    LIST_GET_NEXT(&pending_list, &tcb->link);
	}

	/*
	 * Add the tx control blocks in the pending list to the free list.
	 */
	igb_put_free_list(tx_ring, &pending_list);

	return (desc_num);
}

/*
 * igb_tx_recycle_head_wb
 *
 * Check the head write-back, and recycle all the transmitted
 * tx descriptors and tx control blocks.
 */
uint32_t
igb_tx_recycle_head_wb(igb_tx_ring_t *tx_ring)
{
	uint32_t index;
	uint32_t head_wb;
	int desc_num;
	tx_control_block_t *tcb;
	link_list_t pending_list;
	igb_t *igb = tx_ring->igb;

	/*
	 * The mutex_tryenter() is used to avoid unnecessary
	 * lock contention.
	 */
	if (mutex_tryenter(&tx_ring->recycle_lock) == 0)
		return (0);

	ASSERT(tx_ring->tbd_free <= tx_ring->ring_size);

	if (tx_ring->tbd_free == tx_ring->ring_size) {
		tx_ring->recycle_fail = 0;
		tx_ring->stall_watchdog = 0;
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
	    sizeof (union e1000_adv_tx_desc) * tx_ring->ring_size,
	    sizeof (uint32_t),
	    DDI_DMA_SYNC_FORKERNEL);

	if (igb_check_dma_handle(
	    tx_ring->tbd_area.dma_handle) != DDI_FM_OK) {
		mutex_exit(&tx_ring->recycle_lock);
		ddi_fm_service_impact(igb->dip, DDI_SERVICE_DEGRADED);
		atomic_or_32(&igb->igb_state, IGB_ERROR);
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

	mutex_exit(&tx_ring->recycle_lock);

	/*
	 * Free the resources used by the tx control blocks
	 * in the pending list
	 */
	tcb = (tx_control_block_t *)LIST_GET_HEAD(&pending_list);
	while (tcb) {
		/*
		 * Release the resources occupied by the tx control block
		 */
		igb_free_tcb(tcb);

		tcb = (tx_control_block_t *)
		    LIST_GET_NEXT(&pending_list, &tcb->link);
	}

	/*
	 * Add the tx control blocks in the pending list to the free list.
	 */
	igb_put_free_list(tx_ring, &pending_list);

	return (desc_num);
}

/*
 * igb_free_tcb - free up the tx control block
 *
 * Free the resources of the tx control block, including
 * unbind the previously bound DMA handle, and reset other
 * control fields.
 */
void
igb_free_tcb(tx_control_block_t *tcb)
{
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
 * igb_get_free_list - Get a free tx control block from the free list
 *
 * The atomic operation on the number of the available tx control block
 * in the free list is used to keep this routine mutual exclusive with
 * the routine igb_put_check_list.
 */
static tx_control_block_t *
igb_get_free_list(igb_tx_ring_t *tx_ring)
{
	tx_control_block_t *tcb;

	/*
	 * Check and update the number of the free tx control block
	 * in the free list.
	 */
	if (igb_atomic_reserve(&tx_ring->tcb_free, 1) < 0)
		return (NULL);

	mutex_enter(&tx_ring->tcb_head_lock);

	tcb = tx_ring->free_list[tx_ring->tcb_head];
	ASSERT(tcb != NULL);
	tx_ring->free_list[tx_ring->tcb_head] = NULL;
	tx_ring->tcb_head = NEXT_INDEX(tx_ring->tcb_head, 1,
	    tx_ring->free_list_size);

	mutex_exit(&tx_ring->tcb_head_lock);

	return (tcb);
}

/*
 * igb_put_free_list
 *
 * Put a list of used tx control blocks back to the free list
 *
 * A mutex is used here to ensure the serialization. The mutual exclusion
 * between igb_get_free_list and igb_put_free_list is implemented with
 * the atomic operation on the counter tcb_free.
 */
void
igb_put_free_list(igb_tx_ring_t *tx_ring, link_list_t *pending_list)
{
	uint32_t index;
	int tcb_num;
	tx_control_block_t *tcb;

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
