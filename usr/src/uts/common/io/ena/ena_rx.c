/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2024 Oxide Computer Company
 */
#include "ena.h"

static void
ena_refill_rx(ena_rxq_t *rxq, uint16_t num)
{
	VERIFY3P(rxq, !=, NULL);
	ASSERT(MUTEX_HELD(&rxq->er_lock));
	ASSERT3U(num, <=, rxq->er_sq_num_descs);
	uint16_t tail_mod = rxq->er_sq_tail_idx & (rxq->er_sq_num_descs - 1);

	while (num != 0) {
		enahw_rx_desc_t *desc = &rxq->er_sq_descs[tail_mod];
		ena_rx_ctrl_block_t *rcb = &rxq->er_rcbs[tail_mod];
		uint16_t phase = rxq->er_sq_phase;

		VERIFY3U(tail_mod, <, rxq->er_sq_num_descs);
		VERIFY3P(desc, !=, NULL);
		VERIFY3P(rcb, !=, NULL);
		VERIFY3P(desc, >=, rxq->er_sq_descs);
		VERIFY3P(desc, <=,
		    (rxq->er_sq_descs + rxq->er_sq_num_descs - 1));

		desc->erd_length = rcb->ercb_dma.edb_len;
		desc->erd_req_id = tail_mod;
		VERIFY3P(rcb->ercb_dma.edb_cookie, !=, NULL);
		ena_set_dma_addr_values(rxq->er_ena,
		    rcb->ercb_dma.edb_cookie->dmac_laddress,
		    &desc->erd_buff_addr_lo, &desc->erd_buff_addr_hi);

		ENAHW_RX_DESC_CLEAR_CTRL(desc);
		ENAHW_RX_DESC_SET_PHASE(desc, phase);
		ENAHW_RX_DESC_SET_FIRST(desc);
		ENAHW_RX_DESC_SET_LAST(desc);
		ENAHW_RX_DESC_SET_COMP_REQ(desc);
		DTRACE_PROBE1(ena__refill__rx, enahw_rx_desc_t *, desc);
		rxq->er_sq_tail_idx++;
		tail_mod = rxq->er_sq_tail_idx & (rxq->er_sq_num_descs - 1);

		if (tail_mod == 0) {
			rxq->er_sq_phase ^= 1;
		}

		num--;
	}

	ENA_DMA_SYNC(rxq->er_sq_dma, DDI_DMA_SYNC_FORDEV);
	ena_hw_abs_write32(rxq->er_ena, rxq->er_sq_db_addr,
	    rxq->er_sq_tail_idx);
}

void
ena_free_rx_dma(ena_rxq_t *rxq)
{
	if (rxq->er_rcbs != NULL) {
		for (uint_t i = 0; i < rxq->er_sq_num_descs; i++) {
			ena_rx_ctrl_block_t *rcb = &rxq->er_rcbs[i];
			ena_dma_free(&rcb->ercb_dma);
		}

		kmem_free(rxq->er_rcbs,
		    sizeof (*rxq->er_rcbs) * rxq->er_sq_num_descs);

		rxq->er_rcbs = NULL;
	}

	ena_dma_free(&rxq->er_cq_dma);
	rxq->er_cq_descs = NULL;
	rxq->er_cq_num_descs = 0;

	ena_dma_free(&rxq->er_sq_dma);
	rxq->er_sq_descs = NULL;
	rxq->er_sq_num_descs = 0;

	rxq->er_state &= ~ENA_RXQ_STATE_HOST_ALLOC;
}

static int
ena_alloc_rx_dma(ena_rxq_t *rxq)
{
	ena_t *ena = rxq->er_ena;
	size_t cq_descs_sz;
	size_t sq_descs_sz;
	ena_dma_conf_t conf;
	int err = 0;

	cq_descs_sz = rxq->er_cq_num_descs * sizeof (*rxq->er_cq_descs);
	sq_descs_sz = rxq->er_sq_num_descs * sizeof (*rxq->er_sq_descs);
	/* BEGIN CSTYLED */
	conf = (ena_dma_conf_t) {
		.edc_size = sq_descs_sz,
		.edc_align = ENAHW_IO_SQ_DESC_BUF_ALIGNMENT,
		.edc_sgl = 1,
		.edc_endian = DDI_NEVERSWAP_ACC,
		.edc_stream = B_FALSE,
	};
	/* END CSTYLED */

	if (!ena_dma_alloc(ena, &rxq->er_sq_dma, &conf, sq_descs_sz)) {
		return (ENOMEM);
	}

	rxq->er_sq_descs = (void *)rxq->er_sq_dma.edb_va;
	rxq->er_rcbs = kmem_zalloc(sizeof (*rxq->er_rcbs) *
	    rxq->er_sq_num_descs, KM_SLEEP);

	for (uint_t i = 0; i < rxq->er_sq_num_descs; i++) {
		ena_rx_ctrl_block_t *rcb = &rxq->er_rcbs[i];
		ena_dma_conf_t buf_conf = {
			.edc_size = ena->ena_rx_buf_sz,
			.edc_align = 1,
			.edc_sgl = ena->ena_rx_sgl_max_sz,
			.edc_endian = DDI_NEVERSWAP_ACC,
			.edc_stream = B_TRUE,
		};

		if (!ena_dma_alloc(ena, &rcb->ercb_dma, &buf_conf,
		    ena->ena_rx_buf_sz)) {
			err = ENOMEM;
			goto error;
		}
	}

	/* BEGIN CSTYLED */
	conf = (ena_dma_conf_t) {
		.edc_size = cq_descs_sz,
		.edc_align = ENAHW_IO_CQ_DESC_BUF_ALIGNMENT,
		.edc_sgl = 1,
		.edc_endian = DDI_NEVERSWAP_ACC,
		.edc_stream = B_FALSE,
	};
	/* END CSTYLED */

	if (!ena_dma_alloc(ena, &rxq->er_cq_dma, &conf, cq_descs_sz)) {
		err = ENOMEM;
		goto error;
	}

	rxq->er_cq_descs = (void *)rxq->er_cq_dma.edb_va;
	rxq->er_state |= ENA_RXQ_STATE_HOST_ALLOC;
	return (0);

error:
	ena_free_rx_dma(rxq);
	return (err);
}

boolean_t
ena_alloc_rxq(ena_rxq_t *rxq)
{
	int ret = 0;
	ena_t *ena = rxq->er_ena;
	uint16_t cq_hw_idx, sq_hw_idx;
	uint32_t *cq_unmask_addr, *cq_headdb, *cq_numanode;
	uint32_t *sq_db_addr;

	/*
	 * First, allocate the Rx data buffers.
	 */
	if ((ret = ena_alloc_rx_dma(rxq)) != 0) {
		ena_err(ena, "failed to allocate Rx queue %u data buffers: %d",
		    rxq->er_rxqs_idx, ret);
		return (B_FALSE);
	}

	ASSERT(rxq->er_state & ENA_RXQ_STATE_HOST_ALLOC);

	/*
	 * Second, create the Completion Queue.
	 */
	ret = ena_create_cq(ena,  rxq->er_cq_num_descs,
	    rxq->er_cq_dma.edb_cookie->dmac_laddress, B_FALSE,
	    rxq->er_intr_vector, &cq_hw_idx, &cq_unmask_addr, &cq_headdb,
	    &cq_numanode);

	if (ret != 0) {
		ena_err(ena, "failed to create Rx CQ %u: %d", rxq->er_rxqs_idx,
		    ret);
		return (B_FALSE);
	}

	/* The phase must always start on 1. */
	rxq->er_cq_phase = 1;
	rxq->er_cq_head_idx = 0;
	rxq->er_cq_hw_idx = cq_hw_idx;
	rxq->er_cq_unmask_addr = cq_unmask_addr;
	rxq->er_cq_head_db_addr = cq_headdb;
	rxq->er_cq_numa_addr = cq_numanode;
	rxq->er_state |= ENA_RXQ_STATE_CQ_CREATED;

	/*
	 * Third, create the Submission Queue to match with the above
	 * CQ. At this time we force the SQ and CQ to have the same
	 * number of descriptors as we only use a 1:1 completion
	 * policy. However, in the future, we could loosen this and
	 * use an on-demand completion policy and the two could have a
	 * different number of descriptors.
	 */
	ASSERT3U(rxq->er_sq_num_descs, ==, rxq->er_cq_num_descs);
	ret = ena_create_sq(ena, rxq->er_sq_num_descs,
	    rxq->er_sq_dma.edb_cookie->dmac_laddress, B_FALSE, cq_hw_idx,
	    &sq_hw_idx, &sq_db_addr);

	if (ret != 0) {
		ena_err(ena, "failed to create Rx SQ %u: %d", rxq->er_rxqs_idx,
		    ret);
		return (B_FALSE);
	}

	ASSERT3P(sq_db_addr, !=, NULL);
	rxq->er_sq_hw_idx = sq_hw_idx;
	rxq->er_sq_db_addr = sq_db_addr;
	/* The phase must always start on 1. */
	rxq->er_sq_phase = 1;
	rxq->er_sq_tail_idx = 0;
	rxq->er_sq_avail_descs = rxq->er_sq_num_descs;
	rxq->er_mode = ENA_RXQ_MODE_INTR;
	rxq->er_state |= ENA_RXQ_STATE_SQ_CREATED;

	return (B_TRUE);
}

void
ena_cleanup_rxq(ena_rxq_t *rxq)
{
	int ret = 0;
	ena_t *ena = rxq->er_ena;

	if ((rxq->er_state & ENA_RXQ_STATE_SQ_CREATED) != 0) {
		ret = ena_destroy_sq(ena, rxq->er_sq_hw_idx, B_FALSE);

		if (ret != 0) {
			ena_err(ena, "failed to destroy Rx SQ %u: %d",
			    rxq->er_rxqs_idx, ret);
		}

		rxq->er_sq_hw_idx = 0;
		rxq->er_sq_db_addr = NULL;
		rxq->er_sq_tail_idx = 0;
		rxq->er_sq_phase = 0;
		rxq->er_state &= ~ENA_RXQ_STATE_SQ_CREATED;
		rxq->er_state &= ~ENA_RXQ_STATE_SQ_FILLED;
	}

	if ((rxq->er_state & ENA_RXQ_STATE_CQ_CREATED) != 0) {
		ret = ena_destroy_cq(ena, rxq->er_cq_hw_idx);

		if (ret != 0) {
			ena_err(ena, "failed to destroy Rx CQ %u: %d",
			    rxq->er_rxqs_idx, ret);
		}

		rxq->er_cq_hw_idx = 0;
		rxq->er_cq_head_idx = 0;
		rxq->er_cq_phase = 0;
		rxq->er_cq_head_db_addr = NULL;
		rxq->er_cq_unmask_addr = NULL;
		rxq->er_cq_numa_addr = NULL;
		rxq->er_state &= ~ENA_RXQ_STATE_CQ_CREATED;
	}

	ena_free_rx_dma(rxq);
	ASSERT3S(rxq->er_state, ==, ENA_RXQ_STATE_NONE);
}

void
ena_ring_rx_stop(mac_ring_driver_t rh)
{
	ena_rxq_t *rxq = (ena_rxq_t *)rh;
	uint32_t intr_ctrl;

	intr_ctrl = ena_hw_abs_read32(rxq->er_ena, rxq->er_cq_unmask_addr);
	ENAHW_REG_INTR_MASK(intr_ctrl);
	ena_hw_abs_write32(rxq->er_ena, rxq->er_cq_unmask_addr, intr_ctrl);

	rxq->er_state &= ~ENA_RXQ_STATE_RUNNING;
	rxq->er_state &= ~ENA_RXQ_STATE_READY;
}

int
ena_ring_rx_start(mac_ring_driver_t rh, uint64_t gen_num)
{
	ena_rxq_t *rxq = (ena_rxq_t *)rh;
	ena_t *ena = rxq->er_ena;
	uint32_t intr_ctrl;

	ena_dbg(ena, "ring_rx_start %p: state %x", rxq, rxq->er_state);

	mutex_enter(&rxq->er_lock);
	if ((rxq->er_state & ENA_RXQ_STATE_SQ_FILLED) == 0) {
		/*
		 * The ENA controller gets upset and sets the fatal error bit
		 * in its status register if we write a value to an RX SQ's
		 * doorbell that is past its current head. This makes sense as
		 * it would represent there being more descriptors available
		 * than can fit in the ring. For this reason, we make sure that
		 * we only fill the ring once, even if it is started multiple
		 * times.
		 * The `- 1` below is harder to explain. If we completely fill
		 * the SQ ring, then at some time later that seems to be
		 * independent of how many times we've been around the ring,
		 * the ENA controller will set the fatal error bit and stop
		 * responding. Leaving a gap prevents this somehow and it is
		 * what the other open source drivers do.
		 */
		ena_refill_rx(rxq, rxq->er_sq_num_descs - 1);
		rxq->er_state |= ENA_RXQ_STATE_SQ_FILLED;
	}
	rxq->er_m_gen_num = gen_num;
	rxq->er_intr_limit = ena->ena_rxq_intr_limit;
	mutex_exit(&rxq->er_lock);

	rxq->er_state |= ENA_RXQ_STATE_READY;

	intr_ctrl = ena_hw_abs_read32(ena, rxq->er_cq_unmask_addr);
	ENAHW_REG_INTR_UNMASK(intr_ctrl);
	ena_hw_abs_write32(ena, rxq->er_cq_unmask_addr, intr_ctrl);
	rxq->er_state |= ENA_RXQ_STATE_RUNNING;
	return (0);
}

mblk_t *
ena_ring_rx(ena_rxq_t *rxq, int poll_bytes)
{
	ena_t *ena = rxq->er_ena;
	uint16_t head_mod = rxq->er_cq_head_idx & (rxq->er_cq_num_descs - 1);
	uint64_t total_bytes = 0;
	uint64_t num_frames = 0;
	enahw_rx_cdesc_t *cdesc;
	boolean_t polling = B_TRUE;
	mblk_t *head = NULL;
	mblk_t *tail = NULL;

	ASSERT(MUTEX_HELD(&rxq->er_lock));
	ENA_DMA_SYNC(rxq->er_cq_dma, DDI_DMA_SYNC_FORKERNEL);

	if (poll_bytes == ENA_INTERRUPT_MODE) {
		polling = B_FALSE;
	}

	cdesc = &rxq->er_cq_descs[head_mod];
	VERIFY3P(cdesc, >=, rxq->er_cq_descs);
	VERIFY3P(cdesc, <=, (rxq->er_cq_descs + rxq->er_cq_num_descs - 1));

	while (ENAHW_RX_CDESC_PHASE(cdesc) == rxq->er_cq_phase) {
		boolean_t first, last;
		ena_rx_ctrl_block_t *rcb;
		uint16_t req_id;
		mblk_t *mp;
		enahw_io_l3_proto_t l3proto;
		enahw_io_l4_proto_t l4proto;
		boolean_t l4csum_checked;
		uint32_t hflags = 0;

		VERIFY3U(head_mod, <, rxq->er_cq_num_descs);
		/*
		 * Currently, all incoming frames fit in a single Rx
		 * buffer (erd_length > total frame size). In the
		 * future, if we decide to loan buffers which are
		 * smaller, we will need to modify this code to read
		 * one or more descriptors (based on frame size).
		 *
		 * For this reason we do not expect any frame to span
		 * multiple descriptors. Therefore, we drop any data
		 * not delivered as a single descriptor, i.e., where
		 * 'first' and 'last' are both true.
		 */
		first = ENAHW_RX_CDESC_FIRST(cdesc);
		last = ENAHW_RX_CDESC_LAST(cdesc);

		if (!first || !last) {
			mutex_enter(&rxq->er_stat_lock);
			rxq->er_stat.ers_multi_desc.value.ui64++;
			mutex_exit(&rxq->er_stat_lock);
			goto next_desc;
		}

		req_id = cdesc->erc_req_id;
		VERIFY3U(req_id, <, rxq->er_cq_num_descs);
		rcb = &rxq->er_rcbs[req_id];
		rcb->ercb_offset = cdesc->erc_offset;
		rcb->ercb_length = cdesc->erc_length;
		ASSERT3U(rcb->ercb_length, <=, ena->ena_max_frame_total);
		mp = allocb(rcb->ercb_length + ENA_RX_BUF_IPHDR_ALIGNMENT, 0);

		/*
		 * If we can't allocate an mblk, things are looking
		 * grim. Forget about this frame and move on.
		 */
		if (mp == NULL) {
			mutex_enter(&rxq->er_stat_lock);
			rxq->er_stat.ers_allocb_fail.value.ui64++;
			mutex_exit(&rxq->er_stat_lock);
			goto next_desc;
		}

		/*
		 * As we pull frames we need to link them together as
		 * one chain to be delivered up to mac.
		 */
		if (head == NULL) {
			head = mp;
		} else {
			tail->b_next = mp;
		}

		tail = mp;

		/*
		 * We need to make sure the bytes are copied to the
		 * correct offset to achieve 4-byte IP header
		 * alignment.
		 *
		 * If we start using desballoc on the buffers, then we
		 * will need to make sure to apply this offset to the
		 * DMA buffers as well. Though it may be the case the
		 * device does this implicitly and that's what
		 * cdesc->erc_offset is for; we don't know because
		 * it's not documented.
		 */
		mp->b_wptr += ENA_RX_BUF_IPHDR_ALIGNMENT;
		mp->b_rptr += ENA_RX_BUF_IPHDR_ALIGNMENT;
		bcopy(rcb->ercb_dma.edb_va + rcb->ercb_offset, mp->b_wptr,
		    rcb->ercb_length);
		mp->b_wptr += rcb->ercb_length;
		total_bytes += rcb->ercb_length;
		VERIFY3P(mp->b_wptr, >, mp->b_rptr);
		VERIFY3P(mp->b_wptr, <=, mp->b_datap->db_lim);

		l3proto = ENAHW_RX_CDESC_L3_PROTO(cdesc);
		l4proto = ENAHW_RX_CDESC_L4_PROTO(cdesc);

		/*
		 * When it comes to bad TCP/IP checksums we do not
		 * discard the packet at this level. Instead, we let
		 * it percolate up for further processing and tracking
		 * by the upstream TCP/IP stack.
		 */
		if (ena->ena_rx_l3_ipv4_csum &&
		    l3proto == ENAHW_IO_L3_PROTO_IPV4) {
			boolean_t l3_csum_err =
			    ENAHW_RX_CDESC_L3_CSUM_ERR(cdesc);

			if (l3_csum_err) {
				mutex_enter(&rxq->er_stat_lock);
				rxq->er_stat.ers_hck_ipv4_err.value.ui64++;
				mutex_exit(&rxq->er_stat_lock);
			} else {
				hflags |= HCK_IPV4_HDRCKSUM_OK;
			}
		}

		l4csum_checked = ENAHW_RX_CDESC_L4_CSUM_CHECKED(cdesc);

		if (ena->ena_rx_l4_ipv4_csum && l4csum_checked &&
		    l4proto == ENAHW_IO_L4_PROTO_TCP) {
			boolean_t l4_csum_err =
			    ENAHW_RX_CDESC_L4_CSUM_ERR(cdesc);

			if (l4_csum_err) {
				mutex_enter(&rxq->er_stat_lock);
				rxq->er_stat.ers_hck_l4_err.value.ui64++;
				mutex_exit(&rxq->er_stat_lock);
			} else {
				hflags |= HCK_FULLCKSUM_OK;
			}
		}

		if (hflags != 0) {
			mac_hcksum_set(mp, 0, 0, 0, 0, hflags);
		}

next_desc:
		/*
		 * Technically, if we arrived here due to a failure,
		 * then we did not read a new frame. However, we count
		 * it all the same anyways in order to count it as
		 * progress to the interrupt work limit. The failure
		 * stats will allow us to differentiate good frames
		 * from bad.
		 */
		num_frames++;
		rxq->er_cq_head_idx++;
		head_mod = rxq->er_cq_head_idx & (rxq->er_cq_num_descs - 1);

		if (head_mod == 0) {
			rxq->er_cq_phase ^= 1;
		}

		if (polling && (total_bytes > poll_bytes)) {
			break;
		} else if (!polling && (num_frames >= rxq->er_intr_limit)) {
			mutex_enter(&rxq->er_stat_lock);
			rxq->er_stat.ers_intr_limit.value.ui64++;
			mutex_exit(&rxq->er_stat_lock);
			break;
		}

		cdesc = &rxq->er_cq_descs[head_mod];
		VERIFY3P(cdesc, >=, rxq->er_cq_descs);
		VERIFY3P(cdesc, <=,
		    (rxq->er_cq_descs + rxq->er_cq_num_descs - 1));
	}

	if (num_frames > 0) {
		mutex_enter(&rxq->er_stat_lock);
		rxq->er_stat.ers_packets.value.ui64 += num_frames;
		rxq->er_stat.ers_bytes.value.ui64 += total_bytes;
		mutex_exit(&rxq->er_stat_lock);

		DTRACE_PROBE4(rx__frames, mblk_t *, head, boolean_t, polling,
		    uint64_t, num_frames, uint64_t, total_bytes);
		ena_refill_rx(rxq, num_frames);
	}

	return (head);
}

void
ena_rx_intr_work(ena_rxq_t *rxq)
{
	mblk_t *mp;

	mutex_enter(&rxq->er_lock);
	mp = ena_ring_rx(rxq, ENA_INTERRUPT_MODE);
	mutex_exit(&rxq->er_lock);

	if (mp == NULL) {
		return;
	}

	mac_rx_ring(rxq->er_ena->ena_mh, rxq->er_mrh, mp, rxq->er_m_gen_num);
}

mblk_t *
ena_ring_rx_poll(void *rh, int poll_bytes)
{
	ena_rxq_t *rxq = rh;
	mblk_t *mp;

	ASSERT3S(poll_bytes, >, 0);

	mutex_enter(&rxq->er_lock);
	mp = ena_ring_rx(rxq, poll_bytes);
	mutex_exit(&rxq->er_lock);

	return (mp);
}
