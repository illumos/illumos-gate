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

void
ena_free_tx_dma(ena_txq_t *txq)
{
	if (txq->et_tcbs != NULL) {
		for (uint_t i = 0; i < txq->et_sq_num_descs; i++) {
			ena_tx_control_block_t *tcb = &txq->et_tcbs[i];
			ena_dma_free(&tcb->etcb_dma);
		}

		kmem_free(txq->et_tcbs,
		    sizeof (*txq->et_tcbs) * txq->et_sq_num_descs);

		txq->et_tcbs = NULL;

	}

	ena_dma_free(&txq->et_cq_dma);
	txq->et_cq_descs = NULL;

	ena_dma_free(&txq->et_sq_dma);
	txq->et_sq_descs = NULL;

	txq->et_state &= ~ENA_TXQ_STATE_HOST_ALLOC;
}

static int
ena_alloc_tx_dma(ena_txq_t *txq)
{
	ena_t *ena = txq->et_ena;
	size_t cq_descs_sz;
	size_t sq_descs_sz;
	int err = 0;
	ena_dma_conf_t conf;

	ASSERT0(txq->et_state & ENA_TXQ_STATE_HOST_ALLOC);
	ASSERT3P(ena, !=, NULL);

	cq_descs_sz = txq->et_cq_num_descs * sizeof (*txq->et_cq_descs);
	sq_descs_sz = txq->et_sq_num_descs * sizeof (*txq->et_sq_descs);

	/* BEGIN CSTYLED */
	conf = (ena_dma_conf_t) {
		.edc_size = sq_descs_sz,
		.edc_align = ENAHW_IO_SQ_DESC_BUF_ALIGNMENT,
		.edc_sgl = 1,
		.edc_endian = DDI_NEVERSWAP_ACC,
		.edc_stream = B_FALSE,
	};
	/* END CSTYLED */

	if (!ena_dma_alloc(ena, &txq->et_sq_dma, &conf, sq_descs_sz)) {
		return (ENOMEM);
	}

	bzero(txq->et_sq_dma.edb_va, sq_descs_sz);
	txq->et_sq_descs = (void *)txq->et_sq_dma.edb_va;
	txq->et_tcbs = kmem_zalloc(sizeof (*txq->et_tcbs) *
	    txq->et_sq_num_descs, KM_SLEEP);

	for (uint_t i = 0; i < txq->et_sq_num_descs; i++) {
		ena_tx_control_block_t *tcb = &txq->et_tcbs[i];
		ena_dma_conf_t buf_conf = {
			.edc_size = ena->ena_tx_buf_sz,
			.edc_align = 1,
			.edc_sgl = ena->ena_tx_sgl_max_sz,
			.edc_endian = DDI_NEVERSWAP_ACC,
			.edc_stream = B_TRUE,
		};

		if (!ena_dma_alloc(ena, &tcb->etcb_dma, &buf_conf,
		    ena->ena_tx_buf_sz)) {
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

	if (!ena_dma_alloc(ena, &txq->et_cq_dma, &conf, cq_descs_sz)) {
		err = ENOMEM;
		goto error;
	}

	bzero(txq->et_cq_dma.edb_va, cq_descs_sz);
	txq->et_cq_descs = (void *)txq->et_cq_dma.edb_va;
	txq->et_state |= ENA_TXQ_STATE_HOST_ALLOC;
	return (0);

error:
	ena_free_tx_dma(txq);
	return (err);
}

boolean_t
ena_alloc_txq(ena_txq_t *txq)
{
	int ret = 0;
	ena_t *ena = txq->et_ena;
	uint16_t cq_hw_idx, sq_hw_idx;
	uint32_t *cq_unmask_addr, *cq_numanode;
	uint32_t *sq_db_addr;

	ASSERT3U(txq->et_cq_num_descs, >, 0);

	/*
	 * First, allocate the Tx data buffers.
	 */
	if ((ret = ena_alloc_tx_dma(txq)) != 0) {
		ena_err(ena, "failed to allocate Tx queue %u data buffers: %d",
		    txq->et_txqs_idx, ret);
		return (B_FALSE);
	}

	ASSERT(txq->et_state & ENA_TXQ_STATE_HOST_ALLOC);

	/*
	 * Second, create the Completion Queue.
	 */
	ret = ena_create_cq(ena, txq->et_cq_num_descs,
	    txq->et_cq_dma.edb_cookie->dmac_laddress, B_TRUE,
	    txq->et_intr_vector, &cq_hw_idx, &cq_unmask_addr, &cq_numanode);

	if (ret != 0) {
		ena_err(ena, "failed to create Tx CQ %u: %d", txq->et_txqs_idx,
		    ret);
		return (B_FALSE);
	}

	txq->et_cq_hw_idx = cq_hw_idx;
	txq->et_cq_phase = 1;
	txq->et_cq_unmask_addr = cq_unmask_addr;
	txq->et_cq_numa_addr = cq_numanode;
	txq->et_state |= ENA_TXQ_STATE_CQ_CREATED;

	/*
	 * Third, create the Submission Queue to match with the above
	 * CQ. At this time we force the SQ and CQ to have the same
	 * number of descriptors as we only use a 1:1 completion
	 * policy. However, in the future, we could loosen this and
	 * use an on-demand completion policy and the two could have a
	 * different number of descriptors.
	 */
	ASSERT3U(txq->et_sq_num_descs, ==, txq->et_cq_num_descs);

	ret = ena_create_sq(ena, txq->et_sq_num_descs,
	    txq->et_sq_dma.edb_cookie->dmac_laddress, B_TRUE, cq_hw_idx,
	    &sq_hw_idx, &sq_db_addr);

	if (ret != 0) {
		ena_err(ena, "failed to create Tx SQ %u: %d", txq->et_txqs_idx,
		    ret);
		return (B_FALSE);
	}

	txq->et_sq_hw_idx = sq_hw_idx;
	txq->et_sq_db_addr = sq_db_addr;
	/* The phase must always start on 1. */
	txq->et_sq_phase = 1;
	txq->et_sq_avail_descs = txq->et_sq_num_descs;
	txq->et_blocked = B_FALSE;
	txq->et_state |= ENA_TXQ_STATE_SQ_CREATED;

	return (B_TRUE);
}

void
ena_cleanup_txq(ena_txq_t *txq)
{
	int ret = 0;
	ena_t *ena = txq->et_ena;

	if ((txq->et_state & ENA_TXQ_STATE_SQ_CREATED) != 0) {
		ret = ena_destroy_sq(ena, txq->et_sq_hw_idx, B_TRUE);

		if (ret != 0) {
			ena_err(ena, "failed to destroy Tx SQ %u: %d",
			    txq->et_txqs_idx, ret);
		}

		txq->et_sq_hw_idx = 0;
		txq->et_sq_db_addr = NULL;
		txq->et_sq_tail_idx = 0;
		txq->et_sq_phase = 0;
		txq->et_state &= ~ENA_TXQ_STATE_SQ_CREATED;
	}

	if ((txq->et_state & ENA_TXQ_STATE_CQ_CREATED) != 0) {
		ret = ena_destroy_cq(ena, txq->et_cq_hw_idx);

		if (ret != 0) {
			ena_err(ena, "failed to destroy Tx CQ %u: %d",
			    txq->et_txqs_idx, ret);
		}

		txq->et_cq_hw_idx = 0;
		txq->et_cq_head_idx = 0;
		txq->et_cq_phase = 0;
		txq->et_cq_unmask_addr = NULL;
		txq->et_cq_numa_addr = NULL;
		txq->et_state &= ~ENA_TXQ_STATE_CQ_CREATED;
	}

	ena_free_tx_dma(txq);
	VERIFY3S(txq->et_state, ==, ENA_TXQ_STATE_NONE);
}

void
ena_ring_tx_stop(mac_ring_driver_t rh)
{
	ena_txq_t *txq = (ena_txq_t *)rh;
	uint32_t intr_ctrl;

	intr_ctrl = ena_hw_abs_read32(txq->et_ena, txq->et_cq_unmask_addr);
	ENAHW_REG_INTR_UNMASK(intr_ctrl);
	ena_hw_abs_write32(txq->et_ena, txq->et_cq_unmask_addr, intr_ctrl);

	txq->et_state &= ~ENA_TXQ_STATE_RUNNING;
	txq->et_state &= ~ENA_TXQ_STATE_READY;
}

int
ena_ring_tx_start(mac_ring_driver_t rh, uint64_t gen_num)
{
	ena_txq_t *txq = (ena_txq_t *)rh;
	ena_t *ena = txq->et_ena;
	uint32_t intr_ctrl;

	mutex_enter(&txq->et_lock);
	txq->et_m_gen_num = gen_num;
	mutex_exit(&txq->et_lock);

	txq->et_state |= ENA_TXQ_STATE_READY;

	intr_ctrl = ena_hw_abs_read32(ena, txq->et_cq_unmask_addr);
	ENAHW_REG_INTR_UNMASK(intr_ctrl);
	ena_hw_abs_write32(ena, txq->et_cq_unmask_addr, intr_ctrl);
	txq->et_state |= ENA_TXQ_STATE_RUNNING;
	return (0);
}

static void
ena_tx_copy_fragment(ena_tx_control_block_t *tcb, const mblk_t *mp,
    const size_t off, const size_t len)
{
	const void *soff = mp->b_rptr + off;
	void *doff =
	    (void *)(tcb->etcb_dma.edb_va + tcb->etcb_dma.edb_used_len);

	VERIFY3U(len, >, 0);
	VERIFY3P(soff, >=, mp->b_rptr);
	VERIFY3P(soff, <=, mp->b_wptr);
	VERIFY3U(len, <=, MBLKL(mp));
	VERIFY3U((uintptr_t)soff + len, <=, (uintptr_t)mp->b_wptr);
	VERIFY3U(tcb->etcb_dma.edb_used_len + len, <, tcb->etcb_dma.edb_len);

	bcopy(soff, doff, len);
	tcb->etcb_type = ENA_TCB_COPY;
	tcb->etcb_dma.edb_used_len += len;
}

ena_tx_control_block_t *
ena_pull_tcb(const ena_txq_t *txq, mblk_t *mp)
{
	mblk_t *nmp = mp;
	ena_t *ena = txq->et_ena;
	ena_tx_control_block_t *tcb = NULL;
	const uint16_t tail_mod =
	    txq->et_sq_tail_idx & (txq->et_sq_num_descs - 1);

	ASSERT(MUTEX_HELD(&txq->et_lock));
	VERIFY3U(msgsize(mp), <, ena->ena_tx_buf_sz);

	while (nmp != NULL) {
		const size_t nmp_len = MBLKL(nmp);

		if (nmp_len == 0) {
			nmp = nmp->b_cont;
			continue;
		}

		/* For now TCB is bound to SQ desc. */
		if (tcb == NULL) {
			tcb = &txq->et_tcbs[tail_mod];
		}

		ena_tx_copy_fragment(tcb, nmp, 0, nmp_len);
		nmp = nmp->b_cont;
	}

	ENA_DMA_SYNC(tcb->etcb_dma, DDI_DMA_SYNC_FORDEV);
	VERIFY3P(nmp, ==, NULL);
	VERIFY3P(tcb, !=, NULL);
	return (tcb);
}

static void
ena_fill_tx_data_desc(ena_txq_t *txq, ena_tx_control_block_t *tcb,
    uint16_t tail, uint8_t phase, enahw_tx_data_desc_t *desc,
    mac_ether_offload_info_t *meo, size_t mlen)
{
	VERIFY3U(mlen, <=, ENAHW_TX_DESC_LENGTH_MASK);

#ifdef DEBUG
	/*
	 * If there is no header for the specific layer it will be set
	 * to zero, thus we elide the meoi_flags check here.
	 */
	size_t hdr_len = meo->meoi_l2hlen + meo->meoi_l3hlen + meo->meoi_l4hlen;
	ASSERT3U(hdr_len, <=, txq->et_ena->ena_tx_max_hdr_len);
#endif

	bzero(desc, sizeof (*desc));
	ENAHW_TX_DESC_FIRST_ON(desc);
	ENAHW_TX_DESC_LENGTH(desc, mlen);
	ENAHW_TX_DESC_REQID_HI(desc, tail);
	ENAHW_TX_DESC_REQID_LO(desc, tail);
	ENAHW_TX_DESC_PHASE(desc, phase);
	ENAHW_TX_DESC_DF_ON(desc);
	ENAHW_TX_DESC_LAST_ON(desc);
	ENAHW_TX_DESC_COMP_REQ_ON(desc);
	ENAHW_TX_DESC_META_DESC_OFF(desc);
	ENAHW_TX_DESC_ADDR_LO(desc, tcb->etcb_dma.edb_cookie->dmac_laddress);
	ENAHW_TX_DESC_ADDR_HI(desc, tcb->etcb_dma.edb_cookie->dmac_laddress);
	/*
	 * NOTE: Please see the block comment above
	 * etd_buff_addr_hi_hdr_sz to see why this is set to 0.
	 */
	ENAHW_TX_DESC_HEADER_LENGTH(desc, 0);
	ENAHW_TX_DESC_TSO_OFF(desc);
	ENAHW_TX_DESC_L3_CSUM_OFF(desc);
	ENAHW_TX_DESC_L4_CSUM_OFF(desc);
	/*
	 * Enabling this bit tells the device NOT to calculate the
	 * pseudo header checksum.
	 */
	ENAHW_TX_DESC_L4_CSUM_PARTIAL_ON(desc);
}

static void
ena_submit_tx(ena_txq_t *txq, uint16_t desc_idx)
{
	ena_hw_abs_write32(txq->et_ena, txq->et_sq_db_addr, desc_idx);
}

/*
 * For now we do the simplest thing possible. All Tx uses bcopy to
 * pre-allocated buffers, no checksum, no TSO, etc.
 */
mblk_t *
ena_ring_tx(void *arg, mblk_t *mp)
{
	ena_txq_t *txq = arg;
	ena_t *ena = txq->et_ena;
	mac_ether_offload_info_t meo;
	enahw_tx_data_desc_t *desc;
	ena_tx_control_block_t *tcb;
	const uint16_t tail_mod =
	    txq->et_sq_tail_idx & (txq->et_sq_num_descs - 1);

	VERIFY3P(mp->b_next, ==, NULL);

	/*
	 * The ena_state value is written by atomic operations. The
	 * et_state value is currently Write Once, but if that changes
	 * it should also be written with atomics.
	 */
	if (!(ena->ena_state & ENA_STATE_RUNNING) ||
	    !(txq->et_state & ENA_TXQ_STATE_RUNNING)) {
		freemsg(mp);
		return (NULL);
	}

	if (mac_ether_offload_info(mp, &meo) != 0) {
		freemsg(mp);
		mutex_enter(&txq->et_stat_lock);
		txq->et_stat.ets_hck_meoifail.value.ui64++;
		mutex_exit(&txq->et_stat_lock);
		return (NULL);
	}

	mutex_enter(&txq->et_lock);

	/*
	 * For the moment there is a 1:1 mapping between Tx descs and
	 * Tx contexts. Currently Tx is copy only, and each context
	 * buffer is guaranteed to be as large as MTU + frame header,
	 * see ena_update_buf_sizes().
	 */
	if (txq->et_blocked || txq->et_sq_avail_descs == 0) {
		txq->et_blocked = B_TRUE;
		mutex_enter(&txq->et_stat_lock);
		txq->et_stat.ets_blocked.value.ui64++;
		mutex_exit(&txq->et_stat_lock);
		mutex_exit(&txq->et_lock);
		return (mp);
	}

	ASSERT3U(meo.meoi_len, <=, ena->ena_max_frame_total);
	tcb = ena_pull_tcb(txq, mp);
	ASSERT3P(tcb, !=, NULL);
	tcb->etcb_mp = mp;
	txq->et_sq_avail_descs--;

	/* Fill in the Tx descriptor. */
	desc = &(txq->et_sq_descs[tail_mod].etd_data);
	ena_fill_tx_data_desc(txq, tcb, tail_mod, txq->et_sq_phase, desc, &meo,
	    meo.meoi_len);
	DTRACE_PROBE3(tx__submit, ena_tx_control_block_t *, tcb, uint16_t,
	    tail_mod, enahw_tx_data_desc_t *, desc);

	/*
	 * Remember, we submit the raw tail value to the device, the
	 * hardware performs its own modulo (like we did to get
	 * tail_mod).
	 */
	txq->et_sq_tail_idx++;
	ena_submit_tx(txq, txq->et_sq_tail_idx);

	mutex_enter(&txq->et_stat_lock);
	txq->et_stat.ets_packets.value.ui64++;
	txq->et_stat.ets_bytes.value.ui64 += meo.meoi_len;
	mutex_exit(&txq->et_stat_lock);

	if ((txq->et_sq_tail_idx & (txq->et_sq_num_descs - 1)) == 0) {
		txq->et_sq_phase ^= 1;
	}

	mutex_exit(&txq->et_lock);
	return (NULL);
}

void
ena_tx_intr_work(ena_txq_t *txq)
{
	uint16_t head_mod;
	enahw_tx_cdesc_t *cdesc;
	ena_tx_control_block_t *tcb;
	uint16_t req_id;
	uint64_t recycled = 0;
	boolean_t unblocked = B_FALSE;

	mutex_enter(&txq->et_lock);
	head_mod = txq->et_cq_head_idx & (txq->et_cq_num_descs - 1);
	ENA_DMA_SYNC(txq->et_cq_dma, DDI_DMA_SYNC_FORKERNEL);
	cdesc = &txq->et_cq_descs[head_mod];

	/* Recycle any completed descriptors. */
	while (ENAHW_TX_CDESC_GET_PHASE(cdesc) == txq->et_cq_phase) {
		mblk_t *mp;

		/* Get the corresponding TCB. */
		req_id = cdesc->etc_req_id;
		/*
		 * It would be nice to make this a device reset
		 * instead.
		 */
		VERIFY3U(req_id, <=, txq->et_sq_num_descs);
		tcb = &txq->et_tcbs[req_id];
		DTRACE_PROBE2(tx__complete, uint16_t, req_id,
		    ena_tx_control_block_t *, tcb);

		/* Free the associated mblk. */
		tcb->etcb_dma.edb_used_len = 0;
		mp = tcb->etcb_mp;
		/* Make this a device reset instead. */
		VERIFY3P(mp, !=, NULL);
		freemsg(mp);
		tcb->etcb_mp = NULL;

		/* Add this descriptor back to the free list. */
		txq->et_sq_avail_descs++;
		txq->et_cq_head_idx++;

		/* Check for phase rollover. */
		head_mod = txq->et_cq_head_idx & (txq->et_cq_num_descs - 1);

		if (head_mod == 0) {
			txq->et_cq_phase ^= 1;
		}

		if (txq->et_blocked) {
			txq->et_blocked = B_FALSE;
			unblocked = B_TRUE;
			mac_tx_ring_update(txq->et_ena->ena_mh, txq->et_mrh);
		}

		recycled++;
		cdesc = &txq->et_cq_descs[head_mod];
	}

	if (recycled == 0) {
		mutex_exit(&txq->et_lock);
		return;
	}

	mutex_exit(&txq->et_lock);

	/* Update stats. */
	mutex_enter(&txq->et_stat_lock);
	txq->et_stat.ets_recycled.value.ui64 += recycled;
	if (unblocked) {
		txq->et_stat.ets_unblocked.value.ui64++;
	}
	mutex_exit(&txq->et_stat_lock);
}
