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
 * Copyright 2026 Oxide Computer Company
 */

#include <sys/atomic.h>
#include "ena.h"

void
ena_free_tx_dma(ena_txq_t *txq)
{
	if (txq->et_tcbs != NULL) {
		for (uint_t i = 0; i < txq->et_sq_num_descs; i++) {
			ena_tx_control_block_t *tcb = &txq->et_tcbs[i];
			ena_dma_free(&tcb->etcb_dma);
			if (tcb->etcb_mp != NULL)
				freemsg(tcb->etcb_mp);
		}

		kmem_free(txq->et_tcbs,
		    sizeof (*txq->et_tcbs) * txq->et_sq_num_descs);
		kmem_free(txq->et_tcbs_freelist,
		    sizeof (ena_tx_control_block_t *) * txq->et_sq_num_descs);

		txq->et_tcbs = NULL;
		txq->et_tcbs_freelist = NULL;
		txq->et_tcbs_freelist_size = 0;
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

	ASSERT0(txq->et_state & ENA_TXQ_STATE_HOST_ALLOC);
	ASSERT3P(ena, !=, NULL);

	cq_descs_sz = txq->et_cq_num_descs * sizeof (*txq->et_cq_descs);
	sq_descs_sz = txq->et_sq_num_descs * sizeof (*txq->et_sq_descs);

	ena_dma_conf_t sq_conf = {
		.edc_size = sq_descs_sz,
		.edc_align = ENAHW_IO_SQ_DESC_BUF_ALIGNMENT,
		.edc_sgl = 1,
		.edc_endian = DDI_NEVERSWAP_ACC,
		.edc_stream = false,
	};

	if (!ena_dma_alloc(ena, &txq->et_sq_dma, &sq_conf, sq_descs_sz)) {
		return (ENOMEM);
	}

	txq->et_sq_descs = (void *)txq->et_sq_dma.edb_va;
	txq->et_tcbs = kmem_zalloc(sizeof (*txq->et_tcbs) *
	    txq->et_sq_num_descs, KM_SLEEP);
	txq->et_tcbs_freelist = kmem_zalloc(sizeof (ena_tx_control_block_t *) *
	    txq->et_sq_num_descs, KM_SLEEP);

	for (uint_t i = 0; i < txq->et_sq_num_descs; i++) {
		ena_tx_control_block_t *tcb = &txq->et_tcbs[i];
		ena_dma_conf_t buf_conf = {
			.edc_size = ena->ena_tx_buf_sz,
			.edc_align = 1,
			.edc_sgl = ena->ena_tx_sgl_max_sz,
			.edc_endian = DDI_NEVERSWAP_ACC,
			.edc_stream = true,
		};

		if (!ena_dma_alloc(ena, &tcb->etcb_dma, &buf_conf,
		    ena->ena_tx_buf_sz)) {
			err = ENOMEM;
			goto error;
		}

		tcb->etcb_id = i;
		txq->et_tcbs_freelist[i] = tcb;
	}
	txq->et_tcbs_freelist_size = txq->et_sq_num_descs;

	ena_dma_conf_t cq_conf = {
		.edc_size = cq_descs_sz,
		.edc_align = ENAHW_IO_CQ_DESC_BUF_ALIGNMENT,
		.edc_sgl = 1,
		.edc_endian = DDI_NEVERSWAP_ACC,
		.edc_stream = false,
	};

	if (!ena_dma_alloc(ena, &txq->et_cq_dma, &cq_conf, cq_descs_sz)) {
		err = ENOMEM;
		goto error;
	}

	txq->et_cq_descs = (void *)txq->et_cq_dma.edb_va;
	txq->et_state |= ENA_TXQ_STATE_HOST_ALLOC;
	return (0);

error:
	ena_free_tx_dma(txq);
	return (err);
}

bool
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
		return (false);
	}

	ASSERT(txq->et_state & ENA_TXQ_STATE_HOST_ALLOC);

	/*
	 * Second, create the Completion Queue.
	 */
	ret = ena_create_cq(ena, txq->et_cq_num_descs,
	    txq->et_cq_dma.edb_cookie->dmac_laddress, true,
	    txq->et_intr_vector, &cq_hw_idx, &cq_unmask_addr, &cq_numanode);

	if (ret != 0) {
		ena_err(ena, "failed to create Tx CQ %u: %d", txq->et_txqs_idx,
		    ret);
		return (false);
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
	    txq->et_sq_dma.edb_cookie->dmac_laddress, true, cq_hw_idx,
	    &sq_hw_idx, &sq_db_addr, &txq->et_sq_llq_addr);

	if (ret != 0) {
		ena_err(ena, "failed to create Tx SQ %u: %d", txq->et_txqs_idx,
		    ret);
		return (false);
	}

	txq->et_sq_hw_idx = sq_hw_idx;
	txq->et_sq_db_addr = sq_db_addr;
	/* The phase must always start on 1. */
	txq->et_sq_phase = 1;
	txq->et_sq_avail_descs = txq->et_sq_num_descs;
	txq->et_blocked = false;
	txq->et_stall_watchdog = 0;
	txq->et_state |= ENA_TXQ_STATE_SQ_CREATED;

	/*
	 * Allocate the LLQ bounce buffer, used to stage a complete
	 * LLQ entry before writing it to device memory.
	 */
	if (ena->ena_llq_enabled) {
		txq->et_sq_llq_buf = kmem_zalloc(ena->ena_llq_entry_size_bytes,
		    KM_SLEEP);
		txq->et_sq_llq_entries_left = ena->ena_llq_max_tx_burst_size /
		    ena->ena_llq_entry_size_bytes;
	}

	return (true);
}

void
ena_cleanup_txq(ena_txq_t *txq, bool resetting)
{
	int ret = 0;
	ena_t *ena = txq->et_ena;

	if ((txq->et_state & ENA_TXQ_STATE_SQ_CREATED) != 0) {
		if (!resetting) {
			ret = ena_destroy_sq(ena, txq->et_sq_hw_idx, true);

			if (ret != 0) {
				ena_err(ena, "failed to destroy Tx SQ %u: %d",
				    txq->et_txqs_idx, ret);
			}
		}

		if (txq->et_sq_llq_buf != NULL) {
			kmem_free(txq->et_sq_llq_buf,
			    ena->ena_llq_entry_size_bytes);
			txq->et_sq_llq_buf = NULL;
		}

		txq->et_sq_hw_idx = 0;
		txq->et_sq_db_addr = NULL;
		txq->et_sq_llq_addr = NULL;
		txq->et_sq_tail_idx = 0;
		txq->et_sq_phase = 0;
		txq->et_state &= ~ENA_TXQ_STATE_SQ_CREATED;
	}

	if ((txq->et_state & ENA_TXQ_STATE_CQ_CREATED) != 0) {
		if (!resetting) {
			ret = ena_destroy_cq(ena, txq->et_cq_hw_idx);

			if (ret != 0) {
				ena_err(ena, "failed to destroy Tx CQ %u: %d",
				    txq->et_txqs_idx, ret);
			}
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

	ena_dbg(ena, "ring_tx_start %p: state 0x%x", txq, txq->et_state);

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

static ena_tx_control_block_t *
ena_tcb_alloc(ena_txq_t *txq)
{
	ena_tx_control_block_t *tcb;

	ASSERT(MUTEX_HELD(&txq->et_lock));

	if (txq->et_tcbs_freelist_size == 0)
		return (NULL);
	txq->et_tcbs_freelist_size--;
	tcb = txq->et_tcbs_freelist[txq->et_tcbs_freelist_size];
	txq->et_tcbs_freelist[txq->et_tcbs_freelist_size] = NULL;

	return (tcb);
}

static void
ena_tcb_free(ena_txq_t *txq, ena_tx_control_block_t *tcb)
{
	ASSERT3P(tcb, !=, NULL);
	ASSERT(MUTEX_HELD(&txq->et_lock));
	ASSERT3U(txq->et_tcbs_freelist_size, <, txq->et_sq_num_descs);
	txq->et_tcbs_freelist[txq->et_tcbs_freelist_size++] = tcb;
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

static void
ena_tcb_pull(const ena_txq_t *txq, ena_tx_control_block_t *tcb, mblk_t *mp)
{
	mblk_t *nmp = mp;
	ena_t *ena = txq->et_ena;

	ASSERT(MUTEX_HELD(&txq->et_lock));
	VERIFY3U(msgsize(mp), <, ena->ena_tx_buf_sz);
	ASSERT3P(tcb, !=, NULL);
	VERIFY0(tcb->etcb_dma.edb_used_len);

	while (nmp != NULL) {
		const size_t nmp_len = MBLKL(nmp);

		if (nmp_len == 0) {
			nmp = nmp->b_cont;
			continue;
		}

		ena_tx_copy_fragment(tcb, nmp, 0, nmp_len);
		nmp = nmp->b_cont;
	}

	ENA_DMA_SYNC(tcb->etcb_dma, DDI_DMA_SYNC_FORDEV);

	VERIFY3P(tcb->etcb_mp, ==, NULL);
	tcb->etcb_mp = mp;
}

static void
ena_fill_tx_data_desc(ena_txq_t *txq, ena_tx_control_block_t *tcb,
    uint16_t req_id, uint8_t phase, enahw_tx_data_desc_t *desc,
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
	ENAHW_TX_DESC_REQID_HI(desc, req_id);
	ENAHW_TX_DESC_REQID_LO(desc, req_id);
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

/*
 * Fill in a TX meta descriptor. With DISABLE_META_CACHING the device
 * requires a meta descriptor for every packet. We don't use TSO so
 * MSS is always zero; the meta descriptor carries header offset
 * information.
 */
static void
ena_fill_tx_meta_desc(enahw_tx_meta_desc_t *meta, uint8_t phase,
    mac_ether_offload_info_t *meo)
{
	bzero(meta, sizeof (*meta));
	ENAHW_TX_META_DESC_META_DESC_ON(meta);
	ENAHW_TX_META_DESC_EXT_VALID_ON(meta);
	ENAHW_TX_META_DESC_ETH_META_TYPE_ON(meta);
	ENAHW_TX_META_DESC_META_STORE_ON(meta);
	ENAHW_TX_META_DESC_PHASE(meta, phase);
	ENAHW_TX_META_DESC_FIRST_ON(meta);
	ENAHW_TX_META_DESC_COMP_REQ_ON(meta);
	ENAHW_TX_META_DESC_L3_HDR_OFF(meta, meo->meoi_l2hlen);
}

/*
 * Write a bounce buffer to LLQ device memory using 64-bit stores.
 * See the "LLQ Tx Path" section of the big theory statement for
 * discussion of write-combining safety and ordering.
 */
static void
ena_llq_write_to_dev(ena_txq_t *txq, uint8_t *buf, uint16_t entry_size)
{
	const uint16_t modulo_mask = txq->et_sq_num_descs - 1;
	uint32_t dst_offset;
	volatile uint64_t *dst;
	const uint64_t *src;
	uint16_t count, i;

	/*
	 * The reference drivers place a write barrier here between
	 * filling the bounce buffer and writing it to device memory.
	 * The bounce buffer is only read back by this CPU so it is
	 * not clear why this is needed, but we retain it for parity.
	 */
	membar_producer();

	dst_offset = (txq->et_sq_tail_idx & modulo_mask) * entry_size;
	dst = (volatile uint64_t *)((caddr_t)txq->et_sq_llq_addr + dst_offset);
	src = (const uint64_t *)buf;
	count = entry_size / sizeof (uint64_t);

	for (i = 0; i < count; i++)
		dst[i] = src[i];
}

static void
ena_submit_tx(ena_txq_t *txq, uint16_t desc_idx)
{
	ena_t *ena = txq->et_ena;

	ena_hw_abs_write32(ena, txq->et_sq_db_addr, desc_idx);

	/* Reset the burst counter after each doorbell for LIMIT_TX_BURST */
	if (ena->ena_llq_enabled) {
		txq->et_sq_llq_entries_left = ena->ena_llq_max_tx_burst_size /
		    ena->ena_llq_entry_size_bytes;
	}
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
	const uint16_t modulo_mask = txq->et_sq_num_descs - 1;
	uint16_t tail_mod;

	VERIFY3P(mp->b_next, ==, NULL);

	/*
	 * The ena_state value is written by atomic operations. The
	 * et_state value is currently Write Once, but if that changes
	 * it should also be written with atomics.
	 */
	if (!(ena->ena_state & ENA_STATE_STARTED) ||
	    !(txq->et_state & ENA_TXQ_STATE_RUNNING)) {
		freemsg(mp);
		return (NULL);
	}

	/*
	 * Failing to parse the L2 header would be a surprise.  Until we wire up
	 * other offloads, high level protocols are not a concern.
	 */
	mac_ether_offload_info(mp, &meo);
	if ((meo.meoi_flags & MEOI_L2INFO_SET) == 0) {
		freemsg(mp);
		mutex_enter(&txq->et_stat_lock);
		txq->et_stat.ets_hck_meoifail.value.ui64++;
		mutex_exit(&txq->et_stat_lock);
		return (NULL);
	}

	mutex_enter(&txq->et_lock);

	/*
	 * For the moment there are an equal number of Tx descs and Tx
	 * contexts. Currently Tx is copy only, and each context buffer is
	 * guaranteed to be as large as MTU + frame header, see
	 * ena_update_buf_sizes().
	 */
	if (txq->et_blocked || txq->et_sq_avail_descs == 0) {
		txq->et_blocked = true;
		mutex_enter(&txq->et_stat_lock);
		txq->et_stat.ets_blocked.value.ui64++;
		mutex_exit(&txq->et_stat_lock);
		mutex_exit(&txq->et_lock);
		return (mp);
	}

	ASSERT3U(meo.meoi_len, <=, ena->ena_max_frame_total);

	/*
	 * There are as many pre-allocated TCBs as there are Tx descs so we
	 * should never fail to get one.
	 */
	tcb = ena_tcb_alloc(txq);
	ASSERT3P(tcb, !=, NULL);
	ena_tcb_pull(txq, tcb, mp);

	if (ena->ena_llq_enabled) {
		/*
		 * LLQ: build the bounce buffer with a meta descriptor, data
		 * descriptor, and inline packet header, then write the entire
		 * entry to device memory.
		 *
		 * Layout in the bounce buffer (for 128B entry with
		 * descs_before_header=2):
		 *   [0..15]   meta descriptor
		 *   [16..31]  data descriptor
		 *   [32..127] inline packet header
		 *
		 * The data descriptor still references the DMA buffer for the
		 * remaining packet payload; the inline header is an
		 * optimisation that lets the device begin processing the
		 * header immediately.
		 */
		uint8_t *buf = txq->et_sq_llq_buf;
		enahw_tx_meta_desc_t *meta;
		uint16_t hdr_off;
		size_t hdr_space, hdr_copy;

		bzero(buf, ena->ena_llq_entry_size_bytes);

		/* Slot 0: meta descriptor */
		meta = (enahw_tx_meta_desc_t *)buf;
		ena_fill_tx_meta_desc(meta, txq->et_sq_phase, &meo);

		/* Slot 1: data descriptor */
		desc = (enahw_tx_data_desc_t *)(buf + sizeof (enahw_tx_desc_t));

		/*
		 * Copy the packet header into the bounce buffer after the
		 * descriptor slots.
		 */
		hdr_off = ena->ena_llq_num_descs_before_header *
		    sizeof (enahw_tx_desc_t);
		hdr_space = ena->ena_llq_entry_size_bytes - hdr_off;
		hdr_copy = MIN(meo.meoi_len, hdr_space);
		bcopy(tcb->etcb_dma.edb_va, buf + hdr_off, hdr_copy);

		/*
		 * The data descriptor's address and length must skip past
		 * the inline header bytes that are already in the LLQ
		 * entry.
		 */
		ena_fill_tx_data_desc(txq, tcb, tcb->etcb_id,
		    txq->et_sq_phase, desc, &meo,
		    meo.meoi_len - hdr_copy);
		ENAHW_TX_DESC_FIRST_OFF(desc);
		ENAHW_TX_DESC_HEADER_LENGTH(desc, hdr_copy);
		ENAHW_TX_DESC_ADDR_LO(desc,
		    tcb->etcb_dma.edb_cookie->dmac_laddress + hdr_copy);
		ENAHW_TX_DESC_ADDR_HI(desc,
		    tcb->etcb_dma.edb_cookie->dmac_laddress + hdr_copy);

		ena_llq_write_to_dev(txq, buf, ena->ena_llq_entry_size_bytes);
		/*
		 * Ensure the write-combining stores to the LLQ BAR are
		 * ordered before the upcoming doorbell write.
		 */
		membar_producer();
		/*
		 * Since mac calls us with one packet at a time, we don't
		 * actually do any batching and we never expect to run out
		 * of llq entries.
		 */
		if (ena->ena_llq_max_tx_burst_size > 0) {
			ASSERT3U(txq->et_sq_llq_entries_left, >, 0);
			txq->et_sq_llq_entries_left--;
		}
	} else {
		/* Host placement */
		tail_mod = txq->et_sq_tail_idx & modulo_mask;
		desc = &txq->et_sq_descs[tail_mod].etd_data;
		ena_fill_tx_data_desc(txq, tcb, tcb->etcb_id,
		    txq->et_sq_phase, desc, &meo, meo.meoi_len);
		ENA_DMA_SYNC(txq->et_sq_dma, DDI_DMA_SYNC_FORDEV);
	}

	DTRACE_PROBE3(tx__submit, ena_tx_control_block_t *, tcb, uint16_t,
	    tcb->etcb_id, enahw_tx_data_desc_t *, desc);

	txq->et_sq_avail_descs--;

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

	if ((txq->et_sq_tail_idx & modulo_mask) == 0)
		txq->et_sq_phase ^= 1;

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
	bool unblocked = false;
	const uint16_t modulo_mask = txq->et_cq_num_descs - 1;
	ena_t *ena = txq->et_ena;

	mutex_enter(&txq->et_lock);
	head_mod = txq->et_cq_head_idx & modulo_mask;
	ENA_DMA_SYNC(txq->et_cq_dma, DDI_DMA_SYNC_FORKERNEL);
	cdesc = &txq->et_cq_descs[head_mod];

	/* Recycle any completed descriptors. */
	while (ENAHW_TX_CDESC_GET_PHASE(cdesc) == txq->et_cq_phase) {
		mblk_t *mp;

		/* Get the corresponding TCB. */
		req_id = cdesc->etc_req_id;
		if (req_id > txq->et_sq_num_descs) {
			ena_err(ena, "invalid Tx request ID: 0x%x", req_id);
			ena_trigger_reset(ena, ENAHW_RESET_INV_TX_REQ_ID);
			break;
		}
		tcb = &txq->et_tcbs[req_id];
		DTRACE_PROBE2(tx__complete, uint16_t, req_id,
		    ena_tx_control_block_t *, tcb);

		/* Free the associated mblk. */
		tcb->etcb_dma.edb_used_len = 0;
		mp = tcb->etcb_mp;
		tcb->etcb_mp = NULL;
		VERIFY3P(mp, !=, NULL);
		freemsg(mp);

		/* Add this descriptor back to the free list. */
		ena_tcb_free(txq, tcb);
		txq->et_sq_avail_descs++;

		/* Move on and check for phase rollover. */
		txq->et_cq_head_idx++;
		head_mod = txq->et_cq_head_idx & modulo_mask;
		if (head_mod == 0)
			txq->et_cq_phase ^= 1;

		if (txq->et_blocked) {
			txq->et_blocked = false;
			txq->et_stall_watchdog = 0;
			unblocked = true;
			mac_tx_ring_update(ena->ena_mh, txq->et_mrh);
		}

		recycled++;
		cdesc = &txq->et_cq_descs[head_mod];
	}

	mutex_exit(&txq->et_lock);

	if (recycled == 0)
		return;

	/* Update stats. */
	mutex_enter(&txq->et_stat_lock);
	txq->et_stat.ets_recycled.value.ui64 += recycled;
	if (unblocked) {
		txq->et_stat.ets_unblocked.value.ui64++;
	}
	mutex_exit(&txq->et_stat_lock);
}
