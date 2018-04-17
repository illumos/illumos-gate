/*
* CDDL HEADER START
*
* The contents of this file are subject to the terms of the
* Common Development and Distribution License, v.1,  (the "License").
* You may not use this file except in compliance with the License.
*
* You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
* or http://opensource.org/licenses/CDDL-1.0.
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
* Copyright 2014-2017 Cavium, Inc. 
* The contents of this file are subject to the terms of the Common Development 
* and Distribution License, v.1,  (the "License").

* You may not use this file except in compliance with the License.

* You can obtain a copy of the License at available 
* at http://opensource.org/licenses/CDDL-1.0

* See the License for the specific language governing permissions and 
* limitations under the License.
*/

#include "qede.h"

static qede_dma_handle_entry_t *
qede_get_dmah_entry(qede_tx_ring_t *tx_ring)
{
	qede_dma_handles_list_t *list = &tx_ring->dmah_list;
	qede_dma_handle_entry_t *dmah;

	mutex_enter(&list->lock);
	dmah = list->free_list[list->head];
	list->free_list[list->head] = NULL;
	list->head = (list->head + 1) & TX_RING_MASK;
	mutex_exit(&list->lock);

	return (dmah);
}

static void
qede_put_dmah_entries(qede_tx_ring_t *tx_ring, qede_dma_handle_entry_t *dmah)
{
	qede_dma_handles_list_t *list = &tx_ring->dmah_list;
	qede_dma_handle_entry_t *next;
	u16 index;

	mutex_enter(&list->lock);
	index = list->tail;
	
	while (dmah != NULL) {
		next = dmah->next;
		dmah->next = NULL;
		list->free_list[index] = dmah;
		index = (index + 1) & TX_RING_MASK;
		dmah = next;
	}

	list->tail = index;

	mutex_exit(&list->lock);
}

static qede_tx_bcopy_pkt_t *
qede_get_bcopy_pkt(qede_tx_ring_t *tx_ring)
{
	qede_tx_bcopy_list_t *list = &tx_ring->bcopy_list;
	qede_tx_bcopy_pkt_t *pkt;

	mutex_enter(&list->lock);
	pkt = list->free_list[list->head];
	list->free_list[list->head] = NULL;
	list->head = (list->head + 1) & TX_RING_MASK;
	mutex_exit(&list->lock);

	return (pkt);
}

static void
qede_put_bcopy_pkt(qede_tx_ring_t *tx_ring, qede_tx_bcopy_pkt_t *pkt)
{
	qede_tx_bcopy_list_t *list = &tx_ring->bcopy_list;

	mutex_enter(&list->lock);
	list->free_list[list->tail] = pkt;
	list->tail = (list->tail + 1) & TX_RING_MASK;
	mutex_exit(&list->lock);
}

void 
qede_print_tx_indexes(qede_tx_ring_t *tx_ring)
{
	uint16_t hw_consumer = LE_16(*tx_ring->hw_cons_ptr);
	uint16_t chain_idx = ecore_chain_get_cons_idx(&tx_ring->tx_bd_ring);
	hw_consumer &= TX_RING_MASK;
	chain_idx &= TX_RING_MASK;
	qede_print_err("!indices: hw_cons %d, chain_cons = %d, sw_prod = %d",
	    hw_consumer, chain_idx, tx_ring->sw_tx_prod); 
}

void 
qede_print_rx_indexes(qede_rx_ring_t *rx_ring)
{
	u16 hw_bd_cons = HOST_TO_LE_16(*rx_ring->hw_cons_ptr);
	u16 sw_bd_cons = ecore_chain_get_cons_idx(&rx_ring->rx_cqe_ring);

	hw_bd_cons &= (rx_ring->qede->rx_ring_size - 1);
	sw_bd_cons &= (rx_ring->qede->rx_ring_size - 1);
	qede_print_err("!RX indices: hw_cons %d, chain_cons = %d",
	    hw_bd_cons, sw_bd_cons); 
}


/*
 * Called from tx_completion intr handler.
 * NOTE: statu_block dma mem. must be sync'ed
 * in the interrupt handler
 */
int 
qede_process_tx_completions(qede_tx_ring_t *tx_ring)
{
	int count = 0;
	u16 hw_consumer;
	struct eth_tx_bd *tx_bd;
	uint16_t chain_idx;
	u16 nbd, sw_consumer = tx_ring->sw_tx_cons;
	struct eth_tx_1st_bd *first_bd;
	u16 bd_consumed = 0;
	qede_tx_recycle_list_t *recycle_entry;
	qede_dma_handle_entry_t *dmah, *head = NULL, *tail = NULL;
	qede_tx_bcopy_pkt_t *bcopy_pkt;

	hw_consumer = LE_16(*tx_ring->hw_cons_ptr);
	chain_idx = ecore_chain_get_cons_idx(&tx_ring->tx_bd_ring);

	while (hw_consumer != chain_idx) {
		nbd = 0;
		bd_consumed = 0;
		first_bd = NULL;

		recycle_entry = &tx_ring->tx_recycle_list[sw_consumer];
		if (recycle_entry->dmah_entry != NULL) {
			dmah = recycle_entry->dmah_entry;

			head = dmah;

			if (head->mp) {
				freemsg(head->mp);
			}

			while (dmah != NULL) {
				(void) ddi_dma_unbind_handle(dmah->dma_handle);
				dmah = dmah->next;
			}


			qede_put_dmah_entries(tx_ring,
			    head);
			recycle_entry->dmah_entry = NULL;
		} else if (recycle_entry->bcopy_pkt != NULL) {
			bcopy_pkt = recycle_entry->bcopy_pkt;

			qede_put_bcopy_pkt(tx_ring, bcopy_pkt);
			recycle_entry->bcopy_pkt = NULL;
		} else {
			qede_warn(tx_ring->qede,
			    "Invalid completion at index %d",
			    sw_consumer);
		}

		sw_consumer = (sw_consumer + 1) & TX_RING_MASK;

		first_bd =
		    (struct eth_tx_1st_bd *)ecore_chain_consume(
		    &tx_ring->tx_bd_ring);
		bd_consumed++;
		
		nbd = first_bd->data.nbds;

		while (bd_consumed++ < nbd) {
			ecore_chain_consume(&tx_ring->tx_bd_ring);
		}

		chain_idx = ecore_chain_get_cons_idx(&tx_ring->tx_bd_ring);
		count++;
	}

	tx_ring->sw_tx_cons = sw_consumer;

	if (count && tx_ring->tx_q_sleeping) {
		tx_ring->tx_q_sleeping = 0;
#ifndef NO_CROSSBOW
		RESUME_TX(tx_ring);
#else
		mac_tx_update(tx_ring->qede->mac_handle);
#endif
	}

	return (count);
}

static int
qede_has_tx_work(qede_tx_ring_t *tx_ring)
{
	u16 hw_bd_cons = LE_16(*tx_ring->hw_cons_ptr);
	u16 sw_bd_cons = ecore_chain_get_cons_idx(&tx_ring->tx_bd_ring);

	if (sw_bd_cons == (hw_bd_cons + 1)) {
		return (0);
	}
	return (hw_bd_cons != sw_bd_cons);
}

static int
qede_has_rx_work(qede_rx_ring_t *rx_ring)
{
	u16 hw_bd_cons = HOST_TO_LE_16(*rx_ring->hw_cons_ptr);
	u16 sw_bd_cons = ecore_chain_get_cons_idx(&rx_ring->rx_cqe_ring);
	return (hw_bd_cons != sw_bd_cons);
}

static void
qede_set_cksum_flags(mblk_t *mp,
    uint16_t parse_flags)
{
	uint32_t cksum_flags = 0;
	int error = 0;
	bool l4_is_calc, l4_csum_err, iphdr_len_err;
	
	l4_is_calc =
	    (parse_flags >> PARSING_AND_ERR_FLAGS_L4CHKSMWASCALCULATED_SHIFT)
	    & PARSING_AND_ERR_FLAGS_L4CHKSMWASCALCULATED_MASK;
	l4_csum_err = (parse_flags >> PARSING_AND_ERR_FLAGS_L4CHKSMERROR_SHIFT)
	    & PARSING_AND_ERR_FLAGS_L4CHKSMWASCALCULATED_MASK;
	iphdr_len_err = (parse_flags >> PARSING_AND_ERR_FLAGS_IPHDRERROR_SHIFT)
	    & PARSING_AND_ERR_FLAGS_IPHDRERROR_MASK;

	if (l4_is_calc) {
		if (l4_csum_err) {
			error = 1;
        	} else if (iphdr_len_err) {
            		error = 2;
        	} else {
			cksum_flags =  HCK_FULLCKSUM_OK | HCK_IPV4_HDRCKSUM_OK;
		}
	}
	
	if (error == 1) {
		qede_print_err("!%s: got L4 csum error",__func__);
	} else if (error == 2) {
		qede_print_err("!%s: got IPHDER csum error" ,__func__);
	}

	mac_hcksum_set(mp, 0, 0, 0, 0, cksum_flags);
}

static qede_rx_buffer_t *
qede_get_next_rx_buffer(qede_rx_ring_t *rx_ring,
    uint32_t *free_buffer_count)
{
	qede_rx_buffer_t *rx_buffer;
	uint32_t num_entries;

	rx_buffer = qede_get_from_active_list(rx_ring, &num_entries);
	ASSERT(rx_buffer != NULL);
	ecore_chain_consume(&rx_ring->rx_bd_ring);
	*free_buffer_count = num_entries;

	return (rx_buffer);
}

static uint32_t
qede_get_next_lro_buffer(qede_rx_ring_t *rx_ring,
    qede_lro_info_t *lro_info)
{
	lro_info->rx_buffer[lro_info->bd_count] =
	    qede_get_next_rx_buffer(rx_ring,
	    &lro_info->free_buffer_count);
	lro_info->bd_count++;
	return (DDI_SUCCESS);
}
#ifdef DEBUG_LRO
int agg_count = 0;
bool agg_print = B_TRUE;
#endif
static void
qede_lro_start(qede_rx_ring_t *rx_ring,
    struct eth_fast_path_rx_tpa_start_cqe *cqe)
{
	qede_lro_info_t *lro_info;
	int i, len_on_first_bd, seg_len; 

	lro_info = &rx_ring->lro_info[cqe->tpa_agg_index];

	/* ASSERT(lro_info->agg_state != QEDE_AGG_STATE_NONE); */

#ifdef DEBUG_LRO
	if (agg_count++ < 30)  {
		qede_dump_start_lro_cqe(cqe);
	} else { 
		agg_print = B_FALSE;
	}
#endif

	memset(lro_info, 0, sizeof (qede_lro_info_t));
	lro_info->agg_state = QEDE_AGG_STATE_START;
	rx_ring->lro_active_count++;

	/* Parsing and error flags from the parser */;
		
	lro_info->pars_flags = LE_16(cqe->pars_flags.flags);
	lro_info->pad = LE_16(cqe->placement_offset);
	lro_info->header_len = (uint32_t)cqe->header_len;
	lro_info->vlan_tag = LE_16(cqe->vlan_tag);
	lro_info->rss_hash = LE_32(cqe->rss_hash);

	seg_len = (int)LE_16(cqe->seg_len); 
	len_on_first_bd = (int)LE_16(cqe->len_on_first_bd);
	/*
	 * Get the first bd
	 */
	qede_get_next_lro_buffer(rx_ring, lro_info);

	if (len_on_first_bd < seg_len) {
		/*
		 * We end up here with jumbo frames
		 * since a TCP segment can span
		 * multiple buffer descriptors.
		 */
		for (i = 0; i < ETH_TPA_CQE_START_LEN_LIST_SIZE; i++) {
			if (cqe->ext_bd_len_list[i] == 0) {
			    break;
			}
			qede_get_next_lro_buffer(rx_ring, lro_info);
		}
	}
}

static void
qede_lro_cont(qede_rx_ring_t *rx_ring,
    struct eth_fast_path_rx_tpa_cont_cqe *cqe)
{
	qede_lro_info_t *lro_info;
	int i;

	lro_info = &rx_ring->lro_info[cqe->tpa_agg_index];

	/* ASSERT(lro_info->agg_state != QEDE_AGG_STATE_START); */
#ifdef DEBUG_LRO
	if (agg_print) {
		qede_dump_cont_lro_cqe(cqe);
	}
#endif

	for (i = 0; i < ETH_TPA_CQE_CONT_LEN_LIST_SIZE; i++) {
		if (cqe->len_list[i] == 0) {
			break;
		}
		qede_get_next_lro_buffer(rx_ring, lro_info);
	}
}

static mblk_t *
qede_lro_end(qede_rx_ring_t *rx_ring,
    struct eth_fast_path_rx_tpa_end_cqe *cqe,
    int *pkt_bytes)
{
	qede_lro_info_t *lro_info;
	mblk_t *head = NULL, *tail = NULL, *mp = NULL;
	qede_rx_buffer_t *rx_buffer;
	int i, bd_len;
	uint16_t work_length, total_packet_length;
	uint32_t rx_buf_size = rx_ring->rx_buf_size;
	qede_dma_info_t *dma_info;

	lro_info = &rx_ring->lro_info[cqe->tpa_agg_index];

	/* ASSERT(lro_info->agg_state != QEDE_AGG_STATE_START); */

#ifdef DEBUG_LRO
	if (agg_print) {
		qede_dump_end_lro_cqe(cqe);
	}
#endif

	work_length = total_packet_length = LE_16(cqe->total_packet_len);

	/*
	 * Get any buffer descriptors for this cqe
	 */
	for (i=0; i<ETH_TPA_CQE_END_LEN_LIST_SIZE; i++) {
		if (cqe->len_list[i] == 0) {
		    break;
		}
		qede_get_next_lro_buffer(rx_ring, lro_info);
	}

	/* ASSERT(lro_info->bd_count != cqe->num_of_bds); */

	if (lro_info->free_buffer_count < 
	    rx_ring->rx_low_buffer_threshold) {
		for (i = 0; i < lro_info->bd_count; i++) {
			qede_recycle_copied_rx_buffer(
			    lro_info->rx_buffer[i]);
			lro_info->rx_buffer[i] = NULL;
		}
		rx_ring->rx_low_water_cnt++;
		lro_info->agg_state = QEDE_AGG_STATE_NONE;
		return (NULL);
	}
	/*
	 * Loop through list of buffers for this
	 * aggregation.  For each one:
	 * 1. Calculate the buffer length
	 * 2. Adjust the mblk read/write pointers
	 * 3. Link the mblk to the local chain using
	 *    b_cont pointers.
	 * Note: each buffer will be rx_buf_size except
	 * the first (subtract the placement_offset)
	 * and the last which contains the remainder
	 * of cqe_end->total_packet_len minus length
	 * of all other buffers.
	 */
	for (i = 0; i < lro_info->bd_count; i++) {

		rx_buffer = lro_info->rx_buffer[i];

		bd_len = 
		    (work_length > rx_buf_size) ? rx_buf_size : work_length;
		if (i == 0 &&
		    (cqe->num_of_bds > 1)) {
			bd_len -= lro_info->pad;
		}

		dma_info = &rx_buffer->dma_info;		
		ddi_dma_sync(dma_info->dma_handle,
		    dma_info->offset,
		    rx_buf_size,
		    DDI_DMA_SYNC_FORKERNEL);

		mp = rx_buffer->mp;
		mp->b_next = mp->b_cont = NULL;

		if (head == NULL) {
			head = tail = mp;
			mp->b_rptr += lro_info->pad;
		} else {
			tail->b_cont = mp;
			tail = mp;
		}

		mp->b_wptr = (uchar_t *)((unsigned long)mp->b_rptr + bd_len);
		work_length -= bd_len;
	}

	qede_set_cksum_flags(head, lro_info->pars_flags);
 
	rx_ring->rx_lro_pkt_cnt++;
	rx_ring->lro_active_count--;	
	lro_info->agg_state = QEDE_AGG_STATE_NONE;

#ifdef DEBUG_LRO
	if (agg_print) {
		qede_dump_mblk_chain_bcont_ptr(rx_ring->qede, head);
	}
#endif
	*pkt_bytes = (int)total_packet_length;
	return (head);
}



#ifdef DEBUG_JUMBO
int jumbo_count = 0;
bool jumbo_print = B_TRUE;
#endif
static mblk_t *
qede_reg_jumbo_cqe(qede_rx_ring_t *rx_ring,
   struct eth_fast_path_rx_reg_cqe *cqe)
{
	int i;
	qede_rx_buffer_t *rx_buf, *rx_buffer[ETH_RX_MAX_BUFF_PER_PKT];
	mblk_t *mp = NULL, *head = NULL, *tail = NULL;
	uint32_t free_buffer_count;
	uint16_t work_length;
	uint32_t rx_buf_size = rx_ring->rx_buf_size, bd_len;
	qede_dma_info_t *dma_info;
	u8 pad = cqe->placement_offset;

#ifdef DEBUG_JUMBO
	if (jumbo_count++ < 8) { 
		qede_dump_reg_cqe(cqe);
	} else {
		jumbo_print = B_FALSE;
	}
#endif

	work_length = HOST_TO_LE_16(cqe->pkt_len);

	/*
	 * Get the buffers/mps for this cqe
	 */
	for (i = 0; i < cqe->bd_num; i++) {
		rx_buffer[i] =
		    qede_get_next_rx_buffer(rx_ring, &free_buffer_count);
	}

	/*
	 * If the buffer ring is running low, drop the
	 * packet and return these buffers.
	 */
	if (free_buffer_count < 
	    rx_ring->rx_low_buffer_threshold) {
		for (i = 0; i < cqe->bd_num; i++) {
			qede_recycle_copied_rx_buffer(rx_buffer[i]);
		}
		rx_ring->rx_low_water_cnt++;
		return (NULL);
	}

	for (i = 0; i < cqe->bd_num; i++) {
		rx_buf = rx_buffer[i];

		bd_len = 
		    (work_length > rx_buf_size) ? rx_buf_size : work_length;

		/*
		 * Adjust for placement offset
		 * on first bufffer.
		 */
		if (i == 0) {
			bd_len -= pad;
		}

		dma_info = &rx_buf->dma_info;		
		ddi_dma_sync(dma_info->dma_handle,
		    dma_info->offset,
		    rx_buf_size,
		    DDI_DMA_SYNC_FORKERNEL);

		mp = rx_buf->mp;
		mp->b_next = mp->b_cont = NULL;
		/*
		 * Adjust for placement offset
		 * on first bufffer.
		 */
		if (i == 0) {
			mp->b_rptr += pad;
		}

		mp->b_wptr = (uchar_t *)((unsigned long)mp->b_rptr + bd_len);

		if (head == NULL) {
			head = tail = mp;
		} else {
			tail->b_cont = mp;
			tail = mp;
		}

		work_length -= bd_len;
	}

	qede_set_cksum_flags(head,
		    HOST_TO_LE_16(cqe->pars_flags.flags));
#ifdef DEBUG_JUMBO
	if (jumbo_print) {
		qede_dump_mblk_chain_bcont_ptr(rx_ring->qede, head);
	}
#endif
	rx_ring->rx_jumbo_pkt_cnt++;
	return (head);
}

static mblk_t *
qede_reg_cqe(qede_rx_ring_t *rx_ring,
    struct eth_fast_path_rx_reg_cqe *cqe,
    int *pkt_bytes)
{
	qede_t *qede = rx_ring->qede;
	qede_rx_buffer_t *rx_buffer;
	uint32_t free_buffer_count;
	mblk_t *mp;
	uint16_t pkt_len = HOST_TO_LE_16(cqe->pkt_len);
	u8 pad = cqe->placement_offset;
	qede_dma_info_t *dma_info;
	ddi_dma_handle_t dma_handle;
	char *virt_addr;

	/*
	 * Update the byte count as it will
	 * be the same for normal and jumbo
	 */
	*pkt_bytes = (int)pkt_len;

	if (cqe->bd_num > 1) {
		/*
		 * If this cqe uses more than one
		 * rx buffer then it must be
		 * jumbo.  Call another handler
		 * for this because the process is
		 * quite different.
		 */
		return (qede_reg_jumbo_cqe(rx_ring, cqe));
	}
	
	
	rx_buffer = qede_get_next_rx_buffer(rx_ring,
            &free_buffer_count);

	if (free_buffer_count < 
	    rx_ring->rx_low_buffer_threshold) {
		qede_recycle_copied_rx_buffer(rx_buffer);
		rx_ring->rx_low_water_cnt++;
		*pkt_bytes = 0;
		return (NULL);
	}

	dma_info = &rx_buffer->dma_info;		
	virt_addr = dma_info->virt_addr;
	dma_handle = dma_info->dma_handle;
	ddi_dma_sync(dma_handle,
	    0, 0, DDI_DMA_SYNC_FORKERNEL);

	if (pkt_len <= rx_ring->rx_copy_threshold) {
		mp = allocb(pkt_len + 2, 0); /* IP HDR_ALIGN */
		if (mp != NULL) {
			virt_addr += pad;
			bcopy(virt_addr, mp->b_rptr, pkt_len);
		} else {
			/*
			 * Post the buffer back to fw and
			 * drop packet
			 */
			qede_print_err("!%s(%d): allocb failed",
		    	    __func__,
			    rx_ring->qede->instance);
			qede->allocbFailures++;
                        goto freebuf;
		}
		/* 
		 * We've copied it (or not) and are done with it
		 * so put it back into the passive list.
		 */
		ddi_dma_sync(dma_handle,
	            0, 0, DDI_DMA_SYNC_FORDEV);
		qede_recycle_copied_rx_buffer(rx_buffer);
		rx_ring->rx_copy_cnt++;
	} else {

		/*
		 * We are going to send this mp/buffer
		 * up to the mac layer.  Adjust the 
		 * pointeres and link it to our chain.
		 * the rx_buffer is returned to us in
		 * the recycle function so we drop it
		 * here.
		 */
		mp = rx_buffer->mp;
		mp->b_rptr += pad;
	}
	mp->b_cont = mp->b_next = NULL;
	mp->b_wptr = (uchar_t *)((unsigned long)mp->b_rptr + pkt_len);

	qede_set_cksum_flags(mp,
	    HOST_TO_LE_16(cqe->pars_flags.flags));
#ifdef DEBUG_JUMBO
	if (jumbo_print) {
	    qede_dump_mblk_chain_bnext_ptr(rx_ring->qede, mp);
	}
#endif

	rx_ring->rx_reg_pkt_cnt++;
	return (mp);	

freebuf:
        qede_recycle_copied_rx_buffer(rx_buffer);
        return (NULL);
}

/*
 * Routine to process the rx packets on the
 * passed rx_ring. Can be called for intr or
 * poll context/routines
 */
static mblk_t *
qede_process_rx_ring(qede_rx_ring_t *rx_ring, int nbytes, int npkts)
{
	union eth_rx_cqe *cqe;
	u16 last_cqe_consumer = rx_ring->last_cqe_consumer;
	enum eth_rx_cqe_type cqe_type;
	u16 sw_comp_cons, hw_comp_cons;
	mblk_t *mp = NULL, *first_mp = NULL, *last_mp = NULL;
	int pkt_bytes = 0, byte_cnt = 0, pkt_cnt = 0;

	hw_comp_cons = HOST_TO_LE_16(*rx_ring->hw_cons_ptr);

	/* Completion ring sw consumer */
	sw_comp_cons = ecore_chain_get_cons_idx(&rx_ring->rx_cqe_ring);
	
	while (sw_comp_cons != hw_comp_cons) {
		if ((byte_cnt >= nbytes) ||
		    (pkt_cnt >= npkts)) {
			break;
		}

		cqe = (union eth_rx_cqe *)
		    ecore_chain_consume(&rx_ring->rx_cqe_ring);
		/* Get next element and increment the cons_idx */

		(void) ddi_dma_sync(rx_ring->rx_cqe_dmah,
		    last_cqe_consumer, sizeof (*cqe),
		    DDI_DMA_SYNC_FORKERNEL);

		cqe_type = cqe->fast_path_regular.type;

		switch (cqe_type) {
		case ETH_RX_CQE_TYPE_SLOW_PATH:
			ecore_eth_cqe_completion(&rx_ring->qede->edev.hwfns[0],
			    (struct eth_slow_path_rx_cqe *)cqe);
			goto next_cqe;
		case ETH_RX_CQE_TYPE_REGULAR:
			mp = qede_reg_cqe(rx_ring,
			    &cqe->fast_path_regular,
			    &pkt_bytes);
			break;
		case ETH_RX_CQE_TYPE_TPA_START:
			qede_lro_start(rx_ring,
			    &cqe->fast_path_tpa_start);
			goto next_cqe;
		case ETH_RX_CQE_TYPE_TPA_CONT:
			qede_lro_cont(rx_ring,
			    &cqe->fast_path_tpa_cont);
			goto next_cqe;
		case ETH_RX_CQE_TYPE_TPA_END:
			mp = qede_lro_end(rx_ring,
			    &cqe->fast_path_tpa_end,
			    &pkt_bytes);
			break;
		default:
			if (cqe_type != 0) {
				qede_print_err("!%s(%d): cqe_type %x not "
				    "supported", __func__,
				    rx_ring->qede->instance,
				    cqe_type);
			}
			goto exit_rx;
		}

		/* 
		 * If we arrive here with no mp,
		 * then we hit an RX buffer threshold
		 * where we had to drop the packet and
		 * give the buffers back to the device.
		 */
		if (mp == NULL) {
			rx_ring->rx_drop_cnt++;
			goto next_cqe;
		}

		if (first_mp) {
			last_mp->b_next = mp;
		} else {
			first_mp = mp;
		}
		last_mp = mp;
		pkt_cnt++;
		byte_cnt += pkt_bytes;
next_cqe:
		ecore_chain_recycle_consumed(&rx_ring->rx_cqe_ring);
		last_cqe_consumer = sw_comp_cons;
		sw_comp_cons = ecore_chain_get_cons_idx(&rx_ring->rx_cqe_ring);
		if (!(qede_has_rx_work(rx_ring))) {
			ecore_sb_update_sb_idx(rx_ring->fp->sb_info);
		}
		hw_comp_cons = HOST_TO_LE_16(*rx_ring->hw_cons_ptr);
	}
	rx_ring->rx_pkt_cnt += pkt_cnt;
	rx_ring->rx_byte_cnt += byte_cnt;

exit_rx:
	if (first_mp) {
		last_mp->b_next = NULL;
	}

	/*
	 * Since prod update will result in
	 * reading of the bd's, do a dma_sync
	 */
	qede_replenish_rx_buffers(rx_ring);
	qede_update_rx_q_producer(rx_ring);
	rx_ring->last_cqe_consumer = last_cqe_consumer;

	return (first_mp);
}

mblk_t *
qede_process_fastpath(qede_fastpath_t *fp,
    int nbytes, int npkts, int *work_done)
{
	int i = 0;
	qede_tx_ring_t *tx_ring;
	qede_rx_ring_t *rx_ring;
	mblk_t *mp = NULL;

	rx_ring = fp->rx_ring;

	for (i = 0; i < fp->qede->num_tc; i++) {
		tx_ring = fp->tx_ring[i];
		if (qede_has_tx_work(tx_ring)) {
		/* process tx completions */
			if (mutex_tryenter(&tx_ring->tx_lock) != 0) {
				*work_done +=
				    qede_process_tx_completions(tx_ring);
				mutex_exit(&tx_ring->tx_lock);
			}
		}
	}

	if (!(qede_has_rx_work(rx_ring))) {
		ecore_sb_update_sb_idx(fp->sb_info);
	}

	rx_ring = fp->rx_ring;
	if (qede_has_rx_work(rx_ring)) {
		mutex_enter(&rx_ring->rx_lock);
		mp = qede_process_rx_ring(rx_ring,
		    nbytes, npkts);
		if (mp) {
			*work_done += 1;
		}
		mutex_exit(&rx_ring->rx_lock);
	}

	return (mp);
}

/*
 * Parse the mblk to extract information
 * from the protocol headers.
 * The routine assumes that the l4 header is tcp. Also
 * it does not account for ipv6 headers since ipv6 lso is
 * unsupported
 */
static void
qede_pkt_parse_lso_headers(qede_tx_pktinfo_t *pktinfo, mblk_t *mp)
{
	struct ether_header *eth_hdr =
	    (struct ether_header *)(void *)mp->b_rptr;
	ipha_t *ip_hdr;
	struct tcphdr *tcp_hdr;

	/* mac header type and len */
	if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
		pktinfo->ether_type = ntohs(eth_hdr->ether_type);
		pktinfo->mac_hlen = sizeof (struct ether_header);
	} else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_VLAN) {
		struct ether_vlan_header *vlan_hdr =
		    (struct ether_vlan_header *)(void *)mp->b_rptr;
		pktinfo->ether_type = ntohs(vlan_hdr->ether_type);
		pktinfo->mac_hlen = sizeof (struct ether_vlan_header);
	}

	/* ip header type and len */
	ip_hdr = (ipha_t *)(void *)((u8 *)mp->b_rptr + pktinfo->mac_hlen);
	pktinfo->ip_hlen = IPH_HDR_LENGTH(ip_hdr);

	/* Assume TCP protocol */
	pktinfo->l4_proto = 0x06;

	tcp_hdr = (struct tcphdr *)(void *)
	    ((u8 *)mp->b_rptr + pktinfo->mac_hlen + pktinfo->ip_hlen);
	pktinfo->l4_hlen = TCP_HDR_LENGTH(tcp_hdr);

	
	pktinfo->total_hlen =
	    pktinfo->mac_hlen +
	    pktinfo->ip_hlen +
	    pktinfo->l4_hlen;
}

static void
qede_get_pkt_offload_info(qede_t *qede, mblk_t *mp,
    u32 *use_cksum, boolean_t *use_lso, uint16_t *mss)
{
	u32 pflags;

	mac_hcksum_get(mp, NULL, NULL, NULL, NULL, &pflags);

	*use_cksum = pflags;
	if (qede->lso_enable) {
		u32 pkt_mss = 0;
		u32 lso_flags = 0;

		mac_lso_get(mp, &pkt_mss, &lso_flags);
		*use_lso = (lso_flags == HW_LSO);
		*mss = (u16)pkt_mss;
	}
}

static void
/* LINTED E_FUNC_ARG_UNUSED */
qede_get_pkt_info(qede_t *qede, mblk_t *mp,
    qede_tx_pktinfo_t *pktinfo)
{
	mblk_t *bp;
	size_t size;
	struct ether_header *eth_hdr =
	    (struct ether_header *)(void *)mp->b_rptr;

	pktinfo->total_len = 0;
	pktinfo->mblk_no = 0;

	/*
	 * Count the total length and the number of
	 * chained mblks in the packet
	 */
	for (bp = mp; bp != NULL; bp = bp->b_cont) {
		size = MBLKL(bp);
		if (size == 0) {
			continue;
		}

		pktinfo->total_len += size;
		pktinfo->mblk_no++;
	}
	/* mac header type and len */
	if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
		pktinfo->ether_type = ntohs(eth_hdr->ether_type);
		pktinfo->mac_hlen = sizeof (struct ether_header);
	} else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_VLAN) {
		struct ether_vlan_header *vlan_hdr =
		    (struct ether_vlan_header *)(void *)mp->b_rptr;
		pktinfo->ether_type = ntohs(vlan_hdr->ether_type);
		pktinfo->mac_hlen = sizeof (struct ether_vlan_header);
	}

}

/*
 * Routine to sync dma mem for multiple
 * descriptors in a chain
 */
void
qede_desc_dma_mem_sync(ddi_dma_handle_t *dma_handle,
    uint_t start, uint_t count, uint_t range,
    uint_t unit_size, uint_t direction)
{
	if ((start + count) < range) {
		(void) ddi_dma_sync(*dma_handle,
		    start * unit_size, count * unit_size, direction);
	} else {
		(void) ddi_dma_sync(*dma_handle, start * unit_size,
		    0, direction);
		(void) ddi_dma_sync(*dma_handle, 0,
		    (start + count - range) * unit_size,
		    direction);
	}
}

/*
 * Send tx pkt by copying incoming packet in a
 * preallocated and mapped dma buffer
 * Not designed to handle lso for now
 */
static enum qede_xmit_status
qede_tx_bcopy(qede_tx_ring_t *tx_ring, mblk_t *mp, qede_tx_pktinfo_t *pktinfo)
{
	qede_tx_bcopy_pkt_t *bcopy_pkt = NULL;
	/* Only one bd will be needed for bcopy packets */
	struct eth_tx_1st_bd *first_bd;
	u16 last_producer = tx_ring->sw_tx_prod;
	uint8_t *txb;
	mblk_t *bp;
	u32 mblen;

	bcopy_pkt = qede_get_bcopy_pkt(tx_ring);
	if (bcopy_pkt == NULL) {
		qede_print_err("!%s(%d): entry NULL at _tx_ bcopy_list head",
		    __func__, tx_ring->qede->instance);
		return (XMIT_FAILED);
	}

	/*
	 * Copy the packet data to our copy
	 * buffer
	 */
	txb = bcopy_pkt->virt_addr;

	for (bp = mp; bp != NULL; bp = bp->b_cont) {
		mblen = MBLKL(bp);
		if (mblen == 0) {
			continue;
		}
		bcopy(bp->b_rptr, txb, mblen);
		txb += mblen;
	}

	(void) ddi_dma_sync(bcopy_pkt->dma_handle,
	    0, pktinfo->total_len,
	    DDI_DMA_SYNC_FORDEV);


	mutex_enter(&tx_ring->tx_lock);
	if (ecore_chain_get_elem_left(&tx_ring->tx_bd_ring)<
	    QEDE_TX_COPY_PATH_PAUSE_THRESHOLD) {
		tx_ring->tx_q_sleeping = 1;
		qede_put_bcopy_pkt(tx_ring, bcopy_pkt);
		mutex_exit(&tx_ring->tx_lock);
#ifdef	DEBUG_TX_RECYCLE
		qede_print_err("!%s(%d): Pausing tx queue",
		    __func__, tx_ring->qede->instance);
#endif
		return (XMIT_PAUSE_QUEUE);
	}

	first_bd = ecore_chain_produce(&tx_ring->tx_bd_ring);
	bzero(first_bd, sizeof (*first_bd));
	first_bd->data.nbds = 1;
	first_bd->data.bd_flags.bitfields =
	    (1 << ETH_TX_1ST_BD_FLAGS_START_BD_SHIFT);

	if (pktinfo->cksum_flags & HCK_IPV4_HDRCKSUM) {
		first_bd->data.bd_flags.bitfields |=
		    (1 << ETH_TX_1ST_BD_FLAGS_IP_CSUM_SHIFT);
	}

	if (pktinfo->cksum_flags & HCK_FULLCKSUM) {
		first_bd->data.bd_flags.bitfields |=
		    (1 << ETH_TX_1ST_BD_FLAGS_L4_CSUM_SHIFT);
	}

	BD_SET_ADDR_LEN(first_bd,
	    bcopy_pkt->phys_addr,
	    pktinfo->total_len);

	first_bd->data.bitfields |=
		(pktinfo->total_len & ETH_TX_DATA_1ST_BD_PKT_LEN_MASK) 
		<< ETH_TX_DATA_1ST_BD_PKT_LEN_SHIFT;

	tx_ring->tx_db.data.bd_prod =
	    HOST_TO_LE_16(ecore_chain_get_prod_idx(&tx_ring->tx_bd_ring));

	tx_ring->tx_recycle_list[tx_ring->sw_tx_prod].bcopy_pkt = bcopy_pkt;
	tx_ring->tx_recycle_list[tx_ring->sw_tx_prod].dmah_entry =  NULL;

	tx_ring->sw_tx_prod++;
	tx_ring->sw_tx_prod &= TX_RING_MASK;

	(void) ddi_dma_sync(tx_ring->tx_bd_dmah,
	    last_producer, sizeof (*first_bd),
	    DDI_DMA_SYNC_FORDEV);

	QEDE_DOORBELL_WR(tx_ring, tx_ring->tx_db.raw);
	mutex_exit(&tx_ring->tx_lock);

	freemsg(mp);

	return (XMIT_DONE);
}

/*
 * Send tx packet by mapping the mp(kernel addr)
 * to an existing dma_handle in the driver
 */
static enum qede_xmit_status
qede_tx_mapped(qede_tx_ring_t *tx_ring, mblk_t *mp, qede_tx_pktinfo_t *pktinfo)
{
	enum qede_xmit_status status = XMIT_FAILED;
	int ret;
	qede_dma_handle_entry_t *dmah_entry = NULL; 
	qede_dma_handle_entry_t *head = NULL, *tail = NULL, *hdl;
	struct eth_tx_1st_bd *first_bd;
	struct eth_tx_2nd_bd *second_bd = 0;
	struct eth_tx_3rd_bd *third_bd = 0;
	struct eth_tx_bd *tx_data_bd;
	struct eth_tx_bd local_bd[64] = { 0 };
	ddi_dma_cookie_t cookie[64];
	u32 ncookies, total_cookies = 0, max_cookies = 0, index = 0;
	ddi_dma_handle_t dma_handle;
	mblk_t *bp;
	u32 mblen;
	bool is_premapped = B_FALSE;
	u64 dma_premapped = 0, dma_bound = 0;
	u32 hdl_reserved = 0;
	u8 nbd = 0;
	int i, bd_index;
	u16 last_producer;
	qede_tx_recycle_list_t *tx_recycle_list = tx_ring->tx_recycle_list;
	u64 data_addr;
	size_t data_size;

	if (pktinfo->use_lso) {
		/*
		 * For tso pkt, we can use as many as 255 bds
		 */
		max_cookies = ETH_TX_MAX_BDS_PER_NON_LSO_PACKET - 1;
		qede_pkt_parse_lso_headers(pktinfo, mp);
	} else {
		/*
		 * For non-tso packet, only 18 bds can be used
		 */
		max_cookies = ETH_TX_MAX_BDS_PER_NON_LSO_PACKET - 1;
	}

	for (bp = mp; bp != NULL; bp = bp->b_cont) {
		mblen = MBLKL(bp);
		if (mblen == 0) {
			continue;
		}
		is_premapped = B_FALSE;
		/*
		 * If the mblk is premapped then get the
		 * dma_handle and sync the dma mem. otherwise
		 * reserve an handle from the driver dma
		 * handles list
		 */
#ifdef	DBLK_DMA_PREMAP
		if (bp->b_datap->db_flags & DBLK_DMA_PREMAP) {
#ifdef	DEBUG_PREMAP
			qede_info(tx_ring->qede, "mp is premapped");
#endif
			tx_ring->tx_premap_count++;
			ret = dblk_dma_info_get(tx_ring->pm_handle,
			    bp->b_rptr, mblen,
			    bp->b_datap, &cookie[index],
			    &ncookies, &dma_handle);
			if (ret == DDI_DMA_MAPPED) {
				is_premapped = B_TRUE;
				dma_premapped++;
				(void) ddi_dma_sync(dma_handle, 0, 0,
				    DDI_DMA_SYNC_FORDEV);
			} else {
				tx_ring->tx_premap_fail++;
			}
		}
#endif	/* DBLK_DMA_PREMAP */

		if (!is_premapped) {
			dmah_entry = qede_get_dmah_entry(tx_ring);
			if (dmah_entry == NULL) {
				qede_info(tx_ring->qede, "dmah_entry NULL, "
				    "Fallback to copy mode...");
				status = XMIT_FAILED;
				goto err_map;
			}
	
			if (ddi_dma_addr_bind_handle(dmah_entry->dma_handle,
			    NULL, (caddr_t)bp->b_rptr, mblen,
			    DDI_DMA_STREAMING | DDI_DMA_WRITE,
			    DDI_DMA_DONTWAIT, NULL, &cookie[index], &ncookies)
			    != DDI_DMA_MAPPED) {

#ifdef DEBUG_PULLUP
			qede_info(tx_ring->qede, "addr_bind() failed for "
			    "handle %p, len %d mblk_no %d tot_len 0x%x" 
			    " use_lso %d",  dmah_entry->dma_handle,
			    mblen, pktinfo->mblk_no, pktinfo->total_len, 
			    pktinfo->use_lso);

			qede_info(tx_ring->qede, "Falling back to pullup");
#endif
				status = XMIT_FALLBACK_PULLUP;
				tx_ring->tx_bind_fail++;
				goto err_map;
			}
			tx_ring->tx_bind_count++;

			if (index == 0) {
				dmah_entry->mp = mp;
			} else {
				dmah_entry->mp = NULL;
			}

			/* queue into recycle list for tx completion routine */
			if (tail == NULL) {
				head = tail = dmah_entry;
			} else {
				tail->next = dmah_entry;
				tail = dmah_entry;
			}

			hdl_reserved++;
			dma_bound++;
		} 

		total_cookies += ncookies;
		if (total_cookies > max_cookies) {
			tx_ring->tx_too_many_cookies++;
#ifdef DEBUG_PULLUP
			qede_info(tx_ring->qede, 
			    "total_cookies > max_cookies, "
			    "pktlen %d, mb num %d",
			    pktinfo->total_len, pktinfo->mblk_no);
#endif
			status = XMIT_TOO_MANY_COOKIES;
			goto err_map_sec;
		}

		if (is_premapped) {
			index += ncookies;
		} else {
			index++;
			/*
			 * Dec. ncookies since we already stored cookie[0]
			 */
			ncookies--;

			for (i = 0; i < ncookies; i++, index++)
				ddi_dma_nextcookie(dmah_entry->dma_handle,
				    &cookie[index]);
		}
	}

	/*
	 * Guard against the case where we get a series of mblks that cause us
	 * not to end up with any mapped data.
	 */
	if (total_cookies == 0) {
		status = XMIT_FAILED;
		goto err_map_sec;
	}

	if (total_cookies > max_cookies) {
		tx_ring->tx_too_many_cookies++;
		status = XMIT_TOO_MANY_COOKIES;
		goto err_map_sec;
	}
	first_bd = (struct eth_tx_1st_bd *)&local_bd[0];

	/*
	 * Mark this bd as start bd
	 */
	first_bd->data.bd_flags.bitfields =
	    (1 << ETH_TX_1ST_BD_FLAGS_START_BD_SHIFT);

	if (pktinfo->cksum_flags & HCK_IPV4_HDRCKSUM) {
		first_bd->data.bd_flags.bitfields |=
		    (1 << ETH_TX_1ST_BD_FLAGS_IP_CSUM_SHIFT);
	}

	if (pktinfo->cksum_flags & HCK_FULLCKSUM) {
		first_bd->data.bd_flags.bitfields |=
		    (1 << ETH_TX_1ST_BD_FLAGS_L4_CSUM_SHIFT);
	}


	/* Fill-up local bds with the tx data and flags */
	for (i = 0, bd_index = 0; i < total_cookies; i++, bd_index++) {
		if (bd_index == 0) {
			BD_SET_ADDR_LEN(first_bd,
			    cookie[i].dmac_laddress,
			    cookie[i].dmac_size);

			if (pktinfo->use_lso) {
			first_bd->data.bd_flags.bitfields |=
			    1 << ETH_TX_1ST_BD_FLAGS_LSO_SHIFT;

			second_bd = (struct eth_tx_2nd_bd *)&local_bd[1];

			/*
			 * If the fisrt bd contains
			 * hdr + data (partial or full data), then spilt
			 * the hdr and data between 1st and 2nd
			 * bd respectively
			 */
			if (first_bd->nbytes > pktinfo->total_hlen) {
				data_addr = cookie[0].dmac_laddress
				    + pktinfo->total_hlen;
				data_size = cookie[i].dmac_size
				    - pktinfo->total_hlen;

				BD_SET_ADDR_LEN(second_bd,
				    data_addr,
				    data_size);

				/*
				 * First bd already contains the addr to
				 * to start of pkt, just adjust the dma
				 * len of first_bd
				 */
				first_bd->nbytes = pktinfo->total_hlen;
				bd_index++;
			} else if (first_bd->nbytes < pktinfo->total_hlen) {
#ifdef DEBUG_PULLUP
				qede_info(tx_ring->qede, 
				    "Headers not in single bd");
#endif
				status = XMIT_FALLBACK_PULLUP;
				goto err_map_sec;

			}

			/*
			 * Third bd is used to indicates to fw
			 * that tso needs to be performed. It should
			 * be present even if only two cookies are
			 * needed for the mblk
			 */
			third_bd = (struct eth_tx_3rd_bd *)&local_bd[2];
			third_bd->data.lso_mss |=
			    HOST_TO_LE_16(pktinfo->mss);
			third_bd->data.bitfields |=
			    1 << ETH_TX_DATA_3RD_BD_HDR_NBD_SHIFT;
			}

			continue;
		}

		tx_data_bd = &local_bd[bd_index];
		BD_SET_ADDR_LEN(tx_data_bd,
		    cookie[i].dmac_laddress,
		    cookie[i].dmac_size);
	}

	if (pktinfo->use_lso) {
		if (bd_index < 3) {
			nbd = 3;
		} else {
			nbd = bd_index;
		}
	} else {
		nbd = total_cookies;
		first_bd->data.bitfields |=
		    (pktinfo->total_len & ETH_TX_DATA_1ST_BD_PKT_LEN_MASK) 
		    << ETH_TX_DATA_1ST_BD_PKT_LEN_SHIFT;
	}

	first_bd->data.nbds = nbd;

	mutex_enter(&tx_ring->tx_lock);

	/*
	 * Before copying the local bds into actual,
	 * check if we have enough on the bd_chain
	 */
	if (ecore_chain_get_elem_left(&tx_ring->tx_bd_ring) <
	    nbd) {
		tx_ring->tx_q_sleeping = 1;
		status = XMIT_PAUSE_QUEUE;
#ifdef	DEBUG_TX_RECYCLE
			qede_info(tx_ring->qede, "Pausing tx queue...");
#endif
		mutex_exit(&tx_ring->tx_lock);
		goto err_map_sec ;
	}

	/* Copy the local_bd(s) into the actual bds */
	for (i = 0; i < nbd; i++) {
		tx_data_bd = ecore_chain_produce(&tx_ring->tx_bd_ring);
		bcopy(&local_bd[i], tx_data_bd, sizeof (*tx_data_bd));
	}

	last_producer = tx_ring->sw_tx_prod;

	tx_ring->tx_recycle_list[tx_ring->sw_tx_prod].dmah_entry = head;
	tx_ring->tx_recycle_list[tx_ring->sw_tx_prod].bcopy_pkt = NULL;
	tx_ring->sw_tx_prod = (tx_ring->sw_tx_prod + 1) & TX_RING_MASK;

	tx_ring->tx_db.data.bd_prod =
	    HOST_TO_LE_16(ecore_chain_get_prod_idx(&tx_ring->tx_bd_ring));

	/* Sync the tx_bd dma mem */
	qede_desc_dma_mem_sync(&tx_ring->tx_bd_dmah,
	    last_producer, nbd,
	    tx_ring->tx_ring_size,
	    sizeof (struct eth_tx_bd),
	    DDI_DMA_SYNC_FORDEV);

	/*
	 * Write to doorbell bar
	 */
	QEDE_DOORBELL_WR(tx_ring, tx_ring->tx_db.raw);

	mutex_exit(&tx_ring->tx_lock);

	return (XMIT_DONE);
err_map:
	if (dmah_entry != NULL) {
		if (tail == NULL) {
			head = tail = dmah_entry;
		} else {
			tail->next = dmah_entry;
			tail = dmah_entry;
		}
		hdl_reserved++;
	}

err_map_sec:

	hdl = head;

	while (hdl != NULL) {
		(void) ddi_dma_unbind_handle(hdl->dma_handle);
		hdl = hdl->next;
	}

	if (head != NULL) {
		qede_put_dmah_entries(tx_ring, head);
	}

	return (status);
}

static enum qede_xmit_status
qede_send_tx_packet(qede_t *qede, qede_tx_ring_t *tx_ring, mblk_t *mp)
{
	boolean_t force_pullup = B_FALSE;
	enum qede_xmit_status status = XMIT_FAILED;
	enum qede_xmit_mode xmit_mode = USE_BCOPY;
	qede_tx_pktinfo_t pktinfo;
	mblk_t *original_mp = NULL, *pulled_up_mp = NULL;
	struct ether_vlan_header *ethvhdr;

	mutex_enter(&tx_ring->tx_lock);
	if (ecore_chain_get_elem_left(&tx_ring->tx_bd_ring) <
	    qede->tx_recycle_threshold) {
#ifdef	DEBUG_TX_RECYCLE
		qede_info(qede, "Recyclycling from tx routine");
#endif
		if (qede_process_tx_completions(tx_ring) <
		    qede->tx_recycle_threshold) {
#ifdef	DEBUG_TX_RECYCLE
			qede_info(qede, "Still not enough bd after cleanup, "
			    "pausing tx queue...");
#endif
			tx_ring->tx_q_sleeping = 1;
			mutex_exit(&tx_ring->tx_lock);
			return (XMIT_PAUSE_QUEUE);
		}
	}

	mutex_exit(&tx_ring->tx_lock);

	bzero(&pktinfo, sizeof (pktinfo));

	/* Get the offload reqd. on the pkt */
	qede_get_pkt_offload_info(qede, mp, &pktinfo.cksum_flags,
	    &pktinfo.use_lso, &pktinfo.mss);

do_pullup:
	if (force_pullup) {
		tx_ring->tx_pullup_count++;
#ifdef	DEBUG_PULLUP
		qede_info(qede, "Pulling up original mp %p", mp);
#endif
		/*
		 * Try to accumulate all mblks of this pkt
		 * into a single mblk
		 */
		original_mp = mp;
		if ((pulled_up_mp = msgpullup(mp, -1)) != NULL) {
#ifdef	DEBUG_PULLUP
			qede_info(qede, "New mp %p, ori %p", pulled_up_mp, mp);
#endif
			/*
			 * Proceed with the new single
			 * mp
			 */
			mp = pulled_up_mp;
			xmit_mode = XMIT_MODE_UNUSED;
			pktinfo.pulled_up = B_TRUE;
		} else {
#ifdef	DEBUG_PULLUP
			qede_info(tx_ring->qede, "Pullup failed");
#endif
			status = XMIT_FAILED;
			goto exit;
		}
	}

	qede_get_pkt_info(qede, mp, &pktinfo);


	if ((!pktinfo.use_lso) && 
                 (pktinfo.total_len > (qede->mtu + pktinfo.mac_hlen))) {
  		qede_info(tx_ring->qede, 
		    "Packet drop as packet len 0x%x > 0x%x",
		    pktinfo.total_len, (qede->mtu + QEDE_MAX_ETHER_HDR));
		status = XMIT_FAILED;
		goto exit;
	}


#ifdef	DEBUG_PULLUP
	if (force_pullup) {
	qede_print_err("!%s: mp %p, pktinfo : total_len %d,"
	    " mblk_no %d, ether_type %d\n"
	    "mac_hlen %d, ip_hlen %d, l4_hlen %d\n"
	    "l4_proto %d, use_cksum:use_lso %d:%d mss %d", __func__, mp,
	    pktinfo.total_len, pktinfo.mblk_no, pktinfo.ether_type,
	    pktinfo.mac_hlen, pktinfo.ip_hlen, pktinfo.l4_hlen,
	    pktinfo.l4_proto, pktinfo.cksum_flags, pktinfo.use_lso,
	    pktinfo.mss);
	}
#endif

#ifdef	DEBUG_PREMAP
	if (DBLK_IS_PREMAPPED(mp->b_datap)) {
		qede_print_err("!%s(%d): mp %p id PREMAPPMED",
		    __func__, qede->instance);
	}
#endif

#ifdef	DBLK_DMA_PREMAP	
	if (DBLK_IS_PREMAPPED(mp->b_datap) ||
	    pktinfo.total_len > qede->tx_bcopy_threshold) {
		xmit_mode = USE_DMA_BIND;
	}
#else
	if (pktinfo.total_len > qede->tx_bcopy_threshold) {
		xmit_mode = USE_DMA_BIND;
	}
#endif
	
	if (pktinfo.total_len <= qede->tx_bcopy_threshold) {
		xmit_mode = USE_BCOPY;
	}

	/*
	 * if mac + ip hdr not in one contiguous block,
	 * use copy mode
	 */
	if (MBLKL(mp) < (ETHER_HEADER_LEN + IP_HEADER_LEN)) {
		/*qede_info(qede, "mblk too small, using copy mode, len = %d", MBLKL(mp));*/
		xmit_mode = USE_BCOPY;
	}

	if ((uintptr_t)mp->b_rptr & 1) {
		xmit_mode = USE_BCOPY;
	}

	/*
	 * if too many mblks and hence the dma cookies, needed
	 * for tx, then use bcopy or pullup on packet
	 * currently, ETH_TX_MAX_BDS_PER_NON_LSO_PACKET = 18
	 */
	if (pktinfo.mblk_no > (ETH_TX_MAX_BDS_PER_NON_LSO_PACKET - 1)) {
		if (force_pullup) {
			tx_ring->tx_too_many_mblks++;
			status = XMIT_FAILED;
			goto exit;
		} else {
			xmit_mode = USE_PULLUP;
		}
	}

#ifdef	TX_FORCE_COPY_MODE
	xmit_mode = USE_BCOPY;
#elif	TX_FORCE_MAPPED_MODE
	xmit_mode = USE_DMA_BIND;
#endif

#ifdef	DEBUG_PULLUP
	if (force_pullup) {
		qede_info(qede, "using mode %d on pulled mp %p",
		    xmit_mode, mp);
	}
#endif

	/*
	 * Use Mapped mode for the packet
	 */
	if (xmit_mode == USE_DMA_BIND) {
		status = qede_tx_mapped(tx_ring, mp, &pktinfo);
		if (status == XMIT_DONE) {
			if (pktinfo.use_lso) {
				tx_ring->tx_lso_pkt_count++;
			} else if(pktinfo.total_len > 1518) {
				tx_ring->tx_jumbo_pkt_count++;
			}
			tx_ring->tx_mapped_pkts++;
			goto exit;
                } else if ((status == XMIT_TOO_MANY_COOKIES ||
		    (status == XMIT_FALLBACK_PULLUP)) && !force_pullup) {
			xmit_mode = USE_PULLUP;
		} else {
			status = XMIT_FAILED;
			goto exit;
		}
	}

	if (xmit_mode == USE_BCOPY) {
		status = qede_tx_bcopy(tx_ring, mp, &pktinfo);
		if (status == XMIT_DONE) {
			tx_ring->tx_copy_count++;
			goto exit;
		} else if ((status == XMIT_FALLBACK_PULLUP) &&
		    !force_pullup) {
			xmit_mode = USE_PULLUP;
		} else {
			goto exit;
		}
	}

	if (xmit_mode == USE_PULLUP) {
		force_pullup = B_TRUE;
		tx_ring->tx_pullup_count++;
		goto do_pullup;
	}

exit:
	if (status != XMIT_DONE) {
		/*
		 * if msgpullup succeeded, but something else  failed,
		 * free the pulled-up msg and return original mblk to
		 * stack, indicating tx failure
		 */
		if (pulled_up_mp) {
			qede_info(qede, "tx failed, free pullup pkt %p", mp);
			freemsg(pulled_up_mp);
			mp = original_mp;
		}
	} else {
		tx_ring->tx_byte_count += pktinfo.total_len;
		/*
		 * If tx was successfull after a pullup, then free the
		 * original mp. The pulled-up will be freed as part of
		 * tx completions processing
		 */
		if (pulled_up_mp) {
#ifdef	DEBUG_PULLUP
			qede_info(qede, 
			    "success, free ori mp %p", original_mp);
#endif
			freemsg(original_mp);
		}
	}

	return (status);
}

typedef	uint32_t	ub4; /* unsigned 4-byte quantities */
typedef	uint8_t		ub1;

#define	hashsize(n)	((ub4)1<<(n))
#define	hashmask(n)	(hashsize(n)-1)

#define	mix(a, b, c) \
{ \
	a -= b; a -= c; a ^= (c>>13); \
	b -= c; b -= a; b ^= (a<<8); \
	c -= a; c -= b; c ^= (b>>13); \
	a -= b; a -= c; a ^= (c>>12);  \
	b -= c; b -= a; b ^= (a<<16); \
	c -= a; c -= b; c ^= (b>>5); \
	a -= b; a -= c; a ^= (c>>3);  \
	b -= c; b -= a; b ^= (a<<10); \
	c -= a; c -= b; c ^= (b>>15); \
}

ub4
hash(k, length, initval)
register ub1 *k;	/* the key */
register ub4 length;	/* the length of the key */
register ub4 initval;	/* the previous hash, or an arbitrary value */
{
	register ub4 a, b, c, len;

	/* Set up the internal state */
	len = length;
	a = b = 0x9e3779b9;	/* the golden ratio; an arbitrary value */
	c = initval;		/* the previous hash value */

	/* handle most of the key */
	while (len >= 12) 
	{
		a += (k[0] +((ub4)k[1]<<8) +((ub4)k[2]<<16) +((ub4)k[3]<<24));
		b += (k[4] +((ub4)k[5]<<8) +((ub4)k[6]<<16) +((ub4)k[7]<<24));
		c += (k[8] +((ub4)k[9]<<8) +((ub4)k[10]<<16)+((ub4)k[11]<<24));
		mix(a, b, c);
		k += 12;
		len -= 12;
	}

	/* handle the last 11 bytes */
	c += length;
	/* all the case statements fall through */
	switch (len) 
	{
	/* FALLTHRU */
	case 11: 
		c += ((ub4)k[10]<<24);
	/* FALLTHRU */
	case 10: 
		c += ((ub4)k[9]<<16);
	/* FALLTHRU */
	case 9 : 
		c += ((ub4)k[8]<<8);
	/* the first byte of c is reserved for the length */
	/* FALLTHRU */
	case 8 : 
		b += ((ub4)k[7]<<24);
	/* FALLTHRU */
	case 7 : 
		b += ((ub4)k[6]<<16);
	/* FALLTHRU */
	case 6 : 
		b += ((ub4)k[5]<<8);
	/* FALLTHRU */
	case 5 : 
		b += k[4];
	/* FALLTHRU */
	case 4 : 
		a += ((ub4)k[3]<<24);
	/* FALLTHRU */
	case 3 : 
		a += ((ub4)k[2]<<16);
	/* FALLTHRU */
	case 2 : 
		a += ((ub4)k[1]<<8);
	/* FALLTHRU */
	case 1 : 
		a += k[0];
	/* case 0: nothing left to add */
	}
	mix(a, b, c);
	/* report the result */
	return (c);
}

#ifdef	NO_CROSSBOW
static uint8_t
qede_hash_get_txq(qede_t *qede, caddr_t bp)
{
	struct ip *iphdr = NULL;
	struct ether_header *ethhdr;
	struct ether_vlan_header *ethvhdr;
	struct tcphdr *tcp_hdr;
	struct udphdr *udp_hdr;
	uint32_t etherType;
	int mac_hdr_len, ip_hdr_len;
	uint32_t h = 0; /* 0 by default */
	uint8_t tx_ring_id = 0;
	uint32_t ip_src_addr = 0;
	uint32_t ip_desc_addr = 0;
	uint16_t src_port = 0;
	uint16_t dest_port = 0;
	uint8_t key[12];

	if (qede->num_fp == 1) {
		return (tx_ring_id);
	}

	ethhdr = (struct ether_header *)((void *)bp);
	ethvhdr = (struct ether_vlan_header *)((void *)bp);

	/* Is this vlan packet? */
	if (ntohs(ethvhdr->ether_tpid) == ETHERTYPE_VLAN) {
		mac_hdr_len = sizeof (struct ether_vlan_header);
		etherType = ntohs(ethvhdr->ether_type);
	} else {
		mac_hdr_len = sizeof (struct ether_header);
		etherType = ntohs(ethhdr->ether_type);
	}
	/* Is this IPv4 or IPv6 packet? */
	if (etherType == ETHERTYPE_IP /* 0800 */) {
		if (IPH_HDR_VERSION((ipha_t *)(void *)(bp+mac_hdr_len))
		    == IPV4_VERSION) {
			iphdr = (struct ip *)(void *)(bp+mac_hdr_len);
		}
		if (((unsigned long)iphdr) & 0x3) {
			/*  IP hdr not 4-byte aligned */
			return (tx_ring_id);
		}
	}
	/* ipV4 packets */
	if (iphdr) {

		ip_hdr_len = IPH_HDR_LENGTH(iphdr);
		ip_src_addr = iphdr->ip_src.s_addr;
		ip_desc_addr = iphdr->ip_dst.s_addr;

		if (iphdr->ip_p == IPPROTO_TCP) {
			tcp_hdr = (struct tcphdr *)(void *)
			    ((uint8_t *)iphdr + ip_hdr_len);
			src_port = tcp_hdr->th_sport;
			dest_port = tcp_hdr->th_dport;
		} else if (iphdr->ip_p == IPPROTO_UDP) {
			udp_hdr = (struct udphdr *)(void *)
			    ((uint8_t *)iphdr + ip_hdr_len);
			src_port = udp_hdr->uh_sport;
			dest_port = udp_hdr->uh_dport;
		}
		key[0] = (uint8_t)((ip_src_addr) &0xFF);
		key[1] = (uint8_t)((ip_src_addr >> 8) &0xFF);
		key[2] = (uint8_t)((ip_src_addr >> 16) &0xFF);
		key[3] = (uint8_t)((ip_src_addr >> 24) &0xFF);
		key[4] = (uint8_t)((ip_desc_addr) &0xFF);
		key[5] = (uint8_t)((ip_desc_addr >> 8) &0xFF);
		key[6] = (uint8_t)((ip_desc_addr >> 16) &0xFF);
		key[7] = (uint8_t)((ip_desc_addr >> 24) &0xFF);
		key[8] = (uint8_t)((src_port) &0xFF);
		key[9] = (uint8_t)((src_port >> 8) &0xFF);
		key[10] = (uint8_t)((dest_port) &0xFF);
		key[11] = (uint8_t)((dest_port >> 8) &0xFF);
		h = hash(key, 12, 0); /* return 32 bit */
		tx_ring_id = (h & (qede->num_fp - 1));
		if (tx_ring_id >= qede->num_fp) {
			cmn_err(CE_WARN, "%s bad tx_ring_id %d\n",
			    __func__, tx_ring_id);
			tx_ring_id = 0;
		}
	}
	return (tx_ring_id);
}
#endif

mblk_t *
qede_ring_tx(void *arg, mblk_t *mp)
{
	qede_fastpath_t *fp = (qede_fastpath_t *)arg;
	qede_t *qede = fp->qede;
#ifndef	NO_CROSSBOW
	qede_tx_ring_t *tx_ring = fp->tx_ring[0];
#else
	qede_tx_ring_t *tx_ring;
#endif
	uint32_t ring_id;
	mblk_t *next = NULL;
	enum qede_xmit_status status = XMIT_FAILED;
	caddr_t bp;

	ASSERT(mp->b_next == NULL);

#ifndef	NO_CROSSBOW
	if (!fp || !tx_ring) {
		qede_print_err("!%s: error, fp %p, tx_ring %p",
		    __func__, fp, tx_ring);
		goto exit;
	}
#endif
	if (qede->qede_state != QEDE_STATE_STARTED) {
		qede_print_err("!%s(%d): qede_state %d invalid",
		    __func__, qede->instance, qede->qede_state);
		goto exit;
	}

	if (!qede->params.link_state) {
		qede_print_err("!%s(%d): Link !up for xmit",
		    __func__, qede->instance);
		goto exit;
	}

	while (mp != NULL) {
#ifdef	NO_CROSSBOW
		/*
		 * Figure out which tx ring to send this packet to.
		 * Currently multiple rings are not exposed to mac layer
		 * and fanout done by driver
		 */
		bp = (caddr_t)mp->b_rptr;
		ring_id = qede_hash_get_txq(qede, bp);
		fp = &qede->fp_array[ring_id];
		tx_ring = fp->tx_ring[0];

		if (qede->num_tc > 1) {
			qede_info(qede, 
			    "Traffic classes(%d) > 1 not supported",
			    qede->num_tc);
			goto exit;
		}
#endif
		next = mp->b_next;
		mp->b_next = NULL;

		status = qede_send_tx_packet(qede, tx_ring, mp);
		if (status == XMIT_DONE) {
			tx_ring->tx_pkt_count++;
			mp = next;
		} else if (status == XMIT_PAUSE_QUEUE) {
			tx_ring->tx_ring_pause++;
			mp->b_next = next;
			break;
		} else if (status == XMIT_FAILED) {
			goto exit;
		}
	}

	return (mp);
exit:
	tx_ring->tx_pkt_dropped++;
	freemsgchain(mp);
	mp = NULL;
	return (mp);
}
