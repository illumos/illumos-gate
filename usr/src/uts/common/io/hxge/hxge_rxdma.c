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

#include <hxge_impl.h>
#include <hxge_rxdma.h>
#include <hpi.h>
#include <hpi_vir.h>

/*
 * Number of blocks to accumulate before re-enabling DMA
 * when we get RBR empty.
 */
#define	HXGE_RBR_EMPTY_THRESHOLD	64

/*
 * Globals: tunable parameters (/etc/system or adb)
 *
 */
extern uint32_t hxge_rbr_size;
extern uint32_t hxge_rcr_size;
extern uint32_t hxge_rbr_spare_size;
extern uint32_t hxge_mblks_pending;

/*
 * Tunables to manage the receive buffer blocks.
 *
 * hxge_rx_threshold_hi: copy all buffers.
 * hxge_rx_bcopy_size_type: receive buffer block size type.
 * hxge_rx_threshold_lo: copy only up to tunable block size type.
 */
extern hxge_rxbuf_threshold_t hxge_rx_threshold_hi;
extern hxge_rxbuf_type_t hxge_rx_buf_size_type;
extern hxge_rxbuf_threshold_t hxge_rx_threshold_lo;

/*
 * Static local functions.
 */
static hxge_status_t hxge_map_rxdma(p_hxge_t hxgep);
static void hxge_unmap_rxdma(p_hxge_t hxgep);
static hxge_status_t hxge_rxdma_hw_start_common(p_hxge_t hxgep);
static hxge_status_t hxge_rxdma_hw_start(p_hxge_t hxgep);
static void hxge_rxdma_hw_stop(p_hxge_t hxgep);
static hxge_status_t hxge_map_rxdma_channel(p_hxge_t hxgep, uint16_t channel,
    p_hxge_dma_common_t *dma_buf_p, p_rx_rbr_ring_t *rbr_p,
    uint32_t num_chunks, p_hxge_dma_common_t *dma_rbr_cntl_p,
    p_hxge_dma_common_t *dma_rcr_cntl_p, p_hxge_dma_common_t *dma_mbox_cntl_p,
    p_rx_rcr_ring_t *rcr_p, p_rx_mbox_t *rx_mbox_p);
static void hxge_unmap_rxdma_channel(p_hxge_t hxgep, uint16_t channel,
	p_rx_rbr_ring_t rbr_p, p_rx_rcr_ring_t rcr_p, p_rx_mbox_t rx_mbox_p);
static hxge_status_t hxge_map_rxdma_channel_cfg_ring(p_hxge_t hxgep,
    uint16_t dma_channel, p_hxge_dma_common_t *dma_rbr_cntl_p,
    p_hxge_dma_common_t *dma_rcr_cntl_p, p_hxge_dma_common_t *dma_mbox_cntl_p,
    p_rx_rbr_ring_t *rbr_p, p_rx_rcr_ring_t *rcr_p, p_rx_mbox_t *rx_mbox_p);
static void hxge_unmap_rxdma_channel_cfg_ring(p_hxge_t hxgep,
	p_rx_rcr_ring_t rcr_p, p_rx_mbox_t rx_mbox_p);
static hxge_status_t hxge_map_rxdma_channel_buf_ring(p_hxge_t hxgep,
	uint16_t channel, p_hxge_dma_common_t *dma_buf_p,
	p_rx_rbr_ring_t *rbr_p, uint32_t num_chunks);
static void hxge_unmap_rxdma_channel_buf_ring(p_hxge_t hxgep,
	p_rx_rbr_ring_t rbr_p);
static hxge_status_t hxge_rxdma_start_channel(p_hxge_t hxgep, uint16_t channel,
	p_rx_rbr_ring_t rbr_p, p_rx_rcr_ring_t rcr_p, p_rx_mbox_t mbox_p,
	int n_init_kick);
static hxge_status_t hxge_rxdma_stop_channel(p_hxge_t hxgep, uint16_t channel);
static mblk_t *hxge_rx_pkts(p_hxge_t hxgep, uint_t vindex, p_hxge_ldv_t ldvp,
	p_rx_rcr_ring_t	rcr_p, rdc_stat_t cs, int bytes_to_read);
static uint32_t hxge_scan_for_last_eop(p_rx_rcr_ring_t rcr_p,
    p_rcr_entry_t rcr_desc_rd_head_p, uint32_t num_rcrs);
static void hxge_receive_packet(p_hxge_t hxgep, p_rx_rcr_ring_t rcr_p,
	p_rcr_entry_t rcr_desc_rd_head_p, boolean_t *multi_p,
	mblk_t ** mp, mblk_t ** mp_cont, uint32_t *invalid_rcr_entry);
static hxge_status_t hxge_disable_rxdma_channel(p_hxge_t hxgep,
	uint16_t channel);
static p_rx_msg_t hxge_allocb(size_t, uint32_t, p_hxge_dma_common_t);
static void hxge_freeb(p_rx_msg_t);
static hxge_status_t hxge_rx_err_evnts(p_hxge_t hxgep, uint_t index,
	p_hxge_ldv_t ldvp, rdc_stat_t cs);
static hxge_status_t hxge_rxbuf_index_info_init(p_hxge_t hxgep,
	p_rx_rbr_ring_t rx_dmap);
static hxge_status_t hxge_rxdma_fatal_err_recover(p_hxge_t hxgep,
	uint16_t channel);
static hxge_status_t hxge_rx_port_fatal_err_recover(p_hxge_t hxgep);
static void hxge_rbr_empty_restore(p_hxge_t hxgep,
	p_rx_rbr_ring_t rx_rbr_p);

hxge_status_t
hxge_init_rxdma_channels(p_hxge_t hxgep)
{
	hxge_status_t		status = HXGE_OK;
	block_reset_t		reset_reg;
	int			i;

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL, "==> hxge_init_rxdma_channels"));

	for (i = 0; i < HXGE_MAX_RDCS; i++)
		hxgep->rdc_first_intr[i] = B_TRUE;

	/* Reset RDC block from PEU to clear any previous state */
	reset_reg.value = 0;
	reset_reg.bits.rdc_rst = 1;
	HXGE_REG_WR32(hxgep->hpi_handle, BLOCK_RESET, reset_reg.value);
	HXGE_DELAY(1000);

	status = hxge_map_rxdma(hxgep);
	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "<== hxge_init_rxdma: status 0x%x", status));
		return (status);
	}

	status = hxge_rxdma_hw_start_common(hxgep);
	if (status != HXGE_OK) {
		hxge_unmap_rxdma(hxgep);
	}

	status = hxge_rxdma_hw_start(hxgep);
	if (status != HXGE_OK) {
		hxge_unmap_rxdma(hxgep);
	}

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    "<== hxge_init_rxdma_channels: status 0x%x", status));
	return (status);
}

void
hxge_uninit_rxdma_channels(p_hxge_t hxgep)
{
	HXGE_DEBUG_MSG((hxgep, MEM2_CTL, "==> hxge_uninit_rxdma_channels"));

	hxge_rxdma_hw_stop(hxgep);
	hxge_unmap_rxdma(hxgep);

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL, "<== hxge_uinit_rxdma_channels"));
}

hxge_status_t
hxge_init_rxdma_channel_cntl_stat(p_hxge_t hxgep, uint16_t channel,
    rdc_stat_t *cs_p)
{
	hpi_handle_t	handle;
	hpi_status_t	rs = HPI_SUCCESS;
	hxge_status_t	status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, DMA_CTL,
	    "<== hxge_init_rxdma_channel_cntl_stat"));

	handle = HXGE_DEV_HPI_HANDLE(hxgep);
	rs = hpi_rxdma_control_status(handle, OP_SET, channel, cs_p);

	if (rs != HPI_SUCCESS) {
		status = HXGE_ERROR | rs;
	}
	return (status);
}


hxge_status_t
hxge_enable_rxdma_channel(p_hxge_t hxgep, uint16_t channel,
    p_rx_rbr_ring_t rbr_p, p_rx_rcr_ring_t rcr_p, p_rx_mbox_t mbox_p,
    int n_init_kick)
{
	hpi_handle_t		handle;
	rdc_desc_cfg_t 		rdc_desc;
	rdc_rcr_cfg_b_t		*cfgb_p;
	hpi_status_t		rs = HPI_SUCCESS;

	HXGE_DEBUG_MSG((hxgep, DMA_CTL, "==> hxge_enable_rxdma_channel"));
	handle = HXGE_DEV_HPI_HANDLE(hxgep);

	/*
	 * Use configuration data composed at init time. Write to hardware the
	 * receive ring configurations.
	 */
	rdc_desc.mbox_enable = 1;
	rdc_desc.mbox_addr = mbox_p->mbox_addr;
	HXGE_DEBUG_MSG((hxgep, RX_CTL,
	    "==> hxge_enable_rxdma_channel: mboxp $%p($%p)",
	    mbox_p->mbox_addr, rdc_desc.mbox_addr));

	rdc_desc.rbr_len = rbr_p->rbb_max;
	rdc_desc.rbr_addr = rbr_p->rbr_addr;

	switch (hxgep->rx_bksize_code) {
	case RBR_BKSIZE_4K:
		rdc_desc.page_size = SIZE_4KB;
		break;
	case RBR_BKSIZE_8K:
		rdc_desc.page_size = SIZE_8KB;
		break;
	}

	rdc_desc.size0 = rbr_p->hpi_pkt_buf_size0;
	rdc_desc.valid0 = 1;

	rdc_desc.size1 = rbr_p->hpi_pkt_buf_size1;
	rdc_desc.valid1 = 1;

	rdc_desc.size2 = rbr_p->hpi_pkt_buf_size2;
	rdc_desc.valid2 = 1;

	rdc_desc.full_hdr = rcr_p->full_hdr_flag;
	rdc_desc.offset = rcr_p->sw_priv_hdr_len;

	rdc_desc.rcr_len = rcr_p->comp_size;
	rdc_desc.rcr_addr = rcr_p->rcr_addr;

	cfgb_p = &(rcr_p->rcr_cfgb);
	rdc_desc.rcr_threshold = cfgb_p->bits.pthres;
	rdc_desc.rcr_timeout = cfgb_p->bits.timeout;
	rdc_desc.rcr_timeout_enable = cfgb_p->bits.entout;

	HXGE_DEBUG_MSG((hxgep, DMA_CTL, "==> hxge_enable_rxdma_channel: "
	    "rbr_len qlen %d pagesize code %d rcr_len %d",
	    rdc_desc.rbr_len, rdc_desc.page_size, rdc_desc.rcr_len));
	HXGE_DEBUG_MSG((hxgep, DMA_CTL, "==> hxge_enable_rxdma_channel: "
	    "size 0 %d size 1 %d size 2 %d",
	    rbr_p->hpi_pkt_buf_size0, rbr_p->hpi_pkt_buf_size1,
	    rbr_p->hpi_pkt_buf_size2));

	rs = hpi_rxdma_cfg_rdc_ring(handle, rbr_p->rdc, &rdc_desc);
	if (rs != HPI_SUCCESS) {
		return (HXGE_ERROR | rs);
	}

	/*
	 * Enable the timeout and threshold.
	 */
	rs = hpi_rxdma_cfg_rdc_rcr_threshold(handle, channel,
	    rdc_desc.rcr_threshold);
	if (rs != HPI_SUCCESS) {
		return (HXGE_ERROR | rs);
	}

	rs = hpi_rxdma_cfg_rdc_rcr_timeout(handle, channel,
	    rdc_desc.rcr_timeout);
	if (rs != HPI_SUCCESS) {
		return (HXGE_ERROR | rs);
	}

	/* Kick the DMA engine */
	hpi_rxdma_rdc_rbr_kick(handle, channel, n_init_kick);

	/* Clear the rbr empty bit */
	(void) hpi_rxdma_channel_rbr_empty_clear(handle, channel);

	/*
	 * Enable the DMA
	 */
	rs = hpi_rxdma_cfg_rdc_enable(handle, channel);
	if (rs != HPI_SUCCESS) {
		return (HXGE_ERROR | rs);
	}

	HXGE_DEBUG_MSG((hxgep, DMA_CTL, "<== hxge_enable_rxdma_channel"));

	return (HXGE_OK);
}

static hxge_status_t
hxge_disable_rxdma_channel(p_hxge_t hxgep, uint16_t channel)
{
	hpi_handle_t handle;
	hpi_status_t rs = HPI_SUCCESS;

	HXGE_DEBUG_MSG((hxgep, DMA_CTL, "==> hxge_disable_rxdma_channel"));

	handle = HXGE_DEV_HPI_HANDLE(hxgep);

	/* disable the DMA */
	rs = hpi_rxdma_cfg_rdc_disable(handle, channel);
	if (rs != HPI_SUCCESS) {
		HXGE_DEBUG_MSG((hxgep, RX_CTL,
		    "<== hxge_disable_rxdma_channel:failed (0x%x)", rs));
		return (HXGE_ERROR | rs);
	}
	HXGE_DEBUG_MSG((hxgep, DMA_CTL, "<== hxge_disable_rxdma_channel"));
	return (HXGE_OK);
}

hxge_status_t
hxge_rxdma_channel_rcrflush(p_hxge_t hxgep, uint8_t channel)
{
	hpi_handle_t	handle;
	hxge_status_t	status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, DMA_CTL,
	    "==> hxge_rxdma_channel_rcrflush"));

	handle = HXGE_DEV_HPI_HANDLE(hxgep);
	hpi_rxdma_rdc_rcr_flush(handle, channel);

	HXGE_DEBUG_MSG((hxgep, DMA_CTL,
	    "<== hxge_rxdma_channel_rcrflush"));
	return (status);

}

#define	MID_INDEX(l, r) ((r + l + 1) >> 1)

#define	TO_LEFT -1
#define	TO_RIGHT 1
#define	BOTH_RIGHT (TO_RIGHT + TO_RIGHT)
#define	BOTH_LEFT (TO_LEFT + TO_LEFT)
#define	IN_MIDDLE (TO_RIGHT + TO_LEFT)
#define	NO_HINT 0xffffffff

/*ARGSUSED*/
hxge_status_t
hxge_rxbuf_pp_to_vp(p_hxge_t hxgep, p_rx_rbr_ring_t rbr_p,
    uint8_t pktbufsz_type, uint64_t *pkt_buf_addr_pp,
    uint64_t **pkt_buf_addr_p, uint32_t *bufoffset, uint32_t *msg_index)
{
	int			bufsize;
	uint64_t		pktbuf_pp;
	uint64_t		dvma_addr;
	rxring_info_t		*ring_info;
	int			base_side, end_side;
	int			r_index, l_index, anchor_index;
	int			found, search_done;
	uint32_t		offset, chunk_size, block_size, page_size_mask;
	uint32_t		chunk_index, block_index, total_index;
	int			max_iterations, iteration;
	rxbuf_index_info_t	*bufinfo;

	HXGE_DEBUG_MSG((hxgep, RX2_CTL, "==> hxge_rxbuf_pp_to_vp"));

	HXGE_DEBUG_MSG((hxgep, RX2_CTL,
	    "==> hxge_rxbuf_pp_to_vp: buf_pp $%p btype %d",
	    pkt_buf_addr_pp, pktbufsz_type));

#if defined(__i386)
	pktbuf_pp = (uint64_t)(uint32_t)pkt_buf_addr_pp;
#else
	pktbuf_pp = (uint64_t)pkt_buf_addr_pp;
#endif

	switch (pktbufsz_type) {
	case 0:
		bufsize = rbr_p->pkt_buf_size0;
		break;
	case 1:
		bufsize = rbr_p->pkt_buf_size1;
		break;
	case 2:
		bufsize = rbr_p->pkt_buf_size2;
		break;
	case RCR_SINGLE_BLOCK:
		bufsize = 0;
		anchor_index = 0;
		break;
	default:
		return (HXGE_ERROR);
	}

	if (rbr_p->num_blocks == 1) {
		anchor_index = 0;
		ring_info = rbr_p->ring_info;
		bufinfo = (rxbuf_index_info_t *)ring_info->buffer;

		HXGE_DEBUG_MSG((hxgep, RX2_CTL,
		    "==> hxge_rxbuf_pp_to_vp: (found, 1 block) "
		    "buf_pp $%p btype %d anchor_index %d bufinfo $%p",
		    pkt_buf_addr_pp, pktbufsz_type, anchor_index, bufinfo));

		goto found_index;
	}

	HXGE_DEBUG_MSG((hxgep, RX2_CTL,
	    "==> hxge_rxbuf_pp_to_vp: buf_pp $%p btype %d anchor_index %d",
	    pkt_buf_addr_pp, pktbufsz_type, anchor_index));

	ring_info = rbr_p->ring_info;
	found = B_FALSE;
	bufinfo = (rxbuf_index_info_t *)ring_info->buffer;
	iteration = 0;
	max_iterations = ring_info->max_iterations;

	/*
	 * First check if this block have been seen recently. This is indicated
	 * by a hint which is initialized when the first buffer of the block is
	 * seen. The hint is reset when the last buffer of the block has been
	 * processed. As three block sizes are supported, three hints are kept.
	 * The idea behind the hints is that once the hardware  uses a block
	 * for a buffer  of that size, it will use it exclusively for that size
	 * and will use it until it is exhausted. It is assumed that there
	 * would a single block being used for the same buffer sizes at any
	 * given time.
	 */
	if (ring_info->hint[pktbufsz_type] != NO_HINT) {
		anchor_index = ring_info->hint[pktbufsz_type];
		dvma_addr = bufinfo[anchor_index].dvma_addr;
		chunk_size = bufinfo[anchor_index].buf_size;
		if ((pktbuf_pp >= dvma_addr) &&
		    (pktbuf_pp < (dvma_addr + chunk_size))) {
			found = B_TRUE;
			/*
			 * check if this is the last buffer in the block If so,
			 * then reset the hint for the size;
			 */

			if ((pktbuf_pp + bufsize) >= (dvma_addr + chunk_size))
				ring_info->hint[pktbufsz_type] = NO_HINT;
		}
	}

	if (found == B_FALSE) {
		HXGE_DEBUG_MSG((hxgep, RX2_CTL,
		    "==> hxge_rxbuf_pp_to_vp: (!found)"
		    "buf_pp $%p btype %d anchor_index %d",
		    pkt_buf_addr_pp, pktbufsz_type, anchor_index));

		/*
		 * This is the first buffer of the block of this size. Need to
		 * search the whole information array. the search algorithm
		 * uses a binary tree search algorithm. It assumes that the
		 * information is already sorted with increasing order info[0]
		 * < info[1] < info[2]  .... < info[n-1] where n is the size of
		 * the information array
		 */
		r_index = rbr_p->num_blocks - 1;
		l_index = 0;
		search_done = B_FALSE;
		anchor_index = MID_INDEX(r_index, l_index);
		while (search_done == B_FALSE) {
			if ((r_index == l_index) ||
			    (iteration >= max_iterations))
				search_done = B_TRUE;

			end_side = TO_RIGHT;	/* to the right */
			base_side = TO_LEFT;	/* to the left */
			/* read the DVMA address information and sort it */
			dvma_addr = bufinfo[anchor_index].dvma_addr;
			chunk_size = bufinfo[anchor_index].buf_size;

			HXGE_DEBUG_MSG((hxgep, RX2_CTL,
			    "==> hxge_rxbuf_pp_to_vp: (searching)"
			    "buf_pp $%p btype %d "
			    "anchor_index %d chunk_size %d dvmaaddr $%p",
			    pkt_buf_addr_pp, pktbufsz_type, anchor_index,
			    chunk_size, dvma_addr));

			if (pktbuf_pp >= dvma_addr)
				base_side = TO_RIGHT;	/* to the right */
			if (pktbuf_pp < (dvma_addr + chunk_size))
				end_side = TO_LEFT;	/* to the left */

			switch (base_side + end_side) {
			case IN_MIDDLE:
				/* found */
				found = B_TRUE;
				search_done = B_TRUE;
				if ((pktbuf_pp + bufsize) <
				    (dvma_addr + chunk_size))
					ring_info->hint[pktbufsz_type] =
					    bufinfo[anchor_index].buf_index;
				break;
			case BOTH_RIGHT:
				/* not found: go to the right */
				l_index = anchor_index + 1;
				anchor_index = MID_INDEX(r_index, l_index);
				break;

			case BOTH_LEFT:
				/* not found: go to the left */
				r_index = anchor_index - 1;
				anchor_index = MID_INDEX(r_index, l_index);
				break;
			default:	/* should not come here */
				return (HXGE_ERROR);
			}
			iteration++;
		}

		HXGE_DEBUG_MSG((hxgep, RX2_CTL,
		    "==> hxge_rxbuf_pp_to_vp: (search done)"
		    "buf_pp $%p btype %d anchor_index %d",
		    pkt_buf_addr_pp, pktbufsz_type, anchor_index));
	}

	if (found == B_FALSE) {
		HXGE_DEBUG_MSG((hxgep, RX2_CTL,
		    "==> hxge_rxbuf_pp_to_vp: (search failed)"
		    "buf_pp $%p btype %d anchor_index %d",
		    pkt_buf_addr_pp, pktbufsz_type, anchor_index));
		return (HXGE_ERROR);
	}

found_index:
	HXGE_DEBUG_MSG((hxgep, RX2_CTL,
	    "==> hxge_rxbuf_pp_to_vp: (FOUND1)"
	    "buf_pp $%p btype %d bufsize %d anchor_index %d",
	    pkt_buf_addr_pp, pktbufsz_type, bufsize, anchor_index));

	/* index of the first block in this chunk */
	chunk_index = bufinfo[anchor_index].start_index;
	dvma_addr = bufinfo[anchor_index].dvma_addr;
	page_size_mask = ring_info->block_size_mask;

	HXGE_DEBUG_MSG((hxgep, RX2_CTL,
	    "==> hxge_rxbuf_pp_to_vp: (FOUND3), get chunk)"
	    "buf_pp $%p btype %d bufsize %d "
	    "anchor_index %d chunk_index %d dvma $%p",
	    pkt_buf_addr_pp, pktbufsz_type, bufsize,
	    anchor_index, chunk_index, dvma_addr));

	offset = pktbuf_pp - dvma_addr;	/* offset within the chunk */
	block_size = rbr_p->block_size;	/* System  block(page) size */

	HXGE_DEBUG_MSG((hxgep, RX2_CTL,
	    "==> hxge_rxbuf_pp_to_vp: (FOUND4), get chunk)"
	    "buf_pp $%p btype %d bufsize %d "
	    "anchor_index %d chunk_index %d dvma $%p "
	    "offset %d block_size %d",
	    pkt_buf_addr_pp, pktbufsz_type, bufsize, anchor_index,
	    chunk_index, dvma_addr, offset, block_size));
	HXGE_DEBUG_MSG((hxgep, RX2_CTL, "==> getting total index"));

	block_index = (offset / block_size);	/* index within chunk */
	total_index = chunk_index + block_index;

	HXGE_DEBUG_MSG((hxgep, RX2_CTL,
	    "==> hxge_rxbuf_pp_to_vp: "
	    "total_index %d dvma_addr $%p "
	    "offset %d block_size %d "
	    "block_index %d ",
	    total_index, dvma_addr, offset, block_size, block_index));

#if defined(__i386)
	*pkt_buf_addr_p = (uint64_t *)((uint32_t)bufinfo[anchor_index].kaddr +
	    (uint32_t)offset);
#else
	*pkt_buf_addr_p = (uint64_t *)((uint64_t)bufinfo[anchor_index].kaddr +
	    offset);
#endif

	HXGE_DEBUG_MSG((hxgep, RX2_CTL,
	    "==> hxge_rxbuf_pp_to_vp: "
	    "total_index %d dvma_addr $%p "
	    "offset %d block_size %d "
	    "block_index %d "
	    "*pkt_buf_addr_p $%p",
	    total_index, dvma_addr, offset, block_size,
	    block_index, *pkt_buf_addr_p));

	*msg_index = total_index;
	*bufoffset = (offset & page_size_mask);

	HXGE_DEBUG_MSG((hxgep, RX2_CTL,
	    "==> hxge_rxbuf_pp_to_vp: get msg index: "
	    "msg_index %d bufoffset_index %d",
	    *msg_index, *bufoffset));
	HXGE_DEBUG_MSG((hxgep, RX2_CTL, "<== hxge_rxbuf_pp_to_vp"));

	return (HXGE_OK);
}


/*
 * used by quick sort (qsort) function
 * to perform comparison
 */
static int
hxge_sort_compare(const void *p1, const void *p2)
{

	rxbuf_index_info_t *a, *b;

	a = (rxbuf_index_info_t *)p1;
	b = (rxbuf_index_info_t *)p2;

	if (a->dvma_addr > b->dvma_addr)
		return (1);
	if (a->dvma_addr < b->dvma_addr)
		return (-1);
	return (0);
}

/*
 * Grabbed this sort implementation from common/syscall/avl.c
 *
 * Generic shellsort, from K&R (1st ed, p 58.), somewhat modified.
 * v = Ptr to array/vector of objs
 * n = # objs in the array
 * s = size of each obj (must be multiples of a word size)
 * f = ptr to function to compare two objs
 *	returns (-1 = less than, 0 = equal, 1 = greater than
 */
void
hxge_ksort(caddr_t v, int n, int s, int (*f) ())
{
	int		g, i, j, ii;
	unsigned int	*p1, *p2;
	unsigned int	tmp;

	/* No work to do */
	if (v == NULL || n <= 1)
		return;
	/* Sanity check on arguments */
	ASSERT(((uintptr_t)v & 0x3) == 0 && (s & 0x3) == 0);
	ASSERT(s > 0);

	for (g = n / 2; g > 0; g /= 2) {
		for (i = g; i < n; i++) {
			for (j = i - g; j >= 0 &&
			    (*f) (v + j * s, v + (j + g) * s) == 1; j -= g) {
				p1 = (unsigned *)(v + j * s);
				p2 = (unsigned *)(v + (j + g) * s);
				for (ii = 0; ii < s / 4; ii++) {
					tmp = *p1;
					*p1++ = *p2;
					*p2++ = tmp;
				}
			}
		}
	}
}

/*
 * Initialize data structures required for rxdma
 * buffer dvma->vmem address lookup
 */
/*ARGSUSED*/
static hxge_status_t
hxge_rxbuf_index_info_init(p_hxge_t hxgep, p_rx_rbr_ring_t rbrp)
{
	int		index;
	rxring_info_t	*ring_info;
	int		max_iteration = 0, max_index = 0;

	HXGE_DEBUG_MSG((hxgep, DMA_CTL, "==> hxge_rxbuf_index_info_init"));

	ring_info = rbrp->ring_info;
	ring_info->hint[0] = NO_HINT;
	ring_info->hint[1] = NO_HINT;
	ring_info->hint[2] = NO_HINT;
	ring_info->hint[3] = NO_HINT;
	max_index = rbrp->num_blocks;

	/* read the DVMA address information and sort it */
	/* do init of the information array */

	HXGE_DEBUG_MSG((hxgep, DMA2_CTL,
	    " hxge_rxbuf_index_info_init Sort ptrs"));

	/* sort the array */
	hxge_ksort((void *) ring_info->buffer, max_index,
	    sizeof (rxbuf_index_info_t), hxge_sort_compare);

	for (index = 0; index < max_index; index++) {
		HXGE_DEBUG_MSG((hxgep, DMA2_CTL,
		    " hxge_rxbuf_index_info_init: sorted chunk %d "
		    " ioaddr $%p kaddr $%p size %x",
		    index, ring_info->buffer[index].dvma_addr,
		    ring_info->buffer[index].kaddr,
		    ring_info->buffer[index].buf_size));
	}

	max_iteration = 0;
	while (max_index >= (1ULL << max_iteration))
		max_iteration++;
	ring_info->max_iterations = max_iteration + 1;

	HXGE_DEBUG_MSG((hxgep, DMA2_CTL,
	    " hxge_rxbuf_index_info_init Find max iter %d",
	    ring_info->max_iterations));
	HXGE_DEBUG_MSG((hxgep, DMA_CTL, "<== hxge_rxbuf_index_info_init"));

	return (HXGE_OK);
}

/*ARGSUSED*/
void
hxge_dump_rcr_entry(p_hxge_t hxgep, p_rcr_entry_t entry_p)
{
#ifdef	HXGE_DEBUG

	uint32_t bptr;
	uint64_t pp;

	bptr = entry_p->bits.pkt_buf_addr;

	HXGE_DEBUG_MSG((hxgep, RX_CTL,
	    "\trcr entry $%p "
	    "\trcr entry 0x%0llx "
	    "\trcr entry 0x%08x "
	    "\trcr entry 0x%08x "
	    "\tvalue 0x%0llx\n"
	    "\tmulti = %d\n"
	    "\tpkt_type = 0x%x\n"
	    "\terror = 0x%04x\n"
	    "\tl2_len = %d\n"
	    "\tpktbufsize = %d\n"
	    "\tpkt_buf_addr = $%p\n"
	    "\tpkt_buf_addr (<< 6) = $%p\n",
	    entry_p,
	    *(int64_t *)entry_p,
	    *(int32_t *)entry_p,
	    *(int32_t *)((char *)entry_p + 32),
	    entry_p->value,
	    entry_p->bits.multi,
	    entry_p->bits.pkt_type,
	    entry_p->bits.error,
	    entry_p->bits.l2_len,
	    entry_p->bits.pktbufsz,
	    bptr,
	    entry_p->bits.pkt_buf_addr_l));

	pp = (entry_p->value & RCR_PKT_BUF_ADDR_MASK) <<
	    RCR_PKT_BUF_ADDR_SHIFT;

	HXGE_DEBUG_MSG((hxgep, RX_CTL, "rcr pp 0x%llx l2 len %d",
	    pp, (*(int64_t *)entry_p >> 40) & 0x3fff));
#endif
}

/*ARGSUSED*/
void
hxge_rxdma_stop(p_hxge_t hxgep)
{
	HXGE_DEBUG_MSG((hxgep, RX_CTL, "==> hxge_rxdma_stop"));

	MUTEX_ENTER(&hxgep->vmac_lock);
	(void) hxge_rx_vmac_disable(hxgep);
	(void) hxge_rxdma_hw_mode(hxgep, HXGE_DMA_STOP);
	MUTEX_EXIT(&hxgep->vmac_lock);

	HXGE_DEBUG_MSG((hxgep, RX_CTL, "<== hxge_rxdma_stop"));
}

void
hxge_rxdma_stop_reinit(p_hxge_t hxgep)
{
	HXGE_DEBUG_MSG((hxgep, RX_CTL, "==> hxge_rxdma_stop_reinit"));

	(void) hxge_rxdma_stop(hxgep);
	(void) hxge_uninit_rxdma_channels(hxgep);
	(void) hxge_init_rxdma_channels(hxgep);

	MUTEX_ENTER(&hxgep->vmac_lock);
	(void) hxge_rx_vmac_enable(hxgep);
	MUTEX_EXIT(&hxgep->vmac_lock);

	HXGE_DEBUG_MSG((hxgep, RX_CTL, "<== hxge_rxdma_stop_reinit"));
}

hxge_status_t
hxge_rxdma_hw_mode(p_hxge_t hxgep, boolean_t enable)
{
	int			i, ndmas;
	uint16_t		channel;
	p_rx_rbr_rings_t	rx_rbr_rings;
	p_rx_rbr_ring_t		*rbr_rings;
	hpi_handle_t		handle;
	hpi_status_t		rs = HPI_SUCCESS;
	hxge_status_t		status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    "==> hxge_rxdma_hw_mode: mode %d", enable));

	if (!(hxgep->drv_state & STATE_HW_INITIALIZED)) {
		HXGE_DEBUG_MSG((hxgep, RX_CTL,
		    "<== hxge_rxdma_mode: not initialized"));
		return (HXGE_ERROR);
	}

	rx_rbr_rings = hxgep->rx_rbr_rings;
	if (rx_rbr_rings == NULL) {
		HXGE_DEBUG_MSG((hxgep, RX_CTL,
		    "<== hxge_rxdma_mode: NULL ring pointer"));
		return (HXGE_ERROR);
	}

	if (rx_rbr_rings->rbr_rings == NULL) {
		HXGE_DEBUG_MSG((hxgep, RX_CTL,
		    "<== hxge_rxdma_mode: NULL rbr rings pointer"));
		return (HXGE_ERROR);
	}

	ndmas = rx_rbr_rings->ndmas;
	if (!ndmas) {
		HXGE_DEBUG_MSG((hxgep, RX_CTL,
		    "<== hxge_rxdma_mode: no channel"));
		return (HXGE_ERROR);
	}

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    "==> hxge_rxdma_mode (ndmas %d)", ndmas));

	rbr_rings = rx_rbr_rings->rbr_rings;

	handle = HXGE_DEV_HPI_HANDLE(hxgep);

	for (i = 0; i < ndmas; i++) {
		if (rbr_rings == NULL || rbr_rings[i] == NULL) {
			continue;
		}
		channel = rbr_rings[i]->rdc;
		if (enable) {
			HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
			    "==> hxge_rxdma_hw_mode: channel %d (enable)",
			    channel));
			rs = hpi_rxdma_cfg_rdc_enable(handle, channel);
		} else {
			HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
			    "==> hxge_rxdma_hw_mode: channel %d (disable)",
			    channel));
			rs = hpi_rxdma_cfg_rdc_disable(handle, channel);
		}
	}

	status = ((rs == HPI_SUCCESS) ? HXGE_OK : HXGE_ERROR | rs);
	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    "<== hxge_rxdma_hw_mode: status 0x%x", status));

	return (status);
}

/*
 * Static functions start here.
 */
static p_rx_msg_t
hxge_allocb(size_t size, uint32_t pri, p_hxge_dma_common_t dmabuf_p)
{
	p_rx_msg_t		hxge_mp = NULL;
	p_hxge_dma_common_t	dmamsg_p;
	uchar_t			*buffer;

	hxge_mp = KMEM_ZALLOC(sizeof (rx_msg_t), KM_NOSLEEP);
	if (hxge_mp == NULL) {
		HXGE_ERROR_MSG((NULL, HXGE_ERR_CTL,
		    "Allocation of a rx msg failed."));
		goto hxge_allocb_exit;
	}

	hxge_mp->use_buf_pool = B_FALSE;
	if (dmabuf_p) {
		hxge_mp->use_buf_pool = B_TRUE;

		dmamsg_p = (p_hxge_dma_common_t)&hxge_mp->buf_dma;
		*dmamsg_p = *dmabuf_p;
		dmamsg_p->nblocks = 1;
		dmamsg_p->block_size = size;
		dmamsg_p->alength = size;
		buffer = (uchar_t *)dmabuf_p->kaddrp;

		dmabuf_p->kaddrp = (void *)((char *)dmabuf_p->kaddrp + size);
		dmabuf_p->ioaddr_pp = (void *)
		    ((char *)dmabuf_p->ioaddr_pp + size);

		dmabuf_p->alength -= size;
		dmabuf_p->offset += size;
		dmabuf_p->dma_cookie.dmac_laddress += size;
		dmabuf_p->dma_cookie.dmac_size -= size;
	} else {
		buffer = KMEM_ALLOC(size, KM_NOSLEEP);
		if (buffer == NULL) {
			HXGE_ERROR_MSG((NULL, HXGE_ERR_CTL,
			    "Allocation of a receive page failed."));
			goto hxge_allocb_fail1;
		}
	}

	hxge_mp->rx_mblk_p = desballoc(buffer, size, pri, &hxge_mp->freeb);
	if (hxge_mp->rx_mblk_p == NULL) {
		HXGE_ERROR_MSG((NULL, HXGE_ERR_CTL, "desballoc failed."));
		goto hxge_allocb_fail2;
	}
	hxge_mp->buffer = buffer;
	hxge_mp->block_size = size;
	hxge_mp->freeb.free_func = (void (*) ()) hxge_freeb;
	hxge_mp->freeb.free_arg = (caddr_t)hxge_mp;
	hxge_mp->ref_cnt = 1;
	hxge_mp->free = B_TRUE;
	hxge_mp->rx_use_bcopy = B_FALSE;

	atomic_inc_32(&hxge_mblks_pending);

	goto hxge_allocb_exit;

hxge_allocb_fail2:
	if (!hxge_mp->use_buf_pool) {
		KMEM_FREE(buffer, size);
	}
hxge_allocb_fail1:
	KMEM_FREE(hxge_mp, sizeof (rx_msg_t));
	hxge_mp = NULL;

hxge_allocb_exit:
	return (hxge_mp);
}

p_mblk_t
hxge_dupb(p_rx_msg_t hxge_mp, uint_t offset, size_t size)
{
	p_mblk_t mp;

	HXGE_DEBUG_MSG((NULL, MEM_CTL, "==> hxge_dupb"));
	HXGE_DEBUG_MSG((NULL, MEM_CTL, "hxge_mp = $%p "
	    "offset = 0x%08X " "size = 0x%08X", hxge_mp, offset, size));

	mp = desballoc(&hxge_mp->buffer[offset], size, 0, &hxge_mp->freeb);
	if (mp == NULL) {
		HXGE_DEBUG_MSG((NULL, RX_CTL, "desballoc failed"));
		goto hxge_dupb_exit;
	}

	atomic_inc_32(&hxge_mp->ref_cnt);

hxge_dupb_exit:
	HXGE_DEBUG_MSG((NULL, MEM_CTL, "<== hxge_dupb mp = $%p", hxge_mp));
	return (mp);
}

p_mblk_t
hxge_dupb_bcopy(p_rx_msg_t hxge_mp, uint_t offset, size_t size)
{
	p_mblk_t	mp;
	uchar_t		*dp;

	mp = allocb(size + HXGE_RXBUF_EXTRA, 0);
	if (mp == NULL) {
		HXGE_DEBUG_MSG((NULL, RX_CTL, "desballoc failed"));
		goto hxge_dupb_bcopy_exit;
	}
	dp = mp->b_rptr = mp->b_rptr + HXGE_RXBUF_EXTRA;
	bcopy((void *) &hxge_mp->buffer[offset], dp, size);
	mp->b_wptr = dp + size;

hxge_dupb_bcopy_exit:

	HXGE_DEBUG_MSG((NULL, MEM_CTL, "<== hxge_dupb mp = $%p", hxge_mp));

	return (mp);
}

void hxge_post_page(p_hxge_t hxgep, p_rx_rbr_ring_t rx_rbr_p,
    p_rx_msg_t rx_msg_p);

void
hxge_post_page(p_hxge_t hxgep, p_rx_rbr_ring_t rx_rbr_p, p_rx_msg_t rx_msg_p)
{
	HXGE_DEBUG_MSG((hxgep, RX_CTL, "==> hxge_post_page"));

	/* Reuse this buffer */
	rx_msg_p->free = B_FALSE;
	rx_msg_p->cur_usage_cnt = 0;
	rx_msg_p->max_usage_cnt = 0;
	rx_msg_p->pkt_buf_size = 0;

	if (rx_rbr_p->rbr_use_bcopy) {
		rx_msg_p->rx_use_bcopy = B_FALSE;
		atomic_dec_32(&rx_rbr_p->rbr_consumed);
	}
	atomic_dec_32(&rx_rbr_p->rbr_used);

	/*
	 * Get the rbr header pointer and its offset index.
	 */
	rx_rbr_p->rbr_wr_index = ((rx_rbr_p->rbr_wr_index + 1) &
	    rx_rbr_p->rbr_wrap_mask);
	rx_rbr_p->rbr_desc_vp[rx_rbr_p->rbr_wr_index] = rx_msg_p->shifted_addr;

	/*
	 * Accumulate some buffers in the ring before re-enabling the
	 * DMA channel, if rbr empty was signaled.
	 */
	hpi_rxdma_rdc_rbr_kick(HXGE_DEV_HPI_HANDLE(hxgep), rx_rbr_p->rdc, 1);
	if (rx_rbr_p->rbr_is_empty && (rx_rbr_p->rbb_max -
	    rx_rbr_p->rbr_used) >= HXGE_RBR_EMPTY_THRESHOLD) {
		hxge_rbr_empty_restore(hxgep, rx_rbr_p);
	}

	HXGE_DEBUG_MSG((hxgep, RX_CTL,
	    "<== hxge_post_page (channel %d post_next_index %d)",
	    rx_rbr_p->rdc, rx_rbr_p->rbr_wr_index));
	HXGE_DEBUG_MSG((hxgep, RX_CTL, "<== hxge_post_page"));
}

void
hxge_freeb(p_rx_msg_t rx_msg_p)
{
	size_t		size;
	uchar_t		*buffer = NULL;
	int		ref_cnt;
	boolean_t	free_state = B_FALSE;
	rx_rbr_ring_t	*ring = rx_msg_p->rx_rbr_p;

	HXGE_DEBUG_MSG((NULL, MEM2_CTL, "==> hxge_freeb"));
	HXGE_DEBUG_MSG((NULL, MEM2_CTL,
	    "hxge_freeb:rx_msg_p = $%p (block pending %d)",
	    rx_msg_p, hxge_mblks_pending));

	if (ring == NULL)
		return;

	/*
	 * This is to prevent posting activities while we are recovering
	 * from fatal errors. This should not be a performance drag since
	 * ref_cnt != 0 most times.
	 */
	if (ring->rbr_state == RBR_POSTING)
		MUTEX_ENTER(&ring->post_lock);

	/*
	 * First we need to get the free state, then
	 * atomic decrement the reference count to prevent
	 * the race condition with the interrupt thread that
	 * is processing a loaned up buffer block.
	 */
	free_state = rx_msg_p->free;
	ref_cnt = atomic_dec_32_nv(&rx_msg_p->ref_cnt);
	if (!ref_cnt) {
		atomic_dec_32(&hxge_mblks_pending);

		buffer = rx_msg_p->buffer;
		size = rx_msg_p->block_size;

		HXGE_DEBUG_MSG((NULL, MEM2_CTL, "hxge_freeb: "
		    "will free: rx_msg_p = $%p (block pending %d)",
		    rx_msg_p, hxge_mblks_pending));

		if (!rx_msg_p->use_buf_pool) {
			KMEM_FREE(buffer, size);
		}

		KMEM_FREE(rx_msg_p, sizeof (rx_msg_t));
		/*
		 * Decrement the receive buffer ring's reference
		 * count, too.
		 */
		atomic_dec_32(&ring->rbr_ref_cnt);

		/*
		 * Free the receive buffer ring, iff
		 * 1. all the receive buffers have been freed
		 * 2. and we are in the proper state (that is,
		 *    we are not UNMAPPING).
		 */
		if (ring->rbr_ref_cnt == 0 &&
		    ring->rbr_state == RBR_UNMAPPED) {
			KMEM_FREE(ring, sizeof (*ring));
			/* post_lock has been destroyed already */
			return;
		}
	}

	/*
	 * Repost buffer.
	 */
	if (free_state && (ref_cnt == 1)) {
		HXGE_DEBUG_MSG((NULL, RX_CTL,
		    "hxge_freeb: post page $%p:", rx_msg_p));
		if (ring->rbr_state == RBR_POSTING)
			hxge_post_page(rx_msg_p->hxgep, ring, rx_msg_p);
	}

	if (ring->rbr_state == RBR_POSTING)
		MUTEX_EXIT(&ring->post_lock);

	HXGE_DEBUG_MSG((NULL, MEM2_CTL, "<== hxge_freeb"));
}

uint_t
hxge_rx_intr(caddr_t arg1, caddr_t arg2)
{
	p_hxge_ring_handle_t	rhp;
	p_hxge_ldv_t		ldvp = (p_hxge_ldv_t)arg1;
	p_hxge_t		hxgep = (p_hxge_t)arg2;
	p_hxge_ldg_t		ldgp;
	uint8_t			channel;
	hpi_handle_t		handle;
	rdc_stat_t		cs;
	p_rx_rcr_ring_t		ring;
	p_rx_rbr_ring_t		rbrp;
	mblk_t			*mp = NULL;

	if (ldvp == NULL) {
		HXGE_DEBUG_MSG((NULL, RX_INT_CTL,
		    "<== hxge_rx_intr: arg2 $%p arg1 $%p", hxgep, ldvp));
		return (DDI_INTR_UNCLAIMED);
	}

	if (arg2 == NULL || (void *) ldvp->hxgep != arg2) {
		hxgep = ldvp->hxgep;
	}

	HXGE_DEBUG_MSG((hxgep, RX_INT_CTL,
	    "==> hxge_rx_intr: arg2 $%p arg1 $%p", hxgep, ldvp));

	/*
	 * This interrupt handler is for a specific receive dma channel.
	 */
	handle = HXGE_DEV_HPI_HANDLE(hxgep);

	/*
	 * Get the control and status for this channel.
	 */
	channel = ldvp->vdma_index;
	ring = hxgep->rx_rcr_rings->rcr_rings[channel];
	rhp = &hxgep->rx_ring_handles[channel];
	ldgp = ldvp->ldgp;

	ASSERT(ring != NULL);
#if defined(DEBUG)
	if (rhp->started) {
		ASSERT(ring->ldgp == ldgp);
		ASSERT(ring->ldvp == ldvp);
	}
#endif

	MUTEX_ENTER(&ring->lock);

	if (!ring->poll_flag) {
		RXDMA_REG_READ64(handle, RDC_STAT, channel, &cs.value);
		cs.bits.ptrread = 0;
		cs.bits.pktread = 0;
		RXDMA_REG_WRITE64(handle, RDC_STAT, channel, cs.value);

		/*
		 * Process packets, if we are not in polling mode, the ring is
		 * started and the interface is started. The MAC layer under
		 * load will be operating in polling mode for RX traffic.
		 */
		if ((rhp->started) &&
		    (hxgep->hxge_mac_state == HXGE_MAC_STARTED)) {
			mp = hxge_rx_pkts(hxgep, ldvp->vdma_index,
			    ldvp, ring, cs, -1);
		}

		/* Process error events. */
		if (cs.value & RDC_STAT_ERROR) {
			MUTEX_EXIT(&ring->lock);
			(void) hxge_rx_err_evnts(hxgep, channel, ldvp, cs);
			MUTEX_ENTER(&ring->lock);
		}

		/*
		 * Enable the mailbox update interrupt if we want to use
		 * mailbox. We probably don't need to use mailbox as it only
		 * saves us one pio read.  Also write 1 to rcrthres and
		 * rcrto to clear these two edge triggered bits.
		 */
		rbrp = hxgep->rx_rbr_rings->rbr_rings[channel];
		MUTEX_ENTER(&rbrp->post_lock);
		if (!rbrp->rbr_is_empty) {
			cs.value = 0;
			cs.bits.mex = 1;
			cs.bits.ptrread = 0;
			cs.bits.pktread = 0;
			RXDMA_REG_WRITE64(handle, RDC_STAT, channel, cs.value);
		}
		MUTEX_EXIT(&rbrp->post_lock);

		if (ldgp->nldvs == 1) {
			/*
			 * Re-arm the group.
			 */
			(void) hpi_intr_ldg_mgmt_set(handle, ldgp->ldg, B_TRUE,
			    ldgp->ldg_timer);
		}
	} else if ((ldgp->nldvs == 1) && (ring->poll_flag)) {
		/*
		 * Disarm the group, if we are not a shared interrupt.
		 */
		(void) hpi_intr_ldg_mgmt_set(handle, ldgp->ldg, B_FALSE, 0);
	} else if (ring->poll_flag) {
		/*
		 * Mask-off this device from the group.
		 */
		(void) hpi_intr_mask_set(handle, ldvp->ldv, 1);
	}

	MUTEX_EXIT(&ring->lock);

	/*
	 * Send the packets up the stack.
	 */
	if (mp != NULL) {
		mac_rx_ring(hxgep->mach, ring->rcr_mac_handle, mp,
		    ring->rcr_gen_num);
	}

	HXGE_DEBUG_MSG((NULL, RX_INT_CTL, "<== hxge_rx_intr"));
	return (DDI_INTR_CLAIMED);
}

/*
 * Enable polling for a ring. Interrupt for the ring is disabled when
 * the hxge interrupt comes (see hxge_rx_intr).
 */
int
hxge_enable_poll(void *arg)
{
	p_hxge_ring_handle_t	ring_handle = (p_hxge_ring_handle_t)arg;
	p_rx_rcr_ring_t		ringp;
	p_hxge_t		hxgep;
	p_hxge_ldg_t		ldgp;

	if (ring_handle == NULL) {
		ASSERT(ring_handle != NULL);
		return (1);
	}


	hxgep = ring_handle->hxgep;
	ringp = hxgep->rx_rcr_rings->rcr_rings[ring_handle->index];

	MUTEX_ENTER(&ringp->lock);

	/*
	 * Are we already polling ?
	 */
	if (ringp->poll_flag) {
		MUTEX_EXIT(&ringp->lock);
		return (1);
	}

	ldgp = ringp->ldgp;
	if (ldgp == NULL) {
		MUTEX_EXIT(&ringp->lock);
		return (1);
	}

	/*
	 * Enable polling
	 */
	ringp->poll_flag = B_TRUE;

	MUTEX_EXIT(&ringp->lock);
	return (0);
}

/*
 * Disable polling for a ring and enable its interrupt.
 */
int
hxge_disable_poll(void *arg)
{
	p_hxge_ring_handle_t	ring_handle = (p_hxge_ring_handle_t)arg;
	p_rx_rcr_ring_t		ringp;
	p_hxge_t		hxgep;

	if (ring_handle == NULL) {
		ASSERT(ring_handle != NULL);
		return (0);
	}

	hxgep = ring_handle->hxgep;
	ringp = hxgep->rx_rcr_rings->rcr_rings[ring_handle->index];

	MUTEX_ENTER(&ringp->lock);

	/*
	 * Disable polling: enable interrupt
	 */
	if (ringp->poll_flag) {
		hpi_handle_t		handle;
		rdc_stat_t		cs;
		p_hxge_ldg_t		ldgp;

		/*
		 * Get the control and status for this channel.
		 */
		handle = HXGE_DEV_HPI_HANDLE(hxgep);

		/*
		 * Rearm this logical group if this is a single device
		 * group.
		 */
		ldgp = ringp->ldgp;
		if (ldgp == NULL) {
			MUTEX_EXIT(&ringp->lock);
			return (1);
		}

		ringp->poll_flag = B_FALSE;

		/*
		 * Enable mailbox update, to start interrupts again.
		 */
		cs.value = 0ULL;
		cs.bits.mex = 1;
		cs.bits.pktread = 0;
		cs.bits.ptrread = 0;
		RXDMA_REG_WRITE64(handle, RDC_STAT, ringp->rdc, cs.value);

		if (ldgp->nldvs == 1) {
			/*
			 * Re-arm the group, since it is the only member
			 * of the group.
			 */
			(void) hpi_intr_ldg_mgmt_set(handle, ldgp->ldg, B_TRUE,
			    ldgp->ldg_timer);
		} else {
			/*
			 * Mask-on interrupts for the device and re-arm
			 * the group.
			 */
			(void) hpi_intr_mask_set(handle, ringp->ldvp->ldv, 0);
			(void) hpi_intr_ldg_mgmt_set(handle, ldgp->ldg, B_TRUE,
			    ldgp->ldg_timer);
		}
	}
	MUTEX_EXIT(&ringp->lock);
	return (0);
}

/*
 * Poll 'bytes_to_pickup' bytes of message from the rx ring.
 */
mblk_t *
hxge_rx_poll(void *arg, int bytes_to_pickup)
{
	p_hxge_ring_handle_t	rhp = (p_hxge_ring_handle_t)arg;
	p_rx_rcr_ring_t		ring;
	p_hxge_t		hxgep;
	hpi_handle_t		handle;
	rdc_stat_t		cs;
	mblk_t			*mblk;
	p_hxge_ldv_t		ldvp;

	hxgep = rhp->hxgep;

	/*
	 * Get the control and status for this channel.
	 */
	handle = HXGE_DEV_HPI_HANDLE(hxgep);
	ring = hxgep->rx_rcr_rings->rcr_rings[rhp->index];

	MUTEX_ENTER(&ring->lock);
	ASSERT(ring->poll_flag == B_TRUE);
	ASSERT(rhp->started);

	if (!ring->poll_flag) {
		MUTEX_EXIT(&ring->lock);
		return ((mblk_t *)NULL);
	}

	/*
	 * Get the control and status bits for the ring.
	 */
	RXDMA_REG_READ64(handle, RDC_STAT, rhp->index, &cs.value);
	cs.bits.ptrread = 0;
	cs.bits.pktread = 0;
	RXDMA_REG_WRITE64(handle, RDC_STAT, rhp->index, cs.value);

	/*
	 * Process packets.
	 */
	mblk = hxge_rx_pkts(hxgep, ring->ldvp->vdma_index,
	    ring->ldvp, ring, cs, bytes_to_pickup);
	ldvp = ring->ldvp;

	/*
	 * Process Error Events.
	 */
	if (ldvp && (cs.value & RDC_STAT_ERROR)) {
		/*
		 * Recovery routines will grab the RCR ring lock.
		 */
		MUTEX_EXIT(&ring->lock);
		(void) hxge_rx_err_evnts(hxgep, ldvp->vdma_index, ldvp, cs);
		MUTEX_ENTER(&ring->lock);
	}

	MUTEX_EXIT(&ring->lock);
	return (mblk);
}

/*ARGSUSED*/
mblk_t *
hxge_rx_pkts(p_hxge_t hxgep, uint_t vindex, p_hxge_ldv_t ldvp,
    p_rx_rcr_ring_t rcrp, rdc_stat_t cs, int bytes_to_read)
{
	hpi_handle_t		handle;
	uint8_t			channel;
	uint32_t		comp_rd_index;
	p_rcr_entry_t		rcr_desc_rd_head_p;
	p_rcr_entry_t		rcr_desc_rd_head_pp;
	p_mblk_t		nmp, mp_cont, head_mp, *tail_mp;
	uint16_t		qlen, nrcr_read, npkt_read;
	uint32_t		qlen_hw, npkts, num_rcrs;
	uint32_t		invalid_rcr_entry;
	boolean_t		multi;
	rdc_stat_t		pktcs;
	rdc_rcr_cfg_b_t		rcr_cfg_b;
	uint64_t		rcr_head_index, rcr_tail_index;
	uint64_t		rcr_tail;
	rdc_rcr_tail_t		rcr_tail_reg;
	p_hxge_rx_ring_stats_t	rdc_stats;
	int			totallen = 0;

	HXGE_DEBUG_MSG((hxgep, RX_INT_CTL, "==> hxge_rx_pkts:vindex %d "
	    "channel %d", vindex, ldvp->channel));

	handle = HXGE_DEV_HPI_HANDLE(hxgep);
	channel = rcrp->rdc;
	if (channel != ldvp->channel) {
		HXGE_DEBUG_MSG((hxgep, RX_INT_CTL, "==> hxge_rx_pkts:index %d "
		    "channel %d, and rcr channel %d not matched.",
		    vindex, ldvp->channel, channel));
		return (NULL);
	}

	HXGE_DEBUG_MSG((hxgep, RX_INT_CTL,
	    "==> hxge_rx_pkts: START: rcr channel %d "
	    "head_p $%p head_pp $%p  index %d ",
	    channel, rcrp->rcr_desc_rd_head_p,
	    rcrp->rcr_desc_rd_head_pp, rcrp->comp_rd_index));

	(void) hpi_rxdma_rdc_rcr_qlen_get(handle, channel, &qlen);
	RXDMA_REG_READ64(handle, RDC_RCR_TAIL, channel, &rcr_tail_reg.value);
	rcr_tail = rcr_tail_reg.bits.tail;

	if (!qlen) {
		HXGE_DEBUG_MSG((hxgep, RX_INT_CTL,
		    "<== hxge_rx_pkts:rcr channel %d qlen %d (no pkts)",
		    channel, qlen));
		return (NULL);
	}

	HXGE_DEBUG_MSG((hxgep, RX_CTL, "==> hxge_rx_pkts:rcr channel %d "
	    "qlen %d", channel, qlen));

	comp_rd_index = rcrp->comp_rd_index;

	rcr_desc_rd_head_p = rcrp->rcr_desc_rd_head_p;
	rcr_desc_rd_head_pp = rcrp->rcr_desc_rd_head_pp;
	nrcr_read = npkt_read = 0;

	if (hxgep->rdc_first_intr[channel])
		qlen_hw = qlen;
	else
		qlen_hw = qlen - 1;

	head_mp = NULL;
	tail_mp = &head_mp;
	nmp = mp_cont = NULL;
	multi = B_FALSE;

	rcr_head_index = rcrp->rcr_desc_rd_head_p - rcrp->rcr_desc_first_p;
	rcr_tail_index = rcr_tail - rcrp->rcr_tail_begin;

	if (rcr_tail_index >= rcr_head_index) {
		num_rcrs = rcr_tail_index - rcr_head_index;
	} else {
		/* rcr_tail has wrapped around */
		num_rcrs = (rcrp->comp_size - rcr_head_index) + rcr_tail_index;
	}

	npkts = hxge_scan_for_last_eop(rcrp, rcr_desc_rd_head_p, num_rcrs);
	if (!npkts)
		return (NULL);

	if (qlen_hw > npkts) {
		HXGE_DEBUG_MSG((hxgep, RX_INT_CTL,
		    "Channel %d, rcr_qlen from reg %d and from rcr_tail %d\n",
		    channel, qlen_hw, qlen_sw));
		qlen_hw = npkts;
	}

	while (qlen_hw) {
#ifdef HXGE_DEBUG
		hxge_dump_rcr_entry(hxgep, rcr_desc_rd_head_p);
#endif
		/*
		 * Process one completion ring entry.
		 */
		invalid_rcr_entry = 0;
		hxge_receive_packet(hxgep,
		    rcrp, rcr_desc_rd_head_p, &multi, &nmp, &mp_cont,
		    &invalid_rcr_entry);
		if (invalid_rcr_entry != 0) {
			rdc_stats = rcrp->rdc_stats;
			rdc_stats->rcr_invalids++;
			HXGE_DEBUG_MSG((hxgep, RX_INT_CTL,
			    "Channel %d could only read 0x%x packets, "
			    "but 0x%x pending\n", channel, npkt_read, qlen_hw));
			break;
		}

		/*
		 * message chaining modes (nemo msg chaining)
		 */
		if (nmp) {
			nmp->b_next = NULL;
			if (!multi && !mp_cont) { /* frame fits a partition */
				*tail_mp = nmp;
				tail_mp = &nmp->b_next;
				nmp = NULL;
			} else if (multi && !mp_cont) { /* first segment */
				*tail_mp = nmp;
				tail_mp = &nmp->b_cont;
			} else if (multi && mp_cont) {	/* mid of multi segs */
				*tail_mp = mp_cont;
				tail_mp = &mp_cont->b_cont;
			} else if (!multi && mp_cont) { /* last segment */
				*tail_mp = mp_cont;
				tail_mp = &nmp->b_next;
				totallen += MBLKL(mp_cont);
				nmp = NULL;
			}
		}

		HXGE_DEBUG_MSG((hxgep, RX_INT_CTL,
		    "==> hxge_rx_pkts: loop: rcr channel %d "
		    "before updating: multi %d "
		    "nrcr_read %d "
		    "npk read %d "
		    "head_pp $%p  index %d ",
		    channel, multi,
		    nrcr_read, npkt_read, rcr_desc_rd_head_pp, comp_rd_index));

		if (!multi) {
			qlen_hw--;
			npkt_read++;
		}

		/*
		 * Update the next read entry.
		 */
		comp_rd_index = NEXT_ENTRY(comp_rd_index,
		    rcrp->comp_wrap_mask);

		rcr_desc_rd_head_p = NEXT_ENTRY_PTR(rcr_desc_rd_head_p,
		    rcrp->rcr_desc_first_p, rcrp->rcr_desc_last_p);

		nrcr_read++;

		HXGE_DEBUG_MSG((hxgep, RX_INT_CTL,
		    "<== hxge_rx_pkts: (SAM, process one packet) "
		    "nrcr_read %d", nrcr_read));
		HXGE_DEBUG_MSG((hxgep, RX_INT_CTL,
		    "==> hxge_rx_pkts: loop: rcr channel %d "
		    "multi %d nrcr_read %d npk read %d head_pp $%p  index %d ",
		    channel, multi, nrcr_read, npkt_read, rcr_desc_rd_head_pp,
		    comp_rd_index));

		if ((bytes_to_read != -1) &&
		    (totallen >= bytes_to_read)) {
			break;
		}
	}

	rcrp->rcr_desc_rd_head_pp = rcr_desc_rd_head_pp;
	rcrp->comp_rd_index = comp_rd_index;
	rcrp->rcr_desc_rd_head_p = rcr_desc_rd_head_p;

	if ((hxgep->intr_timeout != rcrp->intr_timeout) ||
	    (hxgep->intr_threshold != rcrp->intr_threshold)) {
		rcrp->intr_timeout = hxgep->intr_timeout;
		rcrp->intr_threshold = hxgep->intr_threshold;
		rcr_cfg_b.value = 0x0ULL;
		if (rcrp->intr_timeout)
			rcr_cfg_b.bits.entout = 1;
		rcr_cfg_b.bits.timeout = rcrp->intr_timeout;
		rcr_cfg_b.bits.pthres = rcrp->intr_threshold;
		RXDMA_REG_WRITE64(handle, RDC_RCR_CFG_B,
		    channel, rcr_cfg_b.value);
	}

	pktcs.value = 0;
	if (hxgep->rdc_first_intr[channel] && (npkt_read > 0)) {
		hxgep->rdc_first_intr[channel] = B_FALSE;
		pktcs.bits.pktread = npkt_read - 1;
	} else
		pktcs.bits.pktread = npkt_read;
	pktcs.bits.ptrread = nrcr_read;
	RXDMA_REG_WRITE64(handle, RDC_STAT, channel, pktcs.value);

	HXGE_DEBUG_MSG((hxgep, RX_INT_CTL,
	    "==> hxge_rx_pkts: EXIT: rcr channel %d "
	    "head_pp $%p  index %016llx ",
	    channel, rcrp->rcr_desc_rd_head_pp, rcrp->comp_rd_index));

	HXGE_DEBUG_MSG((hxgep, RX_INT_CTL, "<== hxge_rx_pkts"));
	return (head_mp);
}

#define	RCR_ENTRY_PATTERN	0x5a5a6b6b7c7c8d8dULL
#define	NO_PORT_BIT		0x20
#define	L4_CS_EQ_BIT		0x40

static uint32_t hxge_scan_for_last_eop(p_rx_rcr_ring_t rcrp,
    p_rcr_entry_t rcr_desc_rd_head_p, uint32_t num_rcrs)
{
	uint64_t	rcr_entry;
	uint32_t	rcrs = 0;
	uint32_t	pkts = 0;

	while (rcrs < num_rcrs) {
		rcr_entry = *((uint64_t *)rcr_desc_rd_head_p);

		if ((rcr_entry == 0x0) || (rcr_entry == RCR_ENTRY_PATTERN))
			break;

		if (!(rcr_entry & RCR_MULTI_MASK))
			pkts++;

		rcr_desc_rd_head_p = NEXT_ENTRY_PTR(rcr_desc_rd_head_p,
		    rcrp->rcr_desc_first_p, rcrp->rcr_desc_last_p);

		rcrs++;
	}

	return (pkts);
}

/*ARGSUSED*/
void
hxge_receive_packet(p_hxge_t hxgep, p_rx_rcr_ring_t rcr_p,
    p_rcr_entry_t rcr_desc_rd_head_p, boolean_t *multi_p, mblk_t **mp,
    mblk_t **mp_cont, uint32_t *invalid_rcr_entry)
{
	p_mblk_t nmp = NULL;
	uint64_t multi;
	uint8_t channel;
	boolean_t first_entry = B_TRUE;
	boolean_t is_tcp_udp = B_FALSE;
	boolean_t buffer_free = B_FALSE;
	boolean_t error_send_up = B_FALSE;
	uint8_t error_type;
	uint16_t l2_len;
	uint16_t skip_len;
	uint8_t pktbufsz_type;
	uint64_t rcr_entry;
	uint64_t *pkt_buf_addr_pp;
	uint64_t *pkt_buf_addr_p;
	uint32_t buf_offset;
	uint32_t bsize;
	uint32_t msg_index;
	p_rx_rbr_ring_t rx_rbr_p;
	p_rx_msg_t *rx_msg_ring_p;
	p_rx_msg_t rx_msg_p;
	uint16_t sw_offset_bytes = 0, hdr_size = 0;
	hxge_status_t status = HXGE_OK;
	boolean_t is_valid = B_FALSE;
	p_hxge_rx_ring_stats_t rdc_stats;
	uint32_t bytes_read;
	uint8_t header0 = 0;
	uint8_t header1 = 0;
	uint64_t pkt_type;
	uint8_t no_port_bit = 0;
	uint8_t l4_cs_eq_bit = 0;

	channel = rcr_p->rdc;

	HXGE_DEBUG_MSG((hxgep, RX2_CTL, "==> hxge_receive_packet"));

	first_entry = (*mp == NULL) ? B_TRUE : B_FALSE;
	rcr_entry = *((uint64_t *)rcr_desc_rd_head_p);

	/* Verify the content of the rcr_entry for a hardware bug workaround */
	if ((rcr_entry == 0x0) || (rcr_entry == RCR_ENTRY_PATTERN)) {
		*invalid_rcr_entry = 1;
		HXGE_DEBUG_MSG((hxgep, RX2_CTL, "hxge_receive_packet "
		    "Channel %d invalid RCR entry 0x%llx found, returning\n",
		    channel, (long long) rcr_entry));
		return;
	}
	*((uint64_t *)rcr_desc_rd_head_p) = RCR_ENTRY_PATTERN;

	multi = (rcr_entry & RCR_MULTI_MASK);
	pkt_type = (rcr_entry & RCR_PKT_TYPE_MASK);

	error_type = ((rcr_entry & RCR_ERROR_MASK) >> RCR_ERROR_SHIFT);
	l2_len = ((rcr_entry & RCR_L2_LEN_MASK) >> RCR_L2_LEN_SHIFT);

	/*
	 * Hardware does not strip the CRC due bug ID 11451 where
	 * the hardware mis handles minimum size packets.
	 */
	l2_len -= ETHERFCSL;

	pktbufsz_type = ((rcr_entry & RCR_PKTBUFSZ_MASK) >>
	    RCR_PKTBUFSZ_SHIFT);
#if defined(__i386)
	pkt_buf_addr_pp = (uint64_t *)(uint32_t)((rcr_entry &
	    RCR_PKT_BUF_ADDR_MASK) << RCR_PKT_BUF_ADDR_SHIFT);
#else
	pkt_buf_addr_pp = (uint64_t *)((rcr_entry & RCR_PKT_BUF_ADDR_MASK) <<
	    RCR_PKT_BUF_ADDR_SHIFT);
#endif

	HXGE_DEBUG_MSG((hxgep, RX2_CTL,
	    "==> hxge_receive_packet: entryp $%p entry 0x%0llx "
	    "pkt_buf_addr_pp $%p l2_len %d multi %d "
	    "error_type 0x%x pktbufsz_type %d ",
	    rcr_desc_rd_head_p, rcr_entry, pkt_buf_addr_pp, l2_len,
	    multi, error_type, pktbufsz_type));

	HXGE_DEBUG_MSG((hxgep, RX2_CTL,
	    "==> hxge_receive_packet: entryp $%p entry 0x%0llx "
	    "pkt_buf_addr_pp $%p l2_len %d multi %d "
	    "error_type 0x%x ", rcr_desc_rd_head_p,
	    rcr_entry, pkt_buf_addr_pp, l2_len, multi, error_type));

	HXGE_DEBUG_MSG((hxgep, RX2_CTL,
	    "==> (rbr) hxge_receive_packet: entry 0x%0llx "
	    "full pkt_buf_addr_pp $%p l2_len %d",
	    rcr_entry, pkt_buf_addr_pp, l2_len));

	/* get the stats ptr */
	rdc_stats = rcr_p->rdc_stats;

	if (!l2_len) {
		HXGE_DEBUG_MSG((hxgep, RX_CTL,
		    "<== hxge_receive_packet: failed: l2 length is 0."));
		return;
	}

	/* shift 6 bits to get the full io address */
#if defined(__i386)
	pkt_buf_addr_pp = (uint64_t *)((uint32_t)pkt_buf_addr_pp <<
	    RCR_PKT_BUF_ADDR_SHIFT_FULL);
#else
	pkt_buf_addr_pp = (uint64_t *)((uint64_t)pkt_buf_addr_pp <<
	    RCR_PKT_BUF_ADDR_SHIFT_FULL);
#endif
	HXGE_DEBUG_MSG((hxgep, RX2_CTL,
	    "==> (rbr) hxge_receive_packet: entry 0x%0llx "
	    "full pkt_buf_addr_pp $%p l2_len %d",
	    rcr_entry, pkt_buf_addr_pp, l2_len));

	rx_rbr_p = rcr_p->rx_rbr_p;
	rx_msg_ring_p = rx_rbr_p->rx_msg_ring;

	if (first_entry) {
		hdr_size = (rcr_p->full_hdr_flag ? RXDMA_HDR_SIZE_FULL :
		    RXDMA_HDR_SIZE_DEFAULT);

		HXGE_DEBUG_MSG((hxgep, RX_CTL,
		    "==> hxge_receive_packet: first entry 0x%016llx "
		    "pkt_buf_addr_pp $%p l2_len %d hdr %d",
		    rcr_entry, pkt_buf_addr_pp, l2_len, hdr_size));
	}

	MUTEX_ENTER(&rx_rbr_p->lock);

	HXGE_DEBUG_MSG((hxgep, RX_CTL,
	    "==> (rbr 1) hxge_receive_packet: entry 0x%0llx "
	    "full pkt_buf_addr_pp $%p l2_len %d",
	    rcr_entry, pkt_buf_addr_pp, l2_len));

	/*
	 * Packet buffer address in the completion entry points to the starting
	 * buffer address (offset 0). Use the starting buffer address to locate
	 * the corresponding kernel address.
	 */
	status = hxge_rxbuf_pp_to_vp(hxgep, rx_rbr_p,
	    pktbufsz_type, pkt_buf_addr_pp, &pkt_buf_addr_p,
	    &buf_offset, &msg_index);

	HXGE_DEBUG_MSG((hxgep, RX_CTL,
	    "==> (rbr 2) hxge_receive_packet: entry 0x%0llx "
	    "full pkt_buf_addr_pp $%p l2_len %d",
	    rcr_entry, pkt_buf_addr_pp, l2_len));

	if (status != HXGE_OK) {
		MUTEX_EXIT(&rx_rbr_p->lock);
		HXGE_DEBUG_MSG((hxgep, RX_CTL,
		    "<== hxge_receive_packet: found vaddr failed %d", status));
		return;
	}

	HXGE_DEBUG_MSG((hxgep, RX2_CTL,
	    "==> (rbr 3) hxge_receive_packet: entry 0x%0llx "
	    "full pkt_buf_addr_pp $%p l2_len %d",
	    rcr_entry, pkt_buf_addr_pp, l2_len));
	HXGE_DEBUG_MSG((hxgep, RX2_CTL,
	    "==> (rbr 4 msgindex %d) hxge_receive_packet: entry 0x%0llx "
	    "full pkt_buf_addr_pp $%p l2_len %d",
	    msg_index, rcr_entry, pkt_buf_addr_pp, l2_len));

	if (msg_index >= rx_rbr_p->tnblocks) {
		MUTEX_EXIT(&rx_rbr_p->lock);
		HXGE_DEBUG_MSG((hxgep, RX2_CTL,
		    "==> hxge_receive_packet: FATAL msg_index (%d) "
		    "should be smaller than tnblocks (%d)\n",
		    msg_index, rx_rbr_p->tnblocks));
		return;
	}

	rx_msg_p = rx_msg_ring_p[msg_index];

	HXGE_DEBUG_MSG((hxgep, RX2_CTL,
	    "==> (rbr 4 msgindex %d) hxge_receive_packet: entry 0x%0llx "
	    "full pkt_buf_addr_pp $%p l2_len %d",
	    msg_index, rcr_entry, pkt_buf_addr_pp, l2_len));

	switch (pktbufsz_type) {
	case RCR_PKTBUFSZ_0:
		bsize = rx_rbr_p->pkt_buf_size0_bytes;
		HXGE_DEBUG_MSG((hxgep, RX2_CTL,
		    "==> hxge_receive_packet: 0 buf %d", bsize));
		break;
	case RCR_PKTBUFSZ_1:
		bsize = rx_rbr_p->pkt_buf_size1_bytes;
		HXGE_DEBUG_MSG((hxgep, RX2_CTL,
		    "==> hxge_receive_packet: 1 buf %d", bsize));
		break;
	case RCR_PKTBUFSZ_2:
		bsize = rx_rbr_p->pkt_buf_size2_bytes;
		HXGE_DEBUG_MSG((hxgep, RX_CTL,
		    "==> hxge_receive_packet: 2 buf %d", bsize));
		break;
	case RCR_SINGLE_BLOCK:
		bsize = rx_msg_p->block_size;
		HXGE_DEBUG_MSG((hxgep, RX2_CTL,
		    "==> hxge_receive_packet: single %d", bsize));

		break;
	default:
		MUTEX_EXIT(&rx_rbr_p->lock);
		return;
	}

	DMA_COMMON_SYNC_OFFSET(rx_msg_p->buf_dma,
	    (buf_offset + sw_offset_bytes), (hdr_size + l2_len),
	    DDI_DMA_SYNC_FORCPU);

	HXGE_DEBUG_MSG((hxgep, RX2_CTL,
	    "==> hxge_receive_packet: after first dump:usage count"));

	if (rx_msg_p->cur_usage_cnt == 0) {
		atomic_inc_32(&rx_rbr_p->rbr_used);
		if (rx_rbr_p->rbr_use_bcopy) {
			atomic_inc_32(&rx_rbr_p->rbr_consumed);
			if (rx_rbr_p->rbr_consumed <
			    rx_rbr_p->rbr_threshold_hi) {
				if (rx_rbr_p->rbr_threshold_lo == 0 ||
				    ((rx_rbr_p->rbr_consumed >=
				    rx_rbr_p->rbr_threshold_lo) &&
				    (rx_rbr_p->rbr_bufsize_type >=
				    pktbufsz_type))) {
					rx_msg_p->rx_use_bcopy = B_TRUE;
				}
			} else {
				rx_msg_p->rx_use_bcopy = B_TRUE;
			}
		}
		HXGE_DEBUG_MSG((hxgep, RX2_CTL,
		    "==> hxge_receive_packet: buf %d (new block) ", bsize));

		rx_msg_p->pkt_buf_size_code = pktbufsz_type;
		rx_msg_p->pkt_buf_size = bsize;
		rx_msg_p->cur_usage_cnt = 1;
		if (pktbufsz_type == RCR_SINGLE_BLOCK) {
			HXGE_DEBUG_MSG((hxgep, RX2_CTL,
			    "==> hxge_receive_packet: buf %d (single block) ",
			    bsize));
			/*
			 * Buffer can be reused once the free function is
			 * called.
			 */
			rx_msg_p->max_usage_cnt = 1;
			buffer_free = B_TRUE;
		} else {
			rx_msg_p->max_usage_cnt = rx_msg_p->block_size / bsize;
			if (rx_msg_p->max_usage_cnt == 1) {
				buffer_free = B_TRUE;
			}
		}
	} else {
		rx_msg_p->cur_usage_cnt++;
		if (rx_msg_p->cur_usage_cnt == rx_msg_p->max_usage_cnt) {
			buffer_free = B_TRUE;
		}
	}

	HXGE_DEBUG_MSG((hxgep, RX_CTL,
	    "msgbuf index = %d l2len %d bytes usage %d max_usage %d ",
	    msg_index, l2_len,
	    rx_msg_p->cur_usage_cnt, rx_msg_p->max_usage_cnt));

	if (error_type) {
		rdc_stats->ierrors++;
		/* Update error stats */
		rdc_stats->errlog.compl_err_type = error_type;
		HXGE_FM_REPORT_ERROR(hxgep, NULL, HXGE_FM_EREPORT_RDMC_RCR_ERR);

		if (error_type & RCR_CTRL_FIFO_DED) {
			rdc_stats->ctrl_fifo_ecc_err++;
			HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
			    " hxge_receive_packet: "
			    " channel %d RCR ctrl_fifo_ded error", channel));
		} else if (error_type & RCR_DATA_FIFO_DED) {
			rdc_stats->data_fifo_ecc_err++;
			HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
			    " hxge_receive_packet: channel %d"
			    " RCR data_fifo_ded error", channel));
		}

		/*
		 * Update and repost buffer block if max usage count is
		 * reached.
		 */
		if (error_send_up == B_FALSE) {
			atomic_inc_32(&rx_msg_p->ref_cnt);
			if (buffer_free == B_TRUE) {
				rx_msg_p->free = B_TRUE;
			}

			MUTEX_EXIT(&rx_rbr_p->lock);
			hxge_freeb(rx_msg_p);
			return;
		}
	}

	HXGE_DEBUG_MSG((hxgep, RX2_CTL,
	    "==> hxge_receive_packet: DMA sync second "));

	bytes_read = rcr_p->rcvd_pkt_bytes;
	skip_len = sw_offset_bytes + hdr_size;

	if (first_entry) {
		header0 = rx_msg_p->buffer[buf_offset];
		no_port_bit = header0 & NO_PORT_BIT;
		header1 = rx_msg_p->buffer[buf_offset + 1];
		l4_cs_eq_bit = header1 & L4_CS_EQ_BIT;
	}

	if (!rx_msg_p->rx_use_bcopy) {
		/*
		 * For loaned up buffers, the driver reference count
		 * will be incremented first and then the free state.
		 */
		if ((nmp = hxge_dupb(rx_msg_p, buf_offset, bsize)) != NULL) {
			if (first_entry) {
				nmp->b_rptr = &nmp->b_rptr[skip_len];
				if (l2_len < bsize - skip_len) {
					nmp->b_wptr = &nmp->b_rptr[l2_len];
				} else {
					nmp->b_wptr = &nmp->b_rptr[bsize
					    - skip_len];
				}
			} else {
				if (l2_len - bytes_read < bsize) {
					nmp->b_wptr =
					    &nmp->b_rptr[l2_len - bytes_read];
				} else {
					nmp->b_wptr = &nmp->b_rptr[bsize];
				}
			}
		}
	} else {
		if (first_entry) {
			nmp = hxge_dupb_bcopy(rx_msg_p, buf_offset + skip_len,
			    l2_len < bsize - skip_len ?
			    l2_len : bsize - skip_len);
		} else {
			nmp = hxge_dupb_bcopy(rx_msg_p, buf_offset,
			    l2_len - bytes_read < bsize ?
			    l2_len - bytes_read : bsize);
		}
	}

	if (nmp != NULL) {
		if (first_entry)
			bytes_read  = nmp->b_wptr - nmp->b_rptr;
		else
			bytes_read += nmp->b_wptr - nmp->b_rptr;

		HXGE_DEBUG_MSG((hxgep, RX_CTL,
		    "==> hxge_receive_packet after dupb: "
		    "rbr consumed %d "
		    "pktbufsz_type %d "
		    "nmp $%p rptr $%p wptr $%p "
		    "buf_offset %d bzise %d l2_len %d skip_len %d",
		    rx_rbr_p->rbr_consumed,
		    pktbufsz_type,
		    nmp, nmp->b_rptr, nmp->b_wptr,
		    buf_offset, bsize, l2_len, skip_len));
	} else {
		cmn_err(CE_WARN, "!hxge_receive_packet: update stats (error)");

		atomic_inc_32(&rx_msg_p->ref_cnt);
		if (buffer_free == B_TRUE) {
			rx_msg_p->free = B_TRUE;
		}

		MUTEX_EXIT(&rx_rbr_p->lock);
		hxge_freeb(rx_msg_p);
		return;
	}

	if (buffer_free == B_TRUE) {
		rx_msg_p->free = B_TRUE;
	}

	/*
	 * ERROR, FRAG and PKT_TYPE are only reported in the first entry. If a
	 * packet is not fragmented and no error bit is set, then L4 checksum
	 * is OK.
	 */
	is_valid = (nmp != NULL);
	if (first_entry) {
		rdc_stats->ipackets++; /* count only 1st seg for jumbo */
		if (l2_len > (STD_FRAME_SIZE - ETHERFCSL))
			rdc_stats->jumbo_pkts++;
		rdc_stats->ibytes += skip_len + l2_len < bsize ?
		    l2_len : bsize;
	} else {
		/*
		 * Add the current portion of the packet to the kstats.
		 * The current portion of the packet is calculated by using
		 * length of the packet and the previously received portion.
		 */
		rdc_stats->ibytes += l2_len - rcr_p->rcvd_pkt_bytes < bsize ?
		    l2_len - rcr_p->rcvd_pkt_bytes : bsize;
	}

	rcr_p->rcvd_pkt_bytes = bytes_read;

	if (rx_msg_p->free && rx_msg_p->rx_use_bcopy) {
		atomic_inc_32(&rx_msg_p->ref_cnt);
		MUTEX_EXIT(&rx_rbr_p->lock);
		hxge_freeb(rx_msg_p);
	} else
		MUTEX_EXIT(&rx_rbr_p->lock);

	if (is_valid) {
		nmp->b_cont = NULL;
		if (first_entry) {
			*mp = nmp;
			*mp_cont = NULL;
		} else {
			*mp_cont = nmp;
		}
	}

	/*
	 * Update stats and hardware checksuming.
	 */
	if (is_valid && !multi) {
		is_tcp_udp = ((pkt_type == RCR_PKT_IS_TCP ||
		    pkt_type == RCR_PKT_IS_UDP) ? B_TRUE : B_FALSE);

		if (!no_port_bit && l4_cs_eq_bit && is_tcp_udp && !error_type) {
			mac_hcksum_set(nmp, 0, 0, 0, 0, HCK_FULLCKSUM_OK);

			HXGE_DEBUG_MSG((hxgep, RX_CTL,
			    "==> hxge_receive_packet: Full tcp/udp cksum "
			    "is_valid 0x%x multi %d error %d",
			    is_valid, multi, error_type));
		}
	}

	HXGE_DEBUG_MSG((hxgep, RX2_CTL,
	    "==> hxge_receive_packet: *mp 0x%016llx", *mp));

	*multi_p = (multi == RCR_MULTI_MASK);

	HXGE_DEBUG_MSG((hxgep, RX_CTL, "<== hxge_receive_packet: "
	    "multi %d nmp 0x%016llx *mp 0x%016llx *mp_cont 0x%016llx",
	    *multi_p, nmp, *mp, *mp_cont));
}

static void
hxge_rx_rbr_empty_recover(p_hxge_t hxgep, uint8_t channel)
{
	hpi_handle_t	handle;
	p_rx_rcr_ring_t	rcrp;
	p_rx_rbr_ring_t	rbrp;

	rcrp = hxgep->rx_rcr_rings->rcr_rings[channel];
	rbrp = rcrp->rx_rbr_p;
	handle = HXGE_DEV_HPI_HANDLE(hxgep);

	/*
	 * Wait for the channel to be quiet
	 */
	(void) hpi_rxdma_cfg_rdc_wait_for_qst(handle, channel);

	/*
	 * Post page will accumulate some buffers before re-enabling
	 * the DMA channel.
	 */

	MUTEX_ENTER(&rbrp->post_lock);
	if ((rbrp->rbb_max - rbrp->rbr_used) >= HXGE_RBR_EMPTY_THRESHOLD) {
		hxge_rbr_empty_restore(hxgep, rbrp);
	} else {
		rbrp->rbr_is_empty = B_TRUE;
	}
	MUTEX_EXIT(&rbrp->post_lock);
}


/*ARGSUSED*/
static hxge_status_t
hxge_rx_err_evnts(p_hxge_t hxgep, uint_t index, p_hxge_ldv_t ldvp,
    rdc_stat_t cs)
{
	p_hxge_rx_ring_stats_t	rdc_stats;
	hpi_handle_t		handle;
	boolean_t		rxchan_fatal = B_FALSE;
	uint8_t			channel;
	hxge_status_t		status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_rx_err_evnts"));

	handle = HXGE_DEV_HPI_HANDLE(hxgep);
	channel = ldvp->channel;

	rdc_stats = &hxgep->statsp->rdc_stats[ldvp->vdma_index];

	if (cs.bits.rbr_cpl_to) {
		rdc_stats->rbr_tmout++;
		HXGE_FM_REPORT_ERROR(hxgep, channel,
		    HXGE_FM_EREPORT_RDMC_RBR_CPL_TO);
		rxchan_fatal = B_TRUE;
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_rx_err_evnts(channel %d): "
		    "fatal error: rx_rbr_timeout", channel));
	}

	if ((cs.bits.rcr_shadow_par_err) || (cs.bits.rbr_prefetch_par_err)) {
		(void) hpi_rxdma_ring_perr_stat_get(handle,
		    &rdc_stats->errlog.pre_par, &rdc_stats->errlog.sha_par);
	}

	if (cs.bits.rcr_shadow_par_err) {
		rdc_stats->rcr_sha_par++;
		HXGE_FM_REPORT_ERROR(hxgep, channel,
		    HXGE_FM_EREPORT_RDMC_RCR_SHA_PAR);
		rxchan_fatal = B_TRUE;
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_rx_err_evnts(channel %d): "
		    "fatal error: rcr_shadow_par_err", channel));
	}

	if (cs.bits.rbr_prefetch_par_err) {
		rdc_stats->rbr_pre_par++;
		HXGE_FM_REPORT_ERROR(hxgep, channel,
		    HXGE_FM_EREPORT_RDMC_RBR_PRE_PAR);
		rxchan_fatal = B_TRUE;
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_rx_err_evnts(channel %d): "
		    "fatal error: rbr_prefetch_par_err", channel));
	}

	if (cs.bits.rbr_pre_empty) {
		rdc_stats->rbr_pre_empty++;
		HXGE_FM_REPORT_ERROR(hxgep, channel,
		    HXGE_FM_EREPORT_RDMC_RBR_PRE_EMPTY);
		rxchan_fatal = B_TRUE;
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_rx_err_evnts(channel %d): "
		    "fatal error: rbr_pre_empty", channel));
	}

	if (cs.bits.peu_resp_err) {
		rdc_stats->peu_resp_err++;
		HXGE_FM_REPORT_ERROR(hxgep, channel,
		    HXGE_FM_EREPORT_RDMC_PEU_RESP_ERR);
		rxchan_fatal = B_TRUE;
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_rx_err_evnts(channel %d): "
		    "fatal error: peu_resp_err", channel));
	}

	if (cs.bits.rcr_thres) {
		rdc_stats->rcr_thres++;
	}

	if (cs.bits.rcr_to) {
		rdc_stats->rcr_to++;
	}

	if (cs.bits.rcr_shadow_full) {
		rdc_stats->rcr_shadow_full++;
		HXGE_FM_REPORT_ERROR(hxgep, channel,
		    HXGE_FM_EREPORT_RDMC_RCR_SHA_FULL);
		rxchan_fatal = B_TRUE;
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_rx_err_evnts(channel %d): "
		    "fatal error: rcr_shadow_full", channel));
	}

	if (cs.bits.rcr_full) {
		rdc_stats->rcrfull++;
		HXGE_FM_REPORT_ERROR(hxgep, channel,
		    HXGE_FM_EREPORT_RDMC_RCRFULL);
		rxchan_fatal = B_TRUE;
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_rx_err_evnts(channel %d): "
		    "fatal error: rcrfull error", channel));
	}

	if (cs.bits.rbr_empty) {
		rdc_stats->rbr_empty++;
		hxge_rx_rbr_empty_recover(hxgep, channel);
	}

	if (cs.bits.rbr_full) {
		rdc_stats->rbrfull++;
		HXGE_FM_REPORT_ERROR(hxgep, channel,
		    HXGE_FM_EREPORT_RDMC_RBRFULL);
		rxchan_fatal = B_TRUE;
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_rx_err_evnts(channel %d): "
		    "fatal error: rbr_full error", channel));
	}

	if (rxchan_fatal) {
		p_rx_rcr_ring_t	rcrp;
		p_rx_rbr_ring_t rbrp;

		rcrp = hxgep->rx_rcr_rings->rcr_rings[channel];
		rbrp = rcrp->rx_rbr_p;

		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    " hxge_rx_err_evnts: fatal error on Channel #%d\n",
		    channel));

		MUTEX_ENTER(&rbrp->post_lock);
		/* This function needs to be inside the post_lock */
		status = hxge_rxdma_fatal_err_recover(hxgep, channel);
		MUTEX_EXIT(&rbrp->post_lock);
		if (status == HXGE_OK) {
			FM_SERVICE_RESTORED(hxgep);
		}
	}

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "<== hxge_rx_err_evnts"));
	return (status);
}

static hxge_status_t
hxge_map_rxdma(p_hxge_t hxgep)
{
	int			i, ndmas;
	uint16_t		channel;
	p_rx_rbr_rings_t	rx_rbr_rings;
	p_rx_rbr_ring_t		*rbr_rings;
	p_rx_rcr_rings_t	rx_rcr_rings;
	p_rx_rcr_ring_t		*rcr_rings;
	p_rx_mbox_areas_t	rx_mbox_areas_p;
	p_rx_mbox_t		*rx_mbox_p;
	p_hxge_dma_pool_t	dma_buf_poolp;
	p_hxge_dma_common_t	*dma_buf_p;
	p_hxge_dma_pool_t	dma_rbr_cntl_poolp;
	p_hxge_dma_common_t	*dma_rbr_cntl_p;
	p_hxge_dma_pool_t	dma_rcr_cntl_poolp;
	p_hxge_dma_common_t	*dma_rcr_cntl_p;
	p_hxge_dma_pool_t	dma_mbox_cntl_poolp;
	p_hxge_dma_common_t	*dma_mbox_cntl_p;
	uint32_t		*num_chunks;
	hxge_status_t		status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL, "==> hxge_map_rxdma"));

	dma_buf_poolp = hxgep->rx_buf_pool_p;
	dma_rbr_cntl_poolp = hxgep->rx_rbr_cntl_pool_p;
	dma_rcr_cntl_poolp = hxgep->rx_rcr_cntl_pool_p;
	dma_mbox_cntl_poolp = hxgep->rx_mbox_cntl_pool_p;

	if (!dma_buf_poolp->buf_allocated ||
	    !dma_rbr_cntl_poolp->buf_allocated ||
	    !dma_rcr_cntl_poolp->buf_allocated ||
	    !dma_mbox_cntl_poolp->buf_allocated) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "<== hxge_map_rxdma: buf not allocated"));
		return (HXGE_ERROR);
	}

	ndmas = dma_buf_poolp->ndmas;
	if (!ndmas) {
		HXGE_DEBUG_MSG((hxgep, RX_CTL,
		    "<== hxge_map_rxdma: no dma allocated"));
		return (HXGE_ERROR);
	}

	num_chunks = dma_buf_poolp->num_chunks;
	dma_buf_p = dma_buf_poolp->dma_buf_pool_p;
	dma_rbr_cntl_p = dma_rbr_cntl_poolp->dma_buf_pool_p;
	dma_rcr_cntl_p = dma_rcr_cntl_poolp->dma_buf_pool_p;
	dma_mbox_cntl_p = dma_mbox_cntl_poolp->dma_buf_pool_p;

	rx_rbr_rings = (p_rx_rbr_rings_t)
	    KMEM_ZALLOC(sizeof (rx_rbr_rings_t), KM_SLEEP);
	rbr_rings = (p_rx_rbr_ring_t *)KMEM_ZALLOC(
	    sizeof (p_rx_rbr_ring_t) * ndmas, KM_SLEEP);

	rx_rcr_rings = (p_rx_rcr_rings_t)
	    KMEM_ZALLOC(sizeof (rx_rcr_rings_t), KM_SLEEP);
	rcr_rings = (p_rx_rcr_ring_t *)KMEM_ZALLOC(
	    sizeof (p_rx_rcr_ring_t) * ndmas, KM_SLEEP);

	rx_mbox_areas_p = (p_rx_mbox_areas_t)
	    KMEM_ZALLOC(sizeof (rx_mbox_areas_t), KM_SLEEP);
	rx_mbox_p = (p_rx_mbox_t *)KMEM_ZALLOC(
	    sizeof (p_rx_mbox_t) * ndmas, KM_SLEEP);

	/*
	 * Timeout should be set based on the system clock divider.
	 * The following timeout value of 1 assumes that the
	 * granularity (1000) is 3 microseconds running at 300MHz.
	 */

	hxgep->intr_threshold = RXDMA_RCR_PTHRES_DEFAULT;
	hxgep->intr_timeout = RXDMA_RCR_TO_DEFAULT;

	/*
	 * Map descriptors from the buffer polls for each dam channel.
	 */
	for (i = 0; i < ndmas; i++) {
		if (((p_hxge_dma_common_t)dma_buf_p[i]) == NULL) {
			status = HXGE_ERROR;
			goto hxge_map_rxdma_fail1;
		}

		/*
		 * Set up and prepare buffer blocks, descriptors and mailbox.
		 */
		channel = ((p_hxge_dma_common_t)dma_buf_p[i])->dma_channel;
		status = hxge_map_rxdma_channel(hxgep, channel,
		    (p_hxge_dma_common_t *)&dma_buf_p[i],
		    (p_rx_rbr_ring_t *)&rbr_rings[i],
		    num_chunks[i],
		    (p_hxge_dma_common_t *)&dma_rbr_cntl_p[i],
		    (p_hxge_dma_common_t *)&dma_rcr_cntl_p[i],
		    (p_hxge_dma_common_t *)&dma_mbox_cntl_p[i],
		    (p_rx_rcr_ring_t *)&rcr_rings[i],
		    (p_rx_mbox_t *)&rx_mbox_p[i]);
		if (status != HXGE_OK) {
			goto hxge_map_rxdma_fail1;
		}
		rbr_rings[i]->index = (uint16_t)i;
		rcr_rings[i]->index = (uint16_t)i;
		rcr_rings[i]->rdc_stats = &hxgep->statsp->rdc_stats[i];
	}

	rx_rbr_rings->ndmas = rx_rcr_rings->ndmas = ndmas;
	rx_rbr_rings->rbr_rings = rbr_rings;
	hxgep->rx_rbr_rings = rx_rbr_rings;
	rx_rcr_rings->rcr_rings = rcr_rings;
	hxgep->rx_rcr_rings = rx_rcr_rings;

	rx_mbox_areas_p->rxmbox_areas = rx_mbox_p;
	hxgep->rx_mbox_areas_p = rx_mbox_areas_p;

	goto hxge_map_rxdma_exit;

hxge_map_rxdma_fail1:
	HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
	    "==> hxge_map_rxdma: unmap rbr,rcr (status 0x%x channel %d i %d)",
	    status, channel, i));
	i--;
	for (; i >= 0; i--) {
		channel = ((p_hxge_dma_common_t)dma_buf_p[i])->dma_channel;
		hxge_unmap_rxdma_channel(hxgep, channel,
		    rbr_rings[i], rcr_rings[i], rx_mbox_p[i]);
	}

	KMEM_FREE(rbr_rings, sizeof (p_rx_rbr_ring_t) * ndmas);
	KMEM_FREE(rx_rbr_rings, sizeof (rx_rbr_rings_t));
	KMEM_FREE(rcr_rings, sizeof (p_rx_rcr_ring_t) * ndmas);
	KMEM_FREE(rx_rcr_rings, sizeof (rx_rcr_rings_t));
	KMEM_FREE(rx_mbox_p, sizeof (p_rx_mbox_t) * ndmas);
	KMEM_FREE(rx_mbox_areas_p, sizeof (rx_mbox_areas_t));

hxge_map_rxdma_exit:
	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    "<== hxge_map_rxdma: (status 0x%x channel %d)", status, channel));

	return (status);
}

static void
hxge_unmap_rxdma(p_hxge_t hxgep)
{
	int			i, ndmas;
	uint16_t		channel;
	p_rx_rbr_rings_t	rx_rbr_rings;
	p_rx_rbr_ring_t		*rbr_rings;
	p_rx_rcr_rings_t	rx_rcr_rings;
	p_rx_rcr_ring_t		*rcr_rings;
	p_rx_mbox_areas_t	rx_mbox_areas_p;
	p_rx_mbox_t		*rx_mbox_p;
	p_hxge_dma_pool_t	dma_buf_poolp;
	p_hxge_dma_pool_t	dma_rbr_cntl_poolp;
	p_hxge_dma_pool_t	dma_rcr_cntl_poolp;
	p_hxge_dma_pool_t	dma_mbox_cntl_poolp;
	p_hxge_dma_common_t	*dma_buf_p;

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL, "==> hxge_unmap_rxdma"));

	dma_buf_poolp = hxgep->rx_buf_pool_p;
	dma_rbr_cntl_poolp = hxgep->rx_rbr_cntl_pool_p;
	dma_rcr_cntl_poolp = hxgep->rx_rcr_cntl_pool_p;
	dma_mbox_cntl_poolp = hxgep->rx_mbox_cntl_pool_p;

	if (!dma_buf_poolp->buf_allocated ||
	    !dma_rbr_cntl_poolp->buf_allocated ||
	    !dma_rcr_cntl_poolp->buf_allocated ||
	    !dma_mbox_cntl_poolp->buf_allocated) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "<== hxge_unmap_rxdma: NULL buf pointers"));
		return;
	}

	rx_rbr_rings = hxgep->rx_rbr_rings;
	rx_rcr_rings = hxgep->rx_rcr_rings;
	if (rx_rbr_rings == NULL || rx_rcr_rings == NULL) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "<== hxge_unmap_rxdma: NULL pointers"));
		return;
	}

	ndmas = rx_rbr_rings->ndmas;
	if (!ndmas) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "<== hxge_unmap_rxdma: no channel"));
		return;
	}

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    "==> hxge_unmap_rxdma (ndmas %d)", ndmas));

	rbr_rings = rx_rbr_rings->rbr_rings;
	rcr_rings = rx_rcr_rings->rcr_rings;
	rx_mbox_areas_p = hxgep->rx_mbox_areas_p;
	rx_mbox_p = rx_mbox_areas_p->rxmbox_areas;
	dma_buf_p = dma_buf_poolp->dma_buf_pool_p;

	for (i = 0; i < ndmas; i++) {
		channel = ((p_hxge_dma_common_t)dma_buf_p[i])->dma_channel;
		HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
		    "==> hxge_unmap_rxdma (ndmas %d) channel %d",
		    ndmas, channel));
		(void) hxge_unmap_rxdma_channel(hxgep, channel,
		    (p_rx_rbr_ring_t)rbr_rings[i],
		    (p_rx_rcr_ring_t)rcr_rings[i],
		    (p_rx_mbox_t)rx_mbox_p[i]);
	}

	KMEM_FREE(rx_rbr_rings, sizeof (rx_rbr_rings_t));
	KMEM_FREE(rbr_rings, sizeof (p_rx_rbr_ring_t) * ndmas);
	KMEM_FREE(rx_rcr_rings, sizeof (rx_rcr_rings_t));
	KMEM_FREE(rcr_rings, sizeof (p_rx_rcr_ring_t) * ndmas);
	KMEM_FREE(rx_mbox_areas_p, sizeof (rx_mbox_areas_t));
	KMEM_FREE(rx_mbox_p, sizeof (p_rx_mbox_t) * ndmas);

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL, "<== hxge_unmap_rxdma"));
}

hxge_status_t
hxge_map_rxdma_channel(p_hxge_t hxgep, uint16_t channel,
    p_hxge_dma_common_t *dma_buf_p, p_rx_rbr_ring_t *rbr_p,
    uint32_t num_chunks, p_hxge_dma_common_t *dma_rbr_cntl_p,
    p_hxge_dma_common_t *dma_rcr_cntl_p, p_hxge_dma_common_t *dma_mbox_cntl_p,
    p_rx_rcr_ring_t *rcr_p, p_rx_mbox_t *rx_mbox_p)
{
	int status = HXGE_OK;

	/*
	 * Set up and prepare buffer blocks, descriptors and mailbox.
	 */
	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    "==> hxge_map_rxdma_channel (channel %d)", channel));

	/*
	 * Receive buffer blocks
	 */
	status = hxge_map_rxdma_channel_buf_ring(hxgep, channel,
	    dma_buf_p, rbr_p, num_chunks);
	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_map_rxdma_channel (channel %d): "
		    "map buffer failed 0x%x", channel, status));
		goto hxge_map_rxdma_channel_exit;
	}

	/*
	 * Receive block ring, completion ring and mailbox.
	 */
	status = hxge_map_rxdma_channel_cfg_ring(hxgep, channel,
	    dma_rbr_cntl_p, dma_rcr_cntl_p, dma_mbox_cntl_p,
	    rbr_p, rcr_p, rx_mbox_p);
	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_map_rxdma_channel (channel %d): "
		    "map config failed 0x%x", channel, status));
		goto hxge_map_rxdma_channel_fail2;
	}
	goto hxge_map_rxdma_channel_exit;

hxge_map_rxdma_channel_fail3:
	/* Free rbr, rcr */
	HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
	    "==> hxge_map_rxdma_channel: free rbr/rcr (status 0x%x channel %d)",
	    status, channel));
	hxge_unmap_rxdma_channel_cfg_ring(hxgep, *rcr_p, *rx_mbox_p);

hxge_map_rxdma_channel_fail2:
	/* Free buffer blocks */
	HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
	    "==> hxge_map_rxdma_channel: free rx buffers"
	    "(hxgep 0x%x status 0x%x channel %d)",
	    hxgep, status, channel));
	hxge_unmap_rxdma_channel_buf_ring(hxgep, *rbr_p);

	status = HXGE_ERROR;

hxge_map_rxdma_channel_exit:
	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    "<== hxge_map_rxdma_channel: (hxgep 0x%x status 0x%x channel %d)",
	    hxgep, status, channel));

	return (status);
}

/*ARGSUSED*/
static void
hxge_unmap_rxdma_channel(p_hxge_t hxgep, uint16_t channel,
    p_rx_rbr_ring_t rbr_p, p_rx_rcr_ring_t rcr_p, p_rx_mbox_t rx_mbox_p)
{
	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    "==> hxge_unmap_rxdma_channel (channel %d)", channel));

	/*
	 * unmap receive block ring, completion ring and mailbox.
	 */
	(void) hxge_unmap_rxdma_channel_cfg_ring(hxgep, rcr_p, rx_mbox_p);

	/* unmap buffer blocks */
	(void) hxge_unmap_rxdma_channel_buf_ring(hxgep, rbr_p);

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL, "<== hxge_unmap_rxdma_channel"));
}

/*ARGSUSED*/
static hxge_status_t
hxge_map_rxdma_channel_cfg_ring(p_hxge_t hxgep, uint16_t dma_channel,
    p_hxge_dma_common_t *dma_rbr_cntl_p, p_hxge_dma_common_t *dma_rcr_cntl_p,
    p_hxge_dma_common_t *dma_mbox_cntl_p, p_rx_rbr_ring_t *rbr_p,
    p_rx_rcr_ring_t *rcr_p, p_rx_mbox_t *rx_mbox_p)
{
	p_rx_rbr_ring_t 	rbrp;
	p_rx_rcr_ring_t 	rcrp;
	p_rx_mbox_t 		mboxp;
	p_hxge_dma_common_t 	cntl_dmap;
	p_hxge_dma_common_t 	dmap;
	p_rx_msg_t 		*rx_msg_ring;
	p_rx_msg_t 		rx_msg_p;
	rdc_rbr_cfg_a_t		*rcfga_p;
	rdc_rbr_cfg_b_t		*rcfgb_p;
	rdc_rcr_cfg_a_t		*cfga_p;
	rdc_rcr_cfg_b_t		*cfgb_p;
	rdc_rx_cfg1_t		*cfig1_p;
	rdc_rx_cfg2_t		*cfig2_p;
	rdc_rbr_kick_t		*kick_p;
	uint32_t		dmaaddrp;
	uint32_t		*rbr_vaddrp;
	uint32_t		bkaddr;
	hxge_status_t		status = HXGE_OK;
	int			i;
	uint32_t 		hxge_port_rcr_size;

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    "==> hxge_map_rxdma_channel_cfg_ring"));

	cntl_dmap = *dma_rbr_cntl_p;

	/*
	 * Map in the receive block ring
	 */
	rbrp = *rbr_p;
	dmap = (p_hxge_dma_common_t)&rbrp->rbr_desc;
	hxge_setup_dma_common(dmap, cntl_dmap, rbrp->rbb_max, 4);

	/*
	 * Zero out buffer block ring descriptors.
	 */
	bzero((caddr_t)dmap->kaddrp, dmap->alength);

	rcfga_p = &(rbrp->rbr_cfga);
	rcfgb_p = &(rbrp->rbr_cfgb);
	kick_p = &(rbrp->rbr_kick);
	rcfga_p->value = 0;
	rcfgb_p->value = 0;
	kick_p->value = 0;
	rbrp->rbr_addr = dmap->dma_cookie.dmac_laddress;
	rcfga_p->value = (rbrp->rbr_addr &
	    (RBR_CFIG_A_STDADDR_MASK | RBR_CFIG_A_STDADDR_BASE_MASK));
	rcfga_p->value |= ((uint64_t)rbrp->rbb_max << RBR_CFIG_A_LEN_SHIFT);

	/* XXXX: how to choose packet buffer sizes */
	rcfgb_p->bits.bufsz0 = rbrp->pkt_buf_size0;
	rcfgb_p->bits.vld0 = 1;
	rcfgb_p->bits.bufsz1 = rbrp->pkt_buf_size1;
	rcfgb_p->bits.vld1 = 1;
	rcfgb_p->bits.bufsz2 = rbrp->pkt_buf_size2;
	rcfgb_p->bits.vld2 = 1;
	rcfgb_p->bits.bksize = hxgep->rx_bksize_code;

	/*
	 * For each buffer block, enter receive block address to the ring.
	 */
	rbr_vaddrp = (uint32_t *)dmap->kaddrp;
	rbrp->rbr_desc_vp = (uint32_t *)dmap->kaddrp;
	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    "==> hxge_map_rxdma_channel_cfg_ring: channel %d "
	    "rbr_vaddrp $%p", dma_channel, rbr_vaddrp));

	rx_msg_ring = rbrp->rx_msg_ring;
	for (i = 0; i < rbrp->tnblocks; i++) {
		rx_msg_p = rx_msg_ring[i];
		rx_msg_p->hxgep = hxgep;
		rx_msg_p->rx_rbr_p = rbrp;
		bkaddr = (uint32_t)
		    ((rx_msg_p->buf_dma.dma_cookie.dmac_laddress >>
		    RBR_BKADDR_SHIFT));
		rx_msg_p->free = B_FALSE;
		rx_msg_p->max_usage_cnt = 0xbaddcafe;

		*rbr_vaddrp++ = bkaddr;
	}

	kick_p->bits.bkadd = rbrp->rbb_max;
	rbrp->rbr_wr_index = (rbrp->rbb_max - 1);

	rbrp->rbr_rd_index = 0;

	rbrp->rbr_consumed = 0;
	rbrp->rbr_used = 0;
	rbrp->rbr_use_bcopy = B_TRUE;
	rbrp->rbr_bufsize_type = RCR_PKTBUFSZ_0;

	/*
	 * Do bcopy on packets greater than bcopy size once the lo threshold is
	 * reached. This lo threshold should be less than the hi threshold.
	 *
	 * Do bcopy on every packet once the hi threshold is reached.
	 */
	if (hxge_rx_threshold_lo >= hxge_rx_threshold_hi) {
		/* default it to use hi */
		hxge_rx_threshold_lo = hxge_rx_threshold_hi;
	}
	if (hxge_rx_buf_size_type > HXGE_RBR_TYPE2) {
		hxge_rx_buf_size_type = HXGE_RBR_TYPE2;
	}
	rbrp->rbr_bufsize_type = hxge_rx_buf_size_type;

	switch (hxge_rx_threshold_hi) {
	default:
	case HXGE_RX_COPY_NONE:
		/* Do not do bcopy at all */
		rbrp->rbr_use_bcopy = B_FALSE;
		rbrp->rbr_threshold_hi = rbrp->rbb_max;
		break;

	case HXGE_RX_COPY_1:
	case HXGE_RX_COPY_2:
	case HXGE_RX_COPY_3:
	case HXGE_RX_COPY_4:
	case HXGE_RX_COPY_5:
	case HXGE_RX_COPY_6:
	case HXGE_RX_COPY_7:
		rbrp->rbr_threshold_hi =
		    rbrp->rbb_max * (hxge_rx_threshold_hi) /
		    HXGE_RX_BCOPY_SCALE;
		break;

	case HXGE_RX_COPY_ALL:
		rbrp->rbr_threshold_hi = 0;
		break;
	}

	switch (hxge_rx_threshold_lo) {
	default:
	case HXGE_RX_COPY_NONE:
		/* Do not do bcopy at all */
		if (rbrp->rbr_use_bcopy) {
			rbrp->rbr_use_bcopy = B_FALSE;
		}
		rbrp->rbr_threshold_lo = rbrp->rbb_max;
		break;

	case HXGE_RX_COPY_1:
	case HXGE_RX_COPY_2:
	case HXGE_RX_COPY_3:
	case HXGE_RX_COPY_4:
	case HXGE_RX_COPY_5:
	case HXGE_RX_COPY_6:
	case HXGE_RX_COPY_7:
		rbrp->rbr_threshold_lo =
		    rbrp->rbb_max * (hxge_rx_threshold_lo) /
		    HXGE_RX_BCOPY_SCALE;
		break;

	case HXGE_RX_COPY_ALL:
		rbrp->rbr_threshold_lo = 0;
		break;
	}

	HXGE_DEBUG_MSG((hxgep, RX_CTL,
	    "hxge_map_rxdma_channel_cfg_ring: channel %d rbb_max %d "
	    "rbrp->rbr_bufsize_type %d rbb_threshold_hi %d "
	    "rbb_threshold_lo %d",
	    dma_channel, rbrp->rbb_max, rbrp->rbr_bufsize_type,
	    rbrp->rbr_threshold_hi, rbrp->rbr_threshold_lo));

	/* Map in the receive completion ring */
	rcrp = (p_rx_rcr_ring_t)KMEM_ZALLOC(sizeof (rx_rcr_ring_t), KM_SLEEP);
	MUTEX_INIT(&rcrp->lock, NULL, MUTEX_DRIVER,
	    (void *) hxgep->interrupt_cookie);
	rcrp->rdc = dma_channel;
	rcrp->hxgep = hxgep;

	hxge_port_rcr_size = hxgep->hxge_port_rcr_size;
	rcrp->comp_size = hxge_port_rcr_size;
	rcrp->comp_wrap_mask = hxge_port_rcr_size - 1;

	cntl_dmap = *dma_rcr_cntl_p;

	dmap = (p_hxge_dma_common_t)&rcrp->rcr_desc;
	hxge_setup_dma_common(dmap, cntl_dmap, rcrp->comp_size,
	    sizeof (rcr_entry_t));
	rcrp->comp_rd_index = 0;
	rcrp->comp_wt_index = 0;
	rcrp->rcr_desc_rd_head_p = rcrp->rcr_desc_first_p =
	    (p_rcr_entry_t)DMA_COMMON_VPTR(rcrp->rcr_desc);
#if defined(__i386)
	rcrp->rcr_desc_rd_head_pp = rcrp->rcr_desc_first_pp =
	    (p_rcr_entry_t)(uint32_t)DMA_COMMON_IOADDR(rcrp->rcr_desc);
#else
	rcrp->rcr_desc_rd_head_pp = rcrp->rcr_desc_first_pp =
	    (p_rcr_entry_t)DMA_COMMON_IOADDR(rcrp->rcr_desc);
#endif
	rcrp->rcr_desc_last_p = rcrp->rcr_desc_rd_head_p +
	    (hxge_port_rcr_size - 1);
	rcrp->rcr_desc_last_pp = rcrp->rcr_desc_rd_head_pp +
	    (hxge_port_rcr_size - 1);

	rcrp->rcr_tail_begin = DMA_COMMON_IOADDR(rcrp->rcr_desc);
	rcrp->rcr_tail_begin = (rcrp->rcr_tail_begin & 0x7ffffULL) >> 3;

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    "==> hxge_map_rxdma_channel_cfg_ring: channel %d "
	    "rbr_vaddrp $%p rcr_desc_rd_head_p $%p "
	    "rcr_desc_rd_head_pp $%p rcr_desc_rd_last_p $%p "
	    "rcr_desc_rd_last_pp $%p ",
	    dma_channel, rbr_vaddrp, rcrp->rcr_desc_rd_head_p,
	    rcrp->rcr_desc_rd_head_pp, rcrp->rcr_desc_last_p,
	    rcrp->rcr_desc_last_pp));

	/*
	 * Zero out buffer block ring descriptors.
	 */
	bzero((caddr_t)dmap->kaddrp, dmap->alength);
	rcrp->intr_timeout = hxgep->intr_timeout;
	rcrp->intr_threshold = hxgep->intr_threshold;
	rcrp->full_hdr_flag = B_FALSE;
	rcrp->sw_priv_hdr_len = 0;

	cfga_p = &(rcrp->rcr_cfga);
	cfgb_p = &(rcrp->rcr_cfgb);
	cfga_p->value = 0;
	cfgb_p->value = 0;
	rcrp->rcr_addr = dmap->dma_cookie.dmac_laddress;

	cfga_p->value = (rcrp->rcr_addr &
	    (RCRCFIG_A_STADDR_MASK | RCRCFIG_A_STADDR_BASE_MASK));

	cfga_p->value |= ((uint64_t)rcrp->comp_size << RCRCFIG_A_LEN_SHIF);

	/*
	 * Timeout should be set based on the system clock divider. The
	 * following timeout value of 1 assumes that the granularity (1000) is
	 * 3 microseconds running at 300MHz.
	 */
	cfgb_p->bits.pthres = rcrp->intr_threshold;
	cfgb_p->bits.timeout = rcrp->intr_timeout;
	cfgb_p->bits.entout = 1;

	/* Map in the mailbox */
	cntl_dmap = *dma_mbox_cntl_p;
	mboxp = (p_rx_mbox_t)KMEM_ZALLOC(sizeof (rx_mbox_t), KM_SLEEP);
	dmap = (p_hxge_dma_common_t)&mboxp->rx_mbox;
	hxge_setup_dma_common(dmap, cntl_dmap, 1, sizeof (rxdma_mailbox_t));
	cfig1_p = (rdc_rx_cfg1_t *)&mboxp->rx_cfg1;
	cfig2_p = (rdc_rx_cfg2_t *)&mboxp->rx_cfg2;
	cfig1_p->value = cfig2_p->value = 0;

	mboxp->mbox_addr = dmap->dma_cookie.dmac_laddress;
	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    "==> hxge_map_rxdma_channel_cfg_ring: "
	    "channel %d cfg1 0x%016llx cfig2 0x%016llx cookie 0x%016llx",
	    dma_channel, cfig1_p->value, cfig2_p->value,
	    mboxp->mbox_addr));

	dmaaddrp = (uint32_t)((dmap->dma_cookie.dmac_laddress >> 32) & 0xfff);
	cfig1_p->bits.mbaddr_h = dmaaddrp;

	dmaaddrp = (uint32_t)(dmap->dma_cookie.dmac_laddress & 0xffffffff);
	dmaaddrp = (uint32_t)(dmap->dma_cookie.dmac_laddress &
	    RXDMA_CFIG2_MBADDR_L_MASK);

	cfig2_p->bits.mbaddr_l = (dmaaddrp >> RXDMA_CFIG2_MBADDR_L_SHIFT);

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    "==> hxge_map_rxdma_channel_cfg_ring: channel %d damaddrp $%p "
	    "cfg1 0x%016llx cfig2 0x%016llx",
	    dma_channel, dmaaddrp, cfig1_p->value, cfig2_p->value));

	cfig2_p->bits.full_hdr = rcrp->full_hdr_flag;
	cfig2_p->bits.offset = rcrp->sw_priv_hdr_len;

	rbrp->rx_rcr_p = rcrp;
	rcrp->rx_rbr_p = rbrp;
	*rcr_p = rcrp;
	*rx_mbox_p = mboxp;

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    "<== hxge_map_rxdma_channel_cfg_ring status 0x%08x", status));
	return (status);
}

/*ARGSUSED*/
static void
hxge_unmap_rxdma_channel_cfg_ring(p_hxge_t hxgep,
    p_rx_rcr_ring_t rcr_p, p_rx_mbox_t rx_mbox_p)
{
	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    "==> hxge_unmap_rxdma_channel_cfg_ring: channel %d", rcr_p->rdc));

	MUTEX_DESTROY(&rcr_p->lock);
	KMEM_FREE(rcr_p, sizeof (rx_rcr_ring_t));
	KMEM_FREE(rx_mbox_p, sizeof (rx_mbox_t));

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    "<== hxge_unmap_rxdma_channel_cfg_ring"));
}

static hxge_status_t
hxge_map_rxdma_channel_buf_ring(p_hxge_t hxgep, uint16_t channel,
    p_hxge_dma_common_t *dma_buf_p,
    p_rx_rbr_ring_t *rbr_p, uint32_t num_chunks)
{
	p_rx_rbr_ring_t		rbrp;
	p_hxge_dma_common_t	dma_bufp, tmp_bufp;
	p_rx_msg_t		*rx_msg_ring;
	p_rx_msg_t		rx_msg_p;
	p_mblk_t		mblk_p;

	rxring_info_t *ring_info;
	hxge_status_t status = HXGE_OK;
	int i, j, index;
	uint32_t size, bsize, nblocks, nmsgs;

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    "==> hxge_map_rxdma_channel_buf_ring: channel %d", channel));

	dma_bufp = tmp_bufp = *dma_buf_p;
	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    " hxge_map_rxdma_channel_buf_ring: channel %d to map %d "
	    "chunks bufp 0x%016llx", channel, num_chunks, dma_bufp));

	nmsgs = 0;
	for (i = 0; i < num_chunks; i++, tmp_bufp++) {
		HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
		    "==> hxge_map_rxdma_channel_buf_ring: channel %d "
		    "bufp 0x%016llx nblocks %d nmsgs %d",
		    channel, tmp_bufp, tmp_bufp->nblocks, nmsgs));
		nmsgs += tmp_bufp->nblocks;
	}
	if (!nmsgs) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "<== hxge_map_rxdma_channel_buf_ring: channel %d "
		    "no msg blocks", channel));
		status = HXGE_ERROR;
		goto hxge_map_rxdma_channel_buf_ring_exit;
	}
	rbrp = (p_rx_rbr_ring_t)KMEM_ZALLOC(sizeof (rx_rbr_ring_t), KM_SLEEP);

	size = nmsgs * sizeof (p_rx_msg_t);
	rx_msg_ring = KMEM_ZALLOC(size, KM_SLEEP);
	ring_info = (rxring_info_t *)KMEM_ZALLOC(sizeof (rxring_info_t),
	    KM_SLEEP);

	MUTEX_INIT(&rbrp->lock, NULL, MUTEX_DRIVER,
	    (void *) hxgep->interrupt_cookie);
	MUTEX_INIT(&rbrp->post_lock, NULL, MUTEX_DRIVER,
	    (void *) hxgep->interrupt_cookie);

	rbrp->rdc = channel;
	rbrp->num_blocks = num_chunks;
	rbrp->tnblocks = nmsgs;
	rbrp->rbb_max = nmsgs;
	rbrp->rbr_max_size = nmsgs;
	rbrp->rbr_wrap_mask = (rbrp->rbb_max - 1);

	/*
	 * Buffer sizes: 256, 1K, and 2K.
	 *
	 * Blk 0 size.
	 */
	rbrp->pkt_buf_size0 = RBR_BUFSZ0_256B;
	rbrp->pkt_buf_size0_bytes = RBR_BUFSZ0_256_BYTES;
	rbrp->hpi_pkt_buf_size0 = SIZE_256B;

	/*
	 * Blk 1 size.
	 */
	rbrp->pkt_buf_size1 = RBR_BUFSZ1_1K;
	rbrp->pkt_buf_size1_bytes = RBR_BUFSZ1_1K_BYTES;
	rbrp->hpi_pkt_buf_size1 = SIZE_1KB;

	/*
	 * Blk 2 size.
	 */
	rbrp->pkt_buf_size2 = RBR_BUFSZ2_2K;
	rbrp->pkt_buf_size2_bytes = RBR_BUFSZ2_2K_BYTES;
	rbrp->hpi_pkt_buf_size2 = SIZE_2KB;

	rbrp->block_size = hxgep->rx_default_block_size;

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    "==> hxge_map_rxdma_channel_buf_ring: channel %d "
	    "actual rbr max %d rbb_max %d nmsgs %d "
	    "rbrp->block_size %d default_block_size %d "
	    "(config hxge_rbr_size %d hxge_rbr_spare_size %d)",
	    channel, rbrp->rbr_max_size, rbrp->rbb_max, nmsgs,
	    rbrp->block_size, hxgep->rx_default_block_size,
	    hxge_rbr_size, hxge_rbr_spare_size));

	/*
	 * Map in buffers from the buffer pool.
	 * Note that num_blocks is the num_chunks. For Sparc, there is likely
	 * only one chunk. For x86, there will be many chunks.
	 * Loop over chunks.
	 */
	index = 0;
	for (i = 0; i < rbrp->num_blocks; i++, dma_bufp++) {
		bsize = dma_bufp->block_size;
		nblocks = dma_bufp->nblocks;
#if defined(__i386)
		ring_info->buffer[i].dvma_addr = (uint32_t)dma_bufp->ioaddr_pp;
#else
		ring_info->buffer[i].dvma_addr = (uint64_t)dma_bufp->ioaddr_pp;
#endif
		ring_info->buffer[i].buf_index = i;
		ring_info->buffer[i].buf_size = dma_bufp->alength;
		ring_info->buffer[i].start_index = index;
#if defined(__i386)
		ring_info->buffer[i].kaddr = (uint32_t)dma_bufp->kaddrp;
#else
		ring_info->buffer[i].kaddr = (uint64_t)dma_bufp->kaddrp;
#endif

		HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
		    " hxge_map_rxdma_channel_buf_ring: map channel %d "
		    "chunk %d nblocks %d chunk_size %x block_size 0x%x "
		    "dma_bufp $%p dvma_addr $%p", channel, i,
		    dma_bufp->nblocks,
		    ring_info->buffer[i].buf_size, bsize, dma_bufp,
		    ring_info->buffer[i].dvma_addr));

		/* loop over blocks within a chunk */
		for (j = 0; j < nblocks; j++) {
			if ((rx_msg_p = hxge_allocb(bsize, BPRI_LO,
			    dma_bufp)) == NULL) {
				HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
				    "allocb failed (index %d i %d j %d)",
				    index, i, j));
				goto hxge_map_rxdma_channel_buf_ring_fail1;
			}
			rx_msg_ring[index] = rx_msg_p;
			rx_msg_p->block_index = index;
			rx_msg_p->shifted_addr = (uint32_t)
			    ((rx_msg_p->buf_dma.dma_cookie.dmac_laddress >>
			    RBR_BKADDR_SHIFT));
			/*
			 * Too much output
			 * HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
			 *	"index %d j %d rx_msg_p $%p mblk %p",
			 *	index, j, rx_msg_p, rx_msg_p->rx_mblk_p));
			 */
			mblk_p = rx_msg_p->rx_mblk_p;
			mblk_p->b_wptr = mblk_p->b_rptr + bsize;

			rbrp->rbr_ref_cnt++;
			index++;
			rx_msg_p->buf_dma.dma_channel = channel;
		}
	}
	if (i < rbrp->num_blocks) {
		goto hxge_map_rxdma_channel_buf_ring_fail1;
	}
	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    "hxge_map_rxdma_channel_buf_ring: done buf init "
	    "channel %d msg block entries %d", channel, index));
	ring_info->block_size_mask = bsize - 1;
	rbrp->rx_msg_ring = rx_msg_ring;
	rbrp->dma_bufp = dma_buf_p;
	rbrp->ring_info = ring_info;

	status = hxge_rxbuf_index_info_init(hxgep, rbrp);
	HXGE_DEBUG_MSG((hxgep, MEM2_CTL, " hxge_map_rxdma_channel_buf_ring: "
	    "channel %d done buf info init", channel));

	/*
	 * Finally, permit hxge_freeb() to call hxge_post_page().
	 */
	rbrp->rbr_state = RBR_POSTING;

	*rbr_p = rbrp;

	goto hxge_map_rxdma_channel_buf_ring_exit;

hxge_map_rxdma_channel_buf_ring_fail1:
	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    " hxge_map_rxdma_channel_buf_ring: failed channel (0x%x)",
	    channel, status));

	index--;
	for (; index >= 0; index--) {
		rx_msg_p = rx_msg_ring[index];
		if (rx_msg_p != NULL) {
			freeb(rx_msg_p->rx_mblk_p);
			rx_msg_ring[index] = NULL;
		}
	}

hxge_map_rxdma_channel_buf_ring_fail:
	MUTEX_DESTROY(&rbrp->post_lock);
	MUTEX_DESTROY(&rbrp->lock);
	KMEM_FREE(ring_info, sizeof (rxring_info_t));
	KMEM_FREE(rx_msg_ring, size);
	KMEM_FREE(rbrp, sizeof (rx_rbr_ring_t));

	status = HXGE_ERROR;

hxge_map_rxdma_channel_buf_ring_exit:
	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    "<== hxge_map_rxdma_channel_buf_ring status 0x%08x", status));

	return (status);
}

/*ARGSUSED*/
static void
hxge_unmap_rxdma_channel_buf_ring(p_hxge_t hxgep,
    p_rx_rbr_ring_t rbr_p)
{
	p_rx_msg_t	*rx_msg_ring;
	p_rx_msg_t	rx_msg_p;
	rxring_info_t	*ring_info;
	int		i;
	uint32_t	size;

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    "==> hxge_unmap_rxdma_channel_buf_ring"));
	if (rbr_p == NULL) {
		HXGE_DEBUG_MSG((hxgep, RX_CTL,
		    "<== hxge_unmap_rxdma_channel_buf_ring: NULL rbrp"));
		return;
	}
	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    "==> hxge_unmap_rxdma_channel_buf_ring: channel %d", rbr_p->rdc));

	rx_msg_ring = rbr_p->rx_msg_ring;
	ring_info = rbr_p->ring_info;

	if (rx_msg_ring == NULL || ring_info == NULL) {
		HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
		    "<== hxge_unmap_rxdma_channel_buf_ring: "
		    "rx_msg_ring $%p ring_info $%p", rx_msg_p, ring_info));
		return;
	}

	size = rbr_p->tnblocks * sizeof (p_rx_msg_t);
	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    " hxge_unmap_rxdma_channel_buf_ring: channel %d chunks %d "
	    "tnblocks %d (max %d) size ptrs %d ", rbr_p->rdc, rbr_p->num_blocks,
	    rbr_p->tnblocks, rbr_p->rbr_max_size, size));

	for (i = 0; i < rbr_p->tnblocks; i++) {
		rx_msg_p = rx_msg_ring[i];
		HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
		    " hxge_unmap_rxdma_channel_buf_ring: "
		    "rx_msg_p $%p", rx_msg_p));
		if (rx_msg_p != NULL) {
			freeb(rx_msg_p->rx_mblk_p);
			rx_msg_ring[i] = NULL;
		}
	}

	/*
	 * We no longer may use the mutex <post_lock>. By setting
	 * <rbr_state> to anything but POSTING, we prevent
	 * hxge_post_page() from accessing a dead mutex.
	 */
	rbr_p->rbr_state = RBR_UNMAPPING;
	MUTEX_DESTROY(&rbr_p->post_lock);

	MUTEX_DESTROY(&rbr_p->lock);
	KMEM_FREE(ring_info, sizeof (rxring_info_t));
	KMEM_FREE(rx_msg_ring, size);

	if (rbr_p->rbr_ref_cnt == 0) {
		/* This is the normal state of affairs. */
		KMEM_FREE(rbr_p, sizeof (*rbr_p));
	} else {
		/*
		 * Some of our buffers are still being used.
		 * Therefore, tell hxge_freeb() this ring is
		 * unmapped, so it may free <rbr_p> for us.
		 */
		rbr_p->rbr_state = RBR_UNMAPPED;
		HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
		    "unmap_rxdma_buf_ring: %d %s outstanding.",
		    rbr_p->rbr_ref_cnt,
		    rbr_p->rbr_ref_cnt == 1 ? "msg" : "msgs"));
	}

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    "<== hxge_unmap_rxdma_channel_buf_ring"));
}

static hxge_status_t
hxge_rxdma_hw_start_common(p_hxge_t hxgep)
{
	hxge_status_t status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL, "==> hxge_rxdma_hw_start_common"));

	/*
	 * Load the sharable parameters by writing to the function zero control
	 * registers. These FZC registers should be initialized only once for
	 * the entire chip.
	 */
	(void) hxge_init_fzc_rx_common(hxgep);

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL, "==> hxge_rxdma_hw_start_common"));

	return (status);
}

static hxge_status_t
hxge_rxdma_hw_start(p_hxge_t hxgep)
{
	int			i, ndmas;
	uint16_t		channel;
	p_rx_rbr_rings_t	rx_rbr_rings;
	p_rx_rbr_ring_t		*rbr_rings;
	p_rx_rcr_rings_t	rx_rcr_rings;
	p_rx_rcr_ring_t		*rcr_rings;
	p_rx_mbox_areas_t	rx_mbox_areas_p;
	p_rx_mbox_t		*rx_mbox_p;
	hxge_status_t		status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL, "==> hxge_rxdma_hw_start"));

	rx_rbr_rings = hxgep->rx_rbr_rings;
	rx_rcr_rings = hxgep->rx_rcr_rings;
	if (rx_rbr_rings == NULL || rx_rcr_rings == NULL) {
		HXGE_DEBUG_MSG((hxgep, RX_CTL,
		    "<== hxge_rxdma_hw_start: NULL ring pointers"));
		return (HXGE_ERROR);
	}

	ndmas = rx_rbr_rings->ndmas;
	if (ndmas == 0) {
		HXGE_DEBUG_MSG((hxgep, RX_CTL,
		    "<== hxge_rxdma_hw_start: no dma channel allocated"));
		return (HXGE_ERROR);
	}
	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    "==> hxge_rxdma_hw_start (ndmas %d)", ndmas));

	/*
	 * Scrub the RDC Rx DMA Prefetch Buffer Command.
	 */
	for (i = 0; i < 128; i++) {
		HXGE_REG_WR64(hxgep->hpi_handle, RDC_PREF_CMD, i);
	}

	/*
	 * Scrub Rx DMA Shadow Tail Command.
	 */
	for (i = 0; i < 64; i++) {
		HXGE_REG_WR64(hxgep->hpi_handle, RDC_SHADOW_CMD, i);
	}

	/*
	 * Scrub Rx DMA Control Fifo Command.
	 */
	for (i = 0; i < 512; i++) {
		HXGE_REG_WR64(hxgep->hpi_handle, RDC_CTRL_FIFO_CMD, i);
	}

	/*
	 * Scrub Rx DMA Data Fifo Command.
	 */
	for (i = 0; i < 1536; i++) {
		HXGE_REG_WR64(hxgep->hpi_handle, RDC_DATA_FIFO_CMD, i);
	}

	/*
	 * Reset the FIFO Error Stat.
	 */
	HXGE_REG_WR64(hxgep->hpi_handle, RDC_FIFO_ERR_STAT, 0xFF);

	/* Set the error mask to receive interrupts */
	HXGE_REG_WR64(hxgep->hpi_handle, RDC_FIFO_ERR_INT_MASK, 0x0);

	rbr_rings = rx_rbr_rings->rbr_rings;
	rcr_rings = rx_rcr_rings->rcr_rings;
	rx_mbox_areas_p = hxgep->rx_mbox_areas_p;
	if (rx_mbox_areas_p) {
		rx_mbox_p = rx_mbox_areas_p->rxmbox_areas;
	}

	for (i = 0; i < ndmas; i++) {
		channel = rbr_rings[i]->rdc;
		HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
		    "==> hxge_rxdma_hw_start (ndmas %d) channel %d",
		    ndmas, channel));
		status = hxge_rxdma_start_channel(hxgep, channel,
		    (p_rx_rbr_ring_t)rbr_rings[i],
		    (p_rx_rcr_ring_t)rcr_rings[i],
		    (p_rx_mbox_t)rx_mbox_p[i], rbr_rings[i]->rbb_max);
		if (status != HXGE_OK) {
			goto hxge_rxdma_hw_start_fail1;
		}
	}

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL, "==> hxge_rxdma_hw_start: "
	    "rx_rbr_rings 0x%016llx rings 0x%016llx",
	    rx_rbr_rings, rx_rcr_rings));
	goto hxge_rxdma_hw_start_exit;

hxge_rxdma_hw_start_fail1:
	HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
	    "==> hxge_rxdma_hw_start: disable "
	    "(status 0x%x channel %d i %d)", status, channel, i));
	for (; i >= 0; i--) {
		channel = rbr_rings[i]->rdc;
		(void) hxge_rxdma_stop_channel(hxgep, channel);
	}

hxge_rxdma_hw_start_exit:
	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    "==> hxge_rxdma_hw_start: (status 0x%x)", status));
	return (status);
}

static void
hxge_rxdma_hw_stop(p_hxge_t hxgep)
{
	int			i, ndmas;
	uint16_t		channel;
	p_rx_rbr_rings_t	rx_rbr_rings;
	p_rx_rbr_ring_t		*rbr_rings;
	p_rx_rcr_rings_t	rx_rcr_rings;

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL, "==> hxge_rxdma_hw_stop"));

	rx_rbr_rings = hxgep->rx_rbr_rings;
	rx_rcr_rings = hxgep->rx_rcr_rings;

	if (rx_rbr_rings == NULL || rx_rcr_rings == NULL) {
		HXGE_DEBUG_MSG((hxgep, RX_CTL,
		    "<== hxge_rxdma_hw_stop: NULL ring pointers"));
		return;
	}

	ndmas = rx_rbr_rings->ndmas;
	if (!ndmas) {
		HXGE_DEBUG_MSG((hxgep, RX_CTL,
		    "<== hxge_rxdma_hw_stop: no dma channel allocated"));
		return;
	}

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    "==> hxge_rxdma_hw_stop (ndmas %d)", ndmas));

	rbr_rings = rx_rbr_rings->rbr_rings;
	for (i = 0; i < ndmas; i++) {
		channel = rbr_rings[i]->rdc;
		HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
		    "==> hxge_rxdma_hw_stop (ndmas %d) channel %d",
		    ndmas, channel));
		(void) hxge_rxdma_stop_channel(hxgep, channel);
	}

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL, "==> hxge_rxdma_hw_stop: "
	    "rx_rbr_rings 0x%016llx rings 0x%016llx",
	    rx_rbr_rings, rx_rcr_rings));

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL, "<== hxge_rxdma_hw_stop"));
}

static hxge_status_t
hxge_rxdma_start_channel(p_hxge_t hxgep, uint16_t channel,
    p_rx_rbr_ring_t rbr_p, p_rx_rcr_ring_t rcr_p, p_rx_mbox_t mbox_p,
    int n_init_kick)
{
	hpi_handle_t		handle;
	hpi_status_t		rs = HPI_SUCCESS;
	rdc_stat_t		cs;
	rdc_int_mask_t		ent_mask;
	hxge_status_t		status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL, "==> hxge_rxdma_start_channel"));

	handle = HXGE_DEV_HPI_HANDLE(hxgep);

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL, "hxge_rxdma_start_channel: "
	    "hpi handle addr $%p acc $%p",
	    hxgep->hpi_handle.regp, hxgep->hpi_handle.regh));

	/* Reset RXDMA channel */
	rs = hpi_rxdma_cfg_rdc_reset(handle, channel);
	if (rs != HPI_SUCCESS) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_rxdma_start_channel: "
		    "reset rxdma failed (0x%08x channel %d)",
		    status, channel));
		return (HXGE_ERROR | rs);
	}
	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    "==> hxge_rxdma_start_channel: reset done: channel %d", channel));

	/*
	 * Initialize the RXDMA channel specific FZC control configurations.
	 * These FZC registers are pertaining to each RX channel (logical
	 * pages).
	 */
	status = hxge_init_fzc_rxdma_channel(hxgep,
	    channel, rbr_p, rcr_p, mbox_p);
	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_rxdma_start_channel: "
		    "init fzc rxdma failed (0x%08x channel %d)",
		    status, channel));
		return (status);
	}
	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    "==> hxge_rxdma_start_channel: fzc done"));

	/*
	 * Zero out the shadow  and prefetch ram.
	 */
	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    "==> hxge_rxdma_start_channel: ram done"));

	/* Set up the interrupt event masks. */
	ent_mask.value = 0;
	rs = hpi_rxdma_event_mask(handle, OP_SET, channel, &ent_mask);
	if (rs != HPI_SUCCESS) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_rxdma_start_channel: "
		    "init rxdma event masks failed (0x%08x channel %d)",
		    status, channel));
		return (HXGE_ERROR | rs);
	}
	HXGE_DEBUG_MSG((hxgep, MEM2_CTL, "==> hxge_rxdma_start_channel: "
	    "event done: channel %d (mask 0x%016llx)",
	    channel, ent_mask.value));

	/*
	 * Load RXDMA descriptors, buffers, mailbox, initialise the receive DMA
	 * channels and enable each DMA channel.
	 */
	status = hxge_enable_rxdma_channel(hxgep,
	    channel, rbr_p, rcr_p, mbox_p, n_init_kick);
	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    " hxge_rxdma_start_channel: "
		    " init enable rxdma failed (0x%08x channel %d)",
		    status, channel));
		return (status);
	}

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL, "==> hxge_rxdma_start_channel: "
	    "control done - channel %d cs 0x%016llx", channel, cs.value));

	/*
	 * Initialize the receive DMA control and status register
	 * Note that rdc_stat HAS to be set after RBR and RCR rings are set
	 */
	cs.value = 0;
	cs.bits.mex = 1;
	cs.bits.rcr_thres = 1;
	cs.bits.rcr_to = 1;
	cs.bits.rbr_empty = 1;
	status = hxge_init_rxdma_channel_cntl_stat(hxgep, channel, &cs);
	HXGE_DEBUG_MSG((hxgep, MEM2_CTL, "==> hxge_rxdma_start_channel: "
	    "channel %d rx_dma_cntl_stat 0x%0016llx", channel, cs.value));
	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_rxdma_start_channel: "
		    "init rxdma control register failed (0x%08x channel %d",
		    status, channel));
		return (status);
	}

	HXGE_DEBUG_MSG((hxgep, MEM2_CTL, "==> hxge_rxdma_start_channel: "
	    "control done - channel %d cs 0x%016llx", channel, cs.value));
	HXGE_DEBUG_MSG((hxgep, MEM2_CTL,
	    "==> hxge_rxdma_start_channel: enable done"));
	HXGE_DEBUG_MSG((hxgep, MEM2_CTL, "<== hxge_rxdma_start_channel"));
	return (HXGE_OK);
}

static hxge_status_t
hxge_rxdma_stop_channel(p_hxge_t hxgep, uint16_t channel)
{
	hpi_handle_t		handle;
	hpi_status_t		rs = HPI_SUCCESS;
	rdc_stat_t		cs;
	rdc_int_mask_t		ent_mask;
	hxge_status_t		status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, RX_CTL, "==> hxge_rxdma_stop_channel"));

	handle = HXGE_DEV_HPI_HANDLE(hxgep);

	HXGE_DEBUG_MSG((hxgep, RX_CTL, "hxge_rxdma_stop_channel: "
	    "hpi handle addr $%p acc $%p",
	    hxgep->hpi_handle.regp, hxgep->hpi_handle.regh));

	/* Reset RXDMA channel */
	rs = hpi_rxdma_cfg_rdc_reset(handle, channel);
	if (rs != HPI_SUCCESS) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    " hxge_rxdma_stop_channel: "
		    " reset rxdma failed (0x%08x channel %d)",
		    rs, channel));
		return (HXGE_ERROR | rs);
	}
	HXGE_DEBUG_MSG((hxgep, RX_CTL,
	    "==> hxge_rxdma_stop_channel: reset done"));

	/* Set up the interrupt event masks. */
	ent_mask.value = RDC_INT_MASK_ALL;
	rs = hpi_rxdma_event_mask(handle, OP_SET, channel, &ent_mask);
	if (rs != HPI_SUCCESS) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_rxdma_stop_channel: "
		    "set rxdma event masks failed (0x%08x channel %d)",
		    rs, channel));
		return (HXGE_ERROR | rs);
	}
	HXGE_DEBUG_MSG((hxgep, RX_CTL,
	    "==> hxge_rxdma_stop_channel: event done"));

	/* Initialize the receive DMA control and status register */
	cs.value = 0;
	status = hxge_init_rxdma_channel_cntl_stat(hxgep, channel, &cs);

	HXGE_DEBUG_MSG((hxgep, RX_CTL, "==> hxge_rxdma_stop_channel: control "
	    " to default (all 0s) 0x%08x", cs.value));

	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    " hxge_rxdma_stop_channel: init rxdma"
		    " control register failed (0x%08x channel %d",
		    status, channel));
		return (status);
	}

	HXGE_DEBUG_MSG((hxgep, RX_CTL,
	    "==> hxge_rxdma_stop_channel: control done"));

	/* disable dma channel */
	status = hxge_disable_rxdma_channel(hxgep, channel);

	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    " hxge_rxdma_stop_channel: "
		    " init enable rxdma failed (0x%08x channel %d)",
		    status, channel));
		return (status);
	}

	HXGE_DEBUG_MSG((hxgep, RX_CTL,
	    "==> hxge_rxdma_stop_channel: disable done"));
	HXGE_DEBUG_MSG((hxgep, RX_CTL, "<== hxge_rxdma_stop_channel"));

	return (HXGE_OK);
}

hxge_status_t
hxge_rxdma_handle_sys_errors(p_hxge_t hxgep)
{
	hpi_handle_t		handle;
	p_hxge_rdc_sys_stats_t	statsp;
	rdc_fifo_err_stat_t	stat;
	hxge_status_t		status = HXGE_OK;

	handle = hxgep->hpi_handle;
	statsp = (p_hxge_rdc_sys_stats_t)&hxgep->statsp->rdc_sys_stats;

	/* Get the error status and clear the register */
	HXGE_REG_RD64(handle, RDC_FIFO_ERR_STAT, &stat.value);
	HXGE_REG_WR64(handle, RDC_FIFO_ERR_STAT, stat.value);

	if (stat.bits.rx_ctrl_fifo_sec) {
		statsp->ctrl_fifo_sec++;
		if (statsp->ctrl_fifo_sec == 1)
			HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
			    "==> hxge_rxdma_handle_sys_errors: "
			    "rx_ctrl_fifo_sec"));
	}

	if (stat.bits.rx_ctrl_fifo_ded) {
		/* Global fatal error encountered */
		statsp->ctrl_fifo_ded++;
		HXGE_FM_REPORT_ERROR(hxgep, NULL,
		    HXGE_FM_EREPORT_RDMC_CTRL_FIFO_DED);
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_rxdma_handle_sys_errors: "
		    "fatal error: rx_ctrl_fifo_ded error"));
	}

	if (stat.bits.rx_data_fifo_sec) {
		statsp->data_fifo_sec++;
		if (statsp->data_fifo_sec == 1)
			HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
			    "==> hxge_rxdma_handle_sys_errors: "
			    "rx_data_fifo_sec"));
	}

	if (stat.bits.rx_data_fifo_ded) {
		/* Global fatal error encountered */
		statsp->data_fifo_ded++;
		HXGE_FM_REPORT_ERROR(hxgep, NULL,
		    HXGE_FM_EREPORT_RDMC_DATA_FIFO_DED);
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_rxdma_handle_sys_errors: "
		    "fatal error: rx_data_fifo_ded error"));
	}

	if (stat.bits.rx_ctrl_fifo_ded || stat.bits.rx_data_fifo_ded) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    " hxge_rxdma_handle_sys_errors: fatal error\n"));
		status = hxge_rx_port_fatal_err_recover(hxgep);
		if (status == HXGE_OK) {
			FM_SERVICE_RESTORED(hxgep);
		}
	}

	return (HXGE_OK);
}

static hxge_status_t
hxge_rxdma_fatal_err_recover(p_hxge_t hxgep, uint16_t channel)
{
	hpi_handle_t		handle;
	hpi_status_t 		rs = HPI_SUCCESS;
	p_rx_rbr_ring_t		rbrp;
	p_rx_rcr_ring_t		rcrp;
	p_rx_mbox_t		mboxp;
	rdc_int_mask_t		ent_mask;
	p_hxge_dma_common_t	dmap;
	p_rx_msg_t		rx_msg_p;
	int			i;
	uint32_t		hxge_port_rcr_size;
	uint64_t		tmp;
	int			n_init_kick = 0;

	HXGE_DEBUG_MSG((hxgep, RX_CTL, "==> hxge_rxdma_fatal_err_recover"));

	/*
	 * Stop the dma channel waits for the stop done. If the stop done bit
	 * is not set, then create an error.
	 */

	handle = HXGE_DEV_HPI_HANDLE(hxgep);

	HXGE_DEBUG_MSG((hxgep, RX_CTL, "Rx DMA stop..."));

	rbrp = (p_rx_rbr_ring_t)hxgep->rx_rbr_rings->rbr_rings[channel];
	rcrp = (p_rx_rcr_ring_t)hxgep->rx_rcr_rings->rcr_rings[channel];

	MUTEX_ENTER(&rcrp->lock);
	MUTEX_ENTER(&rbrp->lock);

	HXGE_DEBUG_MSG((hxgep, RX_CTL, "Disable RxDMA channel..."));

	rs = hpi_rxdma_cfg_rdc_disable(handle, channel);
	if (rs != HPI_SUCCESS) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "hxge_disable_rxdma_channel:failed"));
		goto fail;
	}
	HXGE_DEBUG_MSG((hxgep, RX_CTL, "Disable RxDMA interrupt..."));

	/* Disable interrupt */
	ent_mask.value = RDC_INT_MASK_ALL;
	rs = hpi_rxdma_event_mask(handle, OP_SET, channel, &ent_mask);
	if (rs != HPI_SUCCESS) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "Set rxdma event masks failed (channel %d)", channel));
	}
	HXGE_DEBUG_MSG((hxgep, RX_CTL, "RxDMA channel reset..."));

	/* Reset RXDMA channel */
	rs = hpi_rxdma_cfg_rdc_reset(handle, channel);
	if (rs != HPI_SUCCESS) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "Reset rxdma failed (channel %d)", channel));
		goto fail;
	}
	hxge_port_rcr_size = hxgep->hxge_port_rcr_size;
	mboxp = (p_rx_mbox_t)hxgep->rx_mbox_areas_p->rxmbox_areas[channel];

	rbrp->rbr_wr_index = (rbrp->rbb_max - 1);
	rbrp->rbr_rd_index = 0;

	rcrp->comp_rd_index = 0;
	rcrp->comp_wt_index = 0;
	rcrp->rcr_desc_rd_head_p = rcrp->rcr_desc_first_p =
	    (p_rcr_entry_t)DMA_COMMON_VPTR(rcrp->rcr_desc);
#if defined(__i386)
	rcrp->rcr_desc_rd_head_pp = rcrp->rcr_desc_first_pp =
	    (p_rcr_entry_t)(uint32_t)DMA_COMMON_IOADDR(rcrp->rcr_desc);
#else
	rcrp->rcr_desc_rd_head_pp = rcrp->rcr_desc_first_pp =
	    (p_rcr_entry_t)DMA_COMMON_IOADDR(rcrp->rcr_desc);
#endif

	rcrp->rcr_desc_last_p = rcrp->rcr_desc_rd_head_p +
	    (hxge_port_rcr_size - 1);
	rcrp->rcr_desc_last_pp = rcrp->rcr_desc_rd_head_pp +
	    (hxge_port_rcr_size - 1);

	rcrp->rcr_tail_begin = DMA_COMMON_IOADDR(rcrp->rcr_desc);
	rcrp->rcr_tail_begin = (rcrp->rcr_tail_begin & 0x7ffffULL) >> 3;

	dmap = (p_hxge_dma_common_t)&rcrp->rcr_desc;
	bzero((caddr_t)dmap->kaddrp, dmap->alength);

	HXGE_DEBUG_MSG((hxgep, RX_CTL, "rbr entries = %d\n",
	    rbrp->rbr_max_size));

	/* Count the number of buffers owned by the hardware at this moment */
	for (i = 0; i < rbrp->rbr_max_size; i++) {
		rx_msg_p = rbrp->rx_msg_ring[i];
		if (rx_msg_p->ref_cnt == 1) {
			n_init_kick++;
		}
	}

	HXGE_DEBUG_MSG((hxgep, RX_CTL, "RxDMA channel re-start..."));

	/*
	 * This is error recover! Some buffers are owned by the hardware and
	 * the rest are owned by the apps. We should only kick in those
	 * owned by the hardware initially. The apps will post theirs
	 * eventually.
	 */
	(void) hxge_rxdma_start_channel(hxgep, channel, rbrp, rcrp, mboxp,
	    n_init_kick);

	/*
	 * The DMA channel may disable itself automatically.
	 * The following is a work-around.
	 */
	HXGE_REG_RD64(handle, RDC_RX_CFG1, &tmp);
	rs = hpi_rxdma_cfg_rdc_enable(handle, channel);
	if (rs != HPI_SUCCESS) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "hpi_rxdma_cfg_rdc_enable (channel %d)", channel));
	}

	/*
	 * Delay a bit of time by doing reads.
	 */
	for (i = 0; i < 1024; i++) {
		uint64_t value;
		RXDMA_REG_READ64(HXGE_DEV_HPI_HANDLE(hxgep),
		    RDC_INT_MASK, i & 3, &value);
	}

	MUTEX_EXIT(&rbrp->lock);
	MUTEX_EXIT(&rcrp->lock);

	HXGE_DEBUG_MSG((hxgep, RX_CTL, "<== hxge_rxdma_fatal_err_recover"));
	return (HXGE_OK);

fail:
	MUTEX_EXIT(&rbrp->lock);
	MUTEX_EXIT(&rcrp->lock);
	HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
	    "Error Recovery failed for channel(%d)", channel));
	return (HXGE_ERROR | rs);
}

static hxge_status_t
hxge_rx_port_fatal_err_recover(p_hxge_t hxgep)
{
	hxge_status_t		status = HXGE_OK;
	p_hxge_dma_common_t	*dma_buf_p;
	uint16_t		channel;
	int			ndmas;
	int			i;
	block_reset_t		reset_reg;
	p_rx_rcr_ring_t	rcrp;
	p_rx_rbr_ring_t rbrp;

	HXGE_DEBUG_MSG((hxgep, RX_CTL, "==> hxge_rx_port_fatal_err_recover"));
	HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL, "Recovering from RDC error ..."));

	/* Disable RxMAC */
	HXGE_DEBUG_MSG((hxgep, RX_CTL, "Disable RxMAC...\n"));
	MUTEX_ENTER(&hxgep->vmac_lock);
	if (hxge_rx_vmac_disable(hxgep) != HXGE_OK)
		goto fail;

	HXGE_DELAY(1000);

	/*
	 * Reset RDC block from PEU for this fatal error
	 */
	reset_reg.value = 0;
	reset_reg.bits.rdc_rst = 1;
	HXGE_REG_WR32(hxgep->hpi_handle, BLOCK_RESET, reset_reg.value);

	HXGE_DELAY(1000);

	/* Restore any common settings after PEU reset */
	if (hxge_rxdma_hw_start_common(hxgep) != HXGE_OK)
		goto fail;

	HXGE_DEBUG_MSG((hxgep, RX_CTL, "Stop all RxDMA channels..."));

	ndmas = hxgep->rx_buf_pool_p->ndmas;
	dma_buf_p = hxgep->rx_buf_pool_p->dma_buf_pool_p;

	for (i = 0; i < ndmas; i++) {
		channel = ((p_hxge_dma_common_t)dma_buf_p[i])->dma_channel;
		rcrp = hxgep->rx_rcr_rings->rcr_rings[channel];
		rbrp = rcrp->rx_rbr_p;

		MUTEX_ENTER(&rbrp->post_lock);

		/*
		 * This function needs to be inside the post_lock
		 */
		if (hxge_rxdma_fatal_err_recover(hxgep, channel) != HXGE_OK) {
			HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
			    "Could not recover channel %d", channel));
		}
		MUTEX_EXIT(&rbrp->post_lock);
	}

	HXGE_DEBUG_MSG((hxgep, RX_CTL, "Reset RxMAC..."));

	/* Reset RxMAC */
	if (hxge_rx_vmac_reset(hxgep) != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "hxge_rx_port_fatal_err_recover: Failed to reset RxMAC"));
		goto fail;
	}

	HXGE_DEBUG_MSG((hxgep, RX_CTL, "Re-initialize RxMAC..."));

	/* Re-Initialize RxMAC */
	if ((status = hxge_rx_vmac_init(hxgep)) != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "hxge_rx_port_fatal_err_recover: Failed to reset RxMAC"));
		goto fail;
	}
	HXGE_DEBUG_MSG((hxgep, RX_CTL, "Re-enable RxMAC..."));

	/* Re-enable RxMAC */
	if ((status = hxge_rx_vmac_enable(hxgep)) != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "hxge_rx_port_fatal_err_recover: Failed to enable RxMAC"));
		goto fail;
	}
	MUTEX_EXIT(&hxgep->vmac_lock);

	/* Reset the error mask since PEU reset cleared it */
	HXGE_REG_WR64(hxgep->hpi_handle, RDC_FIFO_ERR_INT_MASK, 0x0);

	HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
	    "Recovery Successful, RxPort Restored"));
	HXGE_DEBUG_MSG((hxgep, RX_CTL, "<== hxge_rx_port_fatal_err_recover"));
	return (HXGE_OK);

fail:
	MUTEX_EXIT(&hxgep->vmac_lock);
	HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
	    "Error Recovery failed for hxge(%d)", hxgep->instance));
	return (status);
}

static void
hxge_rbr_empty_restore(p_hxge_t hxgep, p_rx_rbr_ring_t rx_rbr_p)
{
	hpi_status_t		hpi_status;
	hxge_status_t		status;
	rdc_stat_t		cs;
	p_hxge_rx_ring_stats_t	rdc_stats;

	rdc_stats = &hxgep->statsp->rdc_stats[rx_rbr_p->rdc];

	/*
	 * Complete the processing for the RBR Empty by:
	 *	0) kicking back HXGE_RBR_EMPTY_THRESHOLD
	 *	   packets.
	 *	1) Disable the RX vmac.
	 *	2) Re-enable the affected DMA channel.
	 *	3) Re-enable the RX vmac.
	 */

	/*
	 * Disable the RX VMAC, but setting the framelength
	 * to 0, since there is a hardware bug when disabling
	 * the vmac.
	 */
	MUTEX_ENTER(&hxgep->vmac_lock);
	(void) hxge_rx_vmac_disable(hxgep);

	/*
	 * Re-arm the mex bit for interrupts to be enabled.
	 */
	cs.value = 0;
	cs.bits.mex = 1;
	RXDMA_REG_WRITE64(HXGE_DEV_HPI_HANDLE(hxgep), RDC_STAT,
	    rx_rbr_p->rdc, cs.value);

	hpi_status = hpi_rxdma_cfg_rdc_enable(
	    HXGE_DEV_HPI_HANDLE(hxgep), rx_rbr_p->rdc);
	if (hpi_status != HPI_SUCCESS) {
		rdc_stats->rbr_empty_fail++;

		/* Assume we are already inside the post_lock */
		status = hxge_rxdma_fatal_err_recover(hxgep, rx_rbr_p->rdc);
		if (status != HXGE_OK) {
			HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
			    "hxge(%d): channel(%d) is empty.",
			    hxgep->instance, rx_rbr_p->rdc));
		}
	}

	/*
	 * Re-enable the RX VMAC.
	 */
	(void) hxge_rx_vmac_enable(hxgep);
	MUTEX_EXIT(&hxgep->vmac_lock);

	rdc_stats->rbr_empty_restore++;
	rx_rbr_p->rbr_is_empty = B_FALSE;
}
