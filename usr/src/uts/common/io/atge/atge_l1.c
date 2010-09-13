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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/ethernet.h>
#include <sys/debug.h>
#include <sys/conf.h>
#include <sys/mii.h>
#include <sys/miiregs.h>
#include <sys/sysmacros.h>
#include <sys/dditypes.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/byteorder.h>
#include <sys/note.h>
#include <sys/vlan.h>
#include <sys/stream.h>

#include "atge.h"
#include "atge_l1_reg.h"
#include "atge_cmn_reg.h"

static ddi_dma_attr_t atge_l1_dma_attr_tx_desc = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0x0000ffffffffull,	/* dma_attr_addr_hi */
	0x0000ffffffffull,	/* dma_attr_count_max */
	L1_TX_RING_ALIGN,	/* dma_attr_align */
	0x0000fffc,		/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0x0000ffffffffull,	/* dma_attr_maxxfer */
	0x0000ffffffffull,	/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

static ddi_dma_attr_t atge_l1_dma_attr_rx_desc = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0x0000ffffffffull,	/* dma_attr_addr_hi */
	0x0000ffffffffull,	/* dma_attr_count_max */
	L1_RX_RING_ALIGN,	/* dma_attr_align */
	0x0000fffc,		/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0x0000ffffffffull,	/* dma_attr_maxxfer */
	0x0000ffffffffull,	/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

static ddi_dma_attr_t atge_l1_dma_attr_cmb = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0x0000ffffffffull,	/* dma_attr_addr_hi */
	0x0000ffffffffull,	/* dma_attr_count_max */
	L1_CMB_ALIGN,		/* dma_attr_align */
	0x0000fffc,		/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0x0000ffffffffull,	/* dma_attr_maxxfer */
	0x0000ffffffffull,	/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

static ddi_dma_attr_t atge_l1_dma_attr_smb = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0x0000ffffffffull,	/* dma_attr_addr_hi */
	0x0000ffffffffull,	/* dma_attr_count_max */
	L1_SMB_ALIGN,		/* dma_attr_align */
	0x0000fffc,		/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0x0000ffffffffull,	/* dma_attr_maxxfer */
	0x0000ffffffffull,	/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

static ddi_dma_attr_t atge_l1_dma_attr_rr = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0x0000ffffffffull,	/* dma_attr_addr_hi */
	0x0000ffffffffull,	/* dma_attr_count_max */
	L1_RR_RING_ALIGN,	/* dma_attr_align */
	0x0000fffc,		/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0x0000ffffffffull,	/* dma_attr_maxxfer */
	0x0000ffffffffull,	/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

int
atge_l1_alloc_dma(atge_t *atgep)
{
	atge_l1_data_t *l1;
	atge_dma_t *dma;
	int err;

	l1 = kmem_zalloc(sizeof (atge_l1_data_t), KM_SLEEP);
	atgep->atge_private_data = l1;

	/*
	 * Allocate TX ring descriptor.
	 */
	atgep->atge_tx_buf_len = atgep->atge_mtu +
	    sizeof (struct ether_header) + VLAN_TAGSZ + ETHERFCSL;
	atgep->atge_tx_ring = kmem_alloc(sizeof (atge_ring_t), KM_SLEEP);
	atgep->atge_tx_ring->r_atge = atgep;
	atgep->atge_tx_ring->r_desc_ring = NULL;
	dma = atge_alloc_a_dma_blk(atgep, &atge_l1_dma_attr_tx_desc,
	    ATGE_TX_RING_SZ, DDI_DMA_RDWR);
	if (dma == NULL) {
		atge_error(atgep->atge_dip, "DMA allocation failed for TX"
		    " desc ring");
		return (DDI_FAILURE);
	}
	atgep->atge_tx_ring->r_desc_ring = dma;

	/*
	 * Allocate DMA buffers for TX ring.
	 */
	err = atge_alloc_buffers(atgep->atge_tx_ring, ATGE_TX_RING_CNT,
	    atgep->atge_tx_buf_len, DDI_DMA_WRITE);
	if (err != DDI_SUCCESS) {
		atge_error(atgep->atge_dip, "DMA allocation failed for"
		    " TX Ring");
		return (err);
	}

	/*
	 * Allocate RX ring.
	 */
	atgep->atge_rx_buf_len = atgep->atge_mtu +
	    sizeof (struct ether_header) + VLAN_TAGSZ + ETHERFCSL;
	l1->atge_rx_ring = kmem_alloc(sizeof (atge_ring_t), KM_SLEEP);
	l1->atge_rx_ring->r_atge = atgep;
	l1->atge_rx_ring->r_desc_ring = NULL;
	dma = atge_alloc_a_dma_blk(atgep, &atge_l1_dma_attr_rx_desc,
	    L1_RX_RING_SZ, DDI_DMA_RDWR);
	if (dma == NULL) {
		atge_error(atgep->atge_dip, "DMA allocation failed"
		    " for RX Ring");
		return (DDI_FAILURE);
	}
	l1->atge_rx_ring->r_desc_ring = dma;

	/*
	 * Allocate DMA buffers for RX ring.
	 */
	err = atge_alloc_buffers(l1->atge_rx_ring, L1_RX_RING_CNT,
	    atgep->atge_rx_buf_len, DDI_DMA_WRITE);
	if (err != DDI_SUCCESS) {
		atge_error(atgep->atge_dip, "DMA allocation failed for"
		    " RX buffers");
		return (err);
	}

	/*
	 * Allocate CMB used for fetching interrupt status data.
	 */
	ATGE_DB(("%s: %s() L1_CMB_BLOCK_SZ : %x", atgep->atge_name,
	    __func__, L1_CMB_BLOCK_SZ));

	dma = atge_alloc_a_dma_blk(atgep, &atge_l1_dma_attr_cmb,
	    L1_CMB_BLOCK_SZ, DDI_DMA_RDWR);
	l1->atge_l1_cmb = dma;
	if (dma == NULL) {
		atge_error(atgep->atge_dip, "DMA allocation failed for CMB");
		return (DDI_FAILURE);
	}

	/*
	 * RR ring (Return Ring for RX and TX).
	 */
	ATGE_DB(("%s: %s() L1_RR_RING_SZ : %x", atgep->atge_name,
	    __func__, L1_RR_RING_SZ));

	dma = atge_alloc_a_dma_blk(atgep, &atge_l1_dma_attr_rr,
	    L1_RR_RING_SZ, DDI_DMA_RDWR);
	l1->atge_l1_rr = dma;
	if (dma == NULL) {
		atge_error(atgep->atge_dip, "DMA allocation failed"
		    " for RX RR ring");
		return (DDI_FAILURE);
	}

	/*
	 * SMB for statistics.
	 */
	ATGE_DB(("%s: %s() L1_SMB_BLOCK_SZ : %x", atgep->atge_name,
	    __func__, L1_SMB_BLOCK_SZ));

	dma = atge_alloc_a_dma_blk(atgep, &atge_l1_dma_attr_smb,
	    L1_SMB_BLOCK_SZ, DDI_DMA_RDWR);
	l1->atge_l1_smb = dma;
	if (dma == NULL) {
		atge_error(atgep->atge_dip, "DMA allocation failed for SMB");
		return (DDI_FAILURE);
	}

	atgep->atge_hw_stats = kmem_zalloc(sizeof (atge_l1_smb_t), KM_SLEEP);

	return (DDI_SUCCESS);
}

void
atge_l1_free_dma(atge_t *atgep)
{
	atge_l1_data_t *l1;

	l1 = atgep->atge_private_data;

	/*
	 * Free TX ring.
	 */
	if (atgep->atge_tx_ring != NULL) {
		atge_free_buffers(atgep->atge_tx_ring,  ATGE_TX_RING_CNT);

		if (atgep->atge_tx_ring->r_desc_ring != NULL) {
			atge_free_a_dma_blk(atgep->atge_tx_ring->r_desc_ring);
		}

		kmem_free(atgep->atge_tx_ring, sizeof (atge_ring_t));
		atgep->atge_tx_ring = NULL;
	}

	if (l1 && l1->atge_l1_cmb != NULL) {
		atge_free_a_dma_blk(l1->atge_l1_cmb);
		l1->atge_l1_cmb = NULL;
	}

	if (l1 && l1->atge_l1_rr != NULL) {
		atge_free_a_dma_blk(l1->atge_l1_rr);
		l1->atge_l1_rr = NULL;
	}

	if (l1 && l1->atge_l1_smb != NULL) {
		atge_free_a_dma_blk(l1->atge_l1_smb);
		l1->atge_l1_smb = NULL;
	}

	/*
	 * Free RX ring.
	 */
	if (l1 && l1->atge_rx_ring != NULL) {
		atge_free_buffers(l1->atge_rx_ring,  L1_RX_RING_CNT);

		if (l1->atge_rx_ring->r_desc_ring != NULL) {
			atge_free_a_dma_blk(l1->atge_rx_ring->r_desc_ring);
		}

		kmem_free(l1->atge_rx_ring, sizeof (atge_ring_t));
		l1->atge_rx_ring = NULL;
	}

	/*
	 * Free the memory allocated for gathering hw stats.
	 */
	if (atgep->atge_hw_stats != NULL) {
		kmem_free(atgep->atge_hw_stats, sizeof (atge_l1_smb_t));
		atgep->atge_hw_stats = NULL;
	}
}

void
atge_l1_init_rx_ring(atge_t *atgep)
{
	atge_l1_data_t *l1;
	atge_dma_t *dma;
	l1_rx_desc_t *rx;
	int i;

	l1 = atgep->atge_private_data;
	l1->atge_rx_ring->r_consumer = L1_RX_RING_CNT - 1;
	dma = l1->atge_rx_ring->r_desc_ring;
	bzero(dma->addr, L1_RX_RING_SZ);

	for (i = 0; i < L1_RX_RING_CNT; i++) {
		rx = (l1_rx_desc_t *)(dma->addr + (i * sizeof (l1_rx_desc_t)));

		ATGE_PUT64(dma, &rx->addr,
		    l1->atge_rx_ring->r_buf_tbl[i]->cookie.dmac_laddress);
		ATGE_PUT32(dma, &rx->len,
		    (l1->atge_rx_ring->r_buf_tbl[i]->len & L1_RD_LEN_MASK) <<
		    L1_RD_LEN_SHIFT);
	}

	DMA_SYNC(dma, 0, L1_RX_RING_SZ, DDI_DMA_SYNC_FORDEV);
}

void
atge_l1_init_tx_ring(atge_t *atgep)
{
	atgep->atge_tx_ring->r_producer = 0;
	atgep->atge_tx_ring->r_consumer = 0;
	atgep->atge_tx_ring->r_avail_desc = ATGE_TX_RING_CNT;

	bzero(atgep->atge_tx_ring->r_desc_ring->addr, ATGE_TX_RING_SZ);
	DMA_SYNC(atgep->atge_tx_ring->r_desc_ring, 0, ATGE_TX_RING_SZ,
	    DDI_DMA_SYNC_FORDEV);
}

void
atge_l1_init_rr_ring(atge_t *atgep)
{
	atge_l1_data_t *l1;
	atge_dma_t *dma;

	l1 = atgep->atge_private_data;
	l1->atge_l1_rr_consumers = 0;

	dma = l1->atge_l1_rr;
	bzero(dma->addr, L1_RR_RING_SZ);
	DMA_SYNC(dma, 0, L1_RR_RING_SZ, DDI_DMA_SYNC_FORDEV);
}

void
atge_l1_init_smb(atge_t *atgep)
{
	atge_l1_data_t *l1;
	atge_dma_t *dma;

	l1 = atgep->atge_private_data;
	dma = l1->atge_l1_smb;
	bzero(dma->addr, L1_SMB_BLOCK_SZ);
	DMA_SYNC(dma, 0, L1_SMB_BLOCK_SZ, DDI_DMA_SYNC_FORDEV);
}

void
atge_l1_init_cmb(atge_t *atgep)
{
	atge_l1_data_t *l1;
	atge_dma_t *dma;

	l1 = atgep->atge_private_data;
	dma = l1->atge_l1_cmb;
	bzero(dma->addr, L1_CMB_BLOCK_SZ);
	DMA_SYNC(dma, 0, L1_CMB_BLOCK_SZ, DDI_DMA_SYNC_FORDEV);
}

void
atge_l1_sync_mbox(atge_t *atgep)
{
	atge_l1_data_t *l1;

	l1 = atgep->atge_private_data;

	mutex_enter(&atgep->atge_mbox_lock);
	OUTL(atgep, ATGE_MBOX,
	    ((l1->atge_rx_ring->r_consumer << MBOX_RD_PROD_IDX_SHIFT) &
	    MBOX_RD_PROD_IDX_MASK) |
	    ((l1->atge_l1_rr_consumers <<
	    MBOX_RRD_CONS_IDX_SHIFT) & MBOX_RRD_CONS_IDX_MASK) |
	    ((atgep->atge_tx_ring->r_producer << MBOX_TD_PROD_IDX_SHIFT) &
	    MBOX_TD_PROD_IDX_MASK));
	mutex_exit(&atgep->atge_mbox_lock);
}

void
atge_l1_program_dma(atge_t *atgep)
{
	atge_l1_data_t *l1;
	atge_ring_t *r;

	l1 = atgep->atge_private_data;

	/* TX */
	r = atgep->atge_tx_ring;
	OUTL(atgep, ATGE_DESC_ADDR_HI,
	    ATGE_ADDR_HI(r->r_desc_ring->cookie.dmac_laddress));
	OUTL(atgep, ATGE_DESC_TPD_ADDR_LO,
	    ATGE_ADDR_LO(r->r_desc_ring->cookie.dmac_laddress));

	/* RX */
	r = l1->atge_rx_ring;
	OUTL(atgep, ATGE_DESC_RD_ADDR_LO,
	    ATGE_ADDR_LO(r->r_desc_ring->cookie.dmac_laddress));

	/* RR Ring */
	OUTL(atgep, ATGE_DESC_RRD_ADDR_LO,
	    ATGE_ADDR_LO(l1->atge_l1_rr->cookie.dmac_laddress));

	/* CMB */
	OUTL(atgep, ATGE_DESC_CMB_ADDR_LO,
	    ATGE_ADDR_LO(l1->atge_l1_cmb->cookie.dmac_laddress));

	/* SMB */
	OUTL(atgep, ATGE_DESC_SMB_ADDR_LO,
	    ATGE_ADDR_LO(l1->atge_l1_smb->cookie.dmac_laddress));

	/*
	 * Set RX return ring (RR) counter.
	 */
	OUTL(atgep, ATGE_DESC_RRD_RD_CNT,
	    ((L1_RR_RING_CNT << DESC_RRD_CNT_SHIFT) &
	    DESC_RRD_CNT_MASK) |
	    ((L1_RX_RING_CNT << DESC_RD_CNT_SHIFT) & DESC_RD_CNT_MASK));

	/*
	 * Set TX descriptor counter.
	 */
	OUTL(atgep, ATGE_DESC_TPD_CNT,
	    (ATGE_TX_RING_CNT << DESC_TPD_CNT_SHIFT) & DESC_TPD_CNT_MASK);

	/*
	 * Inform hardware that we have loaded DMA registers.
	 */
	OUTL(atgep, ATGE_DMA_BLOCK, DMA_BLOCK_LOAD);

	/*
	 * Initialize mailbox register (mbox).
	 */
	atge_l1_sync_mbox(atgep);
}

void
atge_l1_gather_stats(atge_t *atgep)
{
	atge_l1_data_t *l1;
	atge_dma_t *dma;
	atge_l1_smb_t *stat;
	atge_l1_smb_t *smb;

	ASSERT(atgep != NULL);

	l1 = atgep->atge_private_data;
	dma = l1->atge_l1_smb;
	DMA_SYNC(dma, 0, L1_SMB_BLOCK_SZ, DDI_DMA_SYNC_FORKERNEL);
	stat = (atge_l1_smb_t *)atgep->atge_hw_stats;
	smb = (atge_l1_smb_t *)dma->addr;

	/* Rx stats. */
	stat->rx_frames += smb->rx_frames;
	stat->rx_bcast_frames += smb->rx_bcast_frames;
	stat->rx_mcast_frames += smb->rx_mcast_frames;
	stat->rx_pause_frames += smb->rx_pause_frames;
	stat->rx_control_frames += smb->rx_control_frames;
	stat->rx_crcerrs += smb->rx_crcerrs;
	stat->rx_lenerrs += smb->rx_lenerrs;
	stat->rx_bytes += smb->rx_bytes;
	stat->rx_runts += smb->rx_runts;
	stat->rx_fragments += smb->rx_fragments;
	stat->rx_pkts_64 += smb->rx_pkts_64;
	stat->rx_pkts_65_127 += smb->rx_pkts_65_127;
	stat->rx_pkts_128_255 += smb->rx_pkts_128_255;
	stat->rx_pkts_256_511 += smb->rx_pkts_256_511;
	stat->rx_pkts_512_1023 += smb->rx_pkts_512_1023;
	stat->rx_pkts_1024_1518 += smb->rx_pkts_1024_1518;
	stat->rx_pkts_1519_max += smb->rx_pkts_1519_max;
	stat->rx_pkts_truncated += smb->rx_pkts_truncated;
	stat->rx_fifo_oflows += smb->rx_fifo_oflows;
	stat->rx_alignerrs += smb->rx_alignerrs;
	stat->rx_bcast_bytes += smb->rx_bcast_bytes;
	stat->rx_mcast_bytes += smb->rx_mcast_bytes;
	stat->rx_pkts_filtered += smb->rx_pkts_filtered;

	/* Tx stats. */
	stat->tx_frames += smb->tx_frames;
	stat->tx_bcast_frames += smb->tx_bcast_frames;
	stat->tx_mcast_frames += smb->tx_mcast_frames;
	stat->tx_pause_frames += smb->tx_pause_frames;
	stat->tx_excess_defer += smb->tx_excess_defer;
	stat->tx_control_frames += smb->tx_control_frames;
	stat->tx_deferred += smb->tx_deferred;
	stat->tx_bytes += smb->tx_bytes;
	stat->tx_pkts_64 += smb->tx_pkts_64;
	stat->tx_pkts_65_127 += smb->tx_pkts_65_127;
	stat->tx_pkts_128_255 += smb->tx_pkts_128_255;
	stat->tx_pkts_256_511 += smb->tx_pkts_256_511;
	stat->tx_pkts_512_1023 += smb->tx_pkts_512_1023;
	stat->tx_pkts_1024_1518 += smb->tx_pkts_1024_1518;
	stat->tx_pkts_1519_max += smb->tx_pkts_1519_max;
	stat->tx_single_colls += smb->tx_single_colls;
	stat->tx_multi_colls += smb->tx_multi_colls;
	stat->tx_late_colls += smb->tx_late_colls;
	stat->tx_excess_colls += smb->tx_excess_colls;
	stat->tx_underrun += smb->tx_underrun;
	stat->tx_desc_underrun += smb->tx_desc_underrun;
	stat->tx_lenerrs += smb->tx_lenerrs;
	stat->tx_pkts_truncated += smb->tx_pkts_truncated;
	stat->tx_bcast_bytes += smb->tx_bcast_bytes;
	stat->tx_mcast_bytes += smb->tx_mcast_bytes;

	/*
	 * Update global counters in atge_t.
	 */
	atgep->atge_brdcstrcv += smb->rx_bcast_frames;
	atgep->atge_multircv += smb->rx_mcast_frames;
	atgep->atge_multixmt += smb->tx_mcast_frames;
	atgep->atge_brdcstxmt += smb->tx_bcast_frames;

	atgep->atge_align_errors += smb->rx_alignerrs;
	atgep->atge_fcs_errors += smb->rx_crcerrs;
	atgep->atge_defer_xmts += smb->tx_deferred;
	atgep->atge_first_collisions += smb->tx_single_colls;
	atgep->atge_multi_collisions += smb->tx_multi_colls * 2;
	atgep->atge_tx_late_collisions += smb->tx_late_colls;
	atgep->atge_ex_collisions += smb->tx_excess_colls;
	atgep->atge_toolong_errors += smb->rx_lenerrs;
	atgep->atge_overflow += smb->rx_fifo_oflows;
	atgep->atge_underflow += (smb->tx_underrun + smb->tx_desc_underrun);
	atgep->atge_runt += smb->rx_runts;


	atgep->atge_collisions += smb->tx_single_colls +
	    smb->tx_multi_colls * 2 + smb->tx_late_colls;

	/*
	 * tx_pkts_truncated counter looks suspicious. It constantly
	 * increments with no sign of Tx errors. Hence we don't factor it.
	 */
	atgep->atge_macxmt_errors += smb->tx_late_colls + smb->tx_underrun;

	atgep->atge_macrcv_errors += smb->rx_crcerrs + smb->rx_lenerrs +
	    smb->rx_runts + smb->rx_pkts_truncated +
	    smb->rx_alignerrs;

	smb->updated = 0;
	DMA_SYNC(dma, 0, L1_SMB_BLOCK_SZ, DDI_DMA_SYNC_FORDEV);
}

void
atge_l1_stop_tx_mac(atge_t *atgep)
{
	uint32_t reg;
	int t;

	ATGE_DB(("%s: %s() called", atgep->atge_name, __func__));

	reg = INL(atgep, ATGE_MAC_CFG);
	if ((reg & ATGE_CFG_TX_ENB) != 0) {
		reg &= ~ATGE_CFG_TX_ENB;
		OUTL(atgep, ATGE_MAC_CFG, reg);
	}

	/* Stop TX DMA engine. */
	reg = INL(atgep, ATGE_DMA_CFG);
	if ((reg & DMA_CFG_RD_ENB) != 0) {
		reg &= ~DMA_CFG_RD_ENB;
		OUTL(atgep, ATGE_DMA_CFG, reg);
	}

	for (t = ATGE_RESET_TIMEOUT; t > 0; t--) {
		if ((INL(atgep, ATGE_IDLE_STATUS) &
		    (IDLE_STATUS_TXMAC | IDLE_STATUS_DMARD)) == 0)
			break;

		drv_usecwait(10);
	}

	if (t == 0) {
		atge_error(atgep->atge_dip, "stopping TX DMA Engine timeout");
	}
}

void
atge_l1_stop_rx_mac(atge_t *atgep)
{
	uint32_t reg;
	int t;

	ATGE_DB(("%s: %s() called", atgep->atge_name, __func__));

	reg = INL(atgep, ATGE_MAC_CFG);
	if ((reg & ATGE_CFG_RX_ENB) != 0) {
		reg &= ~ATGE_CFG_RX_ENB;
		OUTL(atgep, ATGE_MAC_CFG, reg);
	}

	/* Stop RX DMA engine. */
	reg = INL(atgep, ATGE_DMA_CFG);
	if ((reg & DMA_CFG_WR_ENB) != 0) {
		reg &= ~DMA_CFG_WR_ENB;
		OUTL(atgep, ATGE_DMA_CFG, reg);
	}

	for (t = ATGE_RESET_TIMEOUT; t > 0; t--) {
		if ((INL(atgep, ATGE_IDLE_STATUS) &
		    (IDLE_STATUS_RXMAC | IDLE_STATUS_DMAWR)) == 0)
			break;
		drv_usecwait(10);
	}

	if (t == 0) {
		atge_error(atgep->atge_dip, " stopping RX DMA Engine timeout");
	}
}

/*
 * Receives (consumes) packets.
 */
static mblk_t *
atge_l1_rx(atge_t *atgep)
{
	atge_l1_data_t *l1;
	mblk_t *mp = NULL, *rx_head = NULL, *rx_tail = NULL;
	l1_rx_rdesc_t *rx_rr;
	l1_rx_desc_t *rxd;
	uint32_t index, flags, totlen, pktlen, slotlen;
	int nsegs, rx_cons = 0, cnt;
	atge_dma_t *buf;
	uchar_t *bufp;
	int sync = 0;

	l1 = atgep->atge_private_data;
	ASSERT(l1 != NULL);

	DMA_SYNC(l1->atge_l1_rr, 0, L1_RR_RING_SZ, DDI_DMA_SYNC_FORKERNEL);

	while (l1->atge_l1_rr_consumers != l1->atge_l1_rx_prod_cons) {
		rx_rr = (l1_rx_rdesc_t *)(l1->atge_l1_rr->addr +
		    (l1->atge_l1_rr_consumers * sizeof (l1_rx_rdesc_t)));

		index = ATGE_GET32(l1->atge_l1_rr, &rx_rr->index);
		flags = ATGE_GET32(l1->atge_l1_rr, &rx_rr->flags);
		totlen = L1_RX_BYTES(ATGE_GET32(l1->atge_l1_rr, &rx_rr->len));

		rx_cons = L1_RX_CONS(index);
		nsegs = L1_RX_NSEGS(index);

		ATGE_DB(("%s: %s() PKT -- index : %d, flags : %x, totlen : %d,"
		    " rx_cons : %d, nsegs : %d", atgep->atge_name, __func__,
		    index, flags, totlen, rx_cons, nsegs));

		if (nsegs == 0)
			break;

		if ((flags & L1_RRD_ERROR) &&
		    (flags & (L1_RRD_CRC | L1_RRD_CODE | L1_RRD_DRIBBLE |
		    L1_RRD_RUNT | L1_RRD_OFLOW | L1_RRD_TRUNC)) != 0) {
			atge_error(atgep->atge_dip, "errored pkt");

			l1->atge_rx_ring->r_consumer += nsegs;
			l1->atge_rx_ring->r_consumer %= L1_RX_RING_CNT;
			break;
		}

		ASSERT(rx_cons >= 0 && rx_cons <= L1_RX_RING_CNT);

		mp = allocb(totlen + VLAN_TAGSZ, BPRI_MED);
		if (mp != NULL) {
			mp->b_rptr += VLAN_TAGSZ;
			bufp = mp->b_rptr;
			mp->b_wptr = bufp + totlen;
			mp->b_next = NULL;

			atgep->atge_ipackets++;
			atgep->atge_rbytes += totlen;

			/*
			 * If there are more than one segments, then the first
			 * segment should be of size MTU. We couldn't verify
			 * this as our driver does not support changing MTU
			 * or Jumbo Frames.
			 */
			if (nsegs > 1) {
				slotlen = atgep->atge_mtu;
			} else {
				slotlen = totlen;
			}
		} else {
			ATGE_DB(("%s: %s() PKT mp == NULL totlen : %d",
			    atgep->atge_name, __func__, totlen));

			if (slotlen > atgep->atge_rx_buf_len) {
				atgep->atge_toolong_errors++;
			} else if (mp == NULL) {
				atgep->atge_norcvbuf++;
			}

			rx_rr->index = 0;
			break;
		}

		for (cnt = 0, pktlen = 0; cnt < nsegs; cnt++) {
			buf = l1->atge_rx_ring->r_buf_tbl[rx_cons];
			rxd = (l1_rx_desc_t *)(
			    l1->atge_rx_ring->r_desc_ring->addr +
			    (rx_cons * sizeof (l1_rx_desc_t)));

			if (cnt != 0) {
				slotlen = L1_RX_BYTES(ATGE_GET32(
				    l1->atge_rx_ring->r_desc_ring, &rxd->len));
			}

			bcopy(buf->addr, (bufp + pktlen), slotlen);
			pktlen += slotlen;

			ATGE_DB(("%s: %s() len : %d, rxcons : %d, pktlen : %d",
			    atgep->atge_name, __func__, slotlen, rx_cons,
			    pktlen));

			ATGE_INC_SLOT(rx_cons, L1_RX_RING_CNT);
		}

		if (rx_tail == NULL) {
			rx_head = rx_tail = mp;
		} else {
			rx_tail->b_next = mp;
			rx_tail = mp;
		}

		if (cnt != nsegs) {
			l1->atge_rx_ring->r_consumer += nsegs;
			l1->atge_rx_ring->r_consumer %= L1_RX_RING_CNT;
		} else {
			l1->atge_rx_ring->r_consumer = rx_cons;
		}

		/*
		 * Tell the chip that this RR can be reused.
		 */
		rx_rr->index = 0;

		ATGE_INC_SLOT(l1->atge_l1_rr_consumers, L1_RR_RING_CNT);
		sync++;
	}

	if (sync) {
		DMA_SYNC(l1->atge_rx_ring->r_desc_ring, 0, L1_RX_RING_SZ,
		    DDI_DMA_SYNC_FORDEV);

		DMA_SYNC(l1->atge_l1_rr, 0, L1_RR_RING_SZ, DDI_DMA_SYNC_FORDEV);
		atge_l1_sync_mbox(atgep);

		ATGE_DB(("%s: %s() PKT Recved -> r_consumer : %d, rx_cons : %d"
		    " atge_l1_rr_consumers : %d",
		    atgep->atge_name, __func__, l1->atge_rx_ring->r_consumer,
		    rx_cons, l1->atge_l1_rr_consumers));
	}


	return (rx_head);
}

/*
 * The interrupt handler for L1 chip.
 */
/*ARGSUSED*/
uint_t
atge_l1_interrupt(caddr_t arg1, caddr_t arg2)
{
	atge_t *atgep = (void *)arg1;
	mblk_t *rx_head = NULL, *rx_head1 = NULL;
	uint32_t status;
	int resched = 0;

	ASSERT(atgep != NULL);

	mutex_enter(&atgep->atge_intr_lock);

	if (atgep->atge_chip_state & ATGE_CHIP_SUSPENDED) {
		mutex_exit(&atgep->atge_intr_lock);
		return (DDI_INTR_UNCLAIMED);
	}

	status = INL(atgep, ATGE_INTR_STATUS);
	if (status == 0 || (status & atgep->atge_intrs) == 0) {
		mutex_exit(&atgep->atge_intr_lock);

		if (atgep->atge_flags & ATGE_FIXED_TYPE)
			return (DDI_INTR_UNCLAIMED);

		return (DDI_INTR_CLAIMED);
	}

	ATGE_DB(("%s: %s() entry status : %x",
	    atgep->atge_name, __func__, status));

	/*
	 * Disable interrupts.
	 */
	OUTL(atgep, ATGE_INTR_STATUS, status | INTR_DIS_INT);
	FLUSH(atgep, ATGE_INTR_STATUS);

	/*
	 * Check if chip is running, only then do the work.
	 */
	if (atgep->atge_chip_state & ATGE_CHIP_RUNNING) {
		atge_l1_data_t *l1;
		l1_cmb_t *cmb;

		l1 = atgep->atge_private_data;

		DMA_SYNC(l1->atge_l1_cmb, 0, L1_CMB_BLOCK_SZ,
		    DDI_DMA_SYNC_FORKERNEL);

		cmb = (l1_cmb_t *)l1->atge_l1_cmb->addr;
		l1->atge_l1_intr_status =
		    ATGE_GET32(l1->atge_l1_cmb, &cmb->intr_status);
		l1->atge_l1_rx_prod_cons =
		    (ATGE_GET32(l1->atge_l1_cmb, &cmb->rx_prod_cons) &
		    RRD_PROD_MASK) >> RRD_PROD_SHIFT;
		l1->atge_l1_tx_prod_cons =
		    (ATGE_GET32(l1->atge_l1_cmb, &cmb->tx_prod_cons) &
		    TPD_CONS_MASK) >> TPD_CONS_SHIFT;

		ATGE_DB(("%s: %s() atge_l1_intr_status : %x, "
		    "atge_l1_rx_prod_cons : %d, atge_l1_tx_prod_cons : %d"
		    " atge_l1_rr_consumers : %d",
		    atgep->atge_name, __func__, l1->atge_l1_intr_status,
		    l1->atge_l1_rx_prod_cons, l1->atge_l1_tx_prod_cons,
		    l1->atge_l1_rr_consumers));

		/*
		 * Inform the hardware that CMB was served.
		 */
		cmb->intr_status = 0;
		DMA_SYNC(l1->atge_l1_cmb, 0, L1_CMB_BLOCK_SZ,
		    DDI_DMA_SYNC_FORDEV);

		/*
		 * We must check for RX Overflow condition and restart the
		 * chip. This needs to be done only when producer and consumer
		 * counters are same for the RR ring (Return RX).
		 */
		if ((l1->atge_l1_intr_status & (INTR_CMB_RX | INTR_MAC_RX)) &&
		    (l1->atge_l1_intr_status &
		    (INTR_RX_FIFO_OFLOW | INTR_RRD_OFLOW) &&
		    (l1->atge_l1_rr_consumers == l1->atge_l1_rx_prod_cons))) {

			ATGE_DB(("%s: %s() RX OVERFLOW :"
			    " atge_l1_rx_prod_cons : %d,"
			    " l1->atge_l1_rr_consumers : %d",
			    atgep->atge_name, __func__,
			    l1->atge_l1_rx_prod_cons,
			    l1->atge_l1_rr_consumers));

			mutex_enter(&atgep->atge_tx_lock);
			atge_device_restart(atgep);
			mutex_exit(&atgep->atge_tx_lock);
			goto done;
		}

		rx_head = atge_l1_rx(atgep);

		if (l1->atge_l1_intr_status & INTR_SMB)
			atge_l1_gather_stats(atgep);

		if (l1->atge_l1_intr_status & (INTR_CMB_TX | INTR_MAC_TX)) {
			mutex_enter(&atgep->atge_tx_lock);
			atge_tx_reclaim(atgep, l1->atge_l1_tx_prod_cons);
			if (atgep->atge_tx_resched) {
				atgep->atge_tx_resched = 0;
				resched = 1;
			}

			mutex_exit(&atgep->atge_tx_lock);
		}

		if ((status & (INTR_DMA_RD_TO_RST | INTR_DMA_WR_TO_RST)) != 0) {
			atge_error(atgep->atge_dip,
			    "DMA transfer error");

			ATGE_DB(("%s: %s() DMA transfer error",
			    atgep->atge_name, __func__));

			atge_device_stop(atgep);
			goto done;
		}
	}

done:

	OUTL(atgep, ATGE_INTR_STATUS, INTR_DIS_DMA | INTR_DIS_SM);
	mutex_exit(&atgep->atge_intr_lock);

	if (status & INTR_GPHY || atgep->atge_flags & ATGE_MII_CHECK) {
		ATGE_DB(("%s: %s() MII_CHECK Requested",
		    atgep->atge_name, __func__));

		if (status & INTR_GPHY) {
			(void) atge_mii_read(atgep,
			    atgep->atge_phyaddr, ATGE_ISR_ACK_GPHY);
		}

		atgep->atge_flags &= ~ATGE_MII_CHECK;
		mii_reset(atgep->atge_mii);
	}

	/*
	 * Pass the list of packets received from chip to MAC layer.
	 */
	if (rx_head) {
		mac_rx(atgep->atge_mh, 0, rx_head);
	}

	if (rx_head1) {
		mac_rx(atgep->atge_mh, 0, rx_head1);
	}

	/*
	 * Let MAC start sending pkts if the downstream was asked to pause.
	 */
	if (resched)
		mac_tx_update(atgep->atge_mh);

	return (DDI_INTR_CLAIMED);
}

void
atge_l1_send_packet(atge_ring_t *r)
{
	atge_l1_sync_mbox(r->r_atge);
}
