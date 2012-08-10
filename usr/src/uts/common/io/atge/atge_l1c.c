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
 * Copyright (c) 2012 Gary Mills
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2009, Pyun YongHyeon <yongari@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
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
#include "atge_l1c_reg.h"
#include "atge_cmn_reg.h"

static ddi_dma_attr_t atge_l1c_dma_attr_tx_desc = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0x0000ffffffffull,	/* dma_attr_addr_hi */
	0x0000ffffffffull,	/* dma_attr_count_max */
	L1C_TX_RING_ALIGN,	/* dma_attr_align */
	0x0000fffc,		/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0x0000ffffffffull,	/* dma_attr_maxxfer */
	0x0000ffffffffull,	/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

static ddi_dma_attr_t atge_l1c_dma_attr_rx_desc = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0x0000ffffffffull,	/* dma_attr_addr_hi */
	0x0000ffffffffull,	/* dma_attr_count_max */
	L1C_RX_RING_ALIGN,	/* dma_attr_align */
	0x0000fffc,		/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0x0000ffffffffull,	/* dma_attr_maxxfer */
	0x0000ffffffffull,	/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

static ddi_dma_attr_t atge_l1c_dma_attr_cmb = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0x0000ffffffffull,	/* dma_attr_addr_hi */
	0x0000ffffffffull,	/* dma_attr_count_max */
	L1C_CMB_ALIGN,		/* dma_attr_align */
	0x0000fffc,		/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0x0000ffffffffull,	/* dma_attr_maxxfer */
	0x0000ffffffffull,	/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

static ddi_dma_attr_t atge_l1c_dma_attr_smb = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0x0000ffffffffull,	/* dma_attr_addr_hi */
	0x0000ffffffffull,	/* dma_attr_count_max */
	L1C_SMB_ALIGN,		/* dma_attr_align */
	0x0000fffc,		/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0x0000ffffffffull,	/* dma_attr_maxxfer */
	0x0000ffffffffull,	/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

static ddi_dma_attr_t atge_l1c_dma_attr_rr = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0x0000ffffffffull,	/* dma_attr_addr_hi */
	0x0000ffffffffull,	/* dma_attr_count_max */
	L1C_RR_RING_ALIGN,	/* dma_attr_align */
	0x0000fffc,		/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0x0000ffffffffull,	/* dma_attr_maxxfer */
	0x0000ffffffffull,	/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

int
atge_l1c_alloc_dma(atge_t *atgep)
{
	atge_l1c_data_t *l1c;
	atge_dma_t *dma;
	int err;

	l1c = kmem_zalloc(sizeof (atge_l1c_data_t), KM_SLEEP);
	atgep->atge_private_data = l1c;

	/*
	 * Allocate TX ring descriptor.
	 */
	atgep->atge_tx_buf_len = atgep->atge_mtu +
	    sizeof (struct ether_header) + VLAN_TAGSZ + ETHERFCSL;
	atgep->atge_tx_ring = kmem_alloc(sizeof (atge_ring_t), KM_SLEEP);
	atgep->atge_tx_ring->r_atge = atgep;
	atgep->atge_tx_ring->r_desc_ring = NULL;
	dma = atge_alloc_a_dma_blk(atgep, &atge_l1c_dma_attr_tx_desc,
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
	l1c->atge_rx_ring = kmem_alloc(sizeof (atge_ring_t), KM_SLEEP);
	l1c->atge_rx_ring->r_atge = atgep;
	l1c->atge_rx_ring->r_desc_ring = NULL;
	dma = atge_alloc_a_dma_blk(atgep, &atge_l1c_dma_attr_rx_desc,
	    L1C_RX_RING_SZ, DDI_DMA_RDWR);
	if (dma == NULL) {
		atge_error(atgep->atge_dip, "DMA allocation failed"
		    " for RX Ring");
		return (DDI_FAILURE);
	}
	l1c->atge_rx_ring->r_desc_ring = dma;

	/*
	 * Allocate DMA buffers for RX ring.
	 */
	err = atge_alloc_buffers(l1c->atge_rx_ring, L1C_RX_RING_CNT,
	    atgep->atge_rx_buf_len, DDI_DMA_READ);
	if (err != DDI_SUCCESS) {
		atge_error(atgep->atge_dip, "DMA allocation failed for"
		    " RX buffers");
		return (err);
	}

	/*
	 * Allocate CMB used for fetching interrupt status data.
	 */
	ATGE_DB(("%s: %s() L1C_CMB_BLOCK_SZ : 0x%x", atgep->atge_name,
	    __func__, L1C_CMB_BLOCK_SZ));

	dma = atge_alloc_a_dma_blk(atgep, &atge_l1c_dma_attr_cmb,
	    L1C_CMB_BLOCK_SZ, DDI_DMA_RDWR);
	l1c->atge_l1c_cmb = dma;
	if (dma == NULL) {
		atge_error(atgep->atge_dip, "DMA allocation failed for CMB");
		return (DDI_FAILURE);
	}

	/*
	 * RR ring (Return Ring for RX and TX).
	 */
	ATGE_DB(("%s: %s() L1C_RR_RING_SZ : 0x%x", atgep->atge_name,
	    __func__, L1C_RR_RING_SZ));

	dma = atge_alloc_a_dma_blk(atgep, &atge_l1c_dma_attr_rr,
	    L1C_RR_RING_SZ, DDI_DMA_RDWR);
	l1c->atge_l1c_rr = dma;
	if (dma == NULL) {
		atge_error(atgep->atge_dip, "DMA allocation failed"
		    " for RX RR ring");
		return (DDI_FAILURE);
	}

	/*
	 * SMB for statistics.
	 */
	ATGE_DB(("%s: %s() L1C_SMB_BLOCK_SZ : 0x%x", atgep->atge_name,
	    __func__, L1C_SMB_BLOCK_SZ));

	dma = atge_alloc_a_dma_blk(atgep, &atge_l1c_dma_attr_smb,
	    L1C_SMB_BLOCK_SZ, DDI_DMA_RDWR);
	l1c->atge_l1c_smb = dma;
	if (dma == NULL) {
		atge_error(atgep->atge_dip, "DMA allocation failed for SMB");
		return (DDI_FAILURE);
	}

	atgep->atge_hw_stats = kmem_zalloc(sizeof (atge_l1c_smb_t), KM_SLEEP);

	return (DDI_SUCCESS);
}

void
atge_l1c_free_dma(atge_t *atgep)
{
	atge_l1c_data_t *l1c;

	l1c = atgep->atge_private_data;

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

	if (l1c && l1c->atge_l1c_cmb != NULL) {
		atge_free_a_dma_blk(l1c->atge_l1c_cmb);
		l1c->atge_l1c_cmb = NULL;
	}

	if (l1c && l1c->atge_l1c_rr != NULL) {
		atge_free_a_dma_blk(l1c->atge_l1c_rr);
		l1c->atge_l1c_rr = NULL;
	}

	if (l1c && l1c->atge_l1c_smb != NULL) {
		atge_free_a_dma_blk(l1c->atge_l1c_smb);
		l1c->atge_l1c_smb = NULL;
	}

	/*
	 * Free RX ring.
	 */
	if (l1c && l1c->atge_rx_ring != NULL) {
		atge_free_buffers(l1c->atge_rx_ring,  L1C_RX_RING_CNT);

		if (l1c->atge_rx_ring->r_desc_ring != NULL) {
			atge_free_a_dma_blk(l1c->atge_rx_ring->r_desc_ring);
		}

		kmem_free(l1c->atge_rx_ring, sizeof (atge_ring_t));
		l1c->atge_rx_ring = NULL;
	}

	/*
	 * Free the memory allocated for gathering hw stats.
	 */
	if (atgep->atge_hw_stats != NULL) {
		kmem_free(atgep->atge_hw_stats, sizeof (atge_l1c_smb_t));
		atgep->atge_hw_stats = NULL;
	}

	/*
	 * Free the private area.
	 */
	if (l1c != NULL) {
		kmem_free(l1c, sizeof (atge_l1c_data_t));
		atgep->atge_private_data = NULL;
	}
}

void
atge_l1c_init_rx_ring(atge_t *atgep)
{
	atge_l1c_data_t *l1c;
	atge_dma_t *dma;
	l1c_rx_desc_t *rx;
	int i;

	l1c = atgep->atge_private_data;
	l1c->atge_rx_ring->r_consumer = L1C_RX_RING_CNT - 1;
	dma = l1c->atge_rx_ring->r_desc_ring;
	bzero(dma->addr, L1C_RX_RING_SZ);

	for (i = 0; i < L1C_RX_RING_CNT; i++) {
		rx = (l1c_rx_desc_t *)(dma->addr +
		    (i * sizeof (l1c_rx_desc_t)));

		ATGE_PUT64(dma, &rx->addr,
		    l1c->atge_rx_ring->r_buf_tbl[i]->cookie.dmac_laddress);
		/* No length field. */
	}

	DMA_SYNC(dma, 0, 0, DDI_DMA_SYNC_FORDEV);
	/* Let controller know availability of new Rx buffers. */
	OUTL(atgep, ATGE_MBOX_RD0_PROD_IDX, l1c->atge_rx_ring->r_consumer);
}

void
atge_l1c_init_tx_ring(atge_t *atgep)
{
	atgep->atge_tx_ring->r_producer = 0;
	atgep->atge_tx_ring->r_consumer = 0;
	atgep->atge_tx_ring->r_avail_desc = ATGE_TX_RING_CNT;

	bzero(atgep->atge_tx_ring->r_desc_ring->addr, ATGE_TX_RING_SZ);
	DMA_SYNC(atgep->atge_tx_ring->r_desc_ring, 0, 0, DDI_DMA_SYNC_FORDEV);
}

void
atge_l1c_init_rr_ring(atge_t *atgep)
{
	atge_l1c_data_t *l1c;
	atge_dma_t *dma;

	l1c = atgep->atge_private_data;
	l1c->atge_l1c_rr_consumers = 0;

	dma = l1c->atge_l1c_rr;
	bzero(dma->addr, L1C_RR_RING_SZ);
	DMA_SYNC(dma, 0, 0, DDI_DMA_SYNC_FORDEV);
}

void
atge_l1c_init_smb(atge_t *atgep)
{
	atge_l1c_data_t *l1c;
	atge_dma_t *dma;

	l1c = atgep->atge_private_data;
	dma = l1c->atge_l1c_smb;
	bzero(dma->addr, L1C_SMB_BLOCK_SZ);
	DMA_SYNC(dma, 0, 0, DDI_DMA_SYNC_FORDEV);
}

void
atge_l1c_init_cmb(atge_t *atgep)
{
	atge_l1c_data_t *l1c;
	atge_dma_t *dma;

	l1c = atgep->atge_private_data;
	dma = l1c->atge_l1c_cmb;
	bzero(dma->addr, L1C_CMB_BLOCK_SZ);
	DMA_SYNC(dma, 0, 0, DDI_DMA_SYNC_FORDEV);
}

void
atge_l1c_program_dma(atge_t *atgep)
{
	atge_l1c_data_t *l1c;
	atge_ring_t *r;
	uint32_t reg;

	l1c = atgep->atge_private_data;

	/*
	 * Clear WOL status and disable all WOL feature as WOL
	 * would interfere Rx operation under normal environments.
	 */
	(void) INL(atgep, ATGE_WOL_CFG);
	OUTL(atgep, ATGE_WOL_CFG, 0);

	/* TX */
	r = atgep->atge_tx_ring;
	OUTL(atgep, L1C_TX_BASE_ADDR_HI,
	    ATGE_ADDR_HI(r->r_desc_ring->cookie.dmac_laddress));
	OUTL(atgep, L1C_TDL_HEAD_ADDR_LO,
	    ATGE_ADDR_LO(r->r_desc_ring->cookie.dmac_laddress));
	/* We don't use high priority ring. */
	OUTL(atgep, L1C_TDH_HEAD_ADDR_LO, 0);

	/* RX */
	r = l1c->atge_rx_ring;
	OUTL(atgep, L1C_RX_BASE_ADDR_HI,
	    ATGE_ADDR_HI(r->r_desc_ring->cookie.dmac_laddress));
	OUTL(atgep, L1C_RD0_HEAD_ADDR_LO,
	    ATGE_ADDR_LO(r->r_desc_ring->cookie.dmac_laddress));
	/* We use one Rx ring. */
	OUTL(atgep, L1C_RD1_HEAD_ADDR_LO, 0);
	OUTL(atgep, L1C_RD2_HEAD_ADDR_LO, 0);
	OUTL(atgep, L1C_RD3_HEAD_ADDR_LO, 0);

	/* RR Ring */
	/*
	 * Let hardware split jumbo frames into alc_max_buf_sized chunks.
	 * if it do not fit the buffer size. Rx return descriptor holds
	 * a counter that indicates how many fragments were made by the
	 * hardware. The buffer size should be multiple of 8 bytes.
	 * Since hardware has limit on the size of buffer size, always
	 * use the maximum value.
	 * For strict-alignment architectures make sure to reduce buffer
	 * size by 8 bytes to make room for alignment fixup.
	 */
	OUTL(atgep, L1C_RX_BUF_SIZE, RX_BUF_SIZE_MAX); /* XXX */

	/* Set Rx return descriptor base addresses. */
	OUTL(atgep, L1C_RRD0_HEAD_ADDR_LO,
	    ATGE_ADDR_LO(l1c->atge_l1c_rr->cookie.dmac_laddress));
	/* We use one Rx return ring. */
	OUTL(atgep, L1C_RRD1_HEAD_ADDR_LO, 0);
	OUTL(atgep, L1C_RRD2_HEAD_ADDR_LO, 0);
	OUTL(atgep, L1C_RRD3_HEAD_ADDR_LO, 0);

	/* CMB */
	OUTL(atgep, L1C_CMB_BASE_ADDR_LO,
	    ATGE_ADDR_LO(l1c->atge_l1c_cmb->cookie.dmac_laddress));

	/* SMB */
	OUTL(atgep, L1C_SMB_BASE_ADDR_HI,
	    ATGE_ADDR_HI(l1c->atge_l1c_smb->cookie.dmac_laddress));
	OUTL(atgep, L1C_SMB_BASE_ADDR_LO,
	    ATGE_ADDR_LO(l1c->atge_l1c_smb->cookie.dmac_laddress));

	/*
	 * Set RX return ring (RR) counter.
	 */
	/* Set Rx descriptor counter. */
	OUTL(atgep, L1C_RD_RING_CNT,
	    (L1C_RX_RING_CNT << RD_RING_CNT_SHIFT) & RD_RING_CNT_MASK);
	/* Set Rx return descriptor counter. */
	OUTL(atgep, L1C_RRD_RING_CNT,
	    (L1C_RR_RING_CNT << RRD_RING_CNT_SHIFT) & RRD_RING_CNT_MASK);

	/*
	 * Set TX descriptor counter.
	 */
	OUTL(atgep, L1C_TD_RING_CNT,
	    (ATGE_TX_RING_CNT << TD_RING_CNT_SHIFT) & TD_RING_CNT_MASK);

	switch (ATGE_DID(atgep)) {
	case ATGE_CHIP_AR8152V1_DEV_ID:
		/* Reconfigure SRAM - Vendor magic. */
		OUTL(atgep, L1C_SRAM_RX_FIFO_LEN, 0x000002A0);
		OUTL(atgep, L1C_SRAM_TX_FIFO_LEN, 0x00000100);
		OUTL(atgep, L1C_SRAM_RX_FIFO_ADDR, 0x029F0000);
		OUTL(atgep, L1C_SRAM_RD_ADDR, 0x02BF02A0);
		OUTL(atgep, L1C_SRAM_TX_FIFO_ADDR, 0x03BF02C0);
		OUTL(atgep, L1C_SRAM_TRD_ADDR, 0x03DF03C0);
		OUTL(atgep, L1C_TXF_WATER_MARK, 0x00000000);
		OUTL(atgep, L1C_RD_DMA_CFG, 0x00000000);
		break;
	}

	/*
	 * Inform hardware that we have loaded DMA registers.
	 */
	OUTL(atgep, ATGE_DMA_BLOCK, DMA_BLOCK_LOAD);

	/* Configure interrupt moderation timer. */
	reg = ATGE_USECS(atgep->atge_int_rx_mod) << IM_TIMER_RX_SHIFT;
	reg |= ATGE_USECS(atgep->atge_int_tx_mod) << IM_TIMER_TX_SHIFT;
	OUTL(atgep, ATGE_IM_TIMER, reg);
	/*
	 * We don't want to automatic interrupt clear as task queue
	 * for the interrupt should know interrupt status.
	 */
	reg = 0;
	if (ATGE_USECS(atgep->atge_int_rx_mod) != 0)
		reg |= MASTER_IM_RX_TIMER_ENB;
	if (ATGE_USECS(atgep->atge_int_tx_mod) != 0)
		reg |= MASTER_IM_TX_TIMER_ENB;
	OUTL(atgep, ATGE_MASTER_CFG, reg);
}

void
atge_l1c_clear_stats(atge_t *atgep)
{
	atge_l1c_smb_t smb;
	uint32_t *reg;
	int i;

	/*
	 * Clear RX stats first.
	 */
	i = 0;
	reg = &smb.rx_frames;
	while (reg++ <= &smb.rx_pkts_filtered) {
		(void) INL(atgep, ATGE_RX_MIB_BASE + i);
		i += sizeof (uint32_t);
	}

	/*
	 * Clear TX stats.
	 */
	i = 0;
	reg = &smb.tx_frames;
	while (reg++ <= &smb.tx_mcast_bytes) {
		(void) INL(atgep, ATGE_TX_MIB_BASE + i);
		i += sizeof (uint32_t);
	}
}

void
atge_l1c_gather_stats(atge_t *atgep)
{
	atge_l1c_data_t *l1c;
	atge_dma_t *dma;
	atge_l1c_smb_t *stat;
	atge_l1c_smb_t *smb;

	ASSERT(atgep != NULL);

	l1c = atgep->atge_private_data;
	dma = l1c->atge_l1c_smb;
	DMA_SYNC(dma, 0, 0, DDI_DMA_SYNC_FORKERNEL);
	stat = (atge_l1c_smb_t *)atgep->atge_hw_stats;
	smb = (atge_l1c_smb_t *)dma->addr;

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
	DMA_SYNC(dma, 0, 0, DDI_DMA_SYNC_FORDEV);
}

void
atge_l1c_stop_tx_mac(atge_t *atgep)
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
		/* This should be an FMA event. */
		atge_error(atgep->atge_dip, "stopping TX DMA Engine timeout");
	}
}

void
atge_l1c_stop_rx_mac(atge_t *atgep)
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
		/* This should be an FMA event. */
		atge_error(atgep->atge_dip, " stopping RX DMA Engine timeout");
	}
}

/*
 * Receives (consumes) packets.
 */
static mblk_t *
atge_l1c_rx(atge_t *atgep)
{
	atge_l1c_data_t *l1c;
	mblk_t *mp = NULL, *rx_head = NULL, *rx_tail = NULL;
	l1c_rx_rdesc_t *rx_rr;
	uint32_t rdinfo, status, totlen, pktlen, slotlen;
	int nsegs, rx_cons = 0, cnt;
	atge_dma_t *buf;
	uchar_t *bufp;
	int sync = 0;

	l1c = atgep->atge_private_data;
	ASSERT(l1c != NULL);

	DMA_SYNC(l1c->atge_l1c_rr, 0, 0, DDI_DMA_SYNC_FORKERNEL);
	for (;;) {
		rx_rr = (l1c_rx_rdesc_t *)(l1c->atge_l1c_rr->addr +
		    (l1c->atge_l1c_rr_consumers * sizeof (l1c_rx_rdesc_t)));

		rdinfo = ATGE_GET32(l1c->atge_l1c_rr, &rx_rr->rdinfo);
		status = ATGE_GET32(l1c->atge_l1c_rr, &rx_rr->status);

		rx_cons = L1C_RRD_RD_IDX(rdinfo);
		nsegs = L1C_RRD_RD_CNT(rdinfo);
		totlen = L1C_RRD_BYTES(status);

		ATGE_DB(("%s: %s() PKT -- rdinfo : 0x%x,"
		    "status : 0x%x, totlen : %d,"
		    " rx_cons : %d, nsegs : %d", atgep->atge_name, __func__,
		    rdinfo, status, totlen, rx_cons, nsegs));

		if ((status & L1C_RRD_VALID) == 0) {
			break;
		}

		if ((status & (L1C_RRD_ERR_CRC | L1C_RRD_ERR_ALIGN |
		    L1C_RRD_ERR_TRUNC | L1C_RRD_ERR_RUNT |
		    L1C_RRD_ERR_ICMP | L1C_RRD_ERR_LENGTH)) != 0) {
			atge_error(atgep->atge_dip, "errored pkt");

			l1c->atge_rx_ring->r_consumer += nsegs;
			l1c->atge_rx_ring->r_consumer %= L1C_RX_RING_CNT;
			break;
		}

		ASSERT(rx_cons >= 0 && rx_cons <= L1C_RX_RING_CNT);

		mp = allocb(totlen + L1C_HEADROOM, BPRI_MED);
		if (mp != NULL) {
			mp->b_rptr += L1C_HEADROOM;
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

			rx_rr->status = 0;
			break;
		}

		for (cnt = 0, pktlen = 0; cnt < nsegs; cnt++) {
			buf = l1c->atge_rx_ring->r_buf_tbl[rx_cons];

			slotlen = min(atgep->atge_max_frame_size, totlen);

			bcopy(buf->addr, (bufp + pktlen), slotlen);
			pktlen += slotlen;
			totlen -= slotlen;

			ATGE_DB(("%s: %s() len : %d, rxcons : %d, pktlen : %d",
			    atgep->atge_name, __func__, slotlen, rx_cons,
			    pktlen));

			ATGE_INC_SLOT(rx_cons, L1C_RX_RING_CNT);
		}

		if (rx_tail == NULL) {
			rx_head = rx_tail = mp;
		} else {
			rx_tail->b_next = mp;
			rx_tail = mp;
		}

		if (cnt != nsegs) {
			l1c->atge_rx_ring->r_consumer += nsegs;
			l1c->atge_rx_ring->r_consumer %= L1C_RX_RING_CNT;
		} else {
			l1c->atge_rx_ring->r_consumer = rx_cons;
		}

		/*
		 * Tell the chip that this RR can be reused.
		 */
		rx_rr->status = 0;

		ATGE_INC_SLOT(l1c->atge_l1c_rr_consumers, L1C_RR_RING_CNT);
		sync++;
	}

	if (sync) {
		DMA_SYNC(l1c->atge_rx_ring->r_desc_ring, 0, 0,
		    DDI_DMA_SYNC_FORDEV);

		DMA_SYNC(l1c->atge_l1c_rr, 0, 0, DDI_DMA_SYNC_FORDEV);
		/*
		 * Let controller know availability of new Rx buffers.
		 */
		OUTL(atgep, ATGE_MBOX_RD0_PROD_IDX,
		    l1c->atge_rx_ring->r_consumer);

		ATGE_DB(("%s: %s() PKT Recved -> r_consumer : %d, rx_cons : %d"
		    " atge_l1c_rr_consumers : %d",
		    atgep->atge_name, __func__, l1c->atge_rx_ring->r_consumer,
		    rx_cons, l1c->atge_l1c_rr_consumers));
	}


	return (rx_head);
}

/*
 * The interrupt handler for L1C chip.
 */
/*ARGSUSED*/
uint_t
atge_l1c_interrupt(caddr_t arg1, caddr_t arg2)
{
	atge_t *atgep = (void *)arg1;
	mblk_t *rx_head = NULL;
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
	if (status & L1C_INTR_GPHY) {
		/* clear PHY interrupt source before we ack interrupts */
		(void) atge_mii_read(atgep,
		    atgep->atge_phyaddr, ATGE_ISR_ACK_GPHY);
	}

	OUTL(atgep, ATGE_INTR_STATUS, status | L1C_INTR_DIS_INT);
	FLUSH(atgep, ATGE_INTR_STATUS);

	/*
	 * Check if chip is running, only then do the work.
	 */
	if (atgep->atge_chip_state & ATGE_CHIP_RUNNING) {
		atge_l1c_data_t *l1c;

		l1c = atgep->atge_private_data;

		ATGE_DB(("%s: %s() atge_l1c_intr_status : %x, "
		    "atge_l1c_rx_prod_cons : %d, atge_l1c_tx_prod_cons : %d"
		    " atge_l1c_rr_consumers : %d",
		    atgep->atge_name, __func__, l1c->atge_l1c_intr_status,
		    l1c->atge_l1c_rx_prod_cons, l1c->atge_l1c_tx_prod_cons,
		    l1c->atge_l1c_rr_consumers));

		if (status & L1C_INTR_SMB)
			atge_l1c_gather_stats(atgep);

		/*
		 * Check for errors.
		 */
		if (status & (L1C_INTR_DMA_RD_TO_RST |
		    L1C_INTR_DMA_WR_TO_RST | L1C_INTR_TXQ_TO_RST)) {
			/* This should be an FMA event. */
			atge_error(atgep->atge_dip,
			    "L1C chip detected a fatal error, "
			    "interrupt status: %x", status);

			if (status & L1C_INTR_DMA_RD_TO_RST) {
				atge_error(atgep->atge_dip,
				    "DMA read error");
			}
			if (status & L1C_INTR_DMA_WR_TO_RST) {
				atge_error(atgep->atge_dip,
				    "DMA write error");
			}
			if (status & L1C_INTR_TXQ_TO_RST) {
				atge_error(atgep->atge_dip,
				    "Transmit queue error");
			}

			/* This should be an FMA event. */
			atge_device_stop(atgep);
			/*
			 * Device has failed fatally.
			 * It will not be restarted by the driver.
			 */
			goto done;

		}

		rx_head = atge_l1c_rx(atgep);
		if (status & L1C_INTR_TX_PKT) {
			int cons;

			mutex_enter(&atgep->atge_tx_lock);
			cons = INL(atgep, ATGE_MBOX_TD_CONS_IDX) >> 16;
			atge_tx_reclaim(atgep, cons);
			if (atgep->atge_tx_resched) {
				atgep->atge_tx_resched = 0;
				resched = 1;
			}

			mutex_exit(&atgep->atge_tx_lock);
		}
	}

	/* Re-enable interrupts. */
	OUTL(atgep, ATGE_INTR_STATUS, 0);

done:
	mutex_exit(&atgep->atge_intr_lock);

	if (status & L1C_INTR_GPHY) {
		/* link down */
		ATGE_DB(("%s: %s() MII_CHECK Performed",
		    atgep->atge_name, __func__));
		mii_check(atgep->atge_mii);
	}

	/*
	 * Pass the list of packets received from chip to MAC layer.
	 */
	if (rx_head) {
		mac_rx(atgep->atge_mh, 0, rx_head);
	}

	/*
	 * Let MAC start sending pkts if the downstream was asked to pause.
	 */
	if (resched)
		mac_tx_update(atgep->atge_mh);

	return (DDI_INTR_CLAIMED);
}

void
atge_l1c_send_packet(atge_ring_t *r)
{
	atge_t *atgep;

	atgep = r->r_atge;

	mutex_enter(&atgep->atge_mbox_lock);
	/* Sync descriptors. */
	DMA_SYNC(atgep->atge_tx_ring->r_desc_ring, 0, 0, DDI_DMA_SYNC_FORDEV);
	/* Kick. Assume we're using normal Tx priority queue. */
	OUTL(atgep, ATGE_MBOX_TD_PROD_IDX,
	    (atgep->atge_tx_ring->r_producer << MBOX_TD_PROD_LO_IDX_SHIFT) &
	    MBOX_TD_PROD_LO_IDX_MASK);
	mutex_exit(&atgep->atge_mbox_lock);
}
