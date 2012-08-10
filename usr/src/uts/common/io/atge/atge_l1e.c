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
#include "atge_l1e_reg.h"
#include "atge_cmn_reg.h"

/*
 * L1E specfic functions.
 */
void	atge_l1e_device_reset(atge_t *);
void	atge_l1e_stop_rx_mac(atge_t *);
void	atge_l1e_stop_tx_mac(atge_t *);

static ddi_dma_attr_t atge_l1e_dma_attr_tx_desc = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0x0000ffffffffull,	/* dma_attr_addr_hi */
	0x0000ffffffffull,	/* dma_attr_count_max */
	L1E_TX_RING_ALIGN,	/* dma_attr_align */
	0x0000fffc,		/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0x0000ffffffffull,	/* dma_attr_maxxfer */
	0x0000ffffffffull,	/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

static ddi_dma_attr_t atge_l1e_dma_attr_rx_desc = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0x0000ffffffffull,	/* dma_attr_addr_hi */
	0x0000ffffffffull,	/* dma_attr_count_max */
	L1E_RX_PAGE_ALIGN,	/* dma_attr_align */
	0x0000fffc,		/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0x0000ffffffffull,	/* dma_attr_maxxfer */
	0x0000ffffffffull,	/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

static ddi_dma_attr_t atge_l1e_dma_attr_cmb = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0x0000ffffffffull,	/* dma_attr_addr_hi */
	0x0000ffffffffull,	/* dma_attr_count_max */
	L1E_CMB_ALIGN,		/* dma_attr_align */
	0x0000fffc,		/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0x0000ffffffffull,	/* dma_attr_maxxfer */
	0x0000ffffffffull,	/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

void	atge_l1e_rx_next_pkt(atge_t *, uint32_t);

void
atge_rx_desc_free(atge_t *atgep)
{
	atge_l1e_data_t *l1e;
	atge_dma_t *dma;
	int pages;

	l1e = (atge_l1e_data_t *)atgep->atge_private_data;
	if (l1e == NULL)
		return;

	if (l1e->atge_l1e_rx_page == NULL)
		return;

	for (pages = 0; pages < L1E_RX_PAGES; pages++) {
		dma = l1e->atge_l1e_rx_page[pages];
		if (dma != NULL) {
			(void) ddi_dma_unbind_handle(dma->hdl);
			ddi_dma_mem_free(&dma->acchdl);
			ddi_dma_free_handle(&dma->hdl);
			kmem_free(dma, sizeof (atge_dma_t));
		}
	}

	kmem_free(l1e->atge_l1e_rx_page, L1E_RX_PAGES * sizeof (atge_dma_t *));
	l1e->atge_l1e_rx_page = NULL;
}

int
atge_l1e_alloc_dma(atge_t *atgep)
{
	atge_dma_t *dma;
	atge_l1e_data_t *l1e;
	int err;
	int pages;
	int guard_size;

	l1e = kmem_zalloc(sizeof (atge_l1e_data_t), KM_SLEEP);
	atgep->atge_private_data = l1e;

	/*
	 * Allocate TX ring descriptor.
	 */
	atgep->atge_tx_buf_len = atgep->atge_mtu +
	    sizeof (struct ether_header) + VLAN_TAGSZ + ETHERFCSL;
	atgep->atge_tx_ring = kmem_alloc(sizeof (atge_ring_t), KM_SLEEP);
	atgep->atge_tx_ring->r_atge = atgep;
	atgep->atge_tx_ring->r_desc_ring = NULL;
	dma = atge_alloc_a_dma_blk(atgep, &atge_l1e_dma_attr_tx_desc,
	    ATGE_TX_RING_SZ, DDI_DMA_RDWR);
	if (dma == NULL) {
		ATGE_DB(("%s :%s failed",
		    atgep->atge_name, __func__));
		return (DDI_FAILURE);
	}
	atgep->atge_tx_ring->r_desc_ring = dma;

	/*
	 * Allocate DMA buffers for TX ring.
	 */
	err = atge_alloc_buffers(atgep->atge_tx_ring, ATGE_TX_RING_CNT,
	    atgep->atge_tx_buf_len, DDI_DMA_WRITE);
	if (err != DDI_SUCCESS) {
		ATGE_DB(("%s :%s() TX buffers failed",
		    atgep->atge_name, __func__));
		return (err);
	}

	/*
	 * Allocate RX pages.
	 */
	atgep->atge_rx_buf_len = atgep->atge_mtu +
	    sizeof (struct ether_header) + VLAN_TAGSZ + ETHERFCSL;

	if (atgep->atge_flags & ATGE_FLAG_JUMBO)
		guard_size = L1E_JUMBO_FRAMELEN;
	else
		guard_size = L1E_MAX_FRAMELEN;

	l1e->atge_l1e_pagesize = ROUNDUP(guard_size + L1E_RX_PAGE_SZ,
	    L1E_RX_PAGE_ALIGN);
	l1e->atge_l1e_rx_page =
	    kmem_zalloc(L1E_RX_PAGES * sizeof (atge_dma_t *), KM_SLEEP);

	ATGE_DB(("%s: %s() atge_l1e_pagesize : %d, L1E_RX_PAGE_SZ : %d",
	    atgep->atge_name, __func__, l1e->atge_l1e_pagesize,
	    L1E_RX_PAGE_SZ));

	err = DDI_SUCCESS;
	for (pages = 0; pages < L1E_RX_PAGES; pages++) {
		dma = atge_alloc_a_dma_blk(atgep, &atge_l1e_dma_attr_rx_desc,
		    l1e->atge_l1e_pagesize, DDI_DMA_READ);

		if (dma == NULL) {
			err = DDI_FAILURE;
			break;
		}

		l1e->atge_l1e_rx_page[pages] = dma;
	}

	if (err == DDI_FAILURE) {
		ATGE_DB(("%s :%s RX pages failed",
		    atgep->atge_name, __func__));
		return (DDI_FAILURE);
	}

	/*
	 * Allocate CMB used for fetching interrupt status data.
	 */
	ATGE_DB(("%s: %s() L1E_RX_CMB_SZ : %x", atgep->atge_name,
	    __func__, L1E_RX_CMB_SZ));

	err = DDI_SUCCESS;
	dma = atge_alloc_a_dma_blk(atgep, &atge_l1e_dma_attr_cmb,
	    L1E_RX_CMB_SZ * L1E_RX_PAGES, DDI_DMA_RDWR);
	if (dma == NULL) {
		ATGE_DB(("%s :%s() RX CMB failed",
		    atgep->atge_name, __func__));
		return (DDI_FAILURE);
	}
	l1e->atge_l1e_rx_cmb = dma;

	if (err == DDI_FAILURE) {
		ATGE_DB(("%s :%s() RX CMB failed",
		    atgep->atge_name, __func__));
		return (DDI_FAILURE);
	}

	atgep->atge_hw_stats = kmem_zalloc(sizeof (atge_l1e_smb_t), KM_SLEEP);

	return (DDI_SUCCESS);
}

void
atge_l1e_free_dma(atge_t *atgep)
{
	atge_l1e_data_t *l1e;

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

	l1e = atgep->atge_private_data;
	if (l1e == NULL)
		return;

	/*
	 * Free RX CMB.
	 */
	if (l1e->atge_l1e_rx_cmb != NULL) {
		atge_free_a_dma_blk(l1e->atge_l1e_rx_cmb);
		l1e->atge_l1e_rx_cmb = NULL;
	}

	/*
	 * Free RX buffers and RX ring.
	 */
	atge_rx_desc_free(atgep);

	/*
	 * Free the memory allocated for gathering hw stats.
	 */
	if (atgep->atge_hw_stats != NULL) {
		kmem_free(atgep->atge_hw_stats, sizeof (atge_l1e_smb_t));
		atgep->atge_hw_stats = NULL;
	}
}

void
atge_l1e_init_rx_pages(atge_t *atgep)
{
	atge_l1e_data_t *l1e;
	atge_dma_t *dma;
	int pages;

	ASSERT(atgep != NULL);
	l1e = atgep->atge_private_data;

	ASSERT(l1e != NULL);

	l1e->atge_l1e_proc_max = L1E_RX_PAGE_SZ / ETHERMIN;
	l1e->atge_l1e_rx_curp = 0;
	l1e->atge_l1e_rx_seqno = 0;

	for (pages = 0; pages < L1E_RX_PAGES; pages++) {
		l1e->atge_l1e_rx_page_cons = 0;
		l1e->atge_l1e_rx_page_prods[pages] = 0;


		dma = l1e->atge_l1e_rx_page[pages];
		ASSERT(dma != NULL);
		bzero(dma->addr, l1e->atge_l1e_pagesize);
		DMA_SYNC(dma, 0, l1e->atge_l1e_pagesize, DDI_DMA_SYNC_FORDEV);
	}

	dma = l1e->atge_l1e_rx_cmb;
	ASSERT(dma != NULL);
	bzero(dma->addr, L1E_RX_CMB_SZ * L1E_RX_PAGES);
	DMA_SYNC(dma, 0, L1E_RX_CMB_SZ * L1E_RX_PAGES, DDI_DMA_SYNC_FORDEV);
}

void
atge_l1e_init_tx_ring(atge_t *atgep)
{
	ASSERT(atgep != NULL);
	ASSERT(atgep->atge_tx_ring != NULL);
	ASSERT(atgep->atge_tx_ring->r_desc_ring != NULL);

	atgep->atge_tx_ring->r_producer = 0;
	atgep->atge_tx_ring->r_consumer = 0;
	atgep->atge_tx_ring->r_avail_desc = ATGE_TX_RING_CNT;

	bzero(atgep->atge_tx_ring->r_desc_ring->addr, ATGE_TX_RING_SZ);

	DMA_SYNC(atgep->atge_tx_ring->r_desc_ring, 0, ATGE_TX_RING_SZ,
	    DDI_DMA_SYNC_FORDEV);
}

void
atge_l1e_program_dma(atge_t *atgep)
{
	atge_l1e_data_t *l1e;
	uint64_t paddr;
	uint32_t reg;

	l1e = (atge_l1e_data_t *)atgep->atge_private_data;

	/*
	 * Clear WOL status and disable all WOL feature as WOL
	 * would interfere Rx operation under normal environments.
	 */
	(void) INL(atgep, ATGE_WOL_CFG);
	OUTL(atgep, ATGE_WOL_CFG, 0);

	/*
	 * Set Tx descriptor/RXF0/CMB base addresses. They share
	 * the same high address part of DMAable region.
	 */
	paddr = atgep->atge_tx_ring->r_desc_ring->cookie.dmac_laddress;
	OUTL(atgep, ATGE_DESC_ADDR_HI, ATGE_ADDR_HI(paddr));
	OUTL(atgep, ATGE_DESC_TPD_ADDR_LO, ATGE_ADDR_LO(paddr));
	OUTL(atgep, ATGE_DESC_TPD_CNT,
	    (ATGE_TX_RING_CNT << DESC_TPD_CNT_SHIFT) & DESC_TPD_CNT_MASK);

	/* Set Rx page base address, note we use single queue. */
	paddr = l1e->atge_l1e_rx_page[0]->cookie.dmac_laddress;
	OUTL(atgep, L1E_RXF0_PAGE0_ADDR_LO, ATGE_ADDR_LO(paddr));
	paddr = l1e->atge_l1e_rx_page[1]->cookie.dmac_laddress;
	OUTL(atgep, L1E_RXF0_PAGE1_ADDR_LO, ATGE_ADDR_LO(paddr));

	/* Set Tx/Rx CMB addresses. */
	paddr = l1e->atge_l1e_rx_cmb->cookie.dmac_laddress;
	OUTL(atgep, L1E_RXF0_CMB0_ADDR_LO, ATGE_ADDR_LO(paddr));
	paddr = l1e->atge_l1e_rx_cmb->cookie.dmac_laddress + sizeof (uint32_t);
	OUTL(atgep, L1E_RXF0_CMB1_ADDR_LO, ATGE_ADDR_LO(paddr));

	/* Mark RXF0 valid. */
	OUTB(atgep, L1E_RXF0_PAGE0, RXF_VALID);	/* 0 */
	OUTB(atgep, L1E_RXF0_PAGE1, RXF_VALID);	/* 1 */
	OUTB(atgep, L1E_RXF0_PAGE0 + 2, 0);
	OUTB(atgep, L1E_RXF0_PAGE0 + 3, 0);
	OUTB(atgep, L1E_RXF0_PAGE0 + 4, 0);
	OUTB(atgep, L1E_RXF0_PAGE0 + 5, 0);
	OUTB(atgep, L1E_RXF0_PAGE0 + 6, 0);
	OUTB(atgep, L1E_RXF0_PAGE0 + 6, 0);

	/* Set Rx page size, excluding guard frame size. */
	OUTL(atgep, L1E_RXF_PAGE_SIZE, L1E_RX_PAGE_SZ);

	/* Tell hardware that we're ready to load DMA blocks. */
	OUTL(atgep, ATGE_DMA_BLOCK, DMA_BLOCK_LOAD);

	/* Set Rx/Tx interrupt trigger threshold. */
	OUTL(atgep, L1E_INT_TRIG_THRESH, (1 << INT_TRIG_RX_THRESH_SHIFT) |
	    (4 << INT_TRIG_TX_THRESH_SHIFT));

	/*
	 * Set interrupt trigger timer, its purpose and relation
	 * with interrupt moderation mechanism is not clear yet.
	 */
	OUTL(atgep, L1E_INT_TRIG_TIMER,
	    ((ATGE_USECS(10) << INT_TRIG_RX_TIMER_SHIFT) |
	    (ATGE_USECS(1000) << INT_TRIG_TX_TIMER_SHIFT)));

	reg = ATGE_USECS(ATGE_IM_RX_TIMER_DEFAULT) << IM_TIMER_RX_SHIFT;
	reg |= ATGE_USECS(ATGE_IM_TX_TIMER_DEFAULT) << IM_TIMER_TX_SHIFT;
	OUTL(atgep, ATGE_IM_TIMER, reg);

	reg = INL(atgep, ATGE_MASTER_CFG);
	reg &= ~(L1E_MASTER_CHIP_REV_MASK | L1E_MASTER_CHIP_ID_MASK);
	reg &= ~(L1E_MASTER_IM_RX_TIMER_ENB | L1E_MASTER_IM_TX_TIMER_ENB);
	reg |= L1E_MASTER_IM_RX_TIMER_ENB;
	reg |= L1E_MASTER_IM_TX_TIMER_ENB;
	OUTL(atgep, ATGE_MASTER_CFG, reg);

	OUTW(atgep, RX_COALSC_PKT_1e, 0);
	OUTW(atgep, RX_COALSC_TO_1e, 0);
	OUTW(atgep, TX_COALSC_PKT_1e, 1);
	OUTW(atgep, TX_COALSC_TO_1e, 4000/2);		/* 4mS */
}

mblk_t *
atge_l1e_receive(atge_t *atgep)
{
	atge_l1e_data_t *l1e;
	atge_dma_t *dma_rx_page;
	atge_dma_t *dma_rx_cmb;
	uint32_t *ptr;
	uint32_t cons, current_page;
	uchar_t *pageaddr, *bufp;
	rx_rs_t	*rs;
	int prog;
	uint32_t seqno, len, flags;
	mblk_t *mp = NULL, *rx_head, *rx_tail;
	static uint32_t gen = 0;

	l1e = atgep->atge_private_data;

	ASSERT(MUTEX_HELD(&atgep->atge_intr_lock));
	ASSERT(l1e != NULL);

	rx_tail = NULL;
	rx_head = NULL;

	current_page = l1e->atge_l1e_rx_curp;

	/* Sync CMB first */
	dma_rx_cmb = l1e->atge_l1e_rx_cmb;
	DMA_SYNC(dma_rx_cmb, 0, L1E_RX_CMB_SZ * L1E_RX_PAGES,
	    DDI_DMA_SYNC_FORKERNEL);

	dma_rx_page = l1e->atge_l1e_rx_page[current_page];

	/*
	 * Get the producer offset from CMB.
	 */
	ptr = (void *)dma_rx_cmb->addr;

	l1e->atge_l1e_rx_page_prods[current_page] =
	    ATGE_GET32(dma_rx_cmb, ptr + current_page);

	/* Sync current RX Page as well */
	DMA_SYNC(dma_rx_page, l1e->atge_l1e_rx_page_cons,
	    l1e->atge_l1e_rx_page_prods[current_page], DDI_DMA_SYNC_FORKERNEL);

	ATGE_DB(("%s: %s() prod : %d, cons : %d, curr page : %d, gen : (%d)"
	    " cmb[0,1] : %d, %d",
	    atgep->atge_name, __func__,
	    l1e->atge_l1e_rx_page_prods[current_page],
	    l1e->atge_l1e_rx_page_cons, l1e->atge_l1e_rx_curp, gen,
	    ATGE_GET32(dma_rx_cmb, ptr), ATGE_GET32(dma_rx_cmb, ptr + 1)));

	for (prog = 0; prog <= l1e->atge_l1e_proc_max; prog++) {
		cons = l1e->atge_l1e_rx_page_cons;
		if (cons >= l1e->atge_l1e_rx_page_prods[l1e->atge_l1e_rx_curp])
			break;

		dma_rx_page = l1e->atge_l1e_rx_page[l1e->atge_l1e_rx_curp];
		pageaddr = (uchar_t *)dma_rx_page->addr;
		pageaddr = pageaddr + cons;
		rs = (rx_rs_t *)pageaddr;

		seqno = ATGE_GET32(dma_rx_page, &(rs->seqno));
		seqno = L1E_RX_SEQNO(seqno);

		len = ATGE_GET32(dma_rx_page, &(rs->length));
		len = L1E_RX_BYTES(len);

		flags = ATGE_GET32(dma_rx_page, &(rs->flags));

		if (seqno != l1e->atge_l1e_rx_seqno) {
			/*
			 * We have not seen this happening but we
			 * must restart the chip if that happens.
			 */
			ATGE_DB(("%s: %s() MISS-MATCH in seqno :%d,"
			    " atge_l1e_rx_seqno : %d, length : %d, flags : %x",
			    atgep->atge_name, __func__, seqno,
			    l1e->atge_l1e_rx_seqno, len, flags));

			mutex_enter(&atgep->atge_tx_lock);
			atge_device_restart(atgep);
			mutex_exit(&atgep->atge_tx_lock);

			/*
			 * Return all the pkts received before restarting
			 * the chip.
			 */
			return (rx_head);
		} else {
			l1e->atge_l1e_rx_seqno++;
		}

		/*
		 * We will pass the pkt to upper layer provided it's clear
		 * from any error.
		 */
		if ((flags & L1E_RD_ERROR) != 0) {
			if ((flags & (L1E_RD_CRC | L1E_RD_CODE |
			    L1E_RD_DRIBBLE | L1E_RD_RUNT | L1E_RD_OFLOW |
			    L1E_RD_TRUNC)) != 0) {
				ATGE_DB(("%s: %s() ERRORED PKT : %x",
				    atgep->atge_name, __func__, flags));
				atge_l1e_rx_next_pkt(atgep, len);
				atgep->atge_errrcv++;
				continue;
			}
		}

		/*
		 * So we have received a frame/pkt.
		 */
		if (len == 0 || len > atgep->atge_rx_buf_len) {
			ATGE_DB(("%s: %s() PKT len > error : %d",
			    atgep->atge_name, __func__, len));
			atge_l1e_rx_next_pkt(atgep, len);
			continue;
		}

		mp = allocb(len + VLAN_TAGSZ, BPRI_MED);
		if (mp != NULL) {
			mp->b_rptr += VLAN_TAGSZ;
			bufp = mp->b_rptr;
			mp->b_wptr = bufp + len;
			mp->b_next = NULL;

			bcopy(pageaddr + sizeof (rx_rs_t), bufp, len);

			if (rx_tail == NULL)
				rx_head = rx_tail = mp;
			else {
				rx_tail->b_next = mp;
				rx_tail = mp;
			}

			atgep->atge_ipackets++;
			atgep->atge_rbytes += len;
		} else {
			ATGE_DB(("%s: %s() PKT mp == NULL len : %d",
			    atgep->atge_name, __func__, len));

			if (len > atgep->atge_rx_buf_len) {
				atgep->atge_toolong_errors++;
			} else if (mp == NULL) {
				atgep->atge_norcvbuf++;
			}
		}

		atge_l1e_rx_next_pkt(atgep, len);

		ATGE_DB(("%s: %s() seqno :%d, atge_l1e_rx_seqno :"
		    " %d, length : %d,"
		    " flags : %x, cons : %d, prod : %d",
		    atgep->atge_name, __func__, seqno,
		    l1e->atge_l1e_rx_seqno, len, flags,
		    l1e->atge_l1e_rx_page_cons,
		    l1e->atge_l1e_rx_page_prods[l1e->atge_l1e_rx_curp]));
	}

	ATGE_DB(("%s: %s() receive completed (gen : %d) : cons : %d,"
	    " prod :%d, L1E_RX_PAGE_SZ : %d (prog:%d)",
	    atgep->atge_name, __func__, gen,
	    l1e->atge_l1e_rx_page_cons,
	    l1e->atge_l1e_rx_page_prods[l1e->atge_l1e_rx_curp],
	    L1E_RX_PAGE_SZ, prog));

	gen++;
	return (rx_head);
}

void
atge_l1e_rx_next_pkt(atge_t *atgep, uint32_t len)
{
	atge_l1e_data_t *l1e = atgep->atge_private_data;
	atge_dma_t *dma_rx_page;
	atge_dma_t *dma_rx_cmb;
	int curr = l1e->atge_l1e_rx_curp;
	uint32_t *p;

	/*
	 * Update consumer position.
	 */
	l1e->atge_l1e_rx_page_cons +=
	    ROUNDUP(len + sizeof (rx_rs_t), L1E_RX_PAGE_ALIGN);

	/*
	 * If we need to flip to the other page. Note that we use only two
	 * pages.
	 */
	if (l1e->atge_l1e_rx_page_cons >= L1E_RX_PAGE_SZ) {
		ATGE_DB(("%s: %s() cons : %d, prod :%d, L1E_RX_PAGE_SZ : %d",
		    atgep->atge_name, __func__, l1e->atge_l1e_rx_page_cons,
		    l1e->atge_l1e_rx_page_prods[curr], L1E_RX_PAGE_SZ));

		/*
		 * Clear the producer.
		 */
		dma_rx_cmb = l1e->atge_l1e_rx_cmb;
		p = (void *)dma_rx_cmb->addr;
		p = p + curr;
		*p = 0;
		DMA_SYNC(dma_rx_cmb, curr * L1E_RX_CMB_SZ,
		    L1E_RX_CMB_SZ, DDI_DMA_SYNC_FORDEV);

		/*
		 * Notify the NIC that the current RX page is available again.
		 */
		OUTB(atgep, L1E_RXF0_PAGE0 + curr, RXF_VALID);

		/*
		 * End of Rx page reached, let hardware reuse this page.
		 */
		l1e->atge_l1e_rx_page_cons = 0;
		l1e->atge_l1e_rx_page_prods[curr] = 0;

		/*
		 * Switch to alternate Rx page.
		 */
		curr ^= 1;
		l1e->atge_l1e_rx_curp = curr;

		/*
		 * Page flipped, sync CMB and then Rx page.
		 */
		DMA_SYNC(dma_rx_cmb, 0, L1E_RX_PAGES * L1E_RX_CMB_SZ,
		    DDI_DMA_SYNC_FORKERNEL);
		p = (void *)dma_rx_cmb->addr;
		l1e->atge_l1e_rx_page_prods[curr] =
		    ATGE_GET32(dma_rx_cmb, p + curr);

		dma_rx_page = l1e->atge_l1e_rx_page[curr];
		DMA_SYNC(dma_rx_page, 0, l1e->atge_l1e_rx_page_prods[curr],
		    DDI_DMA_SYNC_FORKERNEL);

		ATGE_DB(("%s: %s() PAGE FLIPPED -> %d, producer[0,1]: %d, %d",
		    atgep->atge_name, __func__, curr,
		    ATGE_GET32(dma_rx_cmb, p), ATGE_GET32(dma_rx_cmb, p + 1)));
	}
}

void
atge_l1e_send_packet(atge_ring_t *r)
{
	/*
	 * Ask chip to send the packet now.
	 */
	OUTL(r->r_atge, ATGE_MBOX, r->r_producer);
}

void
atge_l1e_clear_stats(atge_t *atgep)
{
	atge_l1e_smb_t smb;
	uint32_t *reg;
	int i;

	/*
	 * Clear RX stats first.
	 */
	i = 0;
	reg = &smb.rx_frames;
	while (reg++ <= &smb.rx_pkts_filtered) {
		(void) INL(atgep, L1E_RX_MIB_BASE + i);
		i += sizeof (uint32_t);
	}

	/*
	 * Clear TX stats.
	 */
	i = 0;
	reg = &smb.tx_frames;
	while (reg++ <= &smb.tx_mcast_bytes) {
		(void) INL(atgep, L1E_TX_MIB_BASE + i);
		i += sizeof (uint32_t);
	}
}

void
atge_l1e_gather_stats(atge_t *atgep)
{
	atge_l1e_smb_t *stat;
	atge_l1e_smb_t *smb;
	atge_l1e_smb_t local_smb;
	uint32_t *reg;
	int i;

	ASSERT(atgep != NULL);

	stat = (atge_l1e_smb_t *)atgep->atge_hw_stats;

	bzero(&local_smb, sizeof (atge_l1e_smb_t));
	smb = &local_smb;

	/* Read Rx statistics. */
	i = 0;
	reg = &smb->rx_frames;
	while (reg++ <= &smb->rx_pkts_filtered) {
		*reg = INL(atgep, L1E_RX_MIB_BASE + i);
		i += sizeof (uint32_t);
	}

	/* Read Tx statistics. */
	i = 0;
	reg = &smb->tx_frames;
	while (reg++ <= &smb->tx_mcast_bytes) {
		*reg = INL(atgep, L1E_TX_MIB_BASE + i);
		i += sizeof (uint32_t);
	}

	/*
	 * SMB is cleared everytime we read; hence we always do '+='.
	 */

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
	stat->rx_rrs_errs += smb->rx_rrs_errs;
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
	stat->tx_abort += smb->tx_abort;
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
	atgep->atge_sqe_errors += smb->rx_rrs_errs;
	atgep->atge_defer_xmts += smb->tx_deferred;
	atgep->atge_first_collisions += smb->tx_single_colls;
	atgep->atge_multi_collisions += smb->tx_multi_colls * 2;
	atgep->atge_tx_late_collisions += smb->tx_late_colls;
	atgep->atge_ex_collisions += smb->tx_excess_colls;
	atgep->atge_macxmt_errors += smb->tx_abort;
	atgep->atge_toolong_errors += smb->rx_lenerrs;
	atgep->atge_overflow += smb->rx_fifo_oflows;
	atgep->atge_underflow += (smb->tx_underrun + smb->tx_desc_underrun);
	atgep->atge_runt += smb->rx_runts;


	atgep->atge_collisions += smb->tx_single_colls +
	    smb->tx_multi_colls * 2 + smb->tx_late_colls +
	    smb->tx_abort * HDPX_CFG_RETRY_DEFAULT;

	/*
	 * tx_pkts_truncated counter looks suspicious. It constantly
	 * increments with no sign of Tx errors. Hence we don't factor it.
	 */
	atgep->atge_macxmt_errors += smb->tx_abort + smb->tx_late_colls +
	    smb->tx_underrun;

	atgep->atge_macrcv_errors += smb->rx_crcerrs + smb->rx_lenerrs +
	    smb->rx_runts + smb->rx_pkts_truncated +
	    smb->rx_fifo_oflows + smb->rx_rrs_errs +
	    smb->rx_alignerrs;
}

void
atge_l1e_stop_mac(atge_t *atgep)
{
	uint32_t reg;

	reg = INL(atgep, ATGE_MAC_CFG);
	ATGE_DB(("%s: %s() reg : %x", atgep->atge_name, __func__, reg));

	if ((reg & (ATGE_CFG_TX_ENB | ATGE_CFG_RX_ENB)) != 0) {
		reg &= ~ATGE_CFG_TX_ENB | ATGE_CFG_RX_ENB;
		OUTL(atgep, ATGE_MAC_CFG, reg);
		ATGE_DB(("%s: %s() mac stopped", atgep->atge_name, __func__));
	}
}

/*
 * The interrupt handler for L1E/L2E
 */
/*ARGSUSED*/
uint_t
atge_l1e_interrupt(caddr_t arg1, caddr_t arg2)
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
	OUTL(atgep, ATGE_INTR_STATUS, status | INTR_DIS_INT);
	FLUSH(atgep, ATGE_INTR_STATUS);

	/*
	 * Check if chip is running, only then do the work.
	 */
	if (atgep->atge_chip_state & ATGE_CHIP_RUNNING) {
		if (status & INTR_SMB) {
			atge_l1e_gather_stats(atgep);
		}

		/*
		 * Check for errors.
		 */
		if (status & L1E_INTR_ERRORS) {
			atge_error(atgep->atge_dip,
			    "L1E chip found an error intr status : %x",
			    status);

			if (status &
			    (INTR_DMA_RD_TO_RST | INTR_DMA_WR_TO_RST)) {
				atge_error(atgep->atge_dip, "DMA transfer err");

				atge_device_stop(atgep);
				goto done;
			}

			if (status & INTR_TX_FIFO_UNDERRUN) {
				atge_error(atgep->atge_dip, "TX FIFO underrun");
			}
		}

		rx_head = atge_l1e_receive(atgep);

		if (status & INTR_TX_PKT) {
			int cons;

			mutex_enter(&atgep->atge_tx_lock);
			cons = INW(atgep, L1E_TPD_CONS_IDX);
			atge_tx_reclaim(atgep, cons);
			if (atgep->atge_tx_resched) {
				atgep->atge_tx_resched = 0;
				resched = 1;
			}

			mutex_exit(&atgep->atge_tx_lock);
		}
	}

	/*
	 * Enable interrupts.
	 */
	OUTL(atgep, ATGE_INTR_STATUS, 0);

done:

	mutex_exit(&atgep->atge_intr_lock);

	if (status & INTR_GPHY) {
		/*
		 * Ack interrupts from PHY
		 */
		(void) atge_mii_read(atgep,
		    atgep->atge_phyaddr, ATGE_ISR_ACK_GPHY);

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
