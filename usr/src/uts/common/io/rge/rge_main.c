/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "rge.h"

/*
 * This is the string displayed by modinfo, etc.
 * Make sure you keep the version ID up to date!
 */
static char rge_ident[] = "Realtek Gigabit Ethernet Driver v%I%";

/*
 * Used for buffers allocated by ddi_dma_mem_alloc()
 */
static ddi_dma_attr_t dma_attr_buf = {
	DMA_ATTR_V0,		/* dma_attr version */
	(uint32_t)0,		/* dma_attr_addr_lo */
	(uint32_t)0xFFFFFFFF,	/* dma_attr_addr_hi */
	(uint32_t)0xFFFFFFFF,	/* dma_attr_count_max */
	(uint32_t)16,		/* dma_attr_align */
	0xFFFFFFFF,		/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	(uint32_t)0xFFFFFFFF,	/* dma_attr_maxxfer */
	(uint32_t)0xFFFFFFFF,	/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0,			/* dma_attr_flags */
};

/*
 * Used for BDs allocated by ddi_dma_mem_alloc()
 */
static ddi_dma_attr_t dma_attr_desc = {
	DMA_ATTR_V0,		/* dma_attr version */
	(uint32_t)0,		/* dma_attr_addr_lo */
	(uint32_t)0xFFFFFFFF,	/* dma_attr_addr_hi */
	(uint32_t)0xFFFFFFFF,	/* dma_attr_count_max */
	(uint32_t)256,		/* dma_attr_align */
	0xFFFFFFFF,		/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	(uint32_t)0xFFFFFFFF,	/* dma_attr_maxxfer */
	(uint32_t)0xFFFFFFFF,	/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0,			/* dma_attr_flags */
};

/*
 * PIO access attributes for registers
 */
static ddi_device_acc_attr_t rge_reg_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

/*
 * DMA access attributes for descriptors
 */
static ddi_device_acc_attr_t rge_desc_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

/*
 * DMA access attributes for data
 */
static ddi_device_acc_attr_t rge_buf_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

static ether_addr_t rge_broadcast_addr = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

/*
 * Property names
 */
static char debug_propname[] = "rge-debug-flags";


/*
 * Allocate an area of memory and a DMA handle for accessing it
 */
static int
rge_alloc_dma_mem(rge_t *rgep, size_t memsize, ddi_dma_attr_t *dma_attr_p,
	ddi_device_acc_attr_t *acc_attr_p, uint_t dma_flags, dma_area_t *dma_p)
{
	caddr_t vaddr;
	int err;

	/*
	 * Allocate handle
	 */
	err = ddi_dma_alloc_handle(rgep->devinfo, dma_attr_p,
		    DDI_DMA_SLEEP, NULL, &dma_p->dma_hdl);
	if (err != DDI_SUCCESS) {
		dma_p->dma_hdl = NULL;
		return (DDI_FAILURE);
	}

	/*
	 * Allocate memory
	 */
	err = ddi_dma_mem_alloc(dma_p->dma_hdl, memsize, acc_attr_p,
	    dma_flags & (DDI_DMA_CONSISTENT | DDI_DMA_STREAMING),
	    DDI_DMA_SLEEP, NULL, &vaddr, &dma_p->alength, &dma_p->acc_hdl);
	if (err != DDI_SUCCESS) {
		ddi_dma_free_handle(&dma_p->dma_hdl);
		dma_p->dma_hdl = NULL;
		dma_p->acc_hdl = NULL;
		return (DDI_FAILURE);
	}

	/*
	 * Bind the two together
	 */
	dma_p->mem_va = vaddr;
	err = ddi_dma_addr_bind_handle(dma_p->dma_hdl, NULL,
	    vaddr, dma_p->alength, dma_flags, DDI_DMA_SLEEP, NULL,
	    &dma_p->cookie, &dma_p->ncookies);
	if (err != DDI_DMA_MAPPED || dma_p->ncookies != 1) {
		ddi_dma_mem_free(&dma_p->acc_hdl);
		ddi_dma_free_handle(&dma_p->dma_hdl);
		dma_p->acc_hdl = NULL;
		dma_p->dma_hdl = NULL;
		return (DDI_FAILURE);
	}

	dma_p->nslots = ~0U;
	dma_p->size = ~0U;
	dma_p->token = ~0U;
	dma_p->offset = 0;
	return (DDI_SUCCESS);
}

/*
 * Free one allocated area of DMAable memory
 */
static void
rge_free_dma_mem(dma_area_t *dma_p)
{
	if (dma_p->dma_hdl != NULL) {
		if (dma_p->ncookies) {
			(void) ddi_dma_unbind_handle(dma_p->dma_hdl);
			dma_p->ncookies = 0;
		}
		ddi_dma_free_handle(&dma_p->dma_hdl);
		dma_p->dma_hdl = NULL;
	}

	if (dma_p->acc_hdl != NULL) {
		ddi_dma_mem_free(&dma_p->acc_hdl);
		dma_p->acc_hdl = NULL;
	}
}

/*
 * Utility routine to carve a slice off a chunk of allocated memory,
 * updating the chunk descriptor accordingly.  The size of the slice
 * is given by the product of the <qty> and <size> parameters.
 */
static void
rge_slice_chunk(dma_area_t *slice, dma_area_t *chunk,
	uint32_t qty, uint32_t size)
{
	static uint32_t sequence = 0xbcd5704a;
	size_t totsize;

	totsize = qty*size;
	ASSERT(size >= 0);
	ASSERT(totsize <= chunk->alength);

	*slice = *chunk;
	slice->nslots = qty;
	slice->size = size;
	slice->alength = totsize;
	slice->token = ++sequence;

	chunk->mem_va = (caddr_t)chunk->mem_va + totsize;
	chunk->alength -= totsize;
	chunk->offset += totsize;
	chunk->cookie.dmac_laddress += totsize;
	chunk->cookie.dmac_size -= totsize;
}


static int
rge_alloc_bufs(rge_t *rgep)
{
	size_t txdescsize;
	size_t rxdescsize;
	size_t txbuffsize;
	size_t rxbuffsize;
	size_t freebuffsize;
	int split;
	int err;

	/*
	 * Allocate memory & handle for packet statistics
	 */
	err = rge_alloc_dma_mem(rgep,
	    RGE_STATS_DUMP_SIZE,
	    &dma_attr_desc,
	    &rge_desc_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &rgep->dma_area_stats);
	if (err != DDI_SUCCESS)
		return (DDI_FAILURE);
	rgep->hw_stats = DMA_VPTR(rgep->dma_area_stats);

	/*
	 * Allocate memory & handle for Tx descriptor ring
	 */
	txdescsize = RGE_SEND_SLOTS * sizeof (rge_bd_t);
	err = rge_alloc_dma_mem(rgep,
	    txdescsize,
	    &dma_attr_desc,
	    &rge_desc_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &rgep->dma_area_txdesc);
	if (err != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Allocate memory & handle for Rx descriptor ring
	 */
	rxdescsize = RGE_RECV_SLOTS * sizeof (rge_bd_t);
	err = rge_alloc_dma_mem(rgep,
	    rxdescsize,
	    &dma_attr_desc,
	    &rge_desc_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &rgep->dma_area_rxdesc);
	if (err != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Allocate memory & handle for Tx buffers
	 */
	txbuffsize = RGE_SEND_SLOTS * rgep->txbuf_size;
	ASSERT((txbuffsize % RGE_SPLIT) == 0);
	for (split = 0; split < RGE_SPLIT; ++split) {
		err = rge_alloc_dma_mem(rgep,
		    txbuffsize/RGE_SPLIT,
		    &dma_attr_buf,
		    &rge_buf_accattr,
		    DDI_DMA_WRITE | DDI_DMA_STREAMING,
		    &rgep->dma_area_txbuf[split]);
		if (err != DDI_SUCCESS)
			return (DDI_FAILURE);
	}

	/*
	 * Allocate memory & handle for Rx buffers
	 */
	rxbuffsize = RGE_RECV_SLOTS * rgep->rxbuf_size;
	ASSERT((rxbuffsize % RGE_SPLIT) == 0);
	for (split = 0; split < RGE_SPLIT; ++split) {
		err = rge_alloc_dma_mem(rgep,
		    rxbuffsize/RGE_SPLIT,
		    &dma_attr_buf,
		    &rge_buf_accattr,
		    DDI_DMA_READ | DDI_DMA_STREAMING,
		    &rgep->dma_area_rxbuf[split]);
		if (err != DDI_SUCCESS)
			return (DDI_FAILURE);
	}

	/*
	 * Allocate memory & handle for free Rx buffers
	 */
	freebuffsize = RGE_BUF_SLOTS * rgep->rxbuf_size;
	ASSERT((freebuffsize % RGE_SPLIT) == 0);
	for (split = 0; split < RGE_SPLIT; ++split) {
		err = rge_alloc_dma_mem(rgep,
		    freebuffsize/RGE_SPLIT,
		    &dma_attr_buf,
		    &rge_buf_accattr,
		    DDI_DMA_READ | DDI_DMA_STREAMING,
		    &rgep->dma_area_freebuf[split]);
		if (err != DDI_SUCCESS)
			return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * rge_free_bufs() -- free descriptors/buffers allocated for this
 * device instance.
 */
static void
rge_free_bufs(rge_t *rgep)
{
	int i;

	rge_free_dma_mem(&rgep->dma_area_stats);
	rge_free_dma_mem(&rgep->dma_area_txdesc);
	rge_free_dma_mem(&rgep->dma_area_rxdesc);
	for (i = 0; i < RGE_SPLIT; i++) {
		rge_free_dma_mem(&rgep->dma_area_txbuf[i]);
		rge_free_dma_mem(&rgep->dma_area_rxbuf[i]);
		rge_free_dma_mem(&rgep->dma_area_freebuf[i]);
	}
}

/*
 * ========== Transmit and receive ring reinitialisation ==========
 */

/*
 * These <reinit> routines each reset the rx/tx rings to an initial
 * state, assuming that the corresponding <init> routine has already
 * been called exactly once.
 */
static void
rge_reinit_send_ring(rge_t *rgep)
{
	sw_sbd_t *ssbdp;
	rge_bd_t *bdp;
	uint32_t slot;

	/*
	 * re-init send ring
	 */
	DMA_ZERO(rgep->tx_desc);
	ssbdp = rgep->sw_sbds;
	bdp = rgep->tx_ring;
	for (slot = 0; slot < RGE_SEND_SLOTS; slot++) {
		bdp->host_buf_addr =
		    RGE_BSWAP_32(ssbdp->pbuf.cookie.dmac_laddress);
		bdp->host_buf_addr_hi =
		    RGE_BSWAP_32(ssbdp->pbuf.cookie.dmac_laddress >> 32);
		/* last BD in Tx ring */
		if (slot == (RGE_SEND_SLOTS - 1))
			bdp->flags_len = RGE_BSWAP_32(BD_FLAG_EOR);
		ssbdp++;
		bdp++;
	}
	DMA_SYNC(rgep->tx_desc, DDI_DMA_SYNC_FORDEV);
	rgep->tx_next = 0;
	rgep->tc_next = 0;
	rgep->tc_tail = 0;
	rgep->tx_flow = 0;
	rgep->tx_free = RGE_SEND_SLOTS;
}

static void
rge_reinit_recv_ring(rge_t *rgep)
{
	rge_bd_t *bdp;
	sw_rbd_t *srbdp;
	dma_area_t *pbuf;
	uint32_t slot;

	/*
	 * re-init receive ring
	 */
	DMA_ZERO(rgep->rx_desc);
	srbdp = rgep->sw_rbds;
	bdp = rgep->rx_ring;
	for (slot = 0; slot < RGE_RECV_SLOTS; slot++) {
		pbuf = &srbdp->rx_buf->pbuf;
		bdp->host_buf_addr =
		    RGE_BSWAP_32(pbuf->cookie.dmac_laddress + RGE_HEADROOM);
		bdp->host_buf_addr_hi =
		    RGE_BSWAP_32(pbuf->cookie.dmac_laddress >> 32);
		bdp->flags_len = RGE_BSWAP_32(BD_FLAG_HW_OWN |
		    (rgep->rxbuf_size - RGE_HEADROOM));
		/* last BD in Tx ring */
		if (slot == (RGE_RECV_SLOTS - 1))
			bdp->flags_len |= RGE_BSWAP_32(BD_FLAG_EOR);
		srbdp++;
		bdp++;
	}
	DMA_SYNC(rgep->rx_desc, DDI_DMA_SYNC_FORDEV);
	rgep->watchdog = 0;
	rgep->rx_next = 0;
}

static void
rge_reinit_buf_ring(rge_t *rgep)
{
	/*
	 * re-init free buffer ring
	 */
	rgep->rc_next = 0;
	rgep->rf_next = 0;
	if (rgep->rx_free != RGE_BUF_SLOTS)
		rgep->rx_bcopy = B_TRUE;
}

static void
rge_reinit_rings(rge_t *rgep)
{
	rge_reinit_send_ring(rgep);
	rge_reinit_recv_ring(rgep);
	rge_reinit_buf_ring(rgep);
}

static void
rge_init_send_ring(rge_t *rgep)
{
	uint32_t slot;
	uint32_t split;
	rge_bd_t *bdp;
	sw_sbd_t *ssbdp;
	dma_area_t buf_chunk;
	dma_area_t *pbuf;

	/*
	 * Allocate the array of s/w Tx Buffer Descriptors
	 */
	ssbdp = kmem_zalloc(RGE_SEND_SLOTS*sizeof (*ssbdp), KM_SLEEP);
	rgep->sw_sbds = ssbdp;

	/*
	 * Init send ring
	 */
	rgep->tx_next = 0;
	rgep->tc_next = 0;
	rgep->tc_tail = 0;
	rgep->tx_flow = 0;
	rgep->tx_free = RGE_SEND_SLOTS;
	rgep->tx_desc = rgep->dma_area_txdesc;
	DMA_ZERO(rgep->tx_desc);
	bdp = rgep->tx_desc.mem_va;
	rgep->tx_ring = bdp;
	for (split = 0; split < RGE_SPLIT; split++) {
		buf_chunk = rgep->dma_area_txbuf[split];
		for (slot = 0; slot < RGE_SEND_SLOTS/RGE_SPLIT; slot++) {
			rge_slice_chunk(&ssbdp->desc, &rgep->dma_area_txdesc,
			    1, sizeof (rge_bd_t));
			pbuf = &ssbdp->pbuf;
			rge_slice_chunk(pbuf, &buf_chunk, 1, rgep->txbuf_size);
			bdp->host_buf_addr =
			    RGE_BSWAP_32(pbuf->cookie.dmac_laddress);
			bdp->host_buf_addr_hi =
			    RGE_BSWAP_32(pbuf->cookie.dmac_laddress >> 32);
			/* last BD in Tx ring */
			if (split == (RGE_SPLIT - 1) &&
			    slot == (RGE_SEND_SLOTS/RGE_SPLIT -1))
				bdp->flags_len |= RGE_BSWAP_32(BD_FLAG_EOR);
			ssbdp++;
			bdp++;
		}
	}
	DMA_SYNC(rgep->tx_desc, DDI_DMA_SYNC_FORDEV);
}

static int
rge_init_recv_ring(rge_t *rgep)
{
	uint32_t slot;
	uint32_t split;
	rge_bd_t *bdp;
	sw_rbd_t *srbdp;
	dma_buf_t *rx_buf;
	dma_area_t buf_chunk;
	dma_area_t *pbuf;

	/*
	 * Allocate the array of s/w Rx Buffer Descriptors
	 */
	srbdp = kmem_zalloc(RGE_RECV_SLOTS*sizeof (*srbdp), KM_SLEEP);
	rx_buf = kmem_zalloc(RGE_RECV_SLOTS*sizeof (*rx_buf), KM_SLEEP);
	rgep->sw_rbds = srbdp;
	rgep->sw_rbuf = rx_buf;

	/*
	 * Init receive ring
	 */
	rgep->rx_next = 0;
	rgep->rx_desc = rgep->dma_area_rxdesc;
	DMA_ZERO(rgep->rx_desc);
	bdp = rgep->rx_desc.mem_va;
	rgep->rx_ring = bdp;
	for (split = 0; split < RGE_SPLIT; split++) {
		buf_chunk = rgep->dma_area_rxbuf[split];
		for (slot = 0; slot < RGE_RECV_SLOTS/RGE_SPLIT; slot++) {
			srbdp->rx_buf = rx_buf;
			pbuf = &rx_buf->pbuf;
			rge_slice_chunk(pbuf, &buf_chunk, 1, rgep->rxbuf_size);
			pbuf->alength -= RGE_HEADROOM;
			pbuf->offset += RGE_HEADROOM;
			rx_buf->rx_recycle.free_func = rge_rx_recycle;
			rx_buf->rx_recycle.free_arg = (caddr_t)rx_buf;
			rx_buf->private = (caddr_t)rgep;
			rx_buf->mp = desballoc(DMA_VPTR(rx_buf->pbuf),
			    rgep->rxbuf_size, 0, &rx_buf->rx_recycle);
			if (rx_buf->mp == NULL) {
				rge_problem(rgep,
				    "rge_init_recv_ring: desballoc() failed");
				return (DDI_FAILURE);
			}

			bdp->host_buf_addr = RGE_BSWAP_32(RGE_HEADROOM +
			    pbuf->cookie.dmac_laddress);
			bdp->host_buf_addr_hi =
			    RGE_BSWAP_32(pbuf->cookie.dmac_laddress >> 32);
			bdp->flags_len = RGE_BSWAP_32(BD_FLAG_HW_OWN |
			    (rgep->rxbuf_size - RGE_HEADROOM));
			/* last BD in Rx ring */
			if (split == (RGE_SPLIT - 1) &&
			    slot == (RGE_RECV_SLOTS/RGE_SPLIT -1))
				bdp->flags_len |= RGE_BSWAP_32(BD_FLAG_EOR);
			srbdp++;
			bdp++;
			rx_buf++;
		}
	}
	DMA_SYNC(rgep->rx_desc, DDI_DMA_SYNC_FORDEV);
	return (DDI_SUCCESS);
}

static int
rge_init_buf_ring(rge_t *rgep)
{
	uint32_t slot;
	uint32_t split;
	sw_rbd_t *free_rbdp;
	dma_buf_t *rx_buf;
	dma_area_t buf_chunk;
	dma_area_t *pbuf;

	/*
	 * Allocate the array of s/w free Buffer Descriptors
	 */
	free_rbdp = kmem_zalloc(RGE_BUF_SLOTS*sizeof (*free_rbdp), KM_SLEEP);
	rx_buf = kmem_zalloc(RGE_BUF_SLOTS*sizeof (*rx_buf), KM_SLEEP);
	rgep->free_rbds = free_rbdp;
	rgep->sw_freebuf = rx_buf;

	/*
	 * Init free buffer ring
	 */
	rgep->rc_next = 0;
	rgep->rf_next = 0;
	rgep->rx_bcopy = B_FALSE;
	rgep->rx_free = RGE_BUF_SLOTS;
	for (split = 0; split < RGE_SPLIT; split++) {
		buf_chunk = rgep->dma_area_freebuf[split];
		for (slot = 0; slot < RGE_BUF_SLOTS/RGE_SPLIT; slot++) {
			free_rbdp->rx_buf = rx_buf;
			pbuf = &rx_buf->pbuf;
			rge_slice_chunk(pbuf, &buf_chunk, 1, rgep->rxbuf_size);
			pbuf->alength -= RGE_HEADROOM;
			pbuf->offset += RGE_HEADROOM;
			rx_buf->rx_recycle.free_func = rge_rx_recycle;
			rx_buf->rx_recycle.free_arg = (caddr_t)rx_buf;
			rx_buf->private = (caddr_t)rgep;
			rx_buf->mp = desballoc(DMA_VPTR(rx_buf->pbuf),
			    rgep->rxbuf_size, 0, &rx_buf->rx_recycle);
			if (rx_buf->mp == NULL) {
				rge_problem(rgep,
				    "rge_init_buf_ring: desballoc() failed");
				return (DDI_FAILURE);
			}
			free_rbdp++;
			rx_buf++;
		}
	}
	return (DDI_SUCCESS);
}

static int
rge_init_rings(rge_t *rgep)
{
	int err;

	rge_init_send_ring(rgep);
	err = rge_init_recv_ring(rgep);
	err = rge_init_buf_ring(rgep);
	return (err);
}

static void
rge_fini_send_ring(rge_t *rgep)
{
	kmem_free(rgep->sw_sbds, RGE_SEND_SLOTS * sizeof (sw_sbd_t));
}

static void
rge_fini_recv_ring(rge_t *rgep)
{
	dma_buf_t *rx_buf = rgep->sw_rbuf;
	uint32_t slot;

	for (slot = 0; slot < RGE_RECV_SLOTS; slot++, rx_buf++)
		freemsg(rx_buf->mp);
	kmem_free(rgep->sw_rbuf, RGE_RECV_SLOTS * sizeof (dma_buf_t));
	kmem_free(rgep->sw_rbds, RGE_RECV_SLOTS * sizeof (sw_rbd_t));
}

static void
rge_fini_buf_ring(rge_t *rgep)
{
	dma_buf_t *rx_buf = rgep->sw_freebuf;
	uint32_t slot;

	for (slot = 0; slot < RGE_BUF_SLOTS; slot++, rx_buf++)
		freemsg(rx_buf->mp);
	kmem_free(rgep->sw_freebuf, RGE_BUF_SLOTS * sizeof (dma_buf_t));
	kmem_free(rgep->free_rbds, RGE_BUF_SLOTS * sizeof (sw_rbd_t));
}

static void
rge_fini_rings(rge_t *rgep)
{
	rge_fini_send_ring(rgep);
	rge_fini_recv_ring(rgep);
	rge_fini_buf_ring(rgep);
}

/*
 * ========== Internal state management entry points ==========
 */

#undef	RGE_DBG
#define	RGE_DBG		RGE_DBG_NEMO	/* debug flag for this code	*/

/*
 * These routines provide all the functionality required by the
 * corresponding MAC layer entry points, but don't update the
 * MAC state so they can be called internally without disturbing
 * our record of what NEMO thinks we should be doing ...
 */

/*
 *	rge_reset() -- reset h/w & rings to initial state
 */
static void
rge_reset(rge_t *rgep)
{
	ASSERT(mutex_owned(rgep->genlock));

	/*
	 * Grab all the other mutexes in the world (this should
	 * ensure no other threads are manipulating driver state)
	 */
	mutex_enter(rgep->rx_lock);
	mutex_enter(rgep->rc_lock);
	rw_enter(rgep->errlock, RW_WRITER);

	(void) rge_chip_reset(rgep);
	rge_reinit_rings(rgep);
	rge_chip_init(rgep);

	/*
	 * Free the world ...
	 */
	rw_exit(rgep->errlock);
	mutex_exit(rgep->rc_lock);
	mutex_exit(rgep->rx_lock);

	RGE_DEBUG(("rge_reset($%p) done", (void *)rgep));
}

/*
 *	rge_stop() -- stop processing, don't reset h/w or rings
 */
static void
rge_stop(rge_t *rgep)
{
	ASSERT(mutex_owned(rgep->genlock));

	rge_chip_stop(rgep, B_FALSE);

	RGE_DEBUG(("rge_stop($%p) done", (void *)rgep));
}

/*
 *	rge_start() -- start transmitting/receiving
 */
static void
rge_start(rge_t *rgep)
{
	ASSERT(mutex_owned(rgep->genlock));

	/*
	 * Start chip processing, including enabling interrupts
	 */
	rge_chip_start(rgep);
	rgep->watchdog = 0;
}

/*
 * rge_restart - restart transmitting/receiving after error or suspend
 */
void
rge_restart(rge_t *rgep)
{
	uint32_t i;

	ASSERT(mutex_owned(rgep->genlock));
	/*
	 * Wait for posted buffer to be freed...
	 */
	if (!rgep->rx_bcopy) {
		for (i = 0; i < RXBUFF_FREE_LOOP; i++) {
			if (rgep->rx_free == RGE_BUF_SLOTS)
				break;
			drv_usecwait(1000);
			RGE_DEBUG(("rge_restart: waiting for rx buf free..."));
		}
	}
	rge_reset(rgep);
	rgep->stats.chip_reset++;
	if (rgep->rge_mac_state == RGE_MAC_STARTED) {
		rge_start(rgep);
		ddi_trigger_softintr(rgep->resched_id);
	}
}


/*
 * ========== Nemo-required management entry points ==========
 */

#undef	RGE_DBG
#define	RGE_DBG		RGE_DBG_NEMO	/* debug flag for this code	*/

/*
 *	rge_m_stop() -- stop transmitting/receiving
 */
static void
rge_m_stop(void *arg)
{
	rge_t *rgep = arg;		/* private device info	*/
	uint32_t i;

	/*
	 * Just stop processing, then record new MAC state
	 */
	mutex_enter(rgep->genlock);
	rge_stop(rgep);
	rgep->link_up_msg = rgep->link_down_msg = " (stopped)";
	/*
	 * Wait for posted buffer to be freed...
	 */
	if (!rgep->rx_bcopy) {
		for (i = 0; i < RXBUFF_FREE_LOOP; i++) {
			if (rgep->rx_free == RGE_BUF_SLOTS)
				break;
			drv_usecwait(1000);
			RGE_DEBUG(("rge_m_stop: waiting for rx buf free..."));
		}
	}
	rgep->rge_mac_state = RGE_MAC_STOPPED;
	RGE_DEBUG(("rge_m_stop($%p) done", arg));
	mutex_exit(rgep->genlock);
}

/*
 *	rge_m_start() -- start transmitting/receiving
 */
static int
rge_m_start(void *arg)
{
	rge_t *rgep = arg;		/* private device info	*/

	mutex_enter(rgep->genlock);

	/*
	 * Clear hw/sw statistics
	 */
	DMA_ZERO(rgep->dma_area_stats);
	bzero(&rgep->stats, sizeof (rge_stats_t));

	/*
	 * Start processing and record new MAC state
	 */
	rge_reset(rgep);
	rgep->link_up_msg = rgep->link_down_msg = " (initialized)";
	rge_start(rgep);
	rgep->rge_mac_state = RGE_MAC_STARTED;
	RGE_DEBUG(("rge_m_start($%p) done", arg));

	mutex_exit(rgep->genlock);

	return (0);
}

/*
 *	rge_m_unicst_set() -- set the physical network address
 */
static int
rge_m_unicst(void *arg, const uint8_t *macaddr)
{
	rge_t *rgep = arg;		/* private device info	*/

	/*
	 * Remember the new current address in the driver state
	 * Sync the chip's idea of the address too ...
	 */
	mutex_enter(rgep->genlock);
	bcopy(macaddr, rgep->netaddr, ETHERADDRL);
	rge_chip_sync(rgep, RGE_SET_MAC);
	mutex_exit(rgep->genlock);

	return (0);
}

/*
 * Compute the index of the required bit in the multicast hash map.
 * This must mirror the way the hardware actually does it!
 */
static uint32_t
rge_hash_index(const uint8_t *mca)
{
	uint32_t crc = (ulong_t)RGE_HASH_CRC;
	uint32_t const POLY = RGE_HASH_POLY;
	uint32_t msb;
	int bytes;
	uchar_t currentbyte;
	uint32_t index;
	int bit;

	for (bytes = 0; bytes < ETHERADDRL; bytes++) {
		currentbyte = mca[bytes];
		for (bit = 0; bit < 8; bit++) {
			msb = crc >> 31;
			crc <<= 1;
			if (msb ^ (currentbyte & 1)) {
				crc ^= POLY;
				crc |= 0x00000001;
			}
			currentbyte >>= 1;
		}
	}
	index = crc >> 26;

	return (index);
}

/*
 *	rge_m_multicst_add() -- enable/disable a multicast address
 */
static int
rge_m_multicst(void *arg, boolean_t add, const uint8_t *mca)
{
	rge_t *rgep = arg;		/* private device info	*/
	struct ether_addr *addr;
	uint32_t index;
	uint32_t *hashp;

	mutex_enter(rgep->genlock);
	hashp = rgep->mcast_hash;
	addr = (struct ether_addr *)mca;
	index = rge_hash_index(addr->ether_addr_octet);
			/* index value is between 0 and 63 */

	if (add) {
		if (rgep->mcast_refs[index]++) {
			mutex_exit(rgep->genlock);
			return (0);
		}
		hashp[index/32] |= 1<< (index % 32);
	} else {
		if (--rgep->mcast_refs[index]) {
			mutex_exit(rgep->genlock);
			return (0);
		}
		hashp[index/32] &= ~(1<< (index % 32));
	}

	/*
	 * Set multicast register
	 */
	rge_chip_sync(rgep, RGE_SET_MUL);

	mutex_exit(rgep->genlock);
	return (0);
}

/*
 * rge_m_promisc() -- set or reset promiscuous mode on the board
 *
 *	Program the hardware to enable/disable promiscuous and/or
 *	receive-all-multicast modes.
 */
static int
rge_m_promisc(void *arg, boolean_t on)
{
	rge_t *rgep = arg;

	/*
	 * Store MAC layer specified mode and pass to chip layer to update h/w
	 */
	mutex_enter(rgep->genlock);

	if (rgep->promisc == on) {
		mutex_exit(rgep->genlock);
		return (0);
	}
	rgep->promisc = on;
	rge_chip_sync(rgep, RGE_SET_PROMISC);
	RGE_DEBUG(("rge_m_promisc_set($%p) done", arg));
	mutex_exit(rgep->genlock);
	return (0);
}

/*
 * Loopback ioctl code
 */

static lb_property_t loopmodes[] = {
	{ normal,	"normal",	RGE_LOOP_NONE		},
	{ internal,	"PHY",		RGE_LOOP_INTERNAL_PHY	},
	{ internal,	"MAC",		RGE_LOOP_INTERNAL_MAC	}
};

static enum ioc_reply
rge_set_loop_mode(rge_t *rgep, uint32_t mode)
{
	const char *msg;

	/*
	 * If the mode isn't being changed, there's nothing to do ...
	 */
	if (mode == rgep->param_loop_mode)
		return (IOC_ACK);

	/*
	 * Validate the requested mode and prepare a suitable message
	 * to explain the link down/up cycle that the change will
	 * probably induce ...
	 */
	switch (mode) {
	default:
		return (IOC_INVAL);

	case RGE_LOOP_NONE:
		msg = " (loopback disabled)";
		break;

	case RGE_LOOP_INTERNAL_PHY:
		msg = " (PHY internal loopback selected)";
		break;

	case RGE_LOOP_INTERNAL_MAC:
		msg = " (MAC internal loopback selected)";
		break;
	}

	/*
	 * All OK; tell the caller to reprogram
	 * the PHY and/or MAC for the new mode ...
	 */
	rgep->link_down_msg = rgep->link_up_msg = msg;
	rgep->param_loop_mode = mode;
	return (IOC_RESTART_ACK);
}

static enum ioc_reply
rge_loop_ioctl(rge_t *rgep, queue_t *wq, mblk_t *mp, struct iocblk *iocp)
{
	lb_info_sz_t *lbsp;
	lb_property_t *lbpp;
	uint32_t *lbmp;
	int cmd;

	_NOTE(ARGUNUSED(wq))

	/*
	 * Validate format of ioctl
	 */
	if (mp->b_cont == NULL)
		return (IOC_INVAL);

	cmd = iocp->ioc_cmd;
	switch (cmd) {
	default:
		/* NOTREACHED */
		rge_error(rgep, "rge_loop_ioctl: invalid cmd 0x%x", cmd);
		return (IOC_INVAL);

	case LB_GET_INFO_SIZE:
		if (iocp->ioc_count != sizeof (lb_info_sz_t))
			return (IOC_INVAL);
		lbsp = (lb_info_sz_t *)mp->b_cont->b_rptr;
		*lbsp = sizeof (loopmodes);
		return (IOC_REPLY);

	case LB_GET_INFO:
		if (iocp->ioc_count != sizeof (loopmodes))
			return (IOC_INVAL);
		lbpp = (lb_property_t *)mp->b_cont->b_rptr;
		bcopy(loopmodes, lbpp, sizeof (loopmodes));
		return (IOC_REPLY);

	case LB_GET_MODE:
		if (iocp->ioc_count != sizeof (uint32_t))
			return (IOC_INVAL);
		lbmp = (uint32_t *)mp->b_cont->b_rptr;
		*lbmp = rgep->param_loop_mode;
		return (IOC_REPLY);

	case LB_SET_MODE:
		if (iocp->ioc_count != sizeof (uint32_t))
			return (IOC_INVAL);
		lbmp = (uint32_t *)mp->b_cont->b_rptr;
		return (rge_set_loop_mode(rgep, *lbmp));
	}
}

/*
 * Specific rge IOCTLs, the MAC layer handles the generic ones.
 */
static void
rge_m_ioctl(void *arg, queue_t *wq, mblk_t *mp)
{
	rge_t *rgep = arg;
	struct iocblk *iocp;
	enum ioc_reply status;
	boolean_t need_privilege;
	int err;
	int cmd;

	/*
	 * Validate the command before bothering with the mutex ...
	 */
	iocp = (struct iocblk *)mp->b_rptr;
	iocp->ioc_error = 0;
	need_privilege = B_TRUE;
	cmd = iocp->ioc_cmd;
	switch (cmd) {
	default:
		miocnak(wq, mp, 0, EINVAL);
		return;

	case RGE_MII_READ:
	case RGE_MII_WRITE:
	case RGE_DIAG:
	case RGE_PEEK:
	case RGE_POKE:
	case RGE_PHY_RESET:
	case RGE_SOFT_RESET:
	case RGE_HARD_RESET:
		break;

	case LB_GET_INFO_SIZE:
	case LB_GET_INFO:
	case LB_GET_MODE:
		need_privilege = B_FALSE;
		/* FALLTHRU */
	case LB_SET_MODE:
		break;

	case ND_GET:
		need_privilege = B_FALSE;
		/* FALLTHRU */
	case ND_SET:
		break;
	}

	if (need_privilege) {
		/*
		 * Check for specific net_config privilege on Solaris 10+.
		 * Otherwise just check for root access ...
		 */
		if (secpolicy_net_config != NULL)
			err = secpolicy_net_config(iocp->ioc_cr, B_FALSE);
		else
			err = drv_priv(iocp->ioc_cr);
		if (err != 0) {
			miocnak(wq, mp, 0, err);
			return;
		}
	}

	mutex_enter(rgep->genlock);

	switch (cmd) {
	default:
		_NOTE(NOTREACHED)
		status = IOC_INVAL;
		break;

	case RGE_MII_READ:
	case RGE_MII_WRITE:
	case RGE_DIAG:
	case RGE_PEEK:
	case RGE_POKE:
	case RGE_PHY_RESET:
	case RGE_SOFT_RESET:
	case RGE_HARD_RESET:
		status = rge_chip_ioctl(rgep, wq, mp, iocp);
		break;

	case LB_GET_INFO_SIZE:
	case LB_GET_INFO:
	case LB_GET_MODE:
	case LB_SET_MODE:
		status = rge_loop_ioctl(rgep, wq, mp, iocp);
		break;

	case ND_GET:
	case ND_SET:
		status = rge_nd_ioctl(rgep, wq, mp, iocp);
		break;
	}

	/*
	 * Do we need to reprogram the PHY and/or the MAC?
	 * Do it now, while we still have the mutex.
	 *
	 * Note: update the PHY first, 'cos it controls the
	 * speed/duplex parameters that the MAC code uses.
	 */
	switch (status) {
	case IOC_RESTART_REPLY:
	case IOC_RESTART_ACK:
		rge_phy_update(rgep);
		break;
	}

	mutex_exit(rgep->genlock);

	/*
	 * Finally, decide how to reply
	 */
	switch (status) {
	default:
	case IOC_INVAL:
		/*
		 * Error, reply with a NAK and EINVAL or the specified error
		 */
		miocnak(wq, mp, 0, iocp->ioc_error == 0 ?
			EINVAL : iocp->ioc_error);
		break;

	case IOC_DONE:
		/*
		 * OK, reply already sent
		 */
		break;

	case IOC_RESTART_ACK:
	case IOC_ACK:
		/*
		 * OK, reply with an ACK
		 */
		miocack(wq, mp, 0, 0);
		break;

	case IOC_RESTART_REPLY:
	case IOC_REPLY:
		/*
		 * OK, send prepared reply as ACK or NAK
		 */
		mp->b_datap->db_type = iocp->ioc_error == 0 ?
			M_IOCACK : M_IOCNAK;
		qreply(wq, mp);
		break;
	}
}

static void
rge_m_resources(void *arg)
{
	rge_t *rgep = arg;
	mac_rx_fifo_t mrf;

	mutex_enter(rgep->genlock);

	/*
	 * Register Rx rings as resources and save mac
	 * resource id for future reference
	 */
	mrf.mrf_type = MAC_RX_FIFO;
	mrf.mrf_blank = rge_chip_blank;
	mrf.mrf_arg = (void *)rgep;
	mrf.mrf_normal_blank_time = RGE_RX_INT_TIME;
	mrf.mrf_normal_pkt_count = RGE_RX_INT_PKTS;
	rgep->handle = mac_resource_add(rgep->macp, (mac_resource_t *)&mrf);

	mutex_exit(rgep->genlock);
}

/*
 * ========== Per-instance setup/teardown code ==========
 */

#undef	RGE_DBG
#define	RGE_DBG		RGE_DBG_INIT	/* debug flag for this code	*/

static void
rge_unattach(rge_t *rgep)
{
	mac_t *macp;

	/*
	 * Flag that no more activity may be initiated
	 */
	rgep->progress &= ~PROGRESS_READY;
	rgep->rge_mac_state = RGE_MAC_UNATTACH;

	/*
	 * Quiesce the PHY and MAC (leave it reset but still powered).
	 * Clean up and free all RGE data structures
	 */
	if (rgep->cyclic_id) {
		mutex_enter(&cpu_lock);
		cyclic_remove(rgep->cyclic_id);
		mutex_exit(&cpu_lock);
	}

	if (rgep->progress & PROGRESS_KSTATS)
		rge_fini_kstats(rgep);

	if (rgep->progress & PROGRESS_PHY)
		(void) rge_phy_reset(rgep);

	if (rgep->progress & PROGRESS_INTR) {
		mutex_enter(rgep->genlock);
		(void) rge_chip_reset(rgep);
		mutex_exit(rgep->genlock);
		ddi_remove_intr(rgep->devinfo, 0, rgep->iblk);
		rge_fini_rings(rgep);
		mutex_destroy(rgep->rc_lock);
		mutex_destroy(rgep->rx_lock);
		mutex_destroy(rgep->tc_lock);
		mutex_destroy(rgep->tx_lock);
		rw_destroy(rgep->errlock);
		mutex_destroy(rgep->genlock);
	}

	if (rgep->progress & PROGRESS_FACTOTUM)
		ddi_remove_softintr(rgep->factotum_id);

	if (rgep->progress & PROGRESS_RESCHED)
		ddi_remove_softintr(rgep->resched_id);

	rge_free_bufs(rgep);

	if (rgep->progress & PROGRESS_NDD)
		rge_nd_cleanup(rgep);

	if (rgep->progress & PROGRESS_REGS)
		ddi_regs_map_free(&rgep->io_handle);

	if (rgep->progress & PROGRESS_CFG)
		pci_config_teardown(&rgep->cfg_handle);

	ddi_remove_minor_node(rgep->devinfo, NULL);
	macp = rgep->macp;
	kmem_free(macp, sizeof (*macp));
	kmem_free(rgep, sizeof (*rgep));
}

static int
rge_resume(dev_info_t *devinfo)
{
	rge_t *rgep;			/* Our private data	*/
	chip_id_t *cidp;
	chip_id_t chipid;

	rgep = ddi_get_driver_private(devinfo);
	if (rgep == NULL)
		return (DDI_FAILURE);

	/*
	 * Refuse to resume if the data structures aren't consistent
	 */
	if (rgep->devinfo != devinfo)
		return (DDI_FAILURE);

	/*
	 * Read chip ID & set up config space command register(s)
	 * Refuse to resume if the chip has changed its identity!
	 */
	cidp = &rgep->chipid;
	rge_chip_cfg_init(rgep, &chipid);
	if (chipid.vendor != cidp->vendor)
		return (DDI_FAILURE);
	if (chipid.device != cidp->device)
		return (DDI_FAILURE);
	if (chipid.revision != cidp->revision)
		return (DDI_FAILURE);

	/*
	 * All OK, reinitialise h/w & kick off NEMO scheduling
	 */
	mutex_enter(rgep->genlock);
	rge_restart(rgep);
	mutex_exit(rgep->genlock);
	return (DDI_SUCCESS);
}


/*
 * attach(9E) -- Attach a device to the system
 *
 * Called once for each board successfully probed.
 */
static int
rge_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	rge_t *rgep;			/* Our private data	*/
	mac_t *macp;
	mac_info_t *mip;
	chip_id_t *cidp;
	cyc_handler_t cychand;
	cyc_time_t cyctime;
	caddr_t regs;
	int instance;
	int err;

	/*
	 * we don't support high level interrupts in the driver
	 */
	if (ddi_intr_hilevel(devinfo, 0) != 0) {
		cmn_err(CE_WARN,
		    "rge_attach -- unsupported high level interrupt");
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(devinfo);
	RGE_GTRACE(("rge_attach($%p, %d) instance %d",
		(void *)devinfo, cmd, instance));
	RGE_BRKPT(NULL, "rge_attach");

	switch (cmd) {
	default:
		return (DDI_FAILURE);

	case DDI_RESUME:
		return (rge_resume(devinfo));

	case DDI_ATTACH:
		break;
	}

	/*
	 * Allocate mac_t and RGE private structures, and
	 * cross-link them so that given either one of these or
	 * the devinfo the others can be derived.
	 */
	macp = kmem_zalloc(sizeof (*macp), KM_SLEEP);
	rgep = kmem_zalloc(sizeof (*rgep), KM_SLEEP);
	ddi_set_driver_private(devinfo, rgep);
	rgep->devinfo = devinfo;
	rgep->macp = macp;
	macp->m_driver = rgep;

	/*
	 * Initialize more fields in RGE private data
	 */
	rgep->debug = ddi_prop_get_int(DDI_DEV_T_ANY, devinfo,
		DDI_PROP_DONTPASS, debug_propname, rge_debug);
	(void) snprintf(rgep->ifname, sizeof (rgep->ifname), "%s%d",
		RGE_DRIVER_NAME, instance);

	/*
	 * Map config space registers
	 * Read chip ID & set up config space command register(s)
	 *
	 * Note: this leaves the chip accessible by Memory Space
	 * accesses, but with interrupts and Bus Mastering off.
	 * This should ensure that nothing untoward will happen
	 * if it has been left active by the (net-)bootloader.
	 * We'll re-enable Bus Mastering once we've reset the chip,
	 * and allow interrupts only when everything else is set up.
	 */
	err = pci_config_setup(devinfo, &rgep->cfg_handle);
	if (err != DDI_SUCCESS) {
		rge_problem(rgep, "pci_config_setup() failed");
		goto attach_fail;
	}
	rgep->progress |= PROGRESS_CFG;
	cidp = &rgep->chipid;
	bzero(cidp, sizeof (*cidp));
	rge_chip_cfg_init(rgep, cidp);

	/*
	 * Map operating registers
	 */
	err = ddi_regs_map_setup(devinfo, 1, &regs,
	    0, 0, &rge_reg_accattr, &rgep->io_handle);
	if (err != DDI_SUCCESS) {
		rge_problem(rgep, "ddi_regs_map_setup() failed");
		goto attach_fail;
	}
	rgep->io_regs = regs;
	rgep->progress |= PROGRESS_REGS;

	/*
	 * Register NDD-tweakable parameters
	 */
	if (rge_nd_init(rgep)) {
		rge_problem(rgep, "rge_nd_init() failed");
		goto attach_fail;
	}
	rgep->progress |= PROGRESS_NDD;

	/*
	 * Characterise the device, so we know its requirements.
	 * Then allocate the appropriate TX and RX descriptors & buffers.
	 */
	rge_chip_ident(rgep);
	err = rge_alloc_bufs(rgep);
	if (err != DDI_SUCCESS) {
		rge_problem(rgep, "DMA buffer allocation failed");
		goto attach_fail;
	}

	/*
	 * Add the softint handlers:
	 *
	 * Both of these handlers are used to avoid restrictions on the
	 * context and/or mutexes required for some operations.  In
	 * particular, the hardware interrupt handler and its subfunctions
	 * can detect a number of conditions that we don't want to handle
	 * in that context or with that set of mutexes held.  So, these
	 * softints are triggered instead:
	 *
	 * the <resched> softint is triggered if if we have previously
	 * had to refuse to send a packet because of resource shortage
	 * (we've run out of transmit buffers), but the send completion
	 * interrupt handler has now detected that more buffers have
	 * become available.
	 *
	 * the <factotum> is triggered if the h/w interrupt handler
	 * sees the <link state changed> or <error> bits in the status
	 * block.  It's also triggered periodically to poll the link
	 * state, just in case we aren't getting link status change
	 * interrupts ...
	 */
	err = ddi_add_softintr(devinfo, DDI_SOFTINT_LOW, &rgep->resched_id,
		NULL, NULL, rge_reschedule, (caddr_t)rgep);
	if (err != DDI_SUCCESS) {
		rge_problem(rgep, "ddi_add_softintr() failed");
		goto attach_fail;
	}
	rgep->progress |= PROGRESS_RESCHED;
	err = ddi_add_softintr(devinfo, DDI_SOFTINT_LOW, &rgep->factotum_id,
		NULL, NULL, rge_chip_factotum, (caddr_t)rgep);
	if (err != DDI_SUCCESS) {
		rge_problem(rgep, "ddi_add_softintr() failed");
		goto attach_fail;
	}
	rgep->progress |= PROGRESS_FACTOTUM;

	/*
	 * Add the h/w interrupt handler and initialise mutexes
	 */
	err = ddi_add_intr(devinfo, 0, &rgep->iblk, NULL,
		rge_intr, (caddr_t)rgep);
	if (err != DDI_SUCCESS) {
		rge_problem(rgep, "ddi_add_intr() failed");
		goto attach_fail;
	}
	mutex_init(rgep->genlock, NULL, MUTEX_DRIVER, rgep->iblk);
	rw_init(rgep->errlock, NULL, RW_DRIVER, rgep->iblk);
	mutex_init(rgep->tx_lock, NULL, MUTEX_DRIVER, rgep->iblk);
	mutex_init(rgep->tc_lock, NULL, MUTEX_DRIVER, rgep->iblk);
	mutex_init(rgep->rx_lock, NULL, MUTEX_DRIVER, rgep->iblk);
	mutex_init(rgep->rc_lock, NULL, MUTEX_DRIVER, rgep->iblk);
	rgep->progress |= PROGRESS_INTR;

	/*
	 * Initialize rings
	 */
	err = rge_init_rings(rgep);
	if (err != DDI_SUCCESS) {
		rge_problem(rgep, "rge_init_rings() failed");
		goto attach_fail;
	}

	/*
	 * Initialise link state variables
	 * Stop, reset & reinitialise the chip.
	 * Initialise the (internal) PHY.
	 */
	rgep->param_link_up = LINK_STATE_UNKNOWN;
	rgep->link_up_msg = rgep->link_down_msg = " (initialised)";

	/*
	 * Reset chip & rings to initial state; also reset address
	 * filtering, promiscuity, loopback mode.
	 */
	mutex_enter(rgep->genlock);
	(void) rge_chip_reset(rgep);
	rge_chip_sync(rgep, RGE_GET_MAC);
	bzero(rgep->mcast_hash, sizeof (rgep->mcast_hash));
	bzero(rgep->mcast_refs, sizeof (rgep->mcast_refs));
	rgep->promisc = B_FALSE;
	rgep->param_loop_mode = RGE_LOOP_NONE;
	mutex_exit(rgep->genlock);
	rge_phy_init(rgep);
	rgep->progress |= PROGRESS_PHY;

	/*
	 * Create & initialise named kstats
	 */
	rge_init_kstats(rgep, instance);
	rgep->progress |= PROGRESS_KSTATS;

	/*
	 * Initialize pointers to device specific functions which
	 * will be used by the generic layer.
	 */
	mip = &(macp->m_info);
	mip->mi_media = DL_ETHER;
	mip->mi_sdu_min = 0;
	mip->mi_sdu_max = rgep->param_default_mtu;
	mip->mi_cksum = HCKSUM_INET_FULL_V4 | HCKSUM_IPHDRCKSUM;
	mip->mi_poll = DL_CAPAB_POLL;

	mip->mi_addr_length = ETHERADDRL;
	bcopy(rge_broadcast_addr, mip->mi_brdcst_addr, ETHERADDRL);
	bcopy(rgep->netaddr, mip->mi_unicst_addr, ETHERADDRL);

	/*
	 * Register h/w supported statistics
	 */
	MAC_STAT_MIB(mip->mi_stat);
	mip->mi_stat[MAC_STAT_MULTIXMT] = B_FALSE;
	mip->mi_stat[MAC_STAT_BRDCSTXMT] = B_FALSE;
	mip->mi_stat[MAC_STAT_UNKNOWNS] = B_FALSE;
	mip->mi_stat[MAC_STAT_NOXMTBUF] = B_FALSE;

	MAC_STAT_ETHER(mip->mi_stat);
	mip->mi_stat[MAC_STAT_FCS_ERRORS] = B_FALSE;
	mip->mi_stat[MAC_STAT_SQE_ERRORS] = B_FALSE;
	mip->mi_stat[MAC_STAT_TX_LATE_COLLISIONS] = B_FALSE;
	mip->mi_stat[MAC_STAT_EX_COLLISIONS] = B_FALSE;
	mip->mi_stat[MAC_STAT_MACXMT_ERRORS] = B_FALSE;
	mip->mi_stat[MAC_STAT_CARRIER_ERRORS] = B_FALSE;
	mip->mi_stat[MAC_STAT_TOOLONG_ERRORS] = B_FALSE;
	mip->mi_stat[MAC_STAT_MACRCV_ERRORS] = B_FALSE;

	MAC_STAT_MII(mip->mi_stat);
	mip->mi_stat[MAC_STAT_LP_CAP_1000FDX] = B_FALSE;
	mip->mi_stat[MAC_STAT_LP_CAP_1000HDX] = B_FALSE;
	mip->mi_stat[MAC_STAT_LP_CAP_100FDX] = B_FALSE;
	mip->mi_stat[MAC_STAT_LP_CAP_100HDX] = B_FALSE;
	mip->mi_stat[MAC_STAT_LP_CAP_10FDX] = B_FALSE;
	mip->mi_stat[MAC_STAT_LP_CAP_10HDX] = B_FALSE;
	mip->mi_stat[MAC_STAT_LP_CAP_ASMPAUSE] = B_FALSE;
	mip->mi_stat[MAC_STAT_LP_CAP_PAUSE] = B_FALSE;
	mip->mi_stat[MAC_STAT_LP_CAP_AUTONEG] = B_FALSE;
	mip->mi_stat[MAC_STAT_LINK_ASMPAUSE] = B_FALSE;
	mip->mi_stat[MAC_STAT_LINK_PAUSE] = B_FALSE;
	mip->mi_stat[MAC_STAT_LINK_AUTONEG] = B_FALSE;

	macp->m_stat = rge_m_stat;
	macp->m_stop = rge_m_stop;
	macp->m_start = rge_m_start;
	macp->m_unicst = rge_m_unicst;
	macp->m_multicst = rge_m_multicst;
	macp->m_promisc = rge_m_promisc;
	macp->m_tx = rge_m_tx;
	macp->m_resources = rge_m_resources;
	macp->m_ioctl = rge_m_ioctl;

	macp->m_dip = devinfo;
	macp->m_ident = MAC_IDENT;

	/*
	 * Finally, we're ready to register ourselves with the MAC layer
	 * interface; if this succeeds, we're all ready to start()
	 */
	if (mac_register(macp) != 0)
		goto attach_fail;

	cychand.cyh_func = rge_chip_cyclic;
	cychand.cyh_arg = rgep;
	cychand.cyh_level = CY_LOCK_LEVEL;
	cyctime.cyt_when = 0;
	cyctime.cyt_interval = RGE_CYCLIC_PERIOD;
	mutex_enter(&cpu_lock);
	rgep->cyclic_id = cyclic_add(&cychand, &cyctime);
	mutex_exit(&cpu_lock);

	rgep->progress |= PROGRESS_READY;
	return (DDI_SUCCESS);

attach_fail:
	rge_unattach(rgep);
	return (DDI_FAILURE);
}

/*
 *	rge_suspend() -- suspend transmit/receive for powerdown
 */
static int
rge_suspend(rge_t *rgep)
{
	/*
	 * Stop processing and idle (powerdown) the PHY ...
	 */
	mutex_enter(rgep->genlock);
	rge_stop(rgep);
	mutex_exit(rgep->genlock);

	return (DDI_SUCCESS);
}

/*
 * detach(9E) -- Detach a device from the system
 */
static int
rge_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	rge_t *rgep;

	RGE_GTRACE(("rge_detach($%p, %d)", (void *)devinfo, cmd));

	rgep = ddi_get_driver_private(devinfo);

	switch (cmd) {
	default:
		return (DDI_FAILURE);

	case DDI_SUSPEND:
		return (rge_suspend(rgep));

	case DDI_DETACH:
		break;
	}

	/*
	 * If there is any posted buffer, the driver should reject to be
	 * detached. Need notice upper layer to release them.
	 */
	if (rgep->rx_free != RGE_BUF_SLOTS)
		return (DDI_FAILURE);

	/*
	 * Unregister from the MAC layer subsystem.  This can fail, in
	 * particular if there are DLPI style-2 streams still open -
	 * in which case we just return failure without shutting
	 * down chip operations.
	 */
	if (mac_unregister(rgep->macp) != 0)
		return (DDI_FAILURE);

	/*
	 * All activity stopped, so we can clean up & exit
	 */
	rge_unattach(rgep);
	return (DDI_SUCCESS);
}


/*
 * ========== Module Loading Data & Entry Points ==========
 */

#undef	RGE_DBG
#define	RGE_DBG		RGE_DBG_INIT	/* debug flag for this code	*/
DDI_DEFINE_STREAM_OPS(rge_dev_ops, nulldev, nulldev, rge_attach, rge_detach,
    nodev, NULL, D_MP, NULL);

static struct modldrv rge_modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	rge_ident,		/* short description */
	&rge_dev_ops		/* driver specific ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&rge_modldrv, NULL
};


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_init(void)
{
	int status;

	mac_init_ops(&rge_dev_ops, "rge");
	status = mod_install(&modlinkage);
	if (status == DDI_SUCCESS)
		mutex_init(rge_log_mutex, NULL, MUTEX_DRIVER, NULL);
	else
		mac_fini_ops(&rge_dev_ops);

	return (status);
}

int
_fini(void)
{
	int status;

	status = mod_remove(&modlinkage);
	if (status == DDI_SUCCESS) {
		mac_fini_ops(&rge_dev_ops);
		mutex_destroy(rge_log_mutex);
	}
	return (status);
}
