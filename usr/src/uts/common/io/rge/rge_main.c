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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "rge.h"

/*
 * This is the string displayed by modinfo, etc.
 * Make sure you keep the version ID up to date!
 */
static char rge_ident[] = "Realtek 1Gb Ethernet v%I%";

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

/*
 * Property names
 */
static char debug_propname[] = "rge_debug_flags";
static char mtu_propname[] = "default_mtu";
static char msi_propname[] = "msi_enable";

static int		rge_m_start(void *);
static void		rge_m_stop(void *);
static int		rge_m_promisc(void *, boolean_t);
static int		rge_m_multicst(void *, boolean_t, const uint8_t *);
static int		rge_m_unicst(void *, const uint8_t *);
static void		rge_m_resources(void *);
static void		rge_m_ioctl(void *, queue_t *, mblk_t *);
static boolean_t	rge_m_getcapab(void *, mac_capab_t, void *);

#define	RGE_M_CALLBACK_FLAGS	(MC_RESOURCES | MC_IOCTL | MC_GETCAPAB)

static mac_callbacks_t rge_m_callbacks = {
	RGE_M_CALLBACK_FLAGS,
	rge_m_stat,
	rge_m_start,
	rge_m_stop,
	rge_m_promisc,
	rge_m_multicst,
	rge_m_unicst,
	rge_m_tx,
	rge_m_resources,
	rge_m_ioctl,
	rge_m_getcapab
};

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

	return (DDI_SUCCESS);
}

/*
 * rge_free_bufs() -- free descriptors/buffers allocated for this
 * device instance.
 */
static void
rge_free_bufs(rge_t *rgep)
{
	rge_free_dma_mem(&rgep->dma_area_stats);
	rge_free_dma_mem(&rgep->dma_area_txdesc);
	rge_free_dma_mem(&rgep->dma_area_rxdesc);
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
		    RGE_BSWAP_32(pbuf->cookie.dmac_laddress + rgep->head_room);
		bdp->host_buf_addr_hi =
		    RGE_BSWAP_32(pbuf->cookie.dmac_laddress >> 32);
		bdp->flags_len = RGE_BSWAP_32(BD_FLAG_HW_OWN |
		    (rgep->rxbuf_size - rgep->head_room));
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

	if (rgep->chip_flags & CHIP_FLAG_FORCE_BCOPY)
		return;

	/*
	 * If all the up-sending buffers haven't been returned to driver,
	 * use bcopy() only in rx process.
	 */
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
rge_fini_send_ring(rge_t *rgep)
{
	sw_sbd_t *ssbdp;
	uint32_t slot;

	ssbdp = rgep->sw_sbds;
	for (slot = 0; slot < RGE_SEND_SLOTS; ++slot) {
		rge_free_dma_mem(&ssbdp->pbuf);
		ssbdp++;
	}

	kmem_free(rgep->sw_sbds, RGE_SEND_SLOTS * sizeof (sw_sbd_t));
	rgep->sw_sbds = NULL;
}

static void
rge_fini_recv_ring(rge_t *rgep)
{
	sw_rbd_t *srbdp;
	uint32_t slot;

	srbdp = rgep->sw_rbds;
	for (slot = 0; slot < RGE_RECV_SLOTS; ++srbdp, ++slot) {
		if (srbdp->rx_buf) {
			if (srbdp->rx_buf->mp != NULL) {
				freemsg(srbdp->rx_buf->mp);
				srbdp->rx_buf->mp = NULL;
			}
			rge_free_dma_mem(&srbdp->rx_buf->pbuf);
			kmem_free(srbdp->rx_buf, sizeof (dma_buf_t));
			srbdp->rx_buf = NULL;
		}
	}

	kmem_free(rgep->sw_rbds, RGE_RECV_SLOTS * sizeof (sw_rbd_t));
	rgep->sw_rbds = NULL;
}

static void
rge_fini_buf_ring(rge_t *rgep)
{
	sw_rbd_t *srbdp;
	uint32_t slot;

	if (rgep->chip_flags & CHIP_FLAG_FORCE_BCOPY)
		return;

	ASSERT(rgep->rx_free == RGE_BUF_SLOTS);

	srbdp = rgep->free_srbds;
	for (slot = 0; slot < RGE_BUF_SLOTS; ++srbdp, ++slot) {
		if (srbdp->rx_buf != NULL) {
			if (srbdp->rx_buf->mp != NULL) {
				freemsg(srbdp->rx_buf->mp);
				srbdp->rx_buf->mp = NULL;
			}
			rge_free_dma_mem(&srbdp->rx_buf->pbuf);
			kmem_free(srbdp->rx_buf, sizeof (dma_buf_t));
			srbdp->rx_buf = NULL;
		}
	}

	kmem_free(rgep->free_srbds, RGE_BUF_SLOTS * sizeof (sw_rbd_t));
	rgep->free_srbds = NULL;
}

static void
rge_fini_rings(rge_t *rgep)
{
	rge_fini_send_ring(rgep);
	rge_fini_recv_ring(rgep);
	rge_fini_buf_ring(rgep);
}

static int
rge_init_send_ring(rge_t *rgep)
{
	uint32_t slot;
	sw_sbd_t *ssbdp;
	dma_area_t *pbuf;
	dma_area_t desc;
	int err;

	/*
	 * Allocate the array of s/w Tx Buffer Descriptors
	 */
	ssbdp = kmem_zalloc(RGE_SEND_SLOTS*sizeof (*ssbdp), KM_SLEEP);
	rgep->sw_sbds = ssbdp;

	/*
	 * Init send ring
	 */
	rgep->tx_desc = rgep->dma_area_txdesc;
	DMA_ZERO(rgep->tx_desc);
	rgep->tx_ring = rgep->tx_desc.mem_va;

	desc = rgep->tx_desc;
	for (slot = 0; slot < RGE_SEND_SLOTS; slot++) {
		rge_slice_chunk(&ssbdp->desc, &desc, 1, sizeof (rge_bd_t));

		/*
		 * Allocate memory & handle for Tx buffers
		 */
		pbuf = &ssbdp->pbuf;
		err = rge_alloc_dma_mem(rgep, rgep->txbuf_size,
		    &dma_attr_buf, &rge_buf_accattr,
		    DDI_DMA_WRITE | DDI_DMA_STREAMING, pbuf);
		if (err != DDI_SUCCESS) {
			rge_error(rgep,
			    "rge_init_send_ring: alloc tx buffer failed");
			rge_fini_send_ring(rgep);
			return (DDI_FAILURE);
		}
		ssbdp++;
	}
	ASSERT(desc.alength == 0);

	DMA_SYNC(rgep->tx_desc, DDI_DMA_SYNC_FORDEV);
	return (DDI_SUCCESS);
}

static int
rge_init_recv_ring(rge_t *rgep)
{
	uint32_t slot;
	sw_rbd_t *srbdp;
	dma_buf_t *rx_buf;
	dma_area_t *pbuf;
	int err;

	/*
	 * Allocate the array of s/w Rx Buffer Descriptors
	 */
	srbdp = kmem_zalloc(RGE_RECV_SLOTS*sizeof (*srbdp), KM_SLEEP);
	rgep->sw_rbds = srbdp;

	/*
	 * Init receive ring
	 */
	rgep->rx_next = 0;
	rgep->rx_desc = rgep->dma_area_rxdesc;
	DMA_ZERO(rgep->rx_desc);
	rgep->rx_ring = rgep->rx_desc.mem_va;

	for (slot = 0; slot < RGE_RECV_SLOTS; slot++) {
		srbdp->rx_buf = rx_buf =
		    kmem_zalloc(sizeof (dma_buf_t), KM_SLEEP);

		/*
		 * Allocate memory & handle for Rx buffers
		 */
		pbuf = &rx_buf->pbuf;
		err = rge_alloc_dma_mem(rgep, rgep->rxbuf_size,
		    &dma_attr_buf, &rge_buf_accattr,
		    DDI_DMA_READ | DDI_DMA_STREAMING, pbuf);
		if (err != DDI_SUCCESS) {
			rge_fini_recv_ring(rgep);
			rge_error(rgep,
			    "rge_init_recv_ring: alloc rx buffer failed");
			return (DDI_FAILURE);
		}

		pbuf->alength -= rgep->head_room;
		pbuf->offset += rgep->head_room;
		if (!(rgep->chip_flags & CHIP_FLAG_FORCE_BCOPY)) {
			rx_buf->rx_recycle.free_func = rge_rx_recycle;
			rx_buf->rx_recycle.free_arg = (caddr_t)rx_buf;
			rx_buf->private = (caddr_t)rgep;
			rx_buf->mp = desballoc(DMA_VPTR(rx_buf->pbuf),
			    rgep->rxbuf_size, 0, &rx_buf->rx_recycle);
			if (rx_buf->mp == NULL) {
				rge_fini_recv_ring(rgep);
				rge_problem(rgep,
				    "rge_init_recv_ring: desballoc() failed");
				return (DDI_FAILURE);
			}
		}
		srbdp++;
	}
	DMA_SYNC(rgep->rx_desc, DDI_DMA_SYNC_FORDEV);
	return (DDI_SUCCESS);
}

static int
rge_init_buf_ring(rge_t *rgep)
{
	uint32_t slot;
	sw_rbd_t *free_srbdp;
	dma_buf_t *rx_buf;
	dma_area_t *pbuf;
	int err;

	if (rgep->chip_flags & CHIP_FLAG_FORCE_BCOPY) {
		rgep->rx_bcopy = B_TRUE;
		return (DDI_SUCCESS);
	}

	/*
	 * Allocate the array of s/w free Buffer Descriptors
	 */
	free_srbdp = kmem_zalloc(RGE_BUF_SLOTS*sizeof (*free_srbdp), KM_SLEEP);
	rgep->free_srbds = free_srbdp;

	/*
	 * Init free buffer ring
	 */
	rgep->rc_next = 0;
	rgep->rf_next = 0;
	rgep->rx_bcopy = B_FALSE;
	rgep->rx_free = RGE_BUF_SLOTS;
	for (slot = 0; slot < RGE_BUF_SLOTS; slot++) {
		free_srbdp->rx_buf = rx_buf =
		    kmem_zalloc(sizeof (dma_buf_t), KM_SLEEP);

		/*
		 * Allocate memory & handle for free Rx buffers
		 */
		pbuf = &rx_buf->pbuf;
		err = rge_alloc_dma_mem(rgep, rgep->rxbuf_size,
		    &dma_attr_buf, &rge_buf_accattr,
		    DDI_DMA_READ | DDI_DMA_STREAMING, pbuf);
		if (err != DDI_SUCCESS) {
			rge_fini_buf_ring(rgep);
			rge_error(rgep,
			    "rge_init_buf_ring: alloc rx free buffer failed");
			return (DDI_FAILURE);
		}
		pbuf->alength -= rgep->head_room;
		pbuf->offset += rgep->head_room;
		rx_buf->rx_recycle.free_func = rge_rx_recycle;
		rx_buf->rx_recycle.free_arg = (caddr_t)rx_buf;
		rx_buf->private = (caddr_t)rgep;
		rx_buf->mp = desballoc(DMA_VPTR(rx_buf->pbuf),
		    rgep->rxbuf_size, 0, &rx_buf->rx_recycle);
		if (rx_buf->mp == NULL) {
			rge_fini_buf_ring(rgep);
			rge_problem(rgep,
			    "rge_init_buf_ring: desballoc() failed");
			return (DDI_FAILURE);
		}
		free_srbdp++;
	}
	return (DDI_SUCCESS);
}

static int
rge_init_rings(rge_t *rgep)
{
	int err;

	err = rge_init_send_ring(rgep);
	if (err != DDI_SUCCESS)
		return (DDI_FAILURE);

	err = rge_init_recv_ring(rgep);
	if (err != DDI_SUCCESS) {
		rge_fini_send_ring(rgep);
		return (DDI_FAILURE);
	}

	err = rge_init_buf_ring(rgep);
	if (err != DDI_SUCCESS) {
		rge_fini_send_ring(rgep);
		rge_fini_recv_ring(rgep);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
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
		rgep->resched_needed = B_TRUE;
		(void) ddi_intr_trigger_softint(rgep->resched_hdl, NULL);
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
	uint32_t crc = (uint32_t)RGE_HASH_CRC;
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
			if (msb ^ (currentbyte & 1))
				crc ^= POLY;
			currentbyte >>= 1;
		}
	}
	index = crc >> 26;
		/* the index value is between 0 and 63(0x3f) */

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
	uint32_t reg;
	uint8_t *hashp;

	mutex_enter(rgep->genlock);
	hashp = rgep->mcast_hash;
	addr = (struct ether_addr *)mca;
	/*
	 * Calculate the Multicast address hash index value
	 *	Normally, the position of MAR0-MAR7 is
	 *	MAR0: offset 0x08, ..., MAR7: offset 0x0F.
	 *
	 *	For pcie chipset, the position of MAR0-MAR7 is
	 *	different from others:
	 *	MAR0: offset 0x0F, ..., MAR7: offset 0x08.
	 */
	index = rge_hash_index(addr->ether_addr_octet);
	if (rgep->chipid.is_pcie)
		reg = (~(index / RGE_MCAST_NUM)) & 0x7;
	else
		reg = index / RGE_MCAST_NUM;

	if (add) {
		if (rgep->mcast_refs[index]++) {
			mutex_exit(rgep->genlock);
			return (0);
		}
		hashp[reg] |= 1 << (index % RGE_MCAST_NUM);
	} else {
		if (--rgep->mcast_refs[index]) {
			mutex_exit(rgep->genlock);
			return (0);
		}
		hashp[reg] &= ~ (1 << (index % RGE_MCAST_NUM));
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
	case RGE_LOOP_INTERNAL_PHY:
	case RGE_LOOP_INTERNAL_MAC:
		break;
	}

	/*
	 * All OK; tell the caller to reprogram
	 * the PHY and/or MAC for the new mode ...
	 */
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
		 * Check for specific net_config privilege
		 */
		err = secpolicy_net_config(iocp->ioc_cr, B_FALSE);
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
	rgep->handle = mac_resource_add(rgep->mh, (mac_resource_t *)&mrf);

	mutex_exit(rgep->genlock);
}

/* ARGSUSED */
static boolean_t
rge_m_getcapab(void *arg, mac_capab_t cap, void *cap_data)
{
	switch (cap) {
	case MAC_CAPAB_HCKSUM: {
		uint32_t *hcksum_txflags = cap_data;
		*hcksum_txflags = HCKSUM_INET_FULL_V4 | HCKSUM_IPHDRCKSUM;
		break;
	}
	case MAC_CAPAB_POLL:
		/*
		 * There's nothing for us to fill in, simply returning
		 * B_TRUE stating that we support polling is sufficient.
		 */
		break;
	default:
		return (B_FALSE);
	}
	return (B_TRUE);
}

/*
 * ============ Init MSI/Fixed Interrupt routines ==============
 */

/*
 * rge_add_intrs:
 *
 * Register FIXED or MSI interrupts.
 */
static int
rge_add_intrs(rge_t *rgep, int intr_type)
{
	dev_info_t *dip = rgep->devinfo;
	int avail;
	int actual;
	int intr_size;
	int count;
	int i, j;
	int ret;

	/* Get number of interrupts */
	ret = ddi_intr_get_nintrs(dip, intr_type, &count);
	if ((ret != DDI_SUCCESS) || (count == 0)) {
		rge_error(rgep, "ddi_intr_get_nintrs() failure, ret: %d, "
		    "count: %d", ret, count);
		return (DDI_FAILURE);
	}

	/* Get number of available interrupts */
	ret = ddi_intr_get_navail(dip, intr_type, &avail);
	if ((ret != DDI_SUCCESS) || (avail == 0)) {
		rge_error(rgep, "ddi_intr_get_navail() failure, "
		    "ret: %d, avail: %d\n", ret, avail);
		return (DDI_FAILURE);
	}

	/* Allocate an array of interrupt handles */
	intr_size = count * sizeof (ddi_intr_handle_t);
	rgep->htable = kmem_alloc(intr_size, KM_SLEEP);
	rgep->intr_rqst = count;

	/* Call ddi_intr_alloc() */
	ret = ddi_intr_alloc(dip, rgep->htable, intr_type, 0,
	    count, &actual, DDI_INTR_ALLOC_NORMAL);
	if (ret != DDI_SUCCESS || actual == 0) {
		rge_error(rgep, "ddi_intr_alloc() failed %d\n", ret);
		kmem_free(rgep->htable, intr_size);
		return (DDI_FAILURE);
	}
	if (actual < count) {
		rge_log(rgep, "ddi_intr_alloc() Requested: %d, Received: %d\n",
		    count, actual);
	}
	rgep->intr_cnt = actual;

	/*
	 * Get priority for first msi, assume remaining are all the same
	 */
	if ((ret = ddi_intr_get_pri(rgep->htable[0], &rgep->intr_pri)) !=
	    DDI_SUCCESS) {
		rge_error(rgep, "ddi_intr_get_pri() failed %d\n", ret);
		/* Free already allocated intr */
		for (i = 0; i < actual; i++) {
			(void) ddi_intr_free(rgep->htable[i]);
		}
		kmem_free(rgep->htable, intr_size);
		return (DDI_FAILURE);
	}

	/* Test for high level mutex */
	if (rgep->intr_pri >= ddi_intr_get_hilevel_pri()) {
		rge_error(rgep, "rge_add_intrs:"
		    "Hi level interrupt not supported");
		for (i = 0; i < actual; i++)
			(void) ddi_intr_free(rgep->htable[i]);
		kmem_free(rgep->htable, intr_size);
		return (DDI_FAILURE);
	}

	/* Call ddi_intr_add_handler() */
	for (i = 0; i < actual; i++) {
		if ((ret = ddi_intr_add_handler(rgep->htable[i], rge_intr,
		    (caddr_t)rgep, (caddr_t)(uintptr_t)i)) != DDI_SUCCESS) {
			rge_error(rgep, "ddi_intr_add_handler() "
			    "failed %d\n", ret);
			/* Remove already added intr */
			for (j = 0; j < i; j++)
				(void) ddi_intr_remove_handler(rgep->htable[j]);
			/* Free already allocated intr */
			for (i = 0; i < actual; i++) {
				(void) ddi_intr_free(rgep->htable[i]);
			}
			kmem_free(rgep->htable, intr_size);
			return (DDI_FAILURE);
		}
	}

	if ((ret = ddi_intr_get_cap(rgep->htable[0], &rgep->intr_cap))
	    != DDI_SUCCESS) {
		rge_error(rgep, "ddi_intr_get_cap() failed %d\n", ret);
		for (i = 0; i < actual; i++) {
			(void) ddi_intr_remove_handler(rgep->htable[i]);
			(void) ddi_intr_free(rgep->htable[i]);
		}
		kmem_free(rgep->htable, intr_size);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * rge_rem_intrs:
 *
 * Unregister FIXED or MSI interrupts
 */
static void
rge_rem_intrs(rge_t *rgep)
{
	int i;

	/* Disable all interrupts */
	if (rgep->intr_cap & DDI_INTR_FLAG_BLOCK) {
		/* Call ddi_intr_block_disable() */
		(void) ddi_intr_block_disable(rgep->htable, rgep->intr_cnt);
	} else {
		for (i = 0; i < rgep->intr_cnt; i++) {
			(void) ddi_intr_disable(rgep->htable[i]);
		}
	}

	/* Call ddi_intr_remove_handler() */
	for (i = 0; i < rgep->intr_cnt; i++) {
		(void) ddi_intr_remove_handler(rgep->htable[i]);
		(void) ddi_intr_free(rgep->htable[i]);
	}

	kmem_free(rgep->htable, rgep->intr_rqst * sizeof (ddi_intr_handle_t));
}

/*
 * ========== Per-instance setup/teardown code ==========
 */

#undef	RGE_DBG
#define	RGE_DBG		RGE_DBG_INIT	/* debug flag for this code	*/

static void
rge_unattach(rge_t *rgep)
{
	/*
	 * Flag that no more activity may be initiated
	 */
	rgep->progress &= ~PROGRESS_READY;
	rgep->rge_mac_state = RGE_MAC_UNATTACH;

	/*
	 * Quiesce the PHY and MAC (leave it reset but still powered).
	 * Clean up and free all RGE data structures
	 */
	if (rgep->periodic_id != NULL) {
		ddi_periodic_delete(rgep->periodic_id);
		rgep->periodic_id = NULL;
	}

	if (rgep->progress & PROGRESS_KSTATS)
		rge_fini_kstats(rgep);

	if (rgep->progress & PROGRESS_PHY)
		(void) rge_phy_reset(rgep);

	if (rgep->progress & PROGRESS_INIT) {
		mutex_enter(rgep->genlock);
		(void) rge_chip_reset(rgep);
		mutex_exit(rgep->genlock);
		rge_fini_rings(rgep);
	}

	if (rgep->progress & PROGRESS_INTR) {
		rge_rem_intrs(rgep);
		mutex_destroy(rgep->rc_lock);
		mutex_destroy(rgep->rx_lock);
		mutex_destroy(rgep->tc_lock);
		mutex_destroy(rgep->tx_lock);
		rw_destroy(rgep->errlock);
		mutex_destroy(rgep->genlock);
	}

	if (rgep->progress & PROGRESS_FACTOTUM)
		(void) ddi_intr_remove_softint(rgep->factotum_hdl);

	if (rgep->progress & PROGRESS_RESCHED)
		(void) ddi_intr_remove_softint(rgep->resched_hdl);

	rge_free_bufs(rgep);

	if (rgep->progress & PROGRESS_NDD)
		rge_nd_cleanup(rgep);

	if (rgep->progress & PROGRESS_REGS)
		ddi_regs_map_free(&rgep->io_handle);

	if (rgep->progress & PROGRESS_CFG)
		pci_config_teardown(&rgep->cfg_handle);

	ddi_remove_minor_node(rgep->devinfo, NULL);
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
	mac_register_t *macp;
	chip_id_t *cidp;
	int intr_types;
	caddr_t regs;
	int instance;
	int i;
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

	rgep = kmem_zalloc(sizeof (*rgep), KM_SLEEP);
	ddi_set_driver_private(devinfo, rgep);
	rgep->devinfo = devinfo;

	/*
	 * Initialize more fields in RGE private data
	 */
	rgep->rge_mac_state = RGE_MAC_ATTACH;
	rgep->debug = ddi_prop_get_int(DDI_DEV_T_ANY, devinfo,
	    DDI_PROP_DONTPASS, debug_propname, rge_debug);
	rgep->default_mtu = ddi_prop_get_int(DDI_DEV_T_ANY, devinfo,
	    DDI_PROP_DONTPASS, mtu_propname, ETHERMTU);
	rgep->msi_enable = ddi_prop_get_int(DDI_DEV_T_ANY, devinfo,
	    DDI_PROP_DONTPASS, msi_propname, B_TRUE);
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
	err = ddi_intr_add_softint(devinfo, &rgep->resched_hdl,
	    DDI_INTR_SOFTPRI_MIN, rge_reschedule, (caddr_t)rgep);
	if (err != DDI_SUCCESS) {
		rge_problem(rgep, "ddi_intr_add_softint() failed");
		goto attach_fail;
	}
	rgep->progress |= PROGRESS_RESCHED;
	err = ddi_intr_add_softint(devinfo, &rgep->factotum_hdl,
	    DDI_INTR_SOFTPRI_MIN, rge_chip_factotum, (caddr_t)rgep);
	if (err != DDI_SUCCESS) {
		rge_problem(rgep, "ddi_intr_add_softint() failed");
		goto attach_fail;
	}
	rgep->progress |= PROGRESS_FACTOTUM;

	/*
	 * Get supported interrupt types
	 */
	if (ddi_intr_get_supported_types(devinfo, &intr_types)
	    != DDI_SUCCESS) {
		rge_error(rgep, "ddi_intr_get_supported_types failed\n");
		goto attach_fail;
	}

	/*
	 * Add the h/w interrupt handler and initialise mutexes
	 */
	if ((intr_types & DDI_INTR_TYPE_MSI) && rgep->msi_enable) {
		if (rge_add_intrs(rgep, DDI_INTR_TYPE_MSI) != DDI_SUCCESS) {
			rge_error(rgep, "MSI registration failed, "
			    "trying FIXED interrupt type\n");
		} else {
			rge_log(rgep, "Using MSI interrupt type\n");
			rgep->intr_type = DDI_INTR_TYPE_MSI;
			rgep->progress |= PROGRESS_INTR;
		}
	}
	if (!(rgep->progress & PROGRESS_INTR) &&
	    (intr_types & DDI_INTR_TYPE_FIXED)) {
		if (rge_add_intrs(rgep, DDI_INTR_TYPE_FIXED) != DDI_SUCCESS) {
			rge_error(rgep, "FIXED interrupt "
			    "registration failed\n");
			goto attach_fail;
		}
		rge_log(rgep, "Using FIXED interrupt type\n");
		rgep->intr_type = DDI_INTR_TYPE_FIXED;
		rgep->progress |= PROGRESS_INTR;
	}
	if (!(rgep->progress & PROGRESS_INTR)) {
		rge_error(rgep, "No interrupts registered\n");
		goto attach_fail;
	}
	mutex_init(rgep->genlock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(rgep->intr_pri));
	rw_init(rgep->errlock, NULL, RW_DRIVER,
	    DDI_INTR_PRI(rgep->intr_pri));
	mutex_init(rgep->tx_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(rgep->intr_pri));
	mutex_init(rgep->tc_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(rgep->intr_pri));
	mutex_init(rgep->rx_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(rgep->intr_pri));
	mutex_init(rgep->rc_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(rgep->intr_pri));

	/*
	 * Initialize rings
	 */
	err = rge_init_rings(rgep);
	if (err != DDI_SUCCESS) {
		rge_problem(rgep, "rge_init_rings() failed");
		goto attach_fail;
	}
	rgep->progress |= PROGRESS_INIT;

	/*
	 * Now that mutex locks are initialized, enable interrupts.
	 */
	if (rgep->intr_cap & DDI_INTR_FLAG_BLOCK) {
		/* Call ddi_intr_block_enable() for MSI interrupts */
		(void) ddi_intr_block_enable(rgep->htable, rgep->intr_cnt);
	} else {
		/* Call ddi_intr_enable for MSI or FIXED interrupts */
		for (i = 0; i < rgep->intr_cnt; i++) {
			(void) ddi_intr_enable(rgep->htable[i]);
		}
	}

	/*
	 * Initialise link state variables
	 * Stop, reset & reinitialise the chip.
	 * Initialise the (internal) PHY.
	 */
	rgep->param_link_up = LINK_STATE_UNKNOWN;

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

	if ((macp = mac_alloc(MAC_VERSION)) == NULL)
		goto attach_fail;
	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = rgep;
	macp->m_dip = devinfo;
	macp->m_src_addr = rgep->netaddr;
	macp->m_callbacks = &rge_m_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = rgep->default_mtu;

	/*
	 * Finally, we're ready to register ourselves with the MAC layer
	 * interface; if this succeeds, we're all ready to start()
	 */
	err = mac_register(macp, &rgep->mh);
	mac_free(macp);
	if (err != 0)
		goto attach_fail;

	/*
	 * Register a periodical handler.
	 * reg_chip_cyclic() is invoked in kernel context.
	 */
	rgep->periodic_id = ddi_periodic_add(rge_chip_cyclic, rgep,
	    RGE_CYCLIC_PERIOD, DDI_IPL_0);

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
	if (!(rgep->chip_flags & CHIP_FLAG_FORCE_BCOPY) &&
	    rgep->rx_free != RGE_BUF_SLOTS)
		return (DDI_FAILURE);

	/*
	 * Unregister from the MAC layer subsystem.  This can fail, in
	 * particular if there are DLPI style-2 streams still open -
	 * in which case we just return failure without shutting
	 * down chip operations.
	 */
	if (mac_unregister(rgep->mh) != 0)
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
