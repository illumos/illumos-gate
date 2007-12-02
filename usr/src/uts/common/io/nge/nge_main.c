/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file may contain confidential information of Nvidia
 * and should not be distributed in source form without approval
 * from Sun Legal.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "nge.h"

/*
 * Describes the chip's DMA engine
 */

static ddi_dma_attr_t hot_dma_attr = {
	DMA_ATTR_V0,			/* dma_attr version	*/
	0x0000000000000000ull,		/* dma_attr_addr_lo	*/
	0x000000FFFFFFFFFFull,		/* dma_attr_addr_hi	*/
	0x000000007FFFFFFFull,		/* dma_attr_count_max	*/
	0x0000000000000010ull,		/* dma_attr_align	*/
	0x00000FFF,			/* dma_attr_burstsizes	*/
	0x00000001,			/* dma_attr_minxfer	*/
	0x000000000000FFFFull,		/* dma_attr_maxxfer	*/
	0x000000FFFFFFFFFFull,		/* dma_attr_seg		*/
	1,				/* dma_attr_sgllen 	*/
	0x00000001,			/* dma_attr_granular 	*/
	0
};

static ddi_dma_attr_t hot_tx_dma_attr = {
	DMA_ATTR_V0,			/* dma_attr version	*/
	0x0000000000000000ull,		/* dma_attr_addr_lo	*/
	0x000000FFFFFFFFFFull,		/* dma_attr_addr_hi	*/
	0x0000000000003FFFull,		/* dma_attr_count_max	*/
	0x0000000000000010ull,		/* dma_attr_align	*/
	0x00000FFF,			/* dma_attr_burstsizes	*/
	0x00000001,			/* dma_attr_minxfer	*/
	0x0000000000003FFFull,		/* dma_attr_maxxfer	*/
	0x000000FFFFFFFFFFull,		/* dma_attr_seg		*/
	NGE_MAX_COOKIES,		/* dma_attr_sgllen 	*/
	1,				/* dma_attr_granular 	*/
	0
};

static ddi_dma_attr_t sum_dma_attr = {
	DMA_ATTR_V0,			/* dma_attr version	*/
	0x0000000000000000ull,		/* dma_attr_addr_lo	*/
	0x00000000FFFFFFFFull,		/* dma_attr_addr_hi	*/
	0x000000007FFFFFFFull,		/* dma_attr_count_max	*/
	0x0000000000000010ull,		/* dma_attr_align	*/
	0x00000FFF,			/* dma_attr_burstsizes	*/
	0x00000001,			/* dma_attr_minxfer	*/
	0x000000000000FFFFull,		/* dma_attr_maxxfer	*/
	0x00000000FFFFFFFFull,		/* dma_attr_seg		*/
	1,				/* dma_attr_sgllen 	*/
	0x00000001,			/* dma_attr_granular 	*/
	0
};

static ddi_dma_attr_t sum_tx_dma_attr = {
	DMA_ATTR_V0,			/* dma_attr version	*/
	0x0000000000000000ull,		/* dma_attr_addr_lo	*/
	0x00000000FFFFFFFFull,		/* dma_attr_addr_hi	*/
	0x0000000000003FFFull,		/* dma_attr_count_max	*/
	0x0000000000000010ull,		/* dma_attr_align	*/
	0x00000FFF,			/* dma_attr_burstsizes	*/
	0x00000001,			/* dma_attr_minxfer	*/
	0x0000000000003FFFull,		/* dma_attr_maxxfer	*/
	0x00000000FFFFFFFFull,		/* dma_attr_seg		*/
	NGE_MAX_COOKIES,		/* dma_attr_sgllen 	*/
	1,				/* dma_attr_granular 	*/
	0
};

/*
 * DMA access attributes for data.
 */
ddi_device_acc_attr_t nge_data_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

/*
 * DMA access attributes for descriptors.
 */
static ddi_device_acc_attr_t nge_desc_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

/*
 * PIO access attributes for registers
 */
static ddi_device_acc_attr_t nge_reg_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

/*
 * NIC DESC MODE 2
 */

static const nge_desc_attr_t nge_sum_desc = {

	sizeof (sum_rx_bd),
	sizeof (sum_tx_bd),
	&sum_dma_attr,
	&sum_tx_dma_attr,
	nge_sum_rxd_fill,
	nge_sum_rxd_check,
	nge_sum_txd_fill,
	nge_sum_txd_check,
};

/*
 * NIC DESC MODE 3
 */

static const nge_desc_attr_t nge_hot_desc = {

	sizeof (hot_rx_bd),
	sizeof (hot_tx_bd),
	&hot_dma_attr,
	&hot_tx_dma_attr,
	nge_hot_rxd_fill,
	nge_hot_rxd_check,
	nge_hot_txd_fill,
	nge_hot_txd_check,
};

static char nge_ident[] = "nVidia 1Gb Ethernet %I%";
static char clsize_propname[] = "cache-line-size";
static char latency_propname[] = "latency-timer";
static char debug_propname[]	= "nge-debug-flags";
static char rx_data_hw[] = "rx-data-hw";
static char rx_prd_lw[] = "rx-prd-lw";
static char rx_prd_hw[] = "rx-prd-hw";
static char sw_intr_intv[] = "sw-intr-intvl";
static char nge_desc_mode[] = "desc-mode";
static char default_mtu[] = "default_mtu";
static char low_memory_mode[] = "minimal-memory-usage";
extern kmutex_t nge_log_mutex[1];

static int		nge_m_start(void *);
static void		nge_m_stop(void *);
static int		nge_m_promisc(void *, boolean_t);
static int		nge_m_multicst(void *, boolean_t, const uint8_t *);
static int		nge_m_unicst(void *, const uint8_t *);
static void		nge_m_resources(void *);
static void		nge_m_ioctl(void *, queue_t *, mblk_t *);
static boolean_t	nge_m_getcapab(void *, mac_capab_t, void *);

#define		NGE_M_CALLBACK_FLAGS	(MC_RESOURCES | MC_IOCTL | MC_GETCAPAB)

static mac_callbacks_t nge_m_callbacks = {
	NGE_M_CALLBACK_FLAGS,
	nge_m_stat,
	nge_m_start,
	nge_m_stop,
	nge_m_promisc,
	nge_m_multicst,
	nge_m_unicst,
	nge_m_tx,
	nge_m_resources,
	nge_m_ioctl,
	nge_m_getcapab
};

static int nge_add_intrs(nge_t *, int);
static void nge_rem_intrs(nge_t *);
static int nge_register_intrs_and_init_locks(nge_t *);

/*
 * NGE MSI tunable:
 */
boolean_t nge_enable_msi = B_FALSE;

static enum ioc_reply
nge_set_loop_mode(nge_t *ngep, uint32_t mode)
{
	/*
	 * If the mode isn't being changed, there's nothing to do ...
	 */
	if (mode == ngep->param_loop_mode)
		return (IOC_ACK);

	/*
	 * Validate the requested mode and prepare a suitable message
	 * to explain the link down/up cycle that the change will
	 * probably induce ...
	 */
	switch (mode) {
	default:
		return (IOC_INVAL);

	case NGE_LOOP_NONE:
	case NGE_LOOP_EXTERNAL_100:
	case NGE_LOOP_EXTERNAL_10:
	case NGE_LOOP_INTERNAL_PHY:
		break;
	}

	/*
	 * All OK; tell the caller to reprogram
	 * the PHY and/or MAC for the new mode ...
	 */
	ngep->param_loop_mode = mode;
	return (IOC_RESTART_ACK);
}

#undef	NGE_DBG
#define	NGE_DBG		NGE_DBG_INIT

/*
 * Utility routine to carve a slice off a chunk of allocated memory,
 * updating the chunk descriptor accordingly.  The size of the slice
 * is given by the product of the <qty> and <size> parameters.
 */
void
nge_slice_chunk(dma_area_t *slice, dma_area_t *chunk,
    uint32_t qty, uint32_t size)
{
	size_t totsize;

	totsize = qty*size;
	ASSERT(size > 0);
	ASSERT(totsize <= chunk->alength);

	*slice = *chunk;
	slice->nslots = qty;
	slice->size = size;
	slice->alength = totsize;

	chunk->mem_va = (caddr_t)chunk->mem_va + totsize;
	chunk->alength -= totsize;
	chunk->offset += totsize;
	chunk->cookie.dmac_laddress += totsize;
	chunk->cookie.dmac_size -= totsize;
}

/*
 * Allocate an area of memory and a DMA handle for accessing it
 */
int
nge_alloc_dma_mem(nge_t *ngep, size_t memsize, ddi_device_acc_attr_t *attr_p,
    uint_t dma_flags, dma_area_t *dma_p)
{
	int err;
	caddr_t va;

	NGE_TRACE(("nge_alloc_dma_mem($%p, %ld, $%p, 0x%x, $%p)",
	    (void *)ngep, memsize, attr_p, dma_flags, dma_p));
	/*
	 * Allocate handle
	 */
	err = ddi_dma_alloc_handle(ngep->devinfo, ngep->desc_attr.dma_attr,
	    DDI_DMA_DONTWAIT, NULL, &dma_p->dma_hdl);
	if (err != DDI_SUCCESS)
		goto fail;

	/*
	 * Allocate memory
	 */
	err = ddi_dma_mem_alloc(dma_p->dma_hdl, memsize, attr_p,
	    dma_flags & (DDI_DMA_CONSISTENT | DDI_DMA_STREAMING),
	    DDI_DMA_DONTWAIT, NULL, &va, &dma_p->alength, &dma_p->acc_hdl);
	if (err != DDI_SUCCESS)
		goto fail;

	/*
	 * Bind the two together
	 */
	dma_p->mem_va = va;
	err = ddi_dma_addr_bind_handle(dma_p->dma_hdl, NULL,
	    va, dma_p->alength, dma_flags, DDI_DMA_DONTWAIT, NULL,
	    &dma_p->cookie, &dma_p->ncookies);

	if (err != DDI_DMA_MAPPED || dma_p->ncookies != 1)
		goto fail;

	dma_p->nslots = ~0U;
	dma_p->size = ~0U;
	dma_p->offset = 0;

	return (DDI_SUCCESS);

fail:
	nge_free_dma_mem(dma_p);
	NGE_DEBUG(("nge_alloc_dma_mem: fail to alloc dma memory!"));

	return (DDI_FAILURE);
}

/*
 * Free one allocated area of DMAable memory
 */
void
nge_free_dma_mem(dma_area_t *dma_p)
{
	if (dma_p->dma_hdl != NULL) {
		if (dma_p->ncookies) {
			(void) ddi_dma_unbind_handle(dma_p->dma_hdl);
			dma_p->ncookies = 0;
		}
	}
	if (dma_p->acc_hdl != NULL) {
		ddi_dma_mem_free(&dma_p->acc_hdl);
		dma_p->acc_hdl = NULL;
	}
	if (dma_p->dma_hdl != NULL) {
		ddi_dma_free_handle(&dma_p->dma_hdl);
		dma_p->dma_hdl = NULL;
	}
}

#define	ALLOC_TX_BUF	0x1
#define	ALLOC_TX_DESC	0x2
#define	ALLOC_RX_DESC	0x4

int
nge_alloc_bufs(nge_t *ngep)
{
	int err;
	int split;
	int progress;
	size_t txbuffsize;
	size_t rxdescsize;
	size_t txdescsize;

	txbuffsize = ngep->tx_desc * ngep->buf_size;
	rxdescsize = ngep->rx_desc;
	txdescsize = ngep->tx_desc;
	rxdescsize *= ngep->desc_attr.rxd_size;
	txdescsize *= ngep->desc_attr.txd_size;
	progress = 0;

	NGE_TRACE(("nge_alloc_bufs($%p)", (void *)ngep));
	/*
	 * Allocate memory & handles for TX buffers
	 */
	ASSERT((txbuffsize % ngep->nge_split) == 0);
	for (split = 0; split < ngep->nge_split; ++split) {
		err = nge_alloc_dma_mem(ngep, txbuffsize/ngep->nge_split,
		    &nge_data_accattr, DDI_DMA_WRITE | NGE_DMA_MODE,
		    &ngep->send->buf[split]);
		if (err != DDI_SUCCESS)
			goto fail;
	}

	progress |= ALLOC_TX_BUF;

	/*
	 * Allocate memory & handles for receive return rings and
	 * buffer (producer) descriptor rings
	 */
	err = nge_alloc_dma_mem(ngep, rxdescsize, &nge_desc_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, &ngep->recv->desc);
	if (err != DDI_SUCCESS)
		goto fail;
	progress |= ALLOC_RX_DESC;

	/*
	 * Allocate memory & handles for TX descriptor rings,
	 */
	err = nge_alloc_dma_mem(ngep, txdescsize, &nge_desc_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, &ngep->send->desc);
	if (err != DDI_SUCCESS)
		goto fail;
	return (DDI_SUCCESS);

fail:
	if (progress & ALLOC_RX_DESC)
		nge_free_dma_mem(&ngep->recv->desc);
	if (progress & ALLOC_TX_BUF) {
		for (split = 0; split < ngep->nge_split; ++split)
			nge_free_dma_mem(&ngep->send->buf[split]);
	}

	return (DDI_FAILURE);
}

/*
 * This routine frees the transmit and receive buffers and descriptors.
 * Make sure the chip is stopped before calling it!
 */
void
nge_free_bufs(nge_t *ngep)
{
	int split;

	NGE_TRACE(("nge_free_bufs($%p)", (void *)ngep));

	nge_free_dma_mem(&ngep->recv->desc);
	nge_free_dma_mem(&ngep->send->desc);

	for (split = 0; split < ngep->nge_split; ++split)
		nge_free_dma_mem(&ngep->send->buf[split]);
}

/*
 * Clean up initialisation done above before the memory is freed
 */
static void
nge_fini_send_ring(nge_t *ngep)
{
	uint32_t slot;
	size_t dmah_num;
	send_ring_t *srp;
	sw_tx_sbd_t *ssbdp;

	srp = ngep->send;
	ssbdp = srp->sw_sbds;

	NGE_TRACE(("nge_fini_send_ring($%p)", (void *)ngep));

	dmah_num = sizeof (srp->dmahndl) / sizeof (srp->dmahndl[0]);

	for (slot = 0; slot < dmah_num; ++slot) {
		if (srp->dmahndl[slot].hndl) {
			(void) ddi_dma_unbind_handle(srp->dmahndl[slot].hndl);
			ddi_dma_free_handle(&srp->dmahndl[slot].hndl);
			srp->dmahndl[slot].hndl = NULL;
			srp->dmahndl[slot].next = NULL;
		}
	}

	srp->dmah_free.head = NULL;
	srp->dmah_free.tail = NULL;

	kmem_free(ssbdp, srp->desc.nslots*sizeof (*ssbdp));

}

/*
 * Initialise the specified Send Ring, using the information in the
 * <dma_area> descriptors that it contains to set up all the other
 * fields. This routine should be called only once for each ring.
 */
static int
nge_init_send_ring(nge_t *ngep)
{
	size_t dmah_num;
	uint32_t nslots;
	uint32_t err;
	uint32_t slot;
	uint32_t split;
	send_ring_t *srp;
	sw_tx_sbd_t *ssbdp;
	dma_area_t desc;
	dma_area_t pbuf;

	srp = ngep->send;
	srp->desc.nslots = ngep->tx_desc;
	nslots = srp->desc.nslots;

	NGE_TRACE(("nge_init_send_ring($%p)", (void *)ngep));
	/*
	 * Other one-off initialisation of per-ring data
	 */
	srp->ngep = ngep;

	/*
	 * Allocate the array of s/w Send Buffer Descriptors
	 */
	ssbdp = kmem_zalloc(nslots*sizeof (*ssbdp), KM_SLEEP);
	srp->sw_sbds = ssbdp;

	/*
	 * Now initialise each array element once and for all
	 */
	desc = srp->desc;
	for (split = 0; split < ngep->nge_split; ++split) {
		pbuf = srp->buf[split];
		for (slot = 0; slot < nslots/ngep->nge_split; ++ssbdp, ++slot) {
			nge_slice_chunk(&ssbdp->desc, &desc, 1,
			    ngep->desc_attr.txd_size);
			nge_slice_chunk(&ssbdp->pbuf, &pbuf, 1,
			    ngep->buf_size);
		}
		ASSERT(pbuf.alength == 0);
	}
	ASSERT(desc.alength == 0);

	dmah_num = sizeof (srp->dmahndl) / sizeof (srp->dmahndl[0]);

	/* preallocate dma handles for tx buffer */
	for (slot = 0; slot < dmah_num; ++slot) {

		err = ddi_dma_alloc_handle(ngep->devinfo,
		    ngep->desc_attr.tx_dma_attr, DDI_DMA_DONTWAIT,
		    NULL, &srp->dmahndl[slot].hndl);

		if (err != DDI_SUCCESS) {
			nge_fini_send_ring(ngep);
			nge_error(ngep,
			    "nge_init_send_ring: alloc dma handle fails");
			return (DDI_FAILURE);
		}
		srp->dmahndl[slot].next = srp->dmahndl + slot + 1;
	}

	srp->dmah_free.head = srp->dmahndl;
	srp->dmah_free.tail = srp->dmahndl + dmah_num - 1;
	srp->dmah_free.tail->next = NULL;

	return (DDI_SUCCESS);
}

/*
 * Intialize the tx recycle pointer and tx sending pointer of tx ring
 * and set the type of tx's data descriptor by default.
 */
static void
nge_reinit_send_ring(nge_t *ngep)
{
	size_t dmah_num;
	uint32_t slot;
	send_ring_t *srp;
	sw_tx_sbd_t *ssbdp;

	srp = ngep->send;

	/*
	 * Reinitialise control variables ...
	 */

	srp->tx_hwmark = NGE_DESC_MIN;
	srp->tx_lwmark = NGE_DESC_MIN;

	srp->tx_next = 0;
	srp->tx_free = srp->desc.nslots;
	srp->tc_next = 0;

	dmah_num = sizeof (srp->dmahndl) / sizeof (srp->dmahndl[0]);

	for (slot = 0; slot - dmah_num != 0; ++slot)
		srp->dmahndl[slot].next = srp->dmahndl + slot + 1;

	srp->dmah_free.head = srp->dmahndl;
	srp->dmah_free.tail = srp->dmahndl + dmah_num - 1;
	srp->dmah_free.tail->next = NULL;

	/*
	 * Zero and sync all the h/w Send Buffer Descriptors
	 */
	for (slot = 0; slot < srp->desc.nslots; ++slot) {
		ssbdp = &srp->sw_sbds[slot];
		ssbdp->flags = HOST_OWN;
	}

	DMA_ZERO(srp->desc);
	DMA_SYNC(srp->desc, DDI_DMA_SYNC_FORDEV);
}

/*
 * Initialize the slot number of rx's ring
 */
static void
nge_init_recv_ring(nge_t *ngep)
{
	recv_ring_t *rrp;

	rrp = ngep->recv;
	rrp->desc.nslots = ngep->rx_desc;
	rrp->ngep = ngep;
}

/*
 * Intialize the rx recycle pointer and rx sending pointer of rx ring
 */
static void
nge_reinit_recv_ring(nge_t *ngep)
{
	recv_ring_t *rrp;

	rrp = ngep->recv;

	/*
	 * Reinitialise control variables ...
	 */
	rrp->prod_index = 0;
	/*
	 * Zero and sync all the h/w Send Buffer Descriptors
	 */
	DMA_ZERO(rrp->desc);
	DMA_SYNC(rrp->desc, DDI_DMA_SYNC_FORDEV);
}

/*
 * Clean up initialisation done above before the memory is freed
 */
static void
nge_fini_buff_ring(nge_t *ngep)
{
	uint32_t i;
	buff_ring_t *brp;
	dma_area_t *bufp;
	sw_rx_sbd_t *bsbdp;

	brp = ngep->buff;
	bsbdp = brp->sw_rbds;

	NGE_DEBUG(("nge_fini_buff_ring($%p)", (void *)ngep));

	mutex_enter(brp->recycle_lock);
	brp->buf_sign++;
	mutex_exit(brp->recycle_lock);
	for (i = 0; i < ngep->rx_desc; i++, ++bsbdp) {
		if (bsbdp->bufp) {
			if (bsbdp->bufp->mp)
				freemsg(bsbdp->bufp->mp);
			nge_free_dma_mem(bsbdp->bufp);
			kmem_free(bsbdp->bufp, sizeof (dma_area_t));
			bsbdp->bufp = NULL;
		}
	}
	while (brp->free_list != NULL) {
		bufp = brp->free_list;
		brp->free_list = bufp->next;
		bufp->next = NULL;
		if (bufp->mp)
			freemsg(bufp->mp);
		nge_free_dma_mem(bufp);
		kmem_free(bufp, sizeof (dma_area_t));
	}
	while (brp->recycle_list != NULL) {
		bufp = brp->recycle_list;
		brp->recycle_list = bufp->next;
		bufp->next = NULL;
		if (bufp->mp)
			freemsg(bufp->mp);
		nge_free_dma_mem(bufp);
		kmem_free(bufp, sizeof (dma_area_t));
	}


	kmem_free(brp->sw_rbds, (ngep->rx_desc * sizeof (*bsbdp)));
	brp->sw_rbds = NULL;
}

/*
 * Intialize the Rx's data ring and free ring
 */
static int
nge_init_buff_ring(nge_t *ngep)
{
	uint32_t err;
	uint32_t slot;
	uint32_t nslots_buff;
	uint32_t nslots_recv;
	buff_ring_t *brp;
	recv_ring_t *rrp;
	dma_area_t desc;
	dma_area_t *bufp;
	sw_rx_sbd_t *bsbdp;

	rrp = ngep->recv;
	brp = ngep->buff;
	brp->nslots = ngep->rx_buf;
	brp->rx_bcopy = B_FALSE;
	nslots_recv = rrp->desc.nslots;
	nslots_buff = brp->nslots;
	brp->ngep = ngep;

	NGE_TRACE(("nge_init_buff_ring($%p)", (void *)ngep));

	/*
	 * Allocate the array of s/w Recv Buffer Descriptors
	 */
	bsbdp = kmem_zalloc(nslots_recv *sizeof (*bsbdp), KM_SLEEP);
	brp->sw_rbds = bsbdp;
	brp->free_list = NULL;
	brp->recycle_list = NULL;
	for (slot = 0; slot < nslots_buff; ++slot) {
		bufp = kmem_zalloc(sizeof (dma_area_t), KM_SLEEP);
		err = nge_alloc_dma_mem(ngep, (ngep->buf_size
		    + NGE_HEADROOM),
		    &nge_data_accattr, DDI_DMA_READ | NGE_DMA_MODE, bufp);
		if (err != DDI_SUCCESS) {
			kmem_free(bufp, sizeof (dma_area_t));
			return (DDI_FAILURE);
		}

		bufp->alength -= NGE_HEADROOM;
		bufp->offset += NGE_HEADROOM;
		bufp->private = (caddr_t)ngep;
		bufp->rx_recycle.free_func = nge_recv_recycle;
		bufp->rx_recycle.free_arg = (caddr_t)bufp;
		bufp->signature = brp->buf_sign;
		bufp->rx_delivered = B_FALSE;
		bufp->mp = desballoc(DMA_VPTR(*bufp),
		    ngep->buf_size + NGE_HEADROOM,
		    0, &bufp->rx_recycle);

		if (bufp->mp == NULL) {
			return (DDI_FAILURE);
		}
		bufp->next = brp->free_list;
		brp->free_list = bufp;
	}

	/*
	 * Now initialise each array element once and for all
	 */
	desc = rrp->desc;
	for (slot = 0; slot < nslots_recv; ++slot, ++bsbdp) {
		nge_slice_chunk(&bsbdp->desc, &desc, 1,
		    ngep->desc_attr.rxd_size);
		bufp = brp->free_list;
		brp->free_list = bufp->next;
		bsbdp->bufp = bufp;
		bsbdp->flags = CONTROLER_OWN;
		bufp->next = NULL;
	}

	ASSERT(desc.alength == 0);
	return (DDI_SUCCESS);
}

/*
 * Fill the host address of data in rx' descriptor
 * and initialize free pointers of rx free ring
 */
static int
nge_reinit_buff_ring(nge_t *ngep)
{
	uint32_t slot;
	uint32_t nslots_recv;
	buff_ring_t *brp;
	recv_ring_t *rrp;
	sw_rx_sbd_t *bsbdp;
	void *hw_bd_p;

	brp = ngep->buff;
	rrp = ngep->recv;
	bsbdp = brp->sw_rbds;
	nslots_recv = rrp->desc.nslots;
	for (slot = 0; slot < nslots_recv; ++bsbdp, ++slot) {
		hw_bd_p = DMA_VPTR(bsbdp->desc);
	/*
	 * There is a scenario: When the traffic of small tcp
	 * packet is heavy, suspending the tcp traffic will
	 * cause the preallocated buffers for rx not to be
	 * released in time by tcp taffic and cause rx's buffer
	 * pointers not to be refilled in time.
	 *
	 * At this point, if we reinitialize the driver, the bufp
	 * pointer for rx's traffic will be NULL.
	 * So the result of the reinitializion fails.
	 */
		if (bsbdp->bufp == NULL)
			return (DDI_FAILURE);

		ngep->desc_attr.rxd_fill(hw_bd_p, &bsbdp->bufp->cookie,
		    bsbdp->bufp->alength);
	}
	return (DDI_SUCCESS);
}

static void
nge_init_ring_param_lock(nge_t *ngep)
{
	buff_ring_t *brp;
	send_ring_t *srp;

	srp = ngep->send;
	brp = ngep->buff;

	/* Init the locks for send ring */
	mutex_init(srp->tx_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(ngep->intr_pri));
	mutex_init(srp->tc_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(ngep->intr_pri));
	mutex_init(&srp->dmah_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(ngep->intr_pri));

	/* Init parameters of buffer ring */
	brp->free_list = NULL;
	brp->recycle_list = NULL;
	brp->rx_hold = 0;
	brp->buf_sign = 0;

	/* Init recycle list lock */
	mutex_init(brp->recycle_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(ngep->intr_pri));
}

int
nge_init_rings(nge_t *ngep)
{
	uint32_t err;

	err = nge_init_send_ring(ngep);
	if (err != DDI_SUCCESS) {
		return (err);
	}
	nge_init_recv_ring(ngep);

	err = nge_init_buff_ring(ngep);
	if (err != DDI_SUCCESS) {
		nge_fini_send_ring(ngep);
		return (DDI_FAILURE);
	}

	return (err);
}

static int
nge_reinit_ring(nge_t *ngep)
{
	int err;

	nge_reinit_recv_ring(ngep);
	nge_reinit_send_ring(ngep);
	err = nge_reinit_buff_ring(ngep);
	return (err);
}


void
nge_fini_rings(nge_t *ngep)
{
	/*
	 * For receive ring, nothing need to be finished.
	 * So only finish buffer ring and send ring here.
	 */
	nge_fini_buff_ring(ngep);
	nge_fini_send_ring(ngep);
}

/*
 * Loopback ioctl code
 */

static lb_property_t loopmodes[] = {
	{ normal,	"normal",	NGE_LOOP_NONE		},
	{ external,	"100Mbps",	NGE_LOOP_EXTERNAL_100	},
	{ external,	"10Mbps",	NGE_LOOP_EXTERNAL_10	},
	{ internal,	"PHY",		NGE_LOOP_INTERNAL_PHY	},
};

enum ioc_reply
nge_loop_ioctl(nge_t *ngep, mblk_t *mp, struct iocblk *iocp)
{
	int cmd;
	uint32_t *lbmp;
	lb_info_sz_t *lbsp;
	lb_property_t *lbpp;

	/*
	 * Validate format of ioctl
	 */
	if (mp->b_cont == NULL)
		return (IOC_INVAL);

	cmd = iocp->ioc_cmd;

	switch (cmd) {
	default:
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
		*lbmp = ngep->param_loop_mode;
		return (IOC_REPLY);

	case LB_SET_MODE:
		if (iocp->ioc_count != sizeof (uint32_t))
			return (IOC_INVAL);
		lbmp = (uint32_t *)mp->b_cont->b_rptr;
		return (nge_set_loop_mode(ngep, *lbmp));
	}
}

#undef	NGE_DBG
#define	NGE_DBG	NGE_DBG_NEMO


static void
nge_check_desc_prop(nge_t *ngep)
{
	if (ngep->desc_mode != DESC_HOT && ngep->desc_mode != DESC_OFFLOAD)
		ngep->desc_mode = DESC_HOT;

	if (ngep->desc_mode == DESC_OFFLOAD)	{

		ngep->desc_attr = nge_sum_desc;

	}	else if (ngep->desc_mode == DESC_HOT)	{

		ngep->desc_attr = nge_hot_desc;
	}
}

/*
 * nge_get_props -- get the parameters to tune the driver
 */
static void
nge_get_props(nge_t *ngep)
{
	chip_info_t *infop;
	dev_info_t *devinfo;
	nge_dev_spec_param_t *dev_param_p;

	devinfo = ngep->devinfo;
	infop = (chip_info_t *)&ngep->chipinfo;
	dev_param_p = &ngep->dev_spec_param;

	infop->clsize = ddi_prop_get_int(DDI_DEV_T_ANY, devinfo,
	    DDI_PROP_DONTPASS, clsize_propname, 32);

	infop->latency = ddi_prop_get_int(DDI_DEV_T_ANY, devinfo,
	    DDI_PROP_DONTPASS, latency_propname, 64);
	ngep->rx_datahwm = ddi_prop_get_int(DDI_DEV_T_ANY, devinfo,
	    DDI_PROP_DONTPASS, rx_data_hw, 0x20);
	ngep->rx_prdlwm = ddi_prop_get_int(DDI_DEV_T_ANY, devinfo,
	    DDI_PROP_DONTPASS, rx_prd_lw, 0x4);
	ngep->rx_prdhwm = ddi_prop_get_int(DDI_DEV_T_ANY, devinfo,
	    DDI_PROP_DONTPASS, rx_prd_hw, 0xc);

	ngep->sw_intr_intv = ddi_prop_get_int(DDI_DEV_T_ANY, devinfo,
	    DDI_PROP_DONTPASS, sw_intr_intv, SWTR_ITC);
	ngep->debug = ddi_prop_get_int(DDI_DEV_T_ANY, devinfo,
	    DDI_PROP_DONTPASS, debug_propname, NGE_DBG_CHIP);
	ngep->desc_mode = ddi_prop_get_int(DDI_DEV_T_ANY, devinfo,
	    DDI_PROP_DONTPASS, nge_desc_mode, dev_param_p->desc_type);
	ngep->lowmem_mode = ddi_prop_get_int(DDI_DEV_T_ANY, devinfo,
	    DDI_PROP_DONTPASS, low_memory_mode, 0);

	if (dev_param_p->jumbo) {
		ngep->default_mtu = ddi_prop_get_int(DDI_DEV_T_ANY, devinfo,
		    DDI_PROP_DONTPASS, default_mtu, ETHERMTU);
	} else
		ngep->default_mtu = ETHERMTU;

	if (ngep->default_mtu > ETHERMTU &&
	    ngep->default_mtu <= NGE_MTU_2500) {
		ngep->buf_size = NGE_JB2500_BUFSZ;
		ngep->tx_desc = NGE_SEND_JB2500_SLOTS_DESC;
		ngep->rx_desc = NGE_RECV_JB2500_SLOTS_DESC;
		ngep->rx_buf = NGE_RECV_JB2500_SLOTS_DESC * 2;
		ngep->nge_split = NGE_SPLIT_256;
	} else if (ngep->default_mtu > NGE_MTU_2500 &&
	    ngep->default_mtu <= NGE_MTU_4500) {
		ngep->buf_size = NGE_JB4500_BUFSZ;
		ngep->tx_desc = NGE_SEND_JB4500_SLOTS_DESC;
		ngep->rx_desc = NGE_RECV_JB4500_SLOTS_DESC;
		ngep->rx_buf = NGE_RECV_JB4500_SLOTS_DESC * 2;
		ngep->nge_split = NGE_SPLIT_256;
	} else if (ngep->default_mtu > NGE_MTU_4500 &&
	    ngep->default_mtu <= NGE_MAX_MTU) {
		ngep->buf_size = NGE_JB9000_BUFSZ;
		ngep->tx_desc = NGE_SEND_JB9000_SLOTS_DESC;
		ngep->rx_desc = NGE_RECV_JB9000_SLOTS_DESC;
		ngep->rx_buf = NGE_RECV_JB9000_SLOTS_DESC * 2;
		ngep->nge_split = NGE_SPLIT_256;
	} else if (ngep->default_mtu > NGE_MAX_MTU) {
		ngep->default_mtu = NGE_MAX_MTU;
		ngep->buf_size = NGE_JB9000_BUFSZ;
		ngep->tx_desc = NGE_SEND_JB9000_SLOTS_DESC;
		ngep->rx_desc = NGE_RECV_JB9000_SLOTS_DESC;
		ngep->rx_buf = NGE_RECV_JB9000_SLOTS_DESC * 2;
		ngep->nge_split = NGE_SPLIT_256;
	} else if (ngep->lowmem_mode != 0) {
		ngep->default_mtu = ETHERMTU;
		ngep->buf_size = NGE_STD_BUFSZ;
		ngep->tx_desc = NGE_SEND_LOWMEM_SLOTS_DESC;
		ngep->rx_desc = NGE_RECV_LOWMEM_SLOTS_DESC;
		ngep->rx_buf = NGE_RECV_LOWMEM_SLOTS_DESC * 2;
		ngep->nge_split = NGE_SPLIT_32;
	} else {
		ngep->default_mtu = ETHERMTU;
		ngep->buf_size = NGE_STD_BUFSZ;
		ngep->tx_desc = dev_param_p->tx_desc_num;
		ngep->rx_desc = dev_param_p->rx_desc_num;
		ngep->rx_buf = dev_param_p->rx_desc_num * 2;
		ngep->nge_split = dev_param_p->nge_split;
	}

	nge_check_desc_prop(ngep);
}


static int
nge_reset(nge_t *ngep)
{
	int err;
	send_ring_t *srp = ngep->send;

	ASSERT(mutex_owned(ngep->genlock));
	mutex_enter(srp->tc_lock);
	mutex_enter(srp->tx_lock);

	nge_tx_recycle_all(ngep);
	err = nge_reinit_ring(ngep);
	if (err == DDI_FAILURE) {
		mutex_exit(srp->tx_lock);
		mutex_exit(srp->tc_lock);
		return (err);
	}
	err = nge_chip_reset(ngep);
	mutex_exit(srp->tx_lock);
	mutex_exit(srp->tc_lock);
	if (err == DDI_FAILURE)
		return (err);
	ngep->watchdog = 0;
	ngep->resched_needed = B_FALSE;
	ngep->promisc = B_FALSE;
	ngep->param_loop_mode = NGE_LOOP_NONE;
	ngep->factotum_flag = 0;
	ngep->resched_needed = 0;
	ngep->nge_mac_state = NGE_MAC_RESET;
	ngep->max_sdu = ngep->default_mtu + ETHER_HEAD_LEN + ETHERFCSL;
	ngep->max_sdu += VTAG_SIZE;
	ngep->rx_def = 0x16;
	return (DDI_SUCCESS);
}

static void
nge_m_stop(void *arg)
{
	nge_t *ngep = arg;		/* private device info	*/

	NGE_TRACE(("nge_m_stop($%p)", arg));

	/*
	 * If suspended, adapter is already stopped, just return.
	 */
	if (ngep->suspended) {
		ASSERT(ngep->nge_mac_state == NGE_MAC_STOPPED);
		return;
	}

	/*
	 * Just stop processing, then record new MAC state
	 */
	mutex_enter(ngep->genlock);
	rw_enter(ngep->rwlock, RW_WRITER);

	(void) nge_chip_stop(ngep, B_FALSE);
	/* Try to wait all the buffer post to upper layer be released */
	ngep->nge_mac_state = NGE_MAC_STOPPED;

	/* Recycle all the TX BD */
	nge_tx_recycle_all(ngep);
	nge_fini_rings(ngep);
	nge_free_bufs(ngep);

	NGE_DEBUG(("nge_m_stop($%p) done", arg));

	rw_exit(ngep->rwlock);
	mutex_exit(ngep->genlock);
}

static int
nge_m_start(void *arg)
{
	int err;
	nge_t *ngep = arg;

	NGE_TRACE(("nge_m_start($%p)", arg));
	/*
	 * If suspended, don't start, as the resume processing
	 * will recall this function with the suspended flag off.
	 */
	if (ngep->suspended)
		return (DDI_FAILURE);
	/*
	 * Start processing and record new MAC state
	 */
	mutex_enter(ngep->genlock);
	rw_enter(ngep->rwlock, RW_WRITER);
	err = nge_alloc_bufs(ngep);
	if (err != DDI_SUCCESS) {
		nge_problem(ngep, "nge_m_start: DMA buffer allocation failed");
		goto finish;
	}
	err = nge_init_rings(ngep);
	if (err != DDI_SUCCESS) {
		nge_free_bufs(ngep);
		nge_problem(ngep, "nge_init_rings() failed,err=%x");
		goto finish;
	}
	err = nge_restart(ngep);

	NGE_DEBUG(("nge_m_start($%p) done", arg));
	finish:
		rw_exit(ngep->rwlock);
		mutex_exit(ngep->genlock);

		return (err);
}

static int
nge_m_unicst(void *arg, const uint8_t *macaddr)
{
	nge_t *ngep = arg;

	NGE_TRACE(("nge_m_unicst($%p)", arg));
	/*
	 * Remember the new current address in the driver state
	 * Sync the chip's idea of the address too ...
	 */
	mutex_enter(ngep->genlock);

	ethaddr_copy(macaddr, ngep->cur_uni_addr.addr);
	ngep->cur_uni_addr.set = 1;

	/*
	 * If we are suspended, we want to quit now, and not update
	 * the chip.  Doing so might put it in a bad state, but the
	 * resume will get the unicast address installed.
	 */
	if (ngep->suspended)
		return (DDI_SUCCESS);

	nge_chip_sync(ngep);

	NGE_DEBUG(("nge_m_unicst($%p) done", arg));
	mutex_exit(ngep->genlock);

	return (0);
}

static int
nge_m_promisc(void *arg, boolean_t on)
{
	nge_t *ngep = arg;

	NGE_TRACE(("nge_m_promisc($%p)", arg));
	/*
	 * If suspended, we don't do anything, even record the promiscuious
	 * mode, as we won't properly set it on resume.  Just fail.
	 */
	if (ngep->suspended)
		return (DDI_FAILURE);

	/*
	 * Store specified mode and pass to chip layer to update h/w
	 */
	mutex_enter(ngep->genlock);
	if (ngep->promisc == on) {
		mutex_exit(ngep->genlock);
		NGE_DEBUG(("nge_m_promisc($%p) done", arg));
		return (0);
	}
	ngep->promisc = on;
	nge_chip_sync(ngep);
	NGE_DEBUG(("nge_m_promisc($%p) done", arg));
	mutex_exit(ngep->genlock);

	return (0);
}

static void nge_mulparam(nge_t *ngep)
{
	uint8_t number;
	ether_addr_t pand;
	ether_addr_t por;
	mul_item *plist;

	for (number = 0; number < ETHERADDRL; number++) {
		pand[number] = 0x00;
		por[number] = 0x00;
	}
	for (plist = ngep->pcur_mulist; plist != NULL; plist = plist->next) {
		for (number = 0; number < ETHERADDRL; number++) {
			pand[number] &= plist->mul_addr[number];
			por[number] |= plist->mul_addr[number];
		}
	}
	for (number = 0; number < ETHERADDRL; number++) {
		ngep->cur_mul_addr.addr[number]
		    = pand[number] & por[number];
		ngep->cur_mul_mask.addr[number]
		    = pand [number] | (~por[number]);
	}
}
static int
nge_m_multicst(void *arg, boolean_t add, const uint8_t *mca)
{
	boolean_t update;
	boolean_t b_eq;
	nge_t *ngep = arg;
	mul_item *plist;
	mul_item *plist_prev;
	mul_item *pitem;

	NGE_TRACE(("nge_m_multicst($%p, %s, %s)", arg,
	    (add) ? "add" : "remove", ether_sprintf((void *)mca)));

	update = B_FALSE;
	plist = plist_prev = NULL;
	mutex_enter(ngep->genlock);
	if (add) {
		if (ngep->pcur_mulist != NULL) {
			for (plist = ngep->pcur_mulist; plist != NULL;
			    plist = plist->next) {
				b_eq = ether_eq(plist->mul_addr, mca);
				if (b_eq) {
					plist->ref_cnt++;
					break;
				}
				plist_prev = plist;
			}
		}

		if (plist == NULL) {
			pitem = kmem_zalloc(sizeof (mul_item), KM_SLEEP);
			ether_copy(mca, pitem->mul_addr);
			pitem ->ref_cnt++;
			pitem ->next = NULL;
			if (plist_prev == NULL)
				ngep->pcur_mulist = pitem;
			else
				plist_prev->next = pitem;
			update = B_TRUE;
		}
	} else {
		if (ngep->pcur_mulist != NULL) {
			for (plist = ngep->pcur_mulist; plist != NULL;
			    plist = plist->next) {
				b_eq = ether_eq(plist->mul_addr, mca);
				if (b_eq) {
					update = B_TRUE;
					break;
				}
				plist_prev = plist;
			}

			if (update) {
				if ((plist_prev == NULL) &&
				    (plist->next == NULL))
					ngep->pcur_mulist = NULL;
				else if ((plist_prev == NULL) &&
				    (plist->next != NULL))
					ngep->pcur_mulist = plist->next;
				else
					plist_prev->next = plist->next;
				kmem_free(plist, sizeof (mul_item));
			}
		}
	}

	if (update || !ngep->suspended) {
		nge_mulparam(ngep);
		nge_chip_sync(ngep);
	}
	NGE_DEBUG(("nge_m_multicst($%p) done", arg));
	mutex_exit(ngep->genlock);

	return (0);
}

static void
nge_m_ioctl(void *arg, queue_t *wq, mblk_t *mp)
{
	int err;
	int cmd;
	nge_t *ngep = arg;
	struct iocblk *iocp;
	enum ioc_reply status;
	boolean_t need_privilege;

	/*
	 * If suspended, we might actually be able to do some of
	 * these ioctls, but it is harder to make sure they occur
	 * without actually putting the hardware in an undesireable
	 * state.  So just NAK it.
	 */
	if (ngep->suspended) {
		miocnak(wq, mp, 0, EINVAL);
		return;
	}

	/*
	 * Validate the command before bothering with the mutex ...
	 */
	iocp = (struct iocblk *)mp->b_rptr;
	iocp->ioc_error = 0;
	need_privilege = B_TRUE;
	cmd = iocp->ioc_cmd;

	NGE_DEBUG(("nge_m_ioctl:  cmd 0x%x", cmd));
	switch (cmd) {
	default:
		NGE_LDB(NGE_DBG_BADIOC,
		    ("nge_m_ioctl: unknown cmd 0x%x", cmd));

		miocnak(wq, mp, 0, EINVAL);
		return;

	case NGE_MII_READ:
	case NGE_MII_WRITE:
	case NGE_SEE_READ:
	case NGE_SEE_WRITE:
	case NGE_DIAG:
	case NGE_PEEK:
	case NGE_POKE:
	case NGE_PHY_RESET:
	case NGE_SOFT_RESET:
	case NGE_HARD_RESET:
		break;

	case LB_GET_INFO_SIZE:
	case LB_GET_INFO:
	case LB_GET_MODE:
		need_privilege = B_FALSE;
		break;
	case LB_SET_MODE:
		break;

	case ND_GET:
		need_privilege = B_FALSE;
		break;
	case ND_SET:
		break;
	}

	if (need_privilege) {
		/*
		 * Check for specific net_config privilege.
		 */
		err = secpolicy_net_config(iocp->ioc_cr, B_FALSE);
		if (err != 0) {
			NGE_DEBUG(("nge_m_ioctl: rejected cmd 0x%x, err %d",
			    cmd, err));
			miocnak(wq, mp, 0, err);
			return;
		}
	}

	mutex_enter(ngep->genlock);

	switch (cmd) {
	default:
		_NOTE(NOTREACHED)
		status = IOC_INVAL;
	break;

	case NGE_MII_READ:
	case NGE_MII_WRITE:
	case NGE_SEE_READ:
	case NGE_SEE_WRITE:
	case NGE_DIAG:
	case NGE_PEEK:
	case NGE_POKE:
	case NGE_PHY_RESET:
	case NGE_SOFT_RESET:
	case NGE_HARD_RESET:
		status = nge_chip_ioctl(ngep, mp, iocp);
	break;

	case LB_GET_INFO_SIZE:
	case LB_GET_INFO:
	case LB_GET_MODE:
	case LB_SET_MODE:
		status = nge_loop_ioctl(ngep, mp, iocp);
	break;

	case ND_GET:
	case ND_SET:
		status = nge_nd_ioctl(ngep, wq, mp, iocp);
	break;

	}

	/*
	 * Do we need to reprogram the PHY and/or the MAC?
	 * Do it now, while we still have the mutex.
	 *
	 * Note: update the PHY first, 'cos it controls the
	 * speed/duplex parameters that the MAC code uses.
	 */

	NGE_DEBUG(("nge_m_ioctl: cmd 0x%x status %d", cmd, status));

	switch (status) {
	case IOC_RESTART_REPLY:
	case IOC_RESTART_ACK:
		(*ngep->physops->phys_update)(ngep);
		nge_chip_sync(ngep);
		break;

	default:
	break;
	}

	mutex_exit(ngep->genlock);

	/*
	 * Finally, decide how to reply
	 */
	switch (status) {

	default:
	case IOC_INVAL:
		miocnak(wq, mp, 0, iocp->ioc_error == 0 ?
		    EINVAL : iocp->ioc_error);
		break;

	case IOC_DONE:
		break;

	case IOC_RESTART_ACK:
	case IOC_ACK:
		miocack(wq, mp, 0, 0);
		break;

	case IOC_RESTART_REPLY:
	case IOC_REPLY:
		mp->b_datap->db_type = iocp->ioc_error == 0 ?
		    M_IOCACK : M_IOCNAK;
		qreply(wq, mp);
		break;
	}
}

static void
nge_chip_blank(void *arg, time_t ticks, uint_t count)
{
	_NOTE(ARGUNUSED(arg, ticks, count));
}

static void
nge_m_resources(void *arg)
{
	nge_t *ngep = arg;
	recv_ring_t *rrp;
	mac_rx_fifo_t mrf;

	mutex_enter(ngep->genlock);

	/*
	 * Register Rx rings as resources and save mac
	 * resource id for future reference
	 */
	mrf.mrf_type = MAC_RX_FIFO;
	mrf.mrf_blank = nge_chip_blank;
	mrf.mrf_arg = (void *)ngep;
	mrf.mrf_normal_blank_time = NGE_TICKS_CNT;
	mrf.mrf_normal_pkt_count = NGE_RX_PKT_CNT;

	rrp = ngep->recv;
	rrp->handle = mac_resource_add(ngep->mh, (mac_resource_t *)&mrf);
	mutex_exit(ngep->genlock);
}

/* ARGSUSED */
static boolean_t
nge_m_getcapab(void *arg, mac_capab_t cap, void *cap_data)
{
	nge_t	*ngep = arg;
	nge_dev_spec_param_t *dev_param_p;

	dev_param_p = &ngep->dev_spec_param;

	switch (cap) {
	case MAC_CAPAB_HCKSUM: {
		uint32_t *hcksum_txflags = cap_data;

		if (dev_param_p->tx_hw_checksum) {
			*hcksum_txflags = dev_param_p->tx_hw_checksum;
		} else
			return (B_FALSE);
		break;
	}
	case MAC_CAPAB_POLL:
		/*
		 * There's nothing for us to fill in, simply returning
		 * B_TRUE, stating that we support polling is sufficient.
		 */
		break;
	default:
		return (B_FALSE);
	}
	return (B_TRUE);
}

#undef	NGE_DBG
#define	NGE_DBG	NGE_DBG_INIT	/* debug flag for this code	*/
int
nge_restart(nge_t *ngep)
{
	int err = 0;
	err += nge_reset(ngep);
	err += nge_chip_start(ngep);

	if (err) {
		ngep->nge_mac_state = NGE_MAC_STOPPED;
		return (DDI_FAILURE);
	} else {
		ngep->nge_mac_state = NGE_MAC_STARTED;
		return (DDI_SUCCESS);
	}
}

void
nge_wake_factotum(nge_t *ngep)
{
	mutex_enter(ngep->softlock);
	if (ngep->factotum_flag == 0) {
		ngep->factotum_flag = 1;
		(void) ddi_intr_trigger_softint(ngep->factotum_hdl, NULL);
	}
	mutex_exit(ngep->softlock);
}

/*
 * High-level cyclic handler
 *
 * This routine schedules a (low-level) softint callback to the
 * factotum.
 */

static void
nge_chip_cyclic(void *arg)
{
	nge_t *ngep;

	ngep = (nge_t *)arg;

	switch (ngep->nge_chip_state) {
	default:
		return;

	case NGE_CHIP_RUNNING:
		break;

	case NGE_CHIP_FAULT:
	case NGE_CHIP_ERROR:
		break;
	}

	nge_wake_factotum(ngep);
}

static void
nge_unattach(nge_t *ngep)
{
	send_ring_t *srp;
	buff_ring_t *brp;

	srp = ngep->send;
	brp = ngep->buff;
	NGE_TRACE(("nge_unattach($%p)", (void *)ngep));

	/*
	 * Flag that no more activity may be initiated
	 */
	ngep->progress &= ~PROGRESS_READY;
	ngep->nge_mac_state = NGE_MAC_UNATTACH;

	/*
	 * Quiesce the PHY and MAC (leave it reset but still powered).
	 * Clean up and free all NGE data structures
	 */
	if (ngep->periodic_id != NULL) {
		ddi_periodic_delete(ngep->periodic_id);
		ngep->periodic_id = NULL;
	}

	if (ngep->progress & PROGRESS_KSTATS)
		nge_fini_kstats(ngep);

	if (ngep->progress & PROGRESS_NDD)
		nge_nd_cleanup(ngep);

	if (ngep->progress & PROGRESS_HWINT) {
		mutex_enter(ngep->genlock);
		nge_restore_mac_addr(ngep);
		(void) nge_chip_stop(ngep, B_FALSE);
		mutex_exit(ngep->genlock);
	}

	if (ngep->progress & PROGRESS_SWINT)
		nge_rem_intrs(ngep);

	if (ngep->progress & PROGRESS_FACTOTUM)
		(void) ddi_intr_remove_softint(ngep->factotum_hdl);

	if (ngep->progress & PROGRESS_RESCHED)
		(void) ddi_intr_remove_softint(ngep->resched_hdl);

	if (ngep->progress & PROGRESS_INTR) {
		mutex_destroy(srp->tx_lock);
		mutex_destroy(srp->tc_lock);
		mutex_destroy(&srp->dmah_lock);
		mutex_destroy(brp->recycle_lock);

		mutex_destroy(ngep->genlock);
		mutex_destroy(ngep->softlock);
		rw_destroy(ngep->rwlock);
	}

	if (ngep->progress & PROGRESS_REGS)
		ddi_regs_map_free(&ngep->io_handle);

	if (ngep->progress & PROGRESS_CFG)
		pci_config_teardown(&ngep->cfg_handle);

	ddi_remove_minor_node(ngep->devinfo, NULL);

	kmem_free(ngep, sizeof (*ngep));
}

static int
nge_resume(dev_info_t *devinfo)
{
	nge_t		*ngep;
	chip_info_t	*infop;

	ASSERT(devinfo != NULL);

	ngep = ddi_get_driver_private(devinfo);
	/*
	 * If there are state inconsistancies, this is bad.  Returning
	 * DDI_FAILURE here will eventually cause the machine to panic,
	 * so it is best done here so that there is a possibility of
	 * debugging the problem.
	 */
	if (ngep == NULL)
		cmn_err(CE_PANIC,
		    "nge: ngep returned from ddi_get_driver_private was NULL");
	infop = (chip_info_t *)&ngep->chipinfo;

	if (ngep->devinfo != devinfo)
		cmn_err(CE_PANIC,
		    "nge: passed devinfo not the same as saved definfo");

	ngep->suspended = B_FALSE;

	/*
	 * Fetch the config space.  Even though we have most of it cached,
	 * some values *might* change across a suspend/resume.
	 */
	nge_chip_cfg_init(ngep, infop, B_FALSE);

	/*
	 * Start the controller.  In this case (and probably most GLDv3
	 * devices), it is sufficient to call nge_m_start().
	 */
	if (nge_m_start((void *)ngep) != DDI_SUCCESS) {
		/*
		 * We note the failure, but return success, as the
		 * system is still usable without this controller.
		 */
		cmn_err(CE_WARN, "nge: resume: failed to restart controller");
	}
	return (DDI_SUCCESS);
}

/*
 * attach(9E) -- Attach a device to the system
 *
 * Called once for each board successfully probed.
 */
static int
nge_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	int		err;
	int		i;
	int		instance;
	caddr_t		regs;
	nge_t		*ngep;
	chip_info_t	*infop;
	mac_register_t	*macp;

	switch (cmd) {
	default:
		return (DDI_FAILURE);

	case DDI_RESUME:
		return (nge_resume(devinfo));

	case DDI_ATTACH:
		break;
	}

	ngep = kmem_zalloc(sizeof (*ngep), KM_SLEEP);
	instance = ddi_get_instance(devinfo);
	ddi_set_driver_private(devinfo, ngep);
	ngep->devinfo = devinfo;

	(void) snprintf(ngep->ifname, sizeof (ngep->ifname), "%s%d",
	    NGE_DRIVER_NAME, instance);
	err = pci_config_setup(devinfo, &ngep->cfg_handle);
	if (err != DDI_SUCCESS) {
		nge_problem(ngep, "nge_attach: pci_config_setup() failed");
		goto attach_fail;
	}
	infop = (chip_info_t *)&ngep->chipinfo;
	nge_chip_cfg_init(ngep, infop, B_FALSE);
	nge_init_dev_spec_param(ngep);
	nge_get_props(ngep);
	ngep->progress |= PROGRESS_CFG;

	err = ddi_regs_map_setup(devinfo, NGE_PCI_OPREGS_RNUMBER,
	    &regs, 0, 0, &nge_reg_accattr, &ngep->io_handle);
	if (err != DDI_SUCCESS) {
		nge_problem(ngep, "nge_attach: ddi_regs_map_setup() failed");
		goto attach_fail;
	}
	ngep->io_regs = regs;
	ngep->progress |= PROGRESS_REGS;

	err = nge_register_intrs_and_init_locks(ngep);
	if (err != DDI_SUCCESS) {
		nge_problem(ngep, "nge_attach:"
		    " register intrs and init locks failed");
		goto attach_fail;
	}
	nge_init_ring_param_lock(ngep);
	ngep->progress |= PROGRESS_INTR;

	mutex_enter(ngep->genlock);

	/*
	 * Initialise link state variables
	 * Stop, reset & reinitialise the chip.
	 * Initialise the (internal) PHY.
	 */
	nge_phys_init(ngep);
	err = nge_chip_reset(ngep);
	if (err != DDI_SUCCESS) {
		nge_problem(ngep, "nge_attach: nge_chip_reset() failed");
		mutex_exit(ngep->genlock);
		goto attach_fail;
	}
	nge_chip_sync(ngep);

	/*
	 * Now that mutex locks are initialized, enable interrupts.
	 */
	if (ngep->intr_cap & DDI_INTR_FLAG_BLOCK) {
		/* Call ddi_intr_block_enable() for MSI interrupts */
		(void) ddi_intr_block_enable(ngep->htable,
		    ngep->intr_actual_cnt);
	} else {
		/* Call ddi_intr_enable for MSI or FIXED interrupts */
		for (i = 0; i < ngep->intr_actual_cnt; i++) {
			(void) ddi_intr_enable(ngep->htable[i]);
		}
	}

	ngep->link_state = LINK_STATE_UNKNOWN;
	ngep->progress |= PROGRESS_HWINT;

	/*
	 * Register NDD-tweakable parameters
	 */
	if (nge_nd_init(ngep)) {
		nge_problem(ngep, "nge_attach: nge_nd_init() failed");
		mutex_exit(ngep->genlock);
		goto attach_fail;
	}
	ngep->progress |= PROGRESS_NDD;

	/*
	 * Create & initialise named kstats
	 */
	nge_init_kstats(ngep, instance);
	ngep->progress |= PROGRESS_KSTATS;

	mutex_exit(ngep->genlock);

	if ((macp = mac_alloc(MAC_VERSION)) == NULL)
		goto attach_fail;
	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = ngep;
	macp->m_dip = devinfo;
	macp->m_src_addr = infop->vendor_addr.addr;
	macp->m_callbacks = &nge_m_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = ngep->default_mtu;
	/*
	 * Finally, we're ready to register ourselves with the mac
	 * interface; if this succeeds, we're all ready to start()
	 */
	err = mac_register(macp, &ngep->mh);
	mac_free(macp);
	if (err != 0)
		goto attach_fail;

	/*
	 * Register a periodical handler.
	 * nge_chip_cyclic() is invoked in kernel context.
	 */
	ngep->periodic_id = ddi_periodic_add(nge_chip_cyclic, ngep,
	    NGE_CYCLIC_PERIOD, DDI_IPL_0);

	ngep->progress |= PROGRESS_READY;
	return (DDI_SUCCESS);

attach_fail:
	nge_unattach(ngep);
	return (DDI_FAILURE);
}

/*
 * detach(9E) -- Detach a device from the system
 */
static int
nge_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	int i;
	nge_t *ngep;
	mul_item *p, *nextp;
	buff_ring_t *brp;

	NGE_GTRACE(("nge_detach($%p, %d)", (void *)devinfo, cmd));

	ngep = ddi_get_driver_private(devinfo);
	brp = ngep->buff;

	switch (cmd) {
	default:
		return (DDI_FAILURE);

	case DDI_SUSPEND:
		/*
		 * Stop the NIC
		 * I suspect that we can actually suspend if the stop
		 * routine returns a failure, as the resume will
		 * effectively fully reset the hardware (i.e. we don't
		 * really save any hardware state).  However, nge_m_stop
		 * doesn't return an error code.
		 * Note: This driver doesn't currently support WOL, but
		 *	should it in the future, it is important to
		 *	make sure the PHY remains powered so that the
		 *	wakeup packet can actually be recieved.
		 */
		nge_m_stop(ngep);
		ngep->suspended = B_TRUE;
		return (DDI_SUCCESS);

	case DDI_DETACH:
		break;
	}

	/* Try to wait all the buffer post to upper layer be released */
	for (i = 0; i < 1000; i++) {
		if (brp->rx_hold == 0)
			break;
		drv_usecwait(1000);
	}

	/* If there is any posted buffer, reject to detach */
	if (brp->rx_hold != 0)
		return (DDI_FAILURE);

	/* Recycle the multicast table */
	for (p = ngep->pcur_mulist; p != NULL; p = nextp) {
		nextp = p->next;
		kmem_free(p, sizeof (mul_item));
	}
	ngep->pcur_mulist = NULL;

	/*
	 * Unregister from the GLD subsystem.  This can fail, in
	 * particular if there are DLPI style-2 streams still open -
	 * in which case we just return failure without shutting
	 * down chip operations.
	 */
	if (mac_unregister(ngep->mh) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * All activity stopped, so we can clean up & exit
	 */
	nge_unattach(ngep);
	return (DDI_SUCCESS);
}


/*
 * ========== Module Loading Data & Entry Points ==========
 */

DDI_DEFINE_STREAM_OPS(nge_dev_ops, nulldev, nulldev, nge_attach, nge_detach,
    nodev, NULL, D_MP, NULL);


static struct modldrv nge_modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	nge_ident,		/* short description */
	&nge_dev_ops		/* driver specific ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&nge_modldrv, NULL
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

	mac_init_ops(&nge_dev_ops, "nge");
	status = mod_install(&modlinkage);
	if (status != DDI_SUCCESS)
		mac_fini_ops(&nge_dev_ops);
	else
		mutex_init(nge_log_mutex, NULL, MUTEX_DRIVER, NULL);

	return (status);
}

int
_fini(void)
{
	int status;

	status = mod_remove(&modlinkage);
	if (status == DDI_SUCCESS) {
		mac_fini_ops(&nge_dev_ops);
		mutex_destroy(nge_log_mutex);
	}

	return (status);
}

/*
 * ============ Init MSI/Fixed/SoftInterrupt routines ==============
 */

/*
 * Register interrupts and initialize each mutex and condition variables
 */

static int
nge_register_intrs_and_init_locks(nge_t *ngep)
{
	int		err;
	int		intr_types;
	uint_t		soft_prip;
	nge_msi_mask	msi_mask;
	nge_msi_map0_vec map0_vec;
	nge_msi_map1_vec map1_vec;

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
	 * become available.  Its only purpose is to call gld_sched()
	 * to retry the pending transmits (we're not allowed to hold
	 * driver-defined mutexes across gld_sched()).
	 *
	 * the <factotum> is triggered if the h/w interrupt handler
	 * sees the <link state changed> or <error> bits in the status
	 * block.  It's also triggered periodically to poll the link
	 * state, just in case we aren't getting link status change
	 * interrupts ...
	 */
	err = ddi_intr_add_softint(ngep->devinfo, &ngep->resched_hdl,
	    DDI_INTR_SOFTPRI_MIN, nge_reschedule, (caddr_t)ngep);
	if (err != DDI_SUCCESS) {
		nge_problem(ngep,
		    "nge_attach: add nge_reschedule softintr failed");

		return (DDI_FAILURE);
	}
	ngep->progress |= PROGRESS_RESCHED;
	err = ddi_intr_add_softint(ngep->devinfo, &ngep->factotum_hdl,
	    DDI_INTR_SOFTPRI_MIN, nge_chip_factotum, (caddr_t)ngep);
	if (err != DDI_SUCCESS) {
		nge_problem(ngep,
		    "nge_attach: add nge_chip_factotum softintr failed!");

		return (DDI_FAILURE);
	}
	if (ddi_intr_get_softint_pri(ngep->factotum_hdl, &soft_prip)
	    != DDI_SUCCESS) {
		nge_problem(ngep, "nge_attach: get softintr priority failed\n");

		return (DDI_FAILURE);
	}
	ngep->soft_pri = soft_prip;

	ngep->progress |= PROGRESS_FACTOTUM;
	/* Get supported interrupt types */
	if (ddi_intr_get_supported_types(ngep->devinfo, &intr_types)
	    != DDI_SUCCESS) {
		nge_error(ngep, "ddi_intr_get_supported_types failed\n");

		return (DDI_FAILURE);
	}

	NGE_DEBUG(("ddi_intr_get_supported_types() returned: %x",
	    intr_types));

	if ((intr_types & DDI_INTR_TYPE_MSI) && nge_enable_msi) {

		/* MSI Configurations for mcp55 chipset */
		if (ngep->chipinfo.device == DEVICE_ID_MCP55_373 ||
		    ngep->chipinfo.device == DEVICE_ID_MCP55_372) {


			/* Enable the 8 vectors */
			msi_mask.msi_mask_val =
			    nge_reg_get32(ngep, NGE_MSI_MASK);
			msi_mask.msi_msk_bits.vec0 = NGE_SET;
			msi_mask.msi_msk_bits.vec1 = NGE_SET;
			msi_mask.msi_msk_bits.vec2 = NGE_SET;
			msi_mask.msi_msk_bits.vec3 = NGE_SET;
			msi_mask.msi_msk_bits.vec4 = NGE_SET;
			msi_mask.msi_msk_bits.vec5 = NGE_SET;
			msi_mask.msi_msk_bits.vec6 = NGE_SET;
			msi_mask.msi_msk_bits.vec7 = NGE_SET;
			nge_reg_put32(ngep, NGE_MSI_MASK,
			    msi_mask.msi_mask_val);

			/*
			 * Remapping the MSI MAP0 and MAP1. MCP55
			 * is default mapping all the interrupt to 0 vector.
			 * Software needs to remapping this.
			 * This mapping is same as CK804.
			 */
			map0_vec.msi_map0_val =
			    nge_reg_get32(ngep, NGE_MSI_MAP0);
			map1_vec.msi_map1_val =
			    nge_reg_get32(ngep, NGE_MSI_MAP1);
			map0_vec.vecs_bits.reint_vec = 0;
			map0_vec.vecs_bits.rcint_vec = 0;
			map0_vec.vecs_bits.miss_vec = 3;
			map0_vec.vecs_bits.teint_vec = 5;
			map0_vec.vecs_bits.tcint_vec = 5;
			map0_vec.vecs_bits.stint_vec = 2;
			map0_vec.vecs_bits.mint_vec = 6;
			map0_vec.vecs_bits.rfint_vec = 0;
			map1_vec.vecs_bits.tfint_vec = 5;
			map1_vec.vecs_bits.feint_vec = 6;
			map1_vec.vecs_bits.resv8_11 = 3;
			map1_vec.vecs_bits.resv12_15 = 1;
			map1_vec.vecs_bits.resv16_19 = 0;
			map1_vec.vecs_bits.resv20_23 = 7;
			map1_vec.vecs_bits.resv24_31 = 0xff;
			nge_reg_put32(ngep, NGE_MSI_MAP0,
			    map0_vec.msi_map0_val);
			nge_reg_put32(ngep, NGE_MSI_MAP1,
			    map1_vec.msi_map1_val);
		}
		if (nge_add_intrs(ngep, DDI_INTR_TYPE_MSI) != DDI_SUCCESS) {
			NGE_DEBUG(("MSI registration failed, "
			    "trying FIXED interrupt type\n"));
		} else {
			nge_log(ngep, "Using MSI interrupt type\n");

			ngep->intr_type = DDI_INTR_TYPE_MSI;
			ngep->progress |= PROGRESS_SWINT;
		}
	}

	if (!(ngep->progress & PROGRESS_SWINT) &&
	    (intr_types & DDI_INTR_TYPE_FIXED)) {
		if (nge_add_intrs(ngep, DDI_INTR_TYPE_FIXED) != DDI_SUCCESS) {
			nge_error(ngep, "FIXED interrupt "
			    "registration failed\n");

			return (DDI_FAILURE);
		}

		nge_log(ngep, "Using FIXED interrupt type\n");

		ngep->intr_type = DDI_INTR_TYPE_FIXED;
		ngep->progress |= PROGRESS_SWINT;
	}


	if (!(ngep->progress & PROGRESS_SWINT)) {
		nge_error(ngep, "No interrupts registered\n");

		return (DDI_FAILURE);
	}
	mutex_init(ngep->genlock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(ngep->intr_pri));
	mutex_init(ngep->softlock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(ngep->soft_pri));
	rw_init(ngep->rwlock, NULL, RW_DRIVER,
	    DDI_INTR_PRI(ngep->intr_pri));

	return (DDI_SUCCESS);
}

/*
 * nge_add_intrs:
 *
 * Register FIXED or MSI interrupts.
 */
static int
nge_add_intrs(nge_t *ngep, int	intr_type)
{
	dev_info_t	*dip = ngep->devinfo;
	int		avail, actual, intr_size, count = 0;
	int		i, flag, ret;

	NGE_DEBUG(("nge_add_intrs: interrupt type 0x%x\n", intr_type));

	/* Get number of interrupts */
	ret = ddi_intr_get_nintrs(dip, intr_type, &count);
	if ((ret != DDI_SUCCESS) || (count == 0)) {
		nge_error(ngep, "ddi_intr_get_nintrs() failure, ret: %d, "
		    "count: %d", ret, count);

		return (DDI_FAILURE);
	}

	/* Get number of available interrupts */
	ret = ddi_intr_get_navail(dip, intr_type, &avail);
	if ((ret != DDI_SUCCESS) || (avail == 0)) {
		nge_error(ngep, "ddi_intr_get_navail() failure, "
		    "ret: %d, avail: %d\n", ret, avail);

		return (DDI_FAILURE);
	}

	if (avail < count) {
		NGE_DEBUG(("nitrs() returned %d, navail returned %d\n",
		    count, avail));
	}
	flag = DDI_INTR_ALLOC_NORMAL;

	/* Allocate an array of interrupt handles */
	intr_size = count * sizeof (ddi_intr_handle_t);
	ngep->htable = kmem_alloc(intr_size, KM_SLEEP);

	/* Call ddi_intr_alloc() */
	ret = ddi_intr_alloc(dip, ngep->htable, intr_type, 0,
	    count, &actual, flag);

	if ((ret != DDI_SUCCESS) || (actual == 0)) {
		nge_error(ngep, "ddi_intr_alloc() failed %d\n", ret);

		kmem_free(ngep->htable, intr_size);
		return (DDI_FAILURE);
	}

	if (actual < count) {
		NGE_DEBUG(("Requested: %d, Received: %d\n",
		    count, actual));
	}

	ngep->intr_actual_cnt = actual;
	ngep->intr_req_cnt = count;

	/*
	 * Get priority for first msi, assume remaining are all the same
	 */
	if ((ret = ddi_intr_get_pri(ngep->htable[0], &ngep->intr_pri)) !=
	    DDI_SUCCESS) {
		nge_error(ngep, "ddi_intr_get_pri() failed %d\n", ret);

		/* Free already allocated intr */
		for (i = 0; i < actual; i++) {
			(void) ddi_intr_free(ngep->htable[i]);
		}

		kmem_free(ngep->htable, intr_size);

		return (DDI_FAILURE);
	}
	/* Test for high level mutex */
	if (ngep->intr_pri >= ddi_intr_get_hilevel_pri()) {
		nge_error(ngep, "nge_add_intrs:"
		    "Hi level interrupt not supported");

		for (i = 0; i < actual; i++)
			(void) ddi_intr_free(ngep->htable[i]);

		kmem_free(ngep->htable, intr_size);

		return (DDI_FAILURE);
	}


	/* Call ddi_intr_add_handler() */
	for (i = 0; i < actual; i++) {
		if ((ret = ddi_intr_add_handler(ngep->htable[i], nge_chip_intr,
		    (caddr_t)ngep, (caddr_t)(uintptr_t)i)) != DDI_SUCCESS) {
			nge_error(ngep, "ddi_intr_add_handler() "
			    "failed %d\n", ret);

			/* Free already allocated intr */
			for (i = 0; i < actual; i++) {
				(void) ddi_intr_free(ngep->htable[i]);
			}

			kmem_free(ngep->htable, intr_size);

			return (DDI_FAILURE);
		}
	}

	if ((ret = ddi_intr_get_cap(ngep->htable[0], &ngep->intr_cap))
	    != DDI_SUCCESS) {
		nge_error(ngep, "ddi_intr_get_cap() failed %d\n", ret);

		for (i = 0; i < actual; i++) {
			(void) ddi_intr_remove_handler(ngep->htable[i]);
			(void) ddi_intr_free(ngep->htable[i]);
		}

		kmem_free(ngep->htable, intr_size);

		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * nge_rem_intrs:
 *
 * Unregister FIXED or MSI interrupts
 */
static void
nge_rem_intrs(nge_t *ngep)
{
	int	i;

	NGE_DEBUG(("nge_rem_intrs\n"));

	/* Disable all interrupts */
	if (ngep->intr_cap & DDI_INTR_FLAG_BLOCK) {
		/* Call ddi_intr_block_disable() */
		(void) ddi_intr_block_disable(ngep->htable,
		    ngep->intr_actual_cnt);
	} else {
		for (i = 0; i < ngep->intr_actual_cnt; i++) {
			(void) ddi_intr_disable(ngep->htable[i]);
		}
	}

	/* Call ddi_intr_remove_handler() */
	for (i = 0; i < ngep->intr_actual_cnt; i++) {
		(void) ddi_intr_remove_handler(ngep->htable[i]);
		(void) ddi_intr_free(ngep->htable[i]);
	}

	kmem_free(ngep->htable,
	    ngep->intr_req_cnt * sizeof (ddi_intr_handle_t));
}
