/*
 * This file is provided under a CDDLv1 license.  When using or
 * redistributing this file, you may do so under this license.
 * In redistributing this file this license must be included
 * and no other modification of this header file is permitted.
 *
 * CDDL LICENSE SUMMARY
 *
 * Copyright(c) 1999 - 2009 Intel Corporation. All rights reserved.
 *
 * The contents of this file are subject to the terms of Version
 * 1.0 of the Common Development and Distribution License (the "License").
 *
 * You should have received a copy of the License with this software.
 * You can obtain a copy of the License at
 *	http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */

/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * **********************************************************************
 * Module Name:								*
 *   e1000g_alloc.c							*
 *									*
 * Abstract:								*
 *   This file contains some routines that take care of			*
 *   memory allocation for descriptors and buffers.			*
 *									*
 * **********************************************************************
 */

#include "e1000g_sw.h"
#include "e1000g_debug.h"

#define	TX_SW_PKT_AREA_SZ \
	(sizeof (tx_sw_packet_t) * Adapter->tx_freelist_num)

static int e1000g_alloc_tx_descriptors(e1000g_tx_ring_t *);
static int e1000g_alloc_rx_descriptors(e1000g_rx_data_t *);
static void e1000g_free_tx_descriptors(e1000g_tx_ring_t *);
static void e1000g_free_rx_descriptors(e1000g_rx_data_t *);
static int e1000g_alloc_tx_packets(e1000g_tx_ring_t *);
static int e1000g_alloc_rx_packets(e1000g_rx_data_t *);
static void e1000g_free_tx_packets(e1000g_tx_ring_t *);
static void e1000g_free_rx_packets(e1000g_rx_data_t *, boolean_t);
static int e1000g_alloc_dma_buffer(struct e1000g *,
    dma_buffer_t *, size_t, ddi_dma_attr_t *p_dma_attr);

/*
 * In order to avoid address error crossing 64KB boundary
 * during PCI-X packets receving, e1000g_alloc_dma_buffer_82546
 * is used by some necessary adapter types.
 */
static int e1000g_alloc_dma_buffer_82546(struct e1000g *,
    dma_buffer_t *, size_t, ddi_dma_attr_t *p_dma_attr);
static int e1000g_dma_mem_alloc_82546(dma_buffer_t *buf,
    size_t size, size_t *len);
static boolean_t e1000g_cross_64k_bound(void *, uintptr_t);

static void e1000g_free_dma_buffer(dma_buffer_t *);
#ifdef __sparc
static int e1000g_alloc_dvma_buffer(struct e1000g *, dma_buffer_t *, size_t);
static void e1000g_free_dvma_buffer(dma_buffer_t *);
#endif
static int e1000g_alloc_descriptors(struct e1000g *Adapter);
static void e1000g_free_descriptors(struct e1000g *Adapter);
static int e1000g_alloc_packets(struct e1000g *Adapter);
static void e1000g_free_packets(struct e1000g *Adapter);
static p_rx_sw_packet_t e1000g_alloc_rx_sw_packet(e1000g_rx_data_t *,
    ddi_dma_attr_t *p_dma_attr);

/* DMA access attributes for descriptors <Little Endian> */
static ddi_device_acc_attr_t e1000g_desc_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

/* DMA access attributes for DMA buffers */
#ifdef __sparc
static ddi_device_acc_attr_t e1000g_buf_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_BE_ACC,
	DDI_STRICTORDER_ACC,
};
#else
static ddi_device_acc_attr_t e1000g_buf_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
};
#endif

/* DMA attributes for tx mblk buffers */
static ddi_dma_attr_t e1000g_tx_dma_attr = {
	DMA_ATTR_V0,		/* version of this structure */
	0,			/* lowest usable address */
	0xffffffffffffffffULL,	/* highest usable address */
	0x7fffffff,		/* maximum DMAable byte count */
	1,			/* alignment in bytes */
	0x7ff,			/* burst sizes (any?) */
	1,			/* minimum transfer */
	0xffffffffU,		/* maximum transfer */
	0xffffffffffffffffULL,	/* maximum segment length */
	MAX_COOKIES,		/* maximum number of segments */
	1,			/* granularity */
	DDI_DMA_FLAGERR,	/* dma_attr_flags */
};

/* DMA attributes for pre-allocated rx/tx buffers */
static ddi_dma_attr_t e1000g_buf_dma_attr = {
	DMA_ATTR_V0,		/* version of this structure */
	0,			/* lowest usable address */
	0xffffffffffffffffULL,	/* highest usable address */
	0x7fffffff,		/* maximum DMAable byte count */
	1,			/* alignment in bytes */
	0x7ff,			/* burst sizes (any?) */
	1,			/* minimum transfer */
	0xffffffffU,		/* maximum transfer */
	0xffffffffffffffffULL,	/* maximum segment length */
	1,			/* maximum number of segments */
	1,			/* granularity */
	DDI_DMA_FLAGERR,	/* dma_attr_flags */
};

/* DMA attributes for rx/tx descriptors */
static ddi_dma_attr_t e1000g_desc_dma_attr = {
	DMA_ATTR_V0,		/* version of this structure */
	0,			/* lowest usable address */
	0xffffffffffffffffULL,	/* highest usable address */
	0x7fffffff,		/* maximum DMAable byte count */
	E1000_MDALIGN,		/* default alignment is 4k but can be changed */
	0x7ff,			/* burst sizes (any?) */
	1,			/* minimum transfer */
	0xffffffffU,		/* maximum transfer */
	0xffffffffffffffffULL,	/* maximum segment length */
	1,			/* maximum number of segments */
	1,			/* granularity */
	DDI_DMA_FLAGERR,	/* dma_attr_flags */
};

#ifdef __sparc
static ddi_dma_lim_t e1000g_dma_limits = {
	(uint_t)0,		/* dlim_addr_lo */
	(uint_t)0xffffffff,	/* dlim_addr_hi */
	(uint_t)0xffffffff,	/* dlim_cntr_max */
	(uint_t)0xfc00fc,	/* dlim_burstsizes for 32 and 64 bit xfers */
	0x1,			/* dlim_minxfer */
	1024			/* dlim_speed */
};
#endif

#ifdef __sparc
static dma_type_t e1000g_dma_type = USE_DVMA;
#else
static dma_type_t e1000g_dma_type = USE_DMA;
#endif

extern krwlock_t e1000g_dma_type_lock;


int
e1000g_alloc_dma_resources(struct e1000g *Adapter)
{
	int result;

	result = DDI_FAILURE;

	while ((result != DDI_SUCCESS) &&
	    (Adapter->tx_desc_num >= MIN_NUM_TX_DESCRIPTOR) &&
	    (Adapter->rx_desc_num >= MIN_NUM_RX_DESCRIPTOR) &&
	    (Adapter->tx_freelist_num >= MIN_NUM_TX_FREELIST)) {

		result = e1000g_alloc_descriptors(Adapter);

		if (result == DDI_SUCCESS) {
			result = e1000g_alloc_packets(Adapter);

			if (result != DDI_SUCCESS)
				e1000g_free_descriptors(Adapter);
		}

		/*
		 * If the allocation fails due to resource shortage,
		 * we'll reduce the numbers of descriptors/buffers by
		 * half, and try the allocation again.
		 */
		if (result != DDI_SUCCESS) {
			/*
			 * We must ensure the number of descriptors
			 * is always a multiple of 8.
			 */
			Adapter->tx_desc_num =
			    (Adapter->tx_desc_num >> 4) << 3;
			Adapter->rx_desc_num =
			    (Adapter->rx_desc_num >> 4) << 3;

			Adapter->tx_freelist_num >>= 1;
		}
	}

	return (result);
}

/*
 * e1000g_alloc_descriptors - allocate DMA buffers for descriptors
 *
 * This routine allocates neccesary DMA buffers for
 *	Transmit Descriptor Area
 *	Receive Descrpitor Area
 */
static int
e1000g_alloc_descriptors(struct e1000g *Adapter)
{
	int result;
	e1000g_tx_ring_t *tx_ring;
	e1000g_rx_data_t *rx_data;

	if (Adapter->mem_workaround_82546 &&
	    ((Adapter->shared.mac.type == e1000_82545) ||
	    (Adapter->shared.mac.type == e1000_82546) ||
	    (Adapter->shared.mac.type == e1000_82546_rev_3))) {
		/* Align on a 64k boundary for these adapter types */
		Adapter->desc_align = E1000_MDALIGN_82546;
	} else {
		/* Align on a 4k boundary for all other adapter types */
		Adapter->desc_align = E1000_MDALIGN;
	}

	tx_ring = Adapter->tx_ring;

	result = e1000g_alloc_tx_descriptors(tx_ring);
	if (result != DDI_SUCCESS)
		return (DDI_FAILURE);

	rx_data = Adapter->rx_ring->rx_data;

	result = e1000g_alloc_rx_descriptors(rx_data);
	if (result != DDI_SUCCESS) {
		e1000g_free_tx_descriptors(tx_ring);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static void
e1000g_free_descriptors(struct e1000g *Adapter)
{
	e1000g_tx_ring_t *tx_ring;
	e1000g_rx_data_t *rx_data;

	tx_ring = Adapter->tx_ring;
	rx_data = Adapter->rx_ring->rx_data;

	e1000g_free_tx_descriptors(tx_ring);
	e1000g_free_rx_descriptors(rx_data);
}

static int
e1000g_alloc_tx_descriptors(e1000g_tx_ring_t *tx_ring)
{
	int mystat;
	boolean_t alloc_flag;
	size_t size;
	size_t len;
	uintptr_t templong;
	uint_t cookie_count;
	dev_info_t *devinfo;
	ddi_dma_cookie_t cookie;
	struct e1000g *Adapter;
	ddi_dma_attr_t dma_attr;

	Adapter = tx_ring->adapter;
	devinfo = Adapter->dip;

	alloc_flag = B_FALSE;
	dma_attr = e1000g_desc_dma_attr;

	/*
	 * Solaris 7 has a problem with allocating physically contiguous memory
	 * that is aligned on a 4K boundary. The transmit and rx descriptors
	 * need to aligned on a 4kbyte boundary. We first try to allocate the
	 * memory with DMA attributes set to 4K alignment and also no scatter/
	 * gather mechanism specified. In most cases, this does not allocate
	 * memory aligned at a 4Kbyte boundary. We then try asking for memory
	 * aligned on 4K boundary with scatter/gather set to 2. This works when
	 * the amount of memory is less than 4k i.e a page size. If neither of
	 * these options work or if the number of descriptors is greater than
	 * 4K, ie more than 256 descriptors, we allocate 4k extra memory and
	 * and then align the memory at a 4k boundary.
	 */
	size = sizeof (struct e1000_tx_desc) * Adapter->tx_desc_num;

	/*
	 * Memory allocation for the transmit buffer descriptors.
	 */
	dma_attr.dma_attr_sgllen = 1;
	dma_attr.dma_attr_align = Adapter->desc_align;

	/*
	 * Allocate a new DMA handle for the transmit descriptor
	 * memory area.
	 */
	mystat = ddi_dma_alloc_handle(devinfo, &dma_attr,
	    DDI_DMA_DONTWAIT, 0,
	    &tx_ring->tbd_dma_handle);

	if (mystat != DDI_SUCCESS) {
		E1000G_DEBUGLOG_1(Adapter, E1000G_WARN_LEVEL,
		    "Could not allocate tbd dma handle: %d", mystat);
		tx_ring->tbd_dma_handle = NULL;
		return (DDI_FAILURE);
	}

	/*
	 * Allocate memory to DMA data to and from the transmit
	 * descriptors.
	 */
	mystat = ddi_dma_mem_alloc(tx_ring->tbd_dma_handle,
	    size,
	    &e1000g_desc_acc_attr, DDI_DMA_CONSISTENT,
	    DDI_DMA_DONTWAIT, 0,
	    (caddr_t *)&tx_ring->tbd_area,
	    &len, &tx_ring->tbd_acc_handle);

	if ((mystat != DDI_SUCCESS) ||
	    ((uintptr_t)tx_ring->tbd_area & (Adapter->desc_align - 1))) {
		if (mystat == DDI_SUCCESS) {
			ddi_dma_mem_free(&tx_ring->tbd_acc_handle);
			tx_ring->tbd_acc_handle = NULL;
			tx_ring->tbd_area = NULL;
		}
		if (tx_ring->tbd_dma_handle != NULL) {
			ddi_dma_free_handle(&tx_ring->tbd_dma_handle);
			tx_ring->tbd_dma_handle = NULL;
		}
		alloc_flag = B_FALSE;
	} else
		alloc_flag = B_TRUE;

	/*
	 * Initialize the entire transmit buffer descriptor area to zero
	 */
	if (alloc_flag)
		bzero(tx_ring->tbd_area, len);

	/*
	 * If the previous DMA attributes setting could not give us contiguous
	 * memory or the number of descriptors is greater than the page size,
	 * we allocate extra memory and then align it at appropriate boundary.
	 */
	if (!alloc_flag) {
		size = size + Adapter->desc_align;

		/*
		 * DMA attributes set to no scatter/gather and 16 bit alignment
		 */
		dma_attr.dma_attr_align = 1;
		dma_attr.dma_attr_sgllen = 1;

		/*
		 * Allocate a new DMA handle for the transmit descriptor memory
		 * area.
		 */
		mystat = ddi_dma_alloc_handle(devinfo, &dma_attr,
		    DDI_DMA_DONTWAIT, 0,
		    &tx_ring->tbd_dma_handle);

		if (mystat != DDI_SUCCESS) {
			E1000G_DEBUGLOG_1(Adapter, E1000G_WARN_LEVEL,
			    "Could not re-allocate tbd dma handle: %d", mystat);
			tx_ring->tbd_dma_handle = NULL;
			return (DDI_FAILURE);
		}

		/*
		 * Allocate memory to DMA data to and from the transmit
		 * descriptors.
		 */
		mystat = ddi_dma_mem_alloc(tx_ring->tbd_dma_handle,
		    size,
		    &e1000g_desc_acc_attr, DDI_DMA_CONSISTENT,
		    DDI_DMA_DONTWAIT, 0,
		    (caddr_t *)&tx_ring->tbd_area,
		    &len, &tx_ring->tbd_acc_handle);

		if (mystat != DDI_SUCCESS) {
			E1000G_DEBUGLOG_1(Adapter, E1000G_WARN_LEVEL,
			    "Could not allocate tbd dma memory: %d", mystat);
			tx_ring->tbd_acc_handle = NULL;
			tx_ring->tbd_area = NULL;
			if (tx_ring->tbd_dma_handle != NULL) {
				ddi_dma_free_handle(&tx_ring->tbd_dma_handle);
				tx_ring->tbd_dma_handle = NULL;
			}
			return (DDI_FAILURE);
		} else
			alloc_flag = B_TRUE;

		/*
		 * Initialize the entire transmit buffer descriptor area to zero
		 */
		bzero(tx_ring->tbd_area, len);
		/*
		 * Memory has been allocated with the ddi_dma_mem_alloc call,
		 * but has not been aligned.
		 * We now align it on the appropriate boundary.
		 */
		templong = P2NPHASE((uintptr_t)tx_ring->tbd_area,
		    Adapter->desc_align);
		len = size - templong;
		templong += (uintptr_t)tx_ring->tbd_area;
		tx_ring->tbd_area = (struct e1000_tx_desc *)templong;
	}	/* alignment workaround */

	/*
	 * Transmit buffer descriptor memory allocation succeeded
	 */
	ASSERT(alloc_flag);

	/*
	 * Allocates DMA resources for the memory that was allocated by
	 * the ddi_dma_mem_alloc call. The DMA resources then get bound to the
	 * the memory address
	 */
	mystat = ddi_dma_addr_bind_handle(tx_ring->tbd_dma_handle,
	    (struct as *)NULL, (caddr_t)tx_ring->tbd_area,
	    len, DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_DONTWAIT, 0, &cookie, &cookie_count);

	if (mystat != DDI_SUCCESS) {
		E1000G_DEBUGLOG_1(Adapter, E1000G_WARN_LEVEL,
		    "Could not bind tbd dma resource: %d", mystat);
		if (tx_ring->tbd_acc_handle != NULL) {
			ddi_dma_mem_free(&tx_ring->tbd_acc_handle);
			tx_ring->tbd_acc_handle = NULL;
			tx_ring->tbd_area = NULL;
		}
		if (tx_ring->tbd_dma_handle != NULL) {
			ddi_dma_free_handle(&tx_ring->tbd_dma_handle);
			tx_ring->tbd_dma_handle = NULL;
		}
		return (DDI_FAILURE);
	}

	ASSERT(cookie_count == 1);	/* 1 cookie */

	if (cookie_count != 1) {
		E1000G_DEBUGLOG_2(Adapter, E1000G_WARN_LEVEL,
		    "Could not bind tbd dma resource in a single frag. "
		    "Count - %d Len - %d", cookie_count, len);
		e1000g_free_tx_descriptors(tx_ring);
		return (DDI_FAILURE);
	}

	tx_ring->tbd_dma_addr = cookie.dmac_laddress;
	tx_ring->tbd_first = tx_ring->tbd_area;
	tx_ring->tbd_last = tx_ring->tbd_first +
	    (Adapter->tx_desc_num - 1);

	return (DDI_SUCCESS);
}

static int
e1000g_alloc_rx_descriptors(e1000g_rx_data_t *rx_data)
{
	int mystat;
	boolean_t alloc_flag;
	size_t size;
	size_t len;
	uintptr_t templong;
	uint_t cookie_count;
	dev_info_t *devinfo;
	ddi_dma_cookie_t cookie;
	struct e1000g *Adapter;
	ddi_dma_attr_t dma_attr;

	Adapter = rx_data->rx_ring->adapter;
	devinfo = Adapter->dip;

	alloc_flag = B_FALSE;
	dma_attr = e1000g_desc_dma_attr;

	/*
	 * Memory allocation for the receive buffer descriptors.
	 */
	size = (sizeof (struct e1000_rx_desc)) * Adapter->rx_desc_num;

	/*
	 * Asking for aligned memory with DMA attributes set for suitable value
	 */
	dma_attr.dma_attr_sgllen = 1;
	dma_attr.dma_attr_align = Adapter->desc_align;

	/*
	 * Allocate a new DMA handle for the receive descriptors
	 */
	mystat = ddi_dma_alloc_handle(devinfo, &dma_attr,
	    DDI_DMA_DONTWAIT, 0,
	    &rx_data->rbd_dma_handle);

	if (mystat != DDI_SUCCESS) {
		E1000G_DEBUGLOG_1(Adapter, E1000G_WARN_LEVEL,
		    "Could not allocate rbd dma handle: %d", mystat);
		rx_data->rbd_dma_handle = NULL;
		return (DDI_FAILURE);
	}
	/*
	 * Allocate memory to DMA data to and from the receive
	 * descriptors.
	 */
	mystat = ddi_dma_mem_alloc(rx_data->rbd_dma_handle,
	    size,
	    &e1000g_desc_acc_attr, DDI_DMA_CONSISTENT,
	    DDI_DMA_DONTWAIT, 0,
	    (caddr_t *)&rx_data->rbd_area,
	    &len, &rx_data->rbd_acc_handle);

	/*
	 * Check if memory allocation succeeded and also if the
	 * allocated memory is aligned correctly.
	 */
	if ((mystat != DDI_SUCCESS) ||
	    ((uintptr_t)rx_data->rbd_area & (Adapter->desc_align - 1))) {
		if (mystat == DDI_SUCCESS) {
			ddi_dma_mem_free(&rx_data->rbd_acc_handle);
			rx_data->rbd_acc_handle = NULL;
			rx_data->rbd_area = NULL;
		}
		if (rx_data->rbd_dma_handle != NULL) {
			ddi_dma_free_handle(&rx_data->rbd_dma_handle);
			rx_data->rbd_dma_handle = NULL;
		}
		alloc_flag = B_FALSE;
	} else
		alloc_flag = B_TRUE;

	/*
	 * Initialize the allocated receive descriptor memory to zero.
	 */
	if (alloc_flag)
		bzero((caddr_t)rx_data->rbd_area, len);

	/*
	 * If memory allocation did not succeed, do the alignment ourselves
	 */
	if (!alloc_flag) {
		dma_attr.dma_attr_align = 1;
		dma_attr.dma_attr_sgllen = 1;
		size = size + Adapter->desc_align;
		/*
		 * Allocate a new DMA handle for the receive descriptor.
		 */
		mystat = ddi_dma_alloc_handle(devinfo, &dma_attr,
		    DDI_DMA_DONTWAIT, 0,
		    &rx_data->rbd_dma_handle);

		if (mystat != DDI_SUCCESS) {
			E1000G_DEBUGLOG_1(Adapter, E1000G_WARN_LEVEL,
			    "Could not re-allocate rbd dma handle: %d", mystat);
			rx_data->rbd_dma_handle = NULL;
			return (DDI_FAILURE);
		}
		/*
		 * Allocate memory to DMA data to and from the receive
		 * descriptors.
		 */
		mystat = ddi_dma_mem_alloc(rx_data->rbd_dma_handle,
		    size,
		    &e1000g_desc_acc_attr, DDI_DMA_CONSISTENT,
		    DDI_DMA_DONTWAIT, 0,
		    (caddr_t *)&rx_data->rbd_area,
		    &len, &rx_data->rbd_acc_handle);

		if (mystat != DDI_SUCCESS) {
			E1000G_DEBUGLOG_1(Adapter, E1000G_WARN_LEVEL,
			    "Could not allocate rbd dma memory: %d", mystat);
			rx_data->rbd_acc_handle = NULL;
			rx_data->rbd_area = NULL;
			if (rx_data->rbd_dma_handle != NULL) {
				ddi_dma_free_handle(&rx_data->rbd_dma_handle);
				rx_data->rbd_dma_handle = NULL;
			}
			return (DDI_FAILURE);
		} else
			alloc_flag = B_TRUE;

		/*
		 * Initialize the allocated receive descriptor memory to zero.
		 */
		bzero((caddr_t)rx_data->rbd_area, len);
		templong = P2NPHASE((uintptr_t)rx_data->rbd_area,
		    Adapter->desc_align);
		len = size - templong;
		templong += (uintptr_t)rx_data->rbd_area;
		rx_data->rbd_area = (struct e1000_rx_desc *)templong;
	}	/* alignment workaround */

	/*
	 * The memory allocation of the receive descriptors succeeded
	 */
	ASSERT(alloc_flag);

	/*
	 * Allocates DMA resources for the memory that was allocated by
	 * the ddi_dma_mem_alloc call.
	 */
	mystat = ddi_dma_addr_bind_handle(rx_data->rbd_dma_handle,
	    (struct as *)NULL, (caddr_t)rx_data->rbd_area,
	    len, DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_DONTWAIT, 0, &cookie, &cookie_count);

	if (mystat != DDI_SUCCESS) {
		E1000G_DEBUGLOG_1(Adapter, E1000G_WARN_LEVEL,
		    "Could not bind rbd dma resource: %d", mystat);
		if (rx_data->rbd_acc_handle != NULL) {
			ddi_dma_mem_free(&rx_data->rbd_acc_handle);
			rx_data->rbd_acc_handle = NULL;
			rx_data->rbd_area = NULL;
		}
		if (rx_data->rbd_dma_handle != NULL) {
			ddi_dma_free_handle(&rx_data->rbd_dma_handle);
			rx_data->rbd_dma_handle = NULL;
		}
		return (DDI_FAILURE);
	}

	ASSERT(cookie_count == 1);
	if (cookie_count != 1) {
		E1000G_DEBUGLOG_2(Adapter, E1000G_WARN_LEVEL,
		    "Could not bind rbd dma resource in a single frag. "
		    "Count - %d Len - %d", cookie_count, len);
		e1000g_free_rx_descriptors(rx_data);
		return (DDI_FAILURE);
	}

	rx_data->rbd_dma_addr = cookie.dmac_laddress;
	rx_data->rbd_first = rx_data->rbd_area;
	rx_data->rbd_last = rx_data->rbd_first +
	    (Adapter->rx_desc_num - 1);

	return (DDI_SUCCESS);
}

static void
e1000g_free_rx_descriptors(e1000g_rx_data_t *rx_data)
{
	if (rx_data->rbd_dma_handle != NULL) {
		(void) ddi_dma_unbind_handle(rx_data->rbd_dma_handle);
	}
	if (rx_data->rbd_acc_handle != NULL) {
		ddi_dma_mem_free(&rx_data->rbd_acc_handle);
		rx_data->rbd_acc_handle = NULL;
		rx_data->rbd_area = NULL;
	}
	if (rx_data->rbd_dma_handle != NULL) {
		ddi_dma_free_handle(&rx_data->rbd_dma_handle);
		rx_data->rbd_dma_handle = NULL;
	}
	rx_data->rbd_dma_addr = NULL;
	rx_data->rbd_first = NULL;
	rx_data->rbd_last = NULL;
}

static void
e1000g_free_tx_descriptors(e1000g_tx_ring_t *tx_ring)
{
	if (tx_ring->tbd_dma_handle != NULL) {
		(void) ddi_dma_unbind_handle(tx_ring->tbd_dma_handle);
	}
	if (tx_ring->tbd_acc_handle != NULL) {
		ddi_dma_mem_free(&tx_ring->tbd_acc_handle);
		tx_ring->tbd_acc_handle = NULL;
		tx_ring->tbd_area = NULL;
	}
	if (tx_ring->tbd_dma_handle != NULL) {
		ddi_dma_free_handle(&tx_ring->tbd_dma_handle);
		tx_ring->tbd_dma_handle = NULL;
	}
	tx_ring->tbd_dma_addr = NULL;
	tx_ring->tbd_first = NULL;
	tx_ring->tbd_last = NULL;
}


/*
 * e1000g_alloc_packets - allocate DMA buffers for rx/tx
 *
 * This routine allocates neccesary buffers for
 *	 Transmit sw packet structure
 *	 DMA handle for Transmit
 *	 DMA buffer for Transmit
 *	 Receive sw packet structure
 *	 DMA buffer for Receive
 */
static int
e1000g_alloc_packets(struct e1000g *Adapter)
{
	int result;
	e1000g_tx_ring_t *tx_ring;
	e1000g_rx_data_t *rx_data;

	tx_ring = Adapter->tx_ring;
	rx_data = Adapter->rx_ring->rx_data;

again:
	rw_enter(&e1000g_dma_type_lock, RW_READER);

	result = e1000g_alloc_tx_packets(tx_ring);
	if (result != DDI_SUCCESS) {
		if (e1000g_dma_type == USE_DVMA) {
			rw_exit(&e1000g_dma_type_lock);

			rw_enter(&e1000g_dma_type_lock, RW_WRITER);
			e1000g_dma_type = USE_DMA;
			rw_exit(&e1000g_dma_type_lock);

			E1000G_DEBUGLOG_0(Adapter, E1000G_INFO_LEVEL,
			    "No enough dvma resource for Tx packets, "
			    "trying to allocate dma buffers...\n");
			goto again;
		}
		rw_exit(&e1000g_dma_type_lock);

		E1000G_DEBUGLOG_0(Adapter, E1000G_WARN_LEVEL,
		    "Failed to allocate dma buffers for Tx packets\n");
		return (DDI_FAILURE);
	}

	result = e1000g_alloc_rx_packets(rx_data);
	if (result != DDI_SUCCESS) {
		e1000g_free_tx_packets(tx_ring);
		if (e1000g_dma_type == USE_DVMA) {
			rw_exit(&e1000g_dma_type_lock);

			rw_enter(&e1000g_dma_type_lock, RW_WRITER);
			e1000g_dma_type = USE_DMA;
			rw_exit(&e1000g_dma_type_lock);

			E1000G_DEBUGLOG_0(Adapter, E1000G_INFO_LEVEL,
			    "No enough dvma resource for Rx packets, "
			    "trying to allocate dma buffers...\n");
			goto again;
		}
		rw_exit(&e1000g_dma_type_lock);

		E1000G_DEBUGLOG_0(Adapter, E1000G_WARN_LEVEL,
		    "Failed to allocate dma buffers for Rx packets\n");
		return (DDI_FAILURE);
	}

	rw_exit(&e1000g_dma_type_lock);

	return (DDI_SUCCESS);
}

static void
e1000g_free_packets(struct e1000g *Adapter)
{
	e1000g_tx_ring_t *tx_ring;
	e1000g_rx_data_t *rx_data;

	tx_ring = Adapter->tx_ring;
	rx_data = Adapter->rx_ring->rx_data;

	e1000g_free_tx_packets(tx_ring);
	e1000g_free_rx_packets(rx_data, B_FALSE);
}

#ifdef __sparc
static int
e1000g_alloc_dvma_buffer(struct e1000g *Adapter,
    dma_buffer_t *buf, size_t size)
{
	int mystat;
	dev_info_t *devinfo;
	ddi_dma_cookie_t cookie;

	if (e1000g_force_detach)
		devinfo = Adapter->priv_dip;
	else
		devinfo = Adapter->dip;

	mystat = dvma_reserve(devinfo,
	    &e1000g_dma_limits,
	    Adapter->dvma_page_num,
	    &buf->dma_handle);

	if (mystat != DDI_SUCCESS) {
		buf->dma_handle = NULL;
		E1000G_DEBUGLOG_1(Adapter, E1000G_WARN_LEVEL,
		    "Could not allocate dvma buffer handle: %d\n", mystat);
		return (DDI_FAILURE);
	}

	buf->address = kmem_alloc(size, KM_NOSLEEP);

	if (buf->address == NULL) {
		if (buf->dma_handle != NULL) {
			dvma_release(buf->dma_handle);
			buf->dma_handle = NULL;
		}
		E1000G_DEBUGLOG_0(Adapter, E1000G_WARN_LEVEL,
		    "Could not allocate dvma buffer memory\n");
		return (DDI_FAILURE);
	}

	dvma_kaddr_load(buf->dma_handle,
	    buf->address, size, 0, &cookie);

	buf->dma_address = cookie.dmac_laddress;
	buf->size = size;
	buf->len = 0;

	return (DDI_SUCCESS);
}

static void
e1000g_free_dvma_buffer(dma_buffer_t *buf)
{
	if (buf->dma_handle != NULL) {
		dvma_unload(buf->dma_handle, 0, -1);
	} else {
		return;
	}

	buf->dma_address = NULL;

	if (buf->address != NULL) {
		kmem_free(buf->address, buf->size);
		buf->address = NULL;
	}

	if (buf->dma_handle != NULL) {
		dvma_release(buf->dma_handle);
		buf->dma_handle = NULL;
	}

	buf->size = 0;
	buf->len = 0;
}
#endif

static int
e1000g_alloc_dma_buffer(struct e1000g *Adapter,
    dma_buffer_t *buf, size_t size, ddi_dma_attr_t *p_dma_attr)
{
	int mystat;
	dev_info_t *devinfo;
	ddi_dma_cookie_t cookie;
	size_t len;
	uint_t count;

	if (e1000g_force_detach)
		devinfo = Adapter->priv_dip;
	else
		devinfo = Adapter->dip;

	mystat = ddi_dma_alloc_handle(devinfo,
	    p_dma_attr,
	    DDI_DMA_DONTWAIT, 0,
	    &buf->dma_handle);

	if (mystat != DDI_SUCCESS) {
		buf->dma_handle = NULL;
		E1000G_DEBUGLOG_1(Adapter, E1000G_WARN_LEVEL,
		    "Could not allocate dma buffer handle: %d\n", mystat);
		return (DDI_FAILURE);
	}

	mystat = ddi_dma_mem_alloc(buf->dma_handle,
	    size, &e1000g_buf_acc_attr, DDI_DMA_STREAMING,
	    DDI_DMA_DONTWAIT, 0,
	    &buf->address,
	    &len, &buf->acc_handle);

	if (mystat != DDI_SUCCESS) {
		buf->acc_handle = NULL;
		buf->address = NULL;
		if (buf->dma_handle != NULL) {
			ddi_dma_free_handle(&buf->dma_handle);
			buf->dma_handle = NULL;
		}
		E1000G_DEBUGLOG_1(Adapter, E1000G_WARN_LEVEL,
		    "Could not allocate dma buffer memory: %d\n", mystat);
		return (DDI_FAILURE);
	}

	mystat = ddi_dma_addr_bind_handle(buf->dma_handle,
	    (struct as *)NULL,
	    buf->address,
	    len, DDI_DMA_RDWR | DDI_DMA_STREAMING,
	    DDI_DMA_DONTWAIT, 0, &cookie, &count);

	if (mystat != DDI_SUCCESS) {
		if (buf->acc_handle != NULL) {
			ddi_dma_mem_free(&buf->acc_handle);
			buf->acc_handle = NULL;
			buf->address = NULL;
		}
		if (buf->dma_handle != NULL) {
			ddi_dma_free_handle(&buf->dma_handle);
			buf->dma_handle = NULL;
		}
		E1000G_DEBUGLOG_1(Adapter, E1000G_WARN_LEVEL,
		    "Could not bind buffer dma handle: %d\n", mystat);
		return (DDI_FAILURE);
	}

	ASSERT(count == 1);
	if (count != 1) {
		if (buf->dma_handle != NULL) {
			(void) ddi_dma_unbind_handle(buf->dma_handle);
		}
		if (buf->acc_handle != NULL) {
			ddi_dma_mem_free(&buf->acc_handle);
			buf->acc_handle = NULL;
			buf->address = NULL;
		}
		if (buf->dma_handle != NULL) {
			ddi_dma_free_handle(&buf->dma_handle);
			buf->dma_handle = NULL;
		}
		E1000G_DEBUGLOG_1(Adapter, E1000G_WARN_LEVEL,
		    "Could not bind buffer as a single frag. "
		    "Count = %d\n", count);
		return (DDI_FAILURE);
	}

	buf->dma_address = cookie.dmac_laddress;
	buf->size = len;
	buf->len = 0;

	return (DDI_SUCCESS);
}

/*
 * e1000g_alloc_dma_buffer_82546 - allocate a dma buffer along with all
 * necessary handles.  Same as e1000g_alloc_dma_buffer() except ensure
 * that buffer that doesn't cross a 64k boundary.
 */
static int
e1000g_alloc_dma_buffer_82546(struct e1000g *Adapter,
    dma_buffer_t *buf, size_t size, ddi_dma_attr_t *p_dma_attr)
{
	int mystat;
	dev_info_t *devinfo;
	ddi_dma_cookie_t cookie;
	size_t len;
	uint_t count;

	if (e1000g_force_detach)
		devinfo = Adapter->priv_dip;
	else
		devinfo = Adapter->dip;

	mystat = ddi_dma_alloc_handle(devinfo,
	    p_dma_attr,
	    DDI_DMA_DONTWAIT, 0,
	    &buf->dma_handle);

	if (mystat != DDI_SUCCESS) {
		buf->dma_handle = NULL;
		E1000G_DEBUGLOG_1(Adapter, E1000G_WARN_LEVEL,
		    "Could not allocate dma buffer handle: %d\n", mystat);
		return (DDI_FAILURE);
	}

	mystat = e1000g_dma_mem_alloc_82546(buf, size, &len);
	if (mystat != DDI_SUCCESS) {
		buf->acc_handle = NULL;
		buf->address = NULL;
		if (buf->dma_handle != NULL) {
			ddi_dma_free_handle(&buf->dma_handle);
			buf->dma_handle = NULL;
		}
		E1000G_DEBUGLOG_1(Adapter, E1000G_WARN_LEVEL,
		    "Could not allocate dma buffer memory: %d\n", mystat);
		return (DDI_FAILURE);
	}

	mystat = ddi_dma_addr_bind_handle(buf->dma_handle,
	    (struct as *)NULL,
	    buf->address,
	    len, DDI_DMA_READ | DDI_DMA_STREAMING,
	    DDI_DMA_DONTWAIT, 0, &cookie, &count);

	if (mystat != DDI_SUCCESS) {
		if (buf->acc_handle != NULL) {
			ddi_dma_mem_free(&buf->acc_handle);
			buf->acc_handle = NULL;
			buf->address = NULL;
		}
		if (buf->dma_handle != NULL) {
			ddi_dma_free_handle(&buf->dma_handle);
			buf->dma_handle = NULL;
		}
		E1000G_DEBUGLOG_1(Adapter, E1000G_WARN_LEVEL,
		    "Could not bind buffer dma handle: %d\n", mystat);
		return (DDI_FAILURE);
	}

	ASSERT(count == 1);
	if (count != 1) {
		if (buf->dma_handle != NULL) {
			(void) ddi_dma_unbind_handle(buf->dma_handle);
		}
		if (buf->acc_handle != NULL) {
			ddi_dma_mem_free(&buf->acc_handle);
			buf->acc_handle = NULL;
			buf->address = NULL;
		}
		if (buf->dma_handle != NULL) {
			ddi_dma_free_handle(&buf->dma_handle);
			buf->dma_handle = NULL;
		}
		E1000G_DEBUGLOG_1(Adapter, E1000G_WARN_LEVEL,
		    "Could not bind buffer as a single frag. "
		    "Count = %d\n", count);
		return (DDI_FAILURE);
	}

	buf->dma_address = cookie.dmac_laddress;
	buf->size = len;
	buf->len = 0;

	return (DDI_SUCCESS);
}

/*
 * e1000g_dma_mem_alloc_82546 - allocate a dma buffer, making up to
 * ALLOC_RETRY attempts to get a buffer that doesn't cross a 64k boundary.
 */
static int
e1000g_dma_mem_alloc_82546(dma_buffer_t *buf, size_t size, size_t *len)
{
#define	ALLOC_RETRY	10
	int stat;
	int cnt = 0;
	ddi_acc_handle_t hold[ALLOC_RETRY];

	while (cnt < ALLOC_RETRY) {
		hold[cnt] = NULL;

		/* allocate memory */
		stat = ddi_dma_mem_alloc(buf->dma_handle, size,
		    &e1000g_buf_acc_attr, DDI_DMA_STREAMING, DDI_DMA_DONTWAIT,
		    0, &buf->address, len, &buf->acc_handle);

		if (stat != DDI_SUCCESS) {
			break;
		}

		/*
		 * Check 64k bounday:
		 * if it is bad, hold it and retry
		 * if it is good, exit loop
		 */
		if (e1000g_cross_64k_bound(buf->address, *len)) {
			hold[cnt] = buf->acc_handle;
			stat = DDI_FAILURE;
		} else {
			break;
		}

		cnt++;
	}

	/* Release any held buffers crossing 64k bounday */
	for (--cnt; cnt >= 0; cnt--) {
		if (hold[cnt])
			ddi_dma_mem_free(&hold[cnt]);
	}

	return (stat);
}

/*
 * e1000g_cross_64k_bound - If starting and ending address cross a 64k boundary
 * return true; otherwise return false
 */
static boolean_t
e1000g_cross_64k_bound(void *addr, uintptr_t len)
{
	uintptr_t start = (uintptr_t)addr;
	uintptr_t end = start + len - 1;

	return (((start ^ end) >> 16) == 0 ? B_FALSE : B_TRUE);
}

static void
e1000g_free_dma_buffer(dma_buffer_t *buf)
{
	if (buf->dma_handle != NULL) {
		(void) ddi_dma_unbind_handle(buf->dma_handle);
	} else {
		return;
	}

	buf->dma_address = NULL;

	if (buf->acc_handle != NULL) {
		ddi_dma_mem_free(&buf->acc_handle);
		buf->acc_handle = NULL;
		buf->address = NULL;
	}

	if (buf->dma_handle != NULL) {
		ddi_dma_free_handle(&buf->dma_handle);
		buf->dma_handle = NULL;
	}

	buf->size = 0;
	buf->len = 0;
}

static int
e1000g_alloc_tx_packets(e1000g_tx_ring_t *tx_ring)
{
	int j;
	p_tx_sw_packet_t packet;
	int mystat;
	dma_buffer_t *tx_buf;
	struct e1000g *Adapter;
	dev_info_t *devinfo;
	ddi_dma_attr_t dma_attr;

	Adapter = tx_ring->adapter;
	devinfo = Adapter->dip;
	dma_attr = e1000g_buf_dma_attr;

	/*
	 * Memory allocation for the Transmit software structure, the transmit
	 * software packet. This structure stores all the relevant information
	 * for transmitting a single packet.
	 */
	tx_ring->packet_area =
	    kmem_zalloc(TX_SW_PKT_AREA_SZ, KM_NOSLEEP);

	if (tx_ring->packet_area == NULL)
		return (DDI_FAILURE);

	for (j = 0, packet = tx_ring->packet_area;
	    j < Adapter->tx_freelist_num; j++, packet++) {

		ASSERT(packet != NULL);

		/*
		 * Pre-allocate dma handles for transmit. These dma handles
		 * will be dynamically bound to the data buffers passed down
		 * from the upper layers at the time of transmitting. The
		 * dynamic binding only applies for the packets that are larger
		 * than the tx_bcopy_thresh.
		 */
		switch (e1000g_dma_type) {
#ifdef __sparc
		case USE_DVMA:
			mystat = dvma_reserve(devinfo,
			    &e1000g_dma_limits,
			    Adapter->dvma_page_num,
			    &packet->tx_dma_handle);
			break;
#endif
		case USE_DMA:
			mystat = ddi_dma_alloc_handle(devinfo,
			    &e1000g_tx_dma_attr,
			    DDI_DMA_DONTWAIT, 0,
			    &packet->tx_dma_handle);
			break;
		default:
			ASSERT(B_FALSE);
			break;
		}
		if (mystat != DDI_SUCCESS) {
			packet->tx_dma_handle = NULL;
			E1000G_DEBUGLOG_1(Adapter, E1000G_WARN_LEVEL,
			    "Could not allocate tx dma handle: %d\n", mystat);
			goto tx_pkt_fail;
		}

		/*
		 * Pre-allocate transmit buffers for small packets that the
		 * size is less than tx_bcopy_thresh. The data of those small
		 * packets will be bcopy() to the transmit buffers instead of
		 * using dynamical DMA binding. For small packets, bcopy will
		 * bring better performance than DMA binding.
		 */
		tx_buf = packet->tx_buf;

		switch (e1000g_dma_type) {
#ifdef __sparc
		case USE_DVMA:
			mystat = e1000g_alloc_dvma_buffer(Adapter,
			    tx_buf, Adapter->tx_buffer_size);
			break;
#endif
		case USE_DMA:
			mystat = e1000g_alloc_dma_buffer(Adapter,
			    tx_buf, Adapter->tx_buffer_size, &dma_attr);
			break;
		default:
			ASSERT(B_FALSE);
			break;
		}
		if (mystat != DDI_SUCCESS) {
			ASSERT(packet->tx_dma_handle != NULL);
			switch (e1000g_dma_type) {
#ifdef __sparc
			case USE_DVMA:
				dvma_release(packet->tx_dma_handle);
				break;
#endif
			case USE_DMA:
				ddi_dma_free_handle(&packet->tx_dma_handle);
				break;
			default:
				ASSERT(B_FALSE);
				break;
			}
			packet->tx_dma_handle = NULL;
			E1000G_DEBUGLOG_0(Adapter, E1000G_WARN_LEVEL,
			    "Allocate Tx buffer fail\n");
			goto tx_pkt_fail;
		}

		packet->dma_type = e1000g_dma_type;
	} /* for */

	return (DDI_SUCCESS);

tx_pkt_fail:
	e1000g_free_tx_packets(tx_ring);

	return (DDI_FAILURE);
}


int
e1000g_increase_rx_packets(e1000g_rx_data_t *rx_data)
{
	int i;
	p_rx_sw_packet_t packet;
	p_rx_sw_packet_t cur, next;
	struct e1000g *Adapter;
	ddi_dma_attr_t dma_attr;

	Adapter = rx_data->rx_ring->adapter;
	dma_attr = e1000g_buf_dma_attr;
	dma_attr.dma_attr_align = Adapter->rx_buf_align;
	cur = NULL;

	for (i = 0; i < RX_FREELIST_INCREASE_SIZE; i++) {
		packet = e1000g_alloc_rx_sw_packet(rx_data, &dma_attr);
		if (packet == NULL)
			break;
		packet->next = cur;
		cur = packet;
	}
	Adapter->rx_freelist_num += i;
	rx_data->avail_freepkt += i;

	while (cur != NULL) {
		QUEUE_PUSH_TAIL(&rx_data->free_list, &cur->Link);
		next = cur->next;
		cur->next = rx_data->packet_area;
		rx_data->packet_area = cur;

		cur = next;
	}

	return (DDI_SUCCESS);
}


static int
e1000g_alloc_rx_packets(e1000g_rx_data_t *rx_data)
{
	int i;
	p_rx_sw_packet_t packet;
	struct e1000g *Adapter;
	uint32_t packet_num;
	ddi_dma_attr_t dma_attr;

	Adapter = rx_data->rx_ring->adapter;
	dma_attr = e1000g_buf_dma_attr;
	dma_attr.dma_attr_align = Adapter->rx_buf_align;

	/*
	 * Allocate memory for the rx_sw_packet structures. Each one of these
	 * structures will contain a virtual and physical address to an actual
	 * receive buffer in host memory. Since we use one rx_sw_packet per
	 * received packet, the maximum number of rx_sw_packet that we'll
	 * need is equal to the number of receive descriptors plus the freelist
	 * size.
	 */
	packet_num = Adapter->rx_desc_num + RX_FREELIST_INCREASE_SIZE;
	rx_data->packet_area = NULL;

	for (i = 0; i < packet_num; i++) {
		packet = e1000g_alloc_rx_sw_packet(rx_data, &dma_attr);
		if (packet == NULL)
			goto rx_pkt_fail;

		packet->next = rx_data->packet_area;
		rx_data->packet_area = packet;
	}

	Adapter->rx_freelist_num = RX_FREELIST_INCREASE_SIZE;
	return (DDI_SUCCESS);

rx_pkt_fail:
	e1000g_free_rx_packets(rx_data, B_TRUE);
	return (DDI_FAILURE);
}


static p_rx_sw_packet_t
e1000g_alloc_rx_sw_packet(e1000g_rx_data_t *rx_data, ddi_dma_attr_t *p_dma_attr)
{
	int mystat;
	p_rx_sw_packet_t packet;
	dma_buffer_t *rx_buf;
	struct e1000g *Adapter;

	Adapter = rx_data->rx_ring->adapter;

	packet = kmem_zalloc(sizeof (rx_sw_packet_t), KM_NOSLEEP);
	if (packet == NULL) {
		E1000G_DEBUGLOG_0(Adapter, E1000G_WARN_LEVEL,
		    "Cound not allocate memory for Rx SwPacket\n");
		return (NULL);
	}

	rx_buf = packet->rx_buf;

	switch (e1000g_dma_type) {
#ifdef __sparc
	case USE_DVMA:
		mystat = e1000g_alloc_dvma_buffer(Adapter,
		    rx_buf, Adapter->rx_buffer_size);
		break;
#endif
	case USE_DMA:
		if (Adapter->mem_workaround_82546 &&
		    ((Adapter->shared.mac.type == e1000_82545) ||
		    (Adapter->shared.mac.type == e1000_82546) ||
		    (Adapter->shared.mac.type == e1000_82546_rev_3))) {
			mystat = e1000g_alloc_dma_buffer_82546(Adapter,
			    rx_buf, Adapter->rx_buffer_size, p_dma_attr);
		} else {
			mystat = e1000g_alloc_dma_buffer(Adapter,
			    rx_buf, Adapter->rx_buffer_size, p_dma_attr);
		}
		break;
	default:
		ASSERT(B_FALSE);
		break;
	}

	if (mystat != DDI_SUCCESS) {
		if (packet != NULL)
			kmem_free(packet, sizeof (rx_sw_packet_t));

		E1000G_DEBUGLOG_0(Adapter, E1000G_WARN_LEVEL,
		    "Failed to allocate Rx buffer\n");
		return (NULL);
	}

	rx_buf->size -= E1000G_IPALIGNROOM;
	rx_buf->address += E1000G_IPALIGNROOM;
	rx_buf->dma_address += E1000G_IPALIGNROOM;

	packet->rx_data = (caddr_t)rx_data;
	packet->free_rtn.free_func = e1000g_rxfree_func;
	packet->free_rtn.free_arg = (char *)packet;
	/*
	 * esballoc is changed to desballoc which
	 * is undocumented call but as per sun,
	 * we can use it. It gives better efficiency.
	 */
	packet->mp = desballoc((unsigned char *)
	    rx_buf->address,
	    rx_buf->size,
	    BPRI_MED, &packet->free_rtn);

	packet->dma_type = e1000g_dma_type;
	packet->ref_cnt = 1;

	return (packet);
}

void
e1000g_free_rx_sw_packet(p_rx_sw_packet_t packet, boolean_t full_release)
{
	dma_buffer_t *rx_buf;

	if (packet->mp != NULL) {
		freemsg(packet->mp);
		packet->mp = NULL;
	}

	rx_buf = packet->rx_buf;

	switch (packet->dma_type) {
#ifdef __sparc
	case USE_DVMA:
		if (rx_buf->address != NULL) {
			rx_buf->size += E1000G_IPALIGNROOM;
			rx_buf->address -= E1000G_IPALIGNROOM;
		}
		e1000g_free_dvma_buffer(rx_buf);
		break;
#endif
	case USE_DMA:
		e1000g_free_dma_buffer(rx_buf);
		break;
	default:
		break;
	}

	packet->dma_type = USE_NONE;

	if (!full_release)
		return;

	kmem_free(packet, sizeof (rx_sw_packet_t));
}

static void
e1000g_free_rx_packets(e1000g_rx_data_t *rx_data, boolean_t full_release)
{
	p_rx_sw_packet_t packet, next_packet;
	uint32_t ref_cnt;

	mutex_enter(&e1000g_rx_detach_lock);

	packet = rx_data->packet_area;
	while (packet != NULL) {
		next_packet = packet->next;

		ref_cnt = atomic_dec_32_nv(&packet->ref_cnt);
		if (ref_cnt > 0) {
			atomic_inc_32(&rx_data->pending_count);
			atomic_inc_32(&e1000g_mblks_pending);
		} else {
			e1000g_free_rx_sw_packet(packet, full_release);
		}

		packet = next_packet;
	}

	if (full_release)
		rx_data->packet_area = NULL;

	mutex_exit(&e1000g_rx_detach_lock);
}


static void
e1000g_free_tx_packets(e1000g_tx_ring_t *tx_ring)
{
	int j;
	struct e1000g *Adapter;
	p_tx_sw_packet_t packet;
	dma_buffer_t *tx_buf;

	Adapter = tx_ring->adapter;

	for (j = 0, packet = tx_ring->packet_area;
	    j < Adapter->tx_freelist_num; j++, packet++) {

		if (packet == NULL)
			break;

		/* Free the Tx DMA handle for dynamical binding */
		if (packet->tx_dma_handle != NULL) {
			switch (packet->dma_type) {
#ifdef __sparc
			case USE_DVMA:
				dvma_release(packet->tx_dma_handle);
				break;
#endif
			case USE_DMA:
				ddi_dma_free_handle(&packet->tx_dma_handle);
				break;
			default:
				ASSERT(B_FALSE);
				break;
			}
			packet->tx_dma_handle = NULL;
		} else {
			/*
			 * If the dma handle is NULL, then we don't
			 * need to check the packets left. For they
			 * have not been initialized or have been freed.
			 */
			break;
		}

		tx_buf = packet->tx_buf;

		switch (packet->dma_type) {
#ifdef __sparc
		case USE_DVMA:
			e1000g_free_dvma_buffer(tx_buf);
			break;
#endif
		case USE_DMA:
			e1000g_free_dma_buffer(tx_buf);
			break;
		default:
			ASSERT(B_FALSE);
			break;
		}

		packet->dma_type = USE_NONE;
	}
	if (tx_ring->packet_area != NULL) {
		kmem_free(tx_ring->packet_area, TX_SW_PKT_AREA_SZ);
		tx_ring->packet_area = NULL;
	}
}

/*
 * e1000g_release_dma_resources - release allocated DMA resources
 *
 * This function releases any pending buffers that has been
 * previously allocated
 */
void
e1000g_release_dma_resources(struct e1000g *Adapter)
{
	e1000g_free_descriptors(Adapter);
	e1000g_free_packets(Adapter);
}

/* ARGSUSED */
void
e1000g_set_fma_flags(int dma_flag)
{
	if (dma_flag) {
		e1000g_tx_dma_attr.dma_attr_flags = DDI_DMA_FLAGERR;
		e1000g_buf_dma_attr.dma_attr_flags = DDI_DMA_FLAGERR;
		e1000g_desc_dma_attr.dma_attr_flags = DDI_DMA_FLAGERR;
	} else {
		e1000g_tx_dma_attr.dma_attr_flags = 0;
		e1000g_buf_dma_attr.dma_attr_flags = 0;
		e1000g_desc_dma_attr.dma_attr_flags = 0;
	}
}
