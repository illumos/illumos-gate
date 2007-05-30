/*
 * This file is provided under a CDDLv1 license.  When using or
 * redistributing this file, you may do so under this license.
 * In redistributing this file this license must be included
 * and no other modification of this header file is permitted.
 *
 * CDDL LICENSE SUMMARY
 *
 * Copyright(c) 1999 - 2007 Intel Corporation. All rights reserved.
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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms of the CDDLv1.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * **********************************************************************
 * Module Name:								*
 *   e1000galloc.c							*
 *									*
 * Abstract:								*
 *   This file contains some routines that take care of init,		*
 *   uninit, and memory allocation.					*
 *									*
 *									*
 *   This driver runs on the following hardware:			*
 *   - Wiseman based PCI gigabit ethernet adapters			*
 *									*
 * Environment:								*
 *   Kernel Mode -							*
 *									*
 * **********************************************************************
 */

#include "e1000g_sw.h"
#include "e1000g_debug.h"

#define	TX_SW_PKT_AREA_SZ \
	(sizeof (TX_SW_PACKET) * Adapter->NumTxSwPacket)

static int e1000g_alloc_tx_descriptors(e1000g_tx_ring_t *);
static int e1000g_alloc_rx_descriptors(e1000g_rx_ring_t *);
static void e1000g_free_tx_descriptors(e1000g_tx_ring_t *);
static void e1000g_free_rx_descriptors(e1000g_rx_ring_t *);
static int e1000g_alloc_tx_packets(e1000g_tx_ring_t *);
static int e1000g_alloc_rx_packets(e1000g_rx_ring_t *);
static void e1000g_free_tx_packets(e1000g_tx_ring_t *);
static void e1000g_free_rx_packets(e1000g_rx_ring_t *);
static int e1000g_alloc_dma_buffer(struct e1000g *, dma_buffer_t *, size_t);
static void e1000g_free_dma_buffer(dma_buffer_t *);
#ifdef __sparc
static int e1000g_alloc_dvma_buffer(struct e1000g *, dma_buffer_t *, size_t);
static void e1000g_free_dvma_buffer(dma_buffer_t *);
#endif
static int e1000g_alloc_descriptors(struct e1000g *Adapter);
static int e1000g_alloc_packets(struct e1000g *Adapter);
static PRX_SW_PACKET e1000g_alloc_rx_sw_packet(e1000g_rx_ring_t *);

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
	e1000g_tx_ring_t *tx_ring;
	e1000g_rx_ring_t *rx_ring;

	tx_ring = Adapter->tx_ring;
	rx_ring = Adapter->rx_ring;

	if (e1000g_alloc_descriptors(Adapter) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (e1000g_alloc_packets(Adapter) != DDI_SUCCESS) {
		e1000g_free_tx_descriptors(tx_ring);
		e1000g_free_rx_descriptors(rx_ring);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * **********************************************************************
 * Name:	e1000g_alloc_descriptors				*
 *									*
 * Description:								*
 *     This routine Allocates Neccesary Buffers for the device		*
 *     It allocates memory for						*
 *	 Transmit Descriptor Area					*
 *	 Receive Descrpitor Area					*
 *									*
 *     NOTE -- The device must have been reset before this routine	*
 *		      is called.					*
 *									*
 * Author:	       Hari Seshadri					*
 * Functions Called :							*
 *		       DDI mem functions called				*
 *     ddi_dma_alloc_handle() allocates a new  DMA  handle.  A  DMA	*
 *     handle  is  an  opaque  object used as a reference to subse-	*
 *     quently  allocated  DMA  resources.   ddi_dma_alloc_handle()	*
 *     accepts  as parameters the device information referred to by	*
 *     dip  and  the  device's  DMA  attributes  described   by   a	*
 *     ddi_dma_attr(9S)    structure.    A   successful   call   to	*
 *     ddi_dma_alloc_handle() fills in  the  value  pointed  to  by	*
 *     handlep.   A  DMA handle must only be used by the device for	*
 *     which it was allocated and is only valid for one  I/O  tran-	*
 *     saction at a time.						*
 *									*
 *     ddi_dma_mem_alloc() allocates memory for DMA transfers to or	*
 *     from a device.  The allocation will obey the alignment, pad-	*
 *     ding constraints and device granularity as specified by  the	*
 *     DMA    attributes    (see    ddi_dma_attr(9S))   passed   to	*
 *     ddi_dma_alloc_handle(9F) and the more restrictive attributes	*
 *     imposed by the system.Flags should be set to DDI_DMA_STREAMING	*
 *     if  the  device  is  doing  sequential,  unidirectional,		*
 *     block-sized, and block- aligned transfers to or from memory.	*
 *									*
 *									*
 *     ddi_dma_addr_bind_handle() allocates  DMA  resources  for  a	*
 *     memory  object such that a device can perform DMA to or from	*
 *     the object.  DMA resources  are  allocated  considering  the	*
 *     device's  DMA  attributes  as  expressed by ddi_dma_attr(9S)	*
 *     (see ddi_dma_alloc_handle(9F)).					*
 *     ddi_dma_addr_bind_handle() fills in  the  first  DMA  cookie	*
 *     pointed  to by cookiep with the appropriate address, length,	*
 *     and bus type.	*ccountp is set to the number of DMA  cookies	*
 *     representing this DMA object. Subsequent DMA cookies must be	*
 *     retrieved by calling ddi_dma_nextcookie(9F)  the  number  of	*
 *     times specified by *countp - 1.					*
 *									*
 * Arguments:								*
 *      Adapter - A pointer to context sensitive "Adapter" structure.	*
 *									*
 *									*
 * Returns:								*
 *      DDI_SUCCESS on success						*
 *	  DDI_FAILURE on error						*
 *									*
 * Modification log:							*
 * Date      Who  Description						*
 * --------  ---  -----------------------------------------------------	*
 * 11/11/98  Vinay  Cleaned the entire function to prevents panics and	*
 *		   memory corruption					*
 * 17/11/98  Vinay  Optimized it for proper usages of function calls	*
 * 30/04/99  Vinay  Resolved some more memory problems related to race	*
 *		  conditions						*
 * **********************************************************************
 */
static int
e1000g_alloc_descriptors(struct e1000g *Adapter)
{
	int result;
	e1000g_tx_ring_t *tx_ring;
	e1000g_rx_ring_t *rx_ring;

	tx_ring = Adapter->tx_ring;

	result = e1000g_alloc_tx_descriptors(tx_ring);
	if (result != DDI_SUCCESS)
		return (DDI_FAILURE);

	rx_ring = Adapter->rx_ring;

	result = e1000g_alloc_rx_descriptors(rx_ring);
	if (result != DDI_SUCCESS) {
		e1000g_free_tx_descriptors(tx_ring);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
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

	Adapter = tx_ring->adapter;

	alloc_flag = B_FALSE;

	devinfo = Adapter->dip;

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
	size = sizeof (struct e1000_tx_desc) * Adapter->NumTxDescriptors;

	/*
	 * Memory allocation for the transmit buffer descriptors.
	 */
	/*
	 * DMA attributes set to asking for 4k alignment and no
	 * scatter/gather specified.
	 * This typically does not succeed for Solaris 7, but
	 * might work for Solaris 2.6
	 */
	tbd_dma_attr.dma_attr_sgllen = 1;

	/*
	 * Allocate a new DMA handle for the transmit descriptor
	 * memory area.
	 */
	mystat = ddi_dma_alloc_handle(devinfo, &tbd_dma_attr,
	    DDI_DMA_DONTWAIT, 0,
	    &tx_ring->tbd_dma_handle);

	if (mystat != DDI_SUCCESS) {
		e1000g_log(Adapter, CE_WARN,
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
	    &accattr, DDI_DMA_CONSISTENT,
	    DDI_DMA_DONTWAIT, 0,
	    (caddr_t *)&tx_ring->tbd_area,
	    &len, &tx_ring->tbd_acc_handle);

	if ((mystat != DDI_SUCCESS) ||
	    ((uintptr_t)tx_ring->tbd_area & (E1000_MDALIGN - 1))) {
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
	 * we allocate 4K extra memory and then align it at a 4k boundary.
	 */
	if (!alloc_flag) {
		size = size + ROUNDOFF;

		/*
		 * DMA attributes set to no scatter/gather and 16 bit alignment
		 */
		tbd_dma_attr.dma_attr_align = 1;
		tbd_dma_attr.dma_attr_sgllen = 1;

		/*
		 * Allocate a new DMA handle for the transmit descriptor memory
		 * area.
		 */
		mystat = ddi_dma_alloc_handle(devinfo, &tbd_dma_attr,
		    DDI_DMA_DONTWAIT, 0,
		    &tx_ring->tbd_dma_handle);

		if (mystat != DDI_SUCCESS) {
			e1000g_log(Adapter, CE_WARN,
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
		    &accattr, DDI_DMA_CONSISTENT,
		    DDI_DMA_DONTWAIT, 0,
		    (caddr_t *)&tx_ring->tbd_area,
		    &len, &tx_ring->tbd_acc_handle);

		if (mystat != DDI_SUCCESS) {
			e1000g_log(Adapter, CE_WARN,
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
		 * but has not been aligned. We now align it on a 4k boundary.
		 */
		templong = P2NPHASE((uintptr_t)tx_ring->tbd_area, ROUNDOFF);
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
	    DDI_DMA_SLEEP, 0, &cookie, &cookie_count);

	if (mystat != DDI_SUCCESS) {
		e1000g_log(Adapter, CE_WARN,
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
		e1000g_log(Adapter, CE_WARN,
		    "Could not bind tbd dma resource in a single frag. "
		    "Count - %d Len - %d", cookie_count, len);
		e1000g_free_tx_descriptors(tx_ring);
		return (DDI_FAILURE);
	}

	/*
	 * The FirstTxDescriptor is initialized to the physical address that
	 * is obtained from the ddi_dma_addr_bind_handle call
	 */
	tx_ring->tbd_dma_addr = cookie.dmac_laddress;
	tx_ring->tbd_first = tx_ring->tbd_area;
	tx_ring->tbd_last = tx_ring->tbd_first +
	    (Adapter->NumTxDescriptors - 1);

	return (DDI_SUCCESS);
}

static int
e1000g_alloc_rx_descriptors(e1000g_rx_ring_t *rx_ring)
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

	Adapter = rx_ring->adapter;

	alloc_flag = B_FALSE;

	devinfo = Adapter->dip;

	/*
	 * Memory allocation for the receive buffer descriptors.
	 */
	size = (sizeof (struct e1000_rx_desc)) * Adapter->NumRxDescriptors;

	/*
	 * Asking for aligned memory with DMA attributes set for 4k alignment
	 */
	tbd_dma_attr.dma_attr_sgllen = 1;
	tbd_dma_attr.dma_attr_align = E1000_MDALIGN;

	/*
	 * Allocate a new DMA handle for the receive descriptor
	 * memory area. re-use the tbd_dma_attr since rbd has
	 * same attributes.
	 */
	mystat = ddi_dma_alloc_handle(devinfo, &tbd_dma_attr,
	    DDI_DMA_DONTWAIT, 0,
	    &rx_ring->rbd_dma_handle);

	if (mystat != DDI_SUCCESS) {
		e1000g_log(Adapter, CE_WARN,
		    "Could not allocate rbd dma handle: %d", mystat);
		rx_ring->rbd_dma_handle = NULL;
		return (DDI_FAILURE);
	}
	/*
	 * Allocate memory to DMA data to and from the receive
	 * descriptors.
	 */
	mystat = ddi_dma_mem_alloc(rx_ring->rbd_dma_handle,
	    size,
	    &accattr, DDI_DMA_CONSISTENT,
	    DDI_DMA_DONTWAIT, 0,
	    (caddr_t *)&rx_ring->rbd_area,
	    &len, &rx_ring->rbd_acc_handle);

	/*
	 * Check if memory allocation succeeded and also if the
	 * allocated memory is aligned correctly.
	 */
	if ((mystat != DDI_SUCCESS) ||
	    ((uintptr_t)rx_ring->rbd_area & (E1000_MDALIGN - 1))) {
		if (mystat == DDI_SUCCESS) {
			ddi_dma_mem_free(&rx_ring->rbd_acc_handle);
			rx_ring->rbd_acc_handle = NULL;
			rx_ring->rbd_area = NULL;
		}
		if (rx_ring->rbd_dma_handle != NULL) {
			ddi_dma_free_handle(&rx_ring->rbd_dma_handle);
			rx_ring->rbd_dma_handle = NULL;
		}
		alloc_flag = B_FALSE;
	} else
		alloc_flag = B_TRUE;

	/*
	 * Initialize the allocated receive descriptor memory to zero.
	 */
	if (alloc_flag)
		bzero((caddr_t)rx_ring->rbd_area, len);

	/*
	 * If memory allocation did not succeed or if number of descriptors is
	 * greater than a page size ( more than 256 descriptors ), do the
	 * alignment yourself
	 */
	if (!alloc_flag) {
		tbd_dma_attr.dma_attr_align = 1;
		tbd_dma_attr.dma_attr_sgllen = 1;
		size = size + ROUNDOFF;
		/*
		 * Allocate a new DMA handle for the receive descriptor memory
		 * area. re-use the tbd_dma_attr since rbd has same attributes.
		 */
		mystat = ddi_dma_alloc_handle(devinfo, &tbd_dma_attr,
		    DDI_DMA_DONTWAIT, 0,
		    &rx_ring->rbd_dma_handle);

		if (mystat != DDI_SUCCESS) {
			e1000g_log(Adapter, CE_WARN,
			    "Could not re-allocate rbd dma handle: %d", mystat);
			rx_ring->rbd_dma_handle = NULL;
			return (DDI_FAILURE);
		}
		/*
		 * Allocate memory to DMA data to and from the receive
		 * descriptors.
		 */
		mystat = ddi_dma_mem_alloc(rx_ring->rbd_dma_handle,
		    size,
		    &accattr, DDI_DMA_CONSISTENT,
		    DDI_DMA_DONTWAIT, 0,
		    (caddr_t *)&rx_ring->rbd_area,
		    &len, &rx_ring->rbd_acc_handle);

		if (mystat != DDI_SUCCESS) {
			e1000g_log(Adapter, CE_WARN,
			    "Could not allocate rbd dma memory: %d", mystat);
			rx_ring->rbd_acc_handle = NULL;
			rx_ring->rbd_area = NULL;
			if (rx_ring->rbd_dma_handle != NULL) {
				ddi_dma_free_handle(&rx_ring->rbd_dma_handle);
				rx_ring->rbd_dma_handle = NULL;
			}
			return (DDI_FAILURE);
		} else
			alloc_flag = B_TRUE;

		/*
		 * Initialize the allocated receive descriptor memory to zero.
		 */
		bzero((caddr_t)rx_ring->rbd_area, len);
		templong = P2NPHASE((uintptr_t)rx_ring->rbd_area, ROUNDOFF);
		len = size - templong;
		templong += (uintptr_t)rx_ring->rbd_area;
		rx_ring->rbd_area = (struct e1000_rx_desc *)templong;
	}	/* alignment workaround */

	/*
	 * The memory allocation of the receive descriptors succeeded
	 */
	ASSERT(alloc_flag);

	/*
	 * Allocates DMA resources for the memory that was allocated by
	 * the ddi_dma_mem_alloc call.
	 */
	mystat = ddi_dma_addr_bind_handle(rx_ring->rbd_dma_handle,
	    (struct as *)NULL, (caddr_t)rx_ring->rbd_area,
	    len, DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, 0, &cookie, &cookie_count);

	if (mystat != DDI_SUCCESS) {
		e1000g_log(Adapter, CE_WARN,
		    "Could not bind rbd dma resource: %d", mystat);
		if (rx_ring->rbd_acc_handle != NULL) {
			ddi_dma_mem_free(&rx_ring->rbd_acc_handle);
			rx_ring->rbd_acc_handle = NULL;
			rx_ring->rbd_area = NULL;
		}
		if (rx_ring->rbd_dma_handle != NULL) {
			ddi_dma_free_handle(&rx_ring->rbd_dma_handle);
			rx_ring->rbd_dma_handle = NULL;
		}
		return (DDI_FAILURE);
	}

	ASSERT(cookie_count == 1);
	if (cookie_count != 1) {
		e1000g_log(Adapter, CE_WARN,
		    "Could not bind rbd dma resource in a single frag. "
		    "Count - %d Len - %d", cookie_count, len);
		e1000g_free_rx_descriptors(rx_ring);
		return (DDI_FAILURE);
	}
	/*
	 * Initialize the FirstRxDescriptor to the cookie address obtained
	 * from the ddi_dma_addr_bind_handle call.
	 */
	rx_ring->rbd_dma_addr = cookie.dmac_laddress;
	rx_ring->rbd_first = rx_ring->rbd_area;
	rx_ring->rbd_last = rx_ring->rbd_first +
	    (Adapter->NumRxDescriptors - 1);

	return (DDI_SUCCESS);
}

static void
e1000g_free_rx_descriptors(e1000g_rx_ring_t *rx_ring)
{
	if (rx_ring->rbd_dma_handle != NULL) {
		ddi_dma_unbind_handle(rx_ring->rbd_dma_handle);
	}
	if (rx_ring->rbd_acc_handle != NULL) {
		ddi_dma_mem_free(&rx_ring->rbd_acc_handle);
		rx_ring->rbd_acc_handle = NULL;
		rx_ring->rbd_area = NULL;
	}
	if (rx_ring->rbd_dma_handle != NULL) {
		ddi_dma_free_handle(&rx_ring->rbd_dma_handle);
		rx_ring->rbd_dma_handle = NULL;
	}
	rx_ring->rbd_dma_addr = NULL;
	rx_ring->rbd_first = NULL;
	rx_ring->rbd_last = NULL;
}

static void
e1000g_free_tx_descriptors(e1000g_tx_ring_t *tx_ring)
{
	if (tx_ring->tbd_dma_handle != NULL) {
		ddi_dma_unbind_handle(tx_ring->tbd_dma_handle);
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
 * **********************************************************************
 * Name:	e1000g_alloc_packets					*
 *									*
 * Description: This routine Allocates Neccesary Buffers for the device	*
 *      It allocates memory for						*
 *									*
 *	 Transmit packet Structure					*
 *	 Handle for Transmit buffers					*
 *	 Receive packet structure					*
 *	 Buffer for Receive packet					*
 *									*
 *									*
 *       For ddi memory alloc routine see e1000g_Txalloc description	*
 *       NOTE -- The device must have been reset before this routine	*
 *	       is called.						*
 *									*
 * Author:		   Hari Seshadri				*
 * Functions Called :							*
 *									*
 *									*
 *									*
 * Arguments:								*
 *      Adapter - A pointer to our context sensitive "Adapter"		*
 *		structure.						*
 *									*
 *									*
 * Returns:								*
 *      DDI_SUCCESS on sucess						*
 *	  DDI_FAILURE on error						*
 *									*
 *									*
 *									*
 * Modification log:							*
 * Date      Who  Description						*
 * --------  ---  -----------------------------------------------------	*
 * 30/04/99  VA   Cleaned code for memory corruptions, invalid DMA	*
 *		attributes and prevent panics				*
 * **********************************************************************
 */
static int
e1000g_alloc_packets(struct e1000g *Adapter)
{
	int result;
	e1000g_tx_ring_t *tx_ring;
	e1000g_rx_ring_t *rx_ring;

	tx_ring = Adapter->tx_ring;
	rx_ring = Adapter->rx_ring;

again:
	rw_enter(&e1000g_dma_type_lock, RW_READER);

	result = e1000g_alloc_tx_packets(tx_ring);
	if (result != DDI_SUCCESS) {
		if (e1000g_dma_type == USE_DVMA) {
			rw_exit(&e1000g_dma_type_lock);

			rw_enter(&e1000g_dma_type_lock, RW_WRITER);
			e1000g_dma_type = USE_DMA;
			rw_exit(&e1000g_dma_type_lock);

			e1000g_DEBUGLOG_0(Adapter, e1000g_CALLTRACE_LEVEL,
			    "No enough dvma resource for Tx packets, "
			    "trying to allocate dma buffers...\n");
			goto again;
		}
		rw_exit(&e1000g_dma_type_lock);

		e1000g_DEBUGLOG_0(Adapter, e1000g_INFO_LEVEL,
		    "Failed to allocate dma buffers for Tx packets\n");
		return (DDI_FAILURE);
	}

	result = e1000g_alloc_rx_packets(rx_ring);
	if (result != DDI_SUCCESS) {
		e1000g_free_tx_packets(tx_ring);
		if (e1000g_dma_type == USE_DVMA) {
			rw_exit(&e1000g_dma_type_lock);

			rw_enter(&e1000g_dma_type_lock, RW_WRITER);
			e1000g_dma_type = USE_DMA;
			rw_exit(&e1000g_dma_type_lock);

			e1000g_DEBUGLOG_0(Adapter, e1000g_CALLTRACE_LEVEL,
			    "No enough dvma resource for Rx packets, "
			    "trying to allocate dma buffers...\n");
			goto again;
		}
		rw_exit(&e1000g_dma_type_lock);

		e1000g_DEBUGLOG_0(Adapter, e1000g_INFO_LEVEL,
		    "Failed to allocate dma buffers for Rx packets\n");
		return (DDI_FAILURE);
	}

	rw_exit(&e1000g_dma_type_lock);

	return (DDI_SUCCESS);
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
		e1000g_DEBUGLOG_1(Adapter, e1000g_CALLTRACE_LEVEL,
		    "Could not allocate dvma buffer handle: %d\n", mystat);
		return (DDI_FAILURE);
	}

	buf->address = kmem_alloc(size, KM_NOSLEEP);

	if (buf->address == NULL) {
		if (buf->dma_handle != NULL) {
			dvma_release(buf->dma_handle);
			buf->dma_handle = NULL;
		}
		e1000g_DEBUGLOG_0(Adapter, e1000g_CALLTRACE_LEVEL,
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
    dma_buffer_t *buf, size_t size)
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
	    &buf_dma_attr,
	    DDI_DMA_DONTWAIT, 0,
	    &buf->dma_handle);

	if (mystat != DDI_SUCCESS) {
		buf->dma_handle = NULL;
		e1000g_DEBUGLOG_1(Adapter, e1000g_CALLTRACE_LEVEL,
		    "Could not allocate dma buffer handle: %d\n", mystat);
		return (DDI_FAILURE);
	}

	mystat = ddi_dma_mem_alloc(buf->dma_handle,
	    size, &accattr2, DDI_DMA_STREAMING,
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
		e1000g_DEBUGLOG_1(Adapter, e1000g_CALLTRACE_LEVEL,
		    "Could not allocate dma buffer memory: %d\n", mystat);
		return (DDI_FAILURE);
	}

	mystat = ddi_dma_addr_bind_handle(buf->dma_handle,
	    (struct as *)NULL,
	    buf->address,
	    len, DDI_DMA_READ | DDI_DMA_STREAMING,
	    DDI_DMA_SLEEP, 0, &cookie, &count);

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
		e1000g_DEBUGLOG_1(Adapter, e1000g_CALLTRACE_LEVEL,
		    "Could not bind buffer dma handle: %d\n", mystat);
		return (DDI_FAILURE);
	}

	ASSERT(count == 1);
	if (count != 1) {
		if (buf->dma_handle != NULL) {
			ddi_dma_unbind_handle(buf->dma_handle);
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
		e1000g_DEBUGLOG_1(Adapter, e1000g_CALLTRACE_LEVEL,
		    "Could not bind buffer as a single frag. "
		    "Count = %d\n", count);
		return (DDI_FAILURE);
	}

	buf->dma_address = cookie.dmac_laddress;
	buf->size = len;
	buf->len = 0;

	return (DDI_SUCCESS);
}

static void
e1000g_free_dma_buffer(dma_buffer_t *buf)
{
	if (buf->dma_handle != NULL) {
		ddi_dma_unbind_handle(buf->dma_handle);
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
	PTX_SW_PACKET packet;
	int mystat;
	dma_buffer_t *tx_buf;
	struct e1000g *Adapter = tx_ring->adapter;
	dev_info_t *devinfo = Adapter->dip;

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
	    j < Adapter->NumTxSwPacket; j++, packet++) {

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
			    &tx_dma_attr,
			    DDI_DMA_DONTWAIT, 0,
			    &packet->tx_dma_handle);
			break;
		default:
			ASSERT(B_FALSE);
			break;
		}
		if (mystat != DDI_SUCCESS) {
			packet->tx_dma_handle = NULL;
			e1000g_DEBUGLOG_1(Adapter, e1000g_CALLTRACE_LEVEL,
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
			    tx_buf, Adapter->TxBufferSize);
			break;
#endif
		case USE_DMA:
			mystat = e1000g_alloc_dma_buffer(Adapter,
			    tx_buf, Adapter->TxBufferSize);
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
			e1000g_DEBUGLOG_0(Adapter, e1000g_CALLTRACE_LEVEL,
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

static int
e1000g_alloc_rx_packets(e1000g_rx_ring_t *rx_ring)
{
	int i;
	PRX_SW_PACKET packet;
	struct e1000g *Adapter;
	uint32_t packet_num;

	Adapter = rx_ring->adapter;

	/*
	 * Allocate memory for the RX_SW_PACKET structures. Each one of these
	 * structures will contain a virtual and physical address to an actual
	 * receive buffer in host memory. Since we use one RX_SW_PACKET per
	 * received packet, the maximum number of RX_SW_PACKETs that we'll
	 * need is equal to the number of receive descriptors that we've
	 * allocated.
	 *
	 * Pre allocation for recv packet buffer. The Recv intr constructs
	 * a new mp using this buffer
	 *
	 * On Wiseman these Receive buffers must be aligned with 256 byte
	 * boundary
	 * Vinay, Apr19,2000
	 */
	packet_num = Adapter->NumRxDescriptors + Adapter->NumRxFreeList;
	rx_ring->packet_area = NULL;

	for (i = 0; i < packet_num; i++) {
		packet = e1000g_alloc_rx_sw_packet(rx_ring);
		if (packet == NULL)
			goto rx_pkt_fail;

		packet->next = rx_ring->packet_area;
		rx_ring->packet_area = packet;
	}

	return (DDI_SUCCESS);

rx_pkt_fail:
	e1000g_free_rx_packets(rx_ring);

	return (DDI_FAILURE);
}

static PRX_SW_PACKET
e1000g_alloc_rx_sw_packet(e1000g_rx_ring_t *rx_ring)
{
	int mystat;
	PRX_SW_PACKET packet;
	dma_buffer_t *rx_buf;
	struct e1000g *Adapter;

	Adapter = rx_ring->adapter;

	packet = kmem_zalloc(sizeof (RX_SW_PACKET), KM_NOSLEEP);
	if (packet == NULL) {
		e1000g_DEBUGLOG_0(Adapter, e1000g_CALLTRACE_LEVEL,
		    "Cound not allocate memory for Rx SwPacket\n");
		return (NULL);
	}

	rx_buf = packet->rx_buf;

	/*
	 * Make sure that receive buffers are 256 byte aligned
	 */
	buf_dma_attr.dma_attr_align = Adapter->RcvBufferAlignment;

	switch (e1000g_dma_type) {
#ifdef __sparc
	case USE_DVMA:
		mystat = e1000g_alloc_dvma_buffer(Adapter,
		    rx_buf, Adapter->RxBufferSize);
		break;
#endif
	case USE_DMA:
		mystat = e1000g_alloc_dma_buffer(Adapter,
		    rx_buf, Adapter->RxBufferSize);
		break;
	default:
		ASSERT(B_FALSE);
		break;
	}

	if (mystat != DDI_SUCCESS) {
		if (packet != NULL)
			kmem_free(packet, sizeof (RX_SW_PACKET));

		e1000g_DEBUGLOG_0(Adapter, e1000g_CALLTRACE_LEVEL,
		    "Failed to allocate Rx buffer\n");
		return (NULL);
	}

	rx_buf->size -= E1000G_IPALIGNROOM;
	rx_buf->address += E1000G_IPALIGNROOM;
	rx_buf->dma_address += E1000G_IPALIGNROOM;

	packet->rx_ring = (caddr_t)rx_ring;
	packet->free_rtn.free_func = e1000g_rxfree_func;
	packet->free_rtn.free_arg = (char *)packet;
	/*
	 * esballoc is changed to desballoc which
	 * is undocumented call but as per sun,
	 * we can use it. It gives better efficiency.
	 */
	packet->mp = desballoc((unsigned char *)
	    rx_buf->address - E1000G_IPALIGNROOM,
	    rx_buf->size + E1000G_IPALIGNROOM,
	    BPRI_MED, &packet->free_rtn);

	if (packet->mp != NULL) {
		packet->mp->b_rptr += E1000G_IPALIGNROOM;
		packet->mp->b_wptr += E1000G_IPALIGNROOM;
	}

	packet->dma_type = e1000g_dma_type;

	return (packet);
}

void
e1000g_free_rx_sw_packet(PRX_SW_PACKET packet)
{
	dma_buffer_t *rx_buf;

	if (packet->mp != NULL) {
		freemsg(packet->mp);
		packet->mp = NULL;
	}

	rx_buf = packet->rx_buf;
	ASSERT(rx_buf->dma_handle != NULL);

	rx_buf->size += E1000G_IPALIGNROOM;
	rx_buf->address -= E1000G_IPALIGNROOM;

	switch (packet->dma_type) {
#ifdef __sparc
	case USE_DVMA:
		e1000g_free_dvma_buffer(rx_buf);
		break;
#endif
	case USE_DMA:
		e1000g_free_dma_buffer(rx_buf);
		break;
	default:
		ASSERT(B_FALSE);
		break;
	}

	packet->dma_type = USE_NONE;

	kmem_free(packet, sizeof (RX_SW_PACKET));
}

static void
e1000g_free_rx_packets(e1000g_rx_ring_t *rx_ring)
{
	PRX_SW_PACKET packet, next_packet, free_list;

	rw_enter(&e1000g_rx_detach_lock, RW_WRITER);

	free_list = NULL;
	packet = rx_ring->packet_area;
	for (; packet != NULL; packet = next_packet) {
		next_packet = packet->next;

		if (packet->flag & E1000G_RX_SW_SENDUP) {
			e1000g_mblks_pending++;
			packet->flag |= E1000G_RX_SW_DETACHED;
			packet->next = NULL;
		} else {
			packet->next = free_list;
			free_list = packet;
		}
	}
	rx_ring->packet_area = NULL;

	rw_exit(&e1000g_rx_detach_lock);

	packet = free_list;
	for (; packet != NULL; packet = next_packet) {
		next_packet = packet->next;

		ASSERT(packet->flag == E1000G_RX_SW_FREE);
		e1000g_free_rx_sw_packet(packet);
	}
}

static void
e1000g_free_tx_packets(e1000g_tx_ring_t *tx_ring)
{
	int j;
	struct e1000g *Adapter;
	PTX_SW_PACKET packet;
	dma_buffer_t *tx_buf;

	Adapter = tx_ring->adapter;

	for (j = 0, packet = tx_ring->packet_area;
	    j < Adapter->NumTxSwPacket; j++, packet++) {

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
 * **********************************************************************
 * Name:      e1000g_release_dma_resources				*
 *									*
 * Description:								*
 *     This function release any pending buffers. that has been		*
 *     previously allocated						*
 *									*
 * Parameter Passed:							*
 *									*
 * Return Value:							*
 *									*
 * Functions called:							*
 *									*
 *									*
 * **********************************************************************
 */
void
e1000g_release_dma_resources(register struct e1000g *Adapter)
{
	e1000g_tx_ring_t *tx_ring;
	e1000g_rx_ring_t *rx_ring;

	tx_ring = Adapter->tx_ring;
	rx_ring = Adapter->rx_ring;

	/*
	 * Release all the handles, memory and DMA resources that are
	 * allocated for the transmit buffer descriptors.
	 */
	e1000g_free_tx_descriptors(tx_ring);

	/*
	 * Release all the handles, memory and DMA resources that are
	 * allocated for the receive buffer descriptors.
	 */
	e1000g_free_rx_descriptors(rx_ring);

	/*
	 * Free Tx packet resources
	 */
	e1000g_free_tx_packets(tx_ring);

	/*
	 * TX resources done, now free RX resources
	 */
	e1000g_free_rx_packets(rx_ring);
}
