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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*
 * EHCI Host Controller Driver (EHCI)
 *
 * The EHCI driver is a software driver which interfaces to the Universal
 * Serial Bus layer (USBA) and the Host Controller (HC). The interface to
 * the Host Controller is defined by the EHCI Host Controller Interface.
 *
 * This module contains the EHCI driver isochronous code, which handles all
 * Checking of status of USB transfers, error recovery and callbacks.
 */
#include <sys/usb/hcd/ehci/ehcid.h>
#include <sys/usb/hcd/ehci/ehci_xfer.h>
#include <sys/usb/hcd/ehci/ehci_util.h>

/* Adjustable variables for the size of isoc pools */
int ehci_itd_pool_size = EHCI_ITD_POOL_SIZE;

/*
 * pool functions
 */
int ehci_allocate_isoc_pools(
	ehci_state_t		*ehcip);
int ehci_get_itd_pool_size();

/*
 * Isochronous Transfer Wrapper Functions
 */
ehci_isoc_xwrapper_t *ehci_allocate_itw_resources(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	size_t			itw_length,
	usb_flags_t		usb_flags,
	size_t			pkt_count);
static ehci_isoc_xwrapper_t *ehci_allocate_itw(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	size_t			length,
	usb_flags_t		usb_flags);
void ehci_deallocate_itw(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_isoc_xwrapper_t	*itw);
static void ehci_free_itw_dma(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_isoc_xwrapper_t	*itw);

/*
 * transfer descriptor functions
 */
static ehci_itd_t *ehci_allocate_itd(
	ehci_state_t		*ehcip);
void ehci_deallocate_itd(
	ehci_state_t		*ehcip,
	ehci_isoc_xwrapper_t	*itw,
	ehci_itd_t		*old_itd);
uint_t ehci_calc_num_itds(
	ehci_isoc_xwrapper_t	*itw,
	size_t			pkt_count);
int ehci_allocate_itds_for_itw(
	ehci_state_t		*ehcip,
	ehci_isoc_xwrapper_t	*itw,
	uint_t			itd_count);
static void ehci_deallocate_itds_for_itw(
	ehci_state_t		*ehcip,
	ehci_isoc_xwrapper_t	*itw);
void ehci_insert_itd_on_itw(
	ehci_state_t		*ehcip,
	ehci_isoc_xwrapper_t	*itw,
	ehci_itd_t		*itd);
void ehci_insert_itd_into_active_list(
	ehci_state_t		*ehcip,
	ehci_itd_t		*itd);
void ehci_remove_itd_from_active_list(
	ehci_state_t		*ehcip,
	ehci_itd_t		*itd);
ehci_itd_t *ehci_create_done_itd_list(
	ehci_state_t		*ehcip);
int ehci_insert_isoc_to_pfl(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_isoc_xwrapper_t	*itw);
void ehci_remove_isoc_from_pfl(
	ehci_state_t		*ehcip,
	ehci_itd_t		*curr_itd);


/*
 * Isochronous in resource functions
 */
int ehci_allocate_isoc_in_resource(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_isoc_xwrapper_t	*tw,
	usb_flags_t		flags);
void ehci_deallocate_isoc_in_resource(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_isoc_xwrapper_t	*itw);

/*
 * memory addr functions
 */
uint32_t ehci_itd_cpu_to_iommu(
	ehci_state_t		*ehcip,
	ehci_itd_t		*addr);
ehci_itd_t *ehci_itd_iommu_to_cpu(
	ehci_state_t		*ehcip,
	uintptr_t		addr);

/*
 * Error parsing functions
 */
void ehci_parse_isoc_error(
	ehci_state_t		*ehcip,
	ehci_isoc_xwrapper_t	*itw,
	ehci_itd_t		*itd);
static usb_cr_t ehci_parse_itd_error(
	ehci_state_t		*ehcip,
	ehci_isoc_xwrapper_t	*itw,
	ehci_itd_t		*itd);
static usb_cr_t ehci_parse_sitd_error(
	ehci_state_t		*ehcip,
	ehci_isoc_xwrapper_t	*itw,
	ehci_itd_t		*itd);

/*
 * print functions
 */
void ehci_print_itd(
	ehci_state_t		*ehcip,
	ehci_itd_t		*itd);
void ehci_print_sitd(
	ehci_state_t		*ehcip,
	ehci_itd_t		*itd);


/*
 * ehci_allocate_isoc_pools:
 *
 * Allocate the system memory for itd which are for low/full/high speed
 * Transfer Descriptors. Must be aligned to a 32 byte boundary.
 */
int
ehci_allocate_isoc_pools(ehci_state_t	*ehcip)
{
	ddi_device_acc_attr_t		dev_attr;
	size_t				real_length;
	int				result;
	uint_t				ccount;
	int				i;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
	    "ehci_allocate_isoc_pools:");

	/* Byte alignment */
	ehcip->ehci_dma_attr.dma_attr_align = EHCI_DMA_ATTR_TD_QH_ALIGNMENT;

	/* Allocate the itd pool DMA handle */
	result = ddi_dma_alloc_handle(ehcip->ehci_dip,
	    &ehcip->ehci_dma_attr,
	    DDI_DMA_SLEEP,
	    0,
	    &ehcip->ehci_itd_pool_dma_handle);

	if (result != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
		    "ehci_allocate_isoc_pools: Alloc handle failed");

		return (DDI_FAILURE);
	}

	/* The host controller will be little endian */
	dev_attr.devacc_attr_version		= DDI_DEVICE_ATTR_V0;
	dev_attr.devacc_attr_endian_flags	= DDI_STRUCTURE_LE_ACC;
	dev_attr.devacc_attr_dataorder		= DDI_STRICTORDER_ACC;

	/* Allocate the memory */
	result = ddi_dma_mem_alloc(ehcip->ehci_itd_pool_dma_handle,
	    ehci_itd_pool_size * sizeof (ehci_itd_t),
	    &dev_attr,
	    DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP,
	    0,
	    (caddr_t *)&ehcip->ehci_itd_pool_addr,
	    &real_length,
	    &ehcip->ehci_itd_pool_mem_handle);

	if (result != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
		    "ehci_allocate_isoc_pools: Alloc memory failed");

		return (DDI_FAILURE);
	}

	/* Map the ITD pool into the I/O address space */
	result = ddi_dma_addr_bind_handle(
	    ehcip->ehci_itd_pool_dma_handle,
	    NULL,
	    (caddr_t)ehcip->ehci_itd_pool_addr,
	    real_length,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP,
	    NULL,
	    &ehcip->ehci_itd_pool_cookie,
	    &ccount);

	bzero((void *)ehcip->ehci_itd_pool_addr,
	    ehci_itd_pool_size * sizeof (ehci_itd_t));

	/* Process the result */
	if (result == DDI_DMA_MAPPED) {
		/* The cookie count should be 1 */
		if (ccount != 1) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
			    "ehci_allocate_isoc_pools: More than 1 cookie");

			return (DDI_FAILURE);
		}
	} else {
		USB_DPRINTF_L4(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
		    "ehci_allocate_isoc_pools: Result = %d", result);

		ehci_decode_ddi_dma_addr_bind_handle_result(ehcip, result);

		return (DDI_FAILURE);
	}

	/*
	 * DMA addresses for ITD pools are bound
	 */
	ehcip->ehci_dma_addr_bind_flag |= EHCI_ITD_POOL_BOUND;

	/* Initialize the ITD pool */
	for (i = 0; i < ehci_itd_pool_size; i++) {
		Set_ITD(ehcip->ehci_itd_pool_addr[i].itd_state,
		    EHCI_ITD_FREE);
	}

	return (DDI_SUCCESS);
}


int
ehci_get_itd_pool_size()
{
	return (ehci_itd_pool_size);
}


/*
 * Isochronous Transfer Wrapper Functions
 */
/*
 * ehci_allocate_itw_resources:
 *
 * Allocate an iTW and n iTD from the iTD buffer pool and places it into the
 * ITW.  It does an all or nothing transaction.
 *
 * Calculates the number of iTD needed based on pipe speed.
 * For LOW/FULL speed devices, 1 iTD is needed for each packet.
 * For HIGH speed device, 1 iTD is needed for 8 to 24 packets, depending on
 *     the multiplier for "HIGH BANDWIDTH" transfers look at 4.7 in EHCI spec.
 *
 * Returns NULL if there is insufficient resources otherwise ITW.
 */
ehci_isoc_xwrapper_t *
ehci_allocate_itw_resources(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	size_t			itw_length,
	usb_flags_t		usb_flags,
	size_t			pkt_count)
{
	uint_t			itd_count;
	ehci_isoc_xwrapper_t	*itw;

	itw = ehci_allocate_itw(ehcip, pp, itw_length, usb_flags);

	if (itw == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
		    "ehci_allocate_itw_resources: Unable to allocate ITW");
	} else {
		itd_count = ehci_calc_num_itds(itw, pkt_count);
		USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
		    "ehci_allocate_itw_resources: itd_count = 0x%d", itd_count);

		if (ehci_allocate_itds_for_itw(ehcip, itw, itd_count) ==
		    USB_SUCCESS) {
			itw->itw_num_itds = itd_count;
		} else {
			ehci_deallocate_itw(ehcip, pp, itw);
			itw = NULL;
		}
	}

	return (itw);
}


/*
 * ehci_allocate_itw:
 *
 * Creates a Isochronous Transfer Wrapper (itw) and populate it with this
 * endpoint's data.  This involves the allocation of DMA resources.
 *
 * ITW Fields not set by this function:
 * - will be populated itds are allocated
 *   num_ids
 *   itd_head
 *   itd_tail
 *   curr_xfer_reqp
 *   curr_isoc_pktp
 *   itw_itd_free_list
 * - Should be set by the calling function
 *   itw_handle_callback_value
 */
static ehci_isoc_xwrapper_t *
ehci_allocate_itw(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	size_t			length,
	usb_flags_t		usb_flags)
{
	ddi_device_acc_attr_t	dev_attr;
	int			result;
	size_t			real_length;
	uint_t			ccount;	/* Cookie count */
	usba_pipe_handle_data_t *ph = pp->pp_pipe_handle;
	usba_device_t		*usba_device = ph->p_usba_device;
	usb_ep_descr_t		*endpoint = &ph->p_ep;
	ehci_isoc_xwrapper_t	*itw;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_allocate_itw: length = 0x%lx flags = 0x%x",
	    length, usb_flags);

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/* Allocate space for the transfer wrapper */
	itw = kmem_zalloc(sizeof (ehci_isoc_xwrapper_t), KM_NOSLEEP);

	if (itw == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
		    "ehci_allocate_itw: kmem_zalloc failed");

		return (NULL);
	}

	ehcip->ehci_dma_attr.dma_attr_align = EHCI_DMA_ATTR_ALIGNMENT;

	/* Allocate the DMA handle */
	result = ddi_dma_alloc_handle(ehcip->ehci_dip,
	    &ehcip->ehci_dma_attr,
	    DDI_DMA_DONTWAIT,
	    0,
	    &itw->itw_dmahandle);

	if (result != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
		    "ehci_create_transfer_wrapper: Alloc handle failed");

		kmem_free(itw, sizeof (ehci_isoc_xwrapper_t));

		return (NULL);
	}

	/* no need for swapping the raw data in the buffers */
	dev_attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	dev_attr.devacc_attr_endian_flags  = DDI_NEVERSWAP_ACC;
	dev_attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	/* Allocate the memory */
	result = ddi_dma_mem_alloc(itw->itw_dmahandle,
	    length,
	    &dev_attr,
	    DDI_DMA_CONSISTENT,
	    DDI_DMA_DONTWAIT,
	    NULL,
	    (caddr_t *)&itw->itw_buf,
	    &real_length,
	    &itw->itw_accesshandle);

	if (result != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
		    "ehci_create_transfer_wrapper: dma_mem_alloc fail");

		ddi_dma_free_handle(&itw->itw_dmahandle);
		kmem_free(itw, sizeof (ehci_isoc_xwrapper_t));

		return (NULL);
	}

	ASSERT(real_length >= length);

	/* Bind the handle */
	result = ddi_dma_addr_bind_handle(itw->itw_dmahandle,
	    NULL,
	    (caddr_t)itw->itw_buf,
	    real_length,
	    DDI_DMA_RDWR|DDI_DMA_CONSISTENT,
	    DDI_DMA_DONTWAIT,
	    NULL,
	    &itw->itw_cookie,
	    &ccount);

	if (result == DDI_DMA_MAPPED) {
		/* The cookie count should be 1 */
		if (ccount != 1) {
			USB_DPRINTF_L2(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
			    "ehci_create_transfer_wrapper: More than 1 cookie");

			result = ddi_dma_unbind_handle(itw->itw_dmahandle);
			ASSERT(result == DDI_SUCCESS);

			ddi_dma_mem_free(&itw->itw_accesshandle);
			ddi_dma_free_handle(&itw->itw_dmahandle);
			kmem_free(itw, sizeof (ehci_isoc_xwrapper_t));

			return (NULL);
		}
	} else {
		ehci_decode_ddi_dma_addr_bind_handle_result(ehcip, result);

		ddi_dma_mem_free(&itw->itw_accesshandle);
		ddi_dma_free_handle(&itw->itw_dmahandle);
		kmem_free(itw, sizeof (ehci_isoc_xwrapper_t));

		return (NULL);
	}

	/* Store a back pointer to the pipe private structure */
	itw->itw_pipe_private = pp;
	if (pp->pp_itw_head == NULL) {
		pp->pp_itw_head = itw;
		pp->pp_itw_tail = itw;
	} else {
		pp->pp_itw_tail->itw_next = itw;
		pp->pp_itw_tail = itw;
	}

	/*
	 * Store transfer information
	 * itw_buf has been allocated and will be set later
	 */
	itw->itw_length = length;
	itw->itw_flags = usb_flags;
	itw->itw_port_status = usba_device->usb_port_status;
	itw->itw_direction = endpoint->bEndpointAddress & USB_EP_DIR_MASK;

	/*
	 * Store the endpoint information that will be used by the
	 * transfer descriptors later.
	 */
	mutex_enter(&usba_device->usb_mutex);
	itw->itw_hub_addr = usba_device->usb_hs_hub_addr;
	itw->itw_hub_port = usba_device->usb_hs_hub_port;
	itw->itw_endpoint_num = endpoint->bEndpointAddress & USB_EP_NUM_MASK;
	itw->itw_device_addr = usba_device->usb_addr;
	mutex_exit(&usba_device->usb_mutex);

	/* Get and Store 32bit ID */
	itw->itw_id = EHCI_GET_ID((void *)itw);
	ASSERT(itw->itw_id != NULL);

	USB_DPRINTF_L3(PRINT_MASK_ALLOC, ehcip->ehci_log_hdl,
	    "ehci_create_itw: itw = 0x%p real_length = 0x%lx",
	    (void *)itw, real_length);

	ehcip->ehci_periodic_req_count++;
	ehci_toggle_scheduler(ehcip);

	return (itw);
}


/*
 * ehci_deallocate_itw:
 *
 * Deallocate of a Isochronous Transaction Wrapper (TW) and this involves the
 * freeing of DMA resources.
 */
void
ehci_deallocate_itw(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_isoc_xwrapper_t	*itw)
{
	ehci_isoc_xwrapper_t	*prev, *next;

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ehcip->ehci_log_hdl,
	    "ehci_deallocate_itw: itw = 0x%p", (void *)itw);

	/*
	 * If the transfer wrapper has no Host Controller (HC)
	 * Transfer Descriptors (ITD) associated with it,  then
	 * remove the transfer wrapper.
	 */
	if (itw->itw_itd_head) {
		ASSERT(itw->itw_itd_tail != NULL);

		return;
	}

	ASSERT(itw->itw_itd_tail == NULL);

	/* Make sure we return all the unused itd's to the pool as well */
	ehci_deallocate_itds_for_itw(ehcip, itw);

	/*
	 * If pp->pp_tw_head and pp->pp_tw_tail are pointing to
	 * given TW then set the head and  tail  equal to NULL.
	 * Otherwise search for this TW in the linked TW's list
	 * and then remove this TW from the list.
	 */
	if (pp->pp_itw_head == itw) {
		if (pp->pp_itw_tail == itw) {
			pp->pp_itw_head = NULL;
			pp->pp_itw_tail = NULL;
		} else {
			pp->pp_itw_head = itw->itw_next;
		}
	} else {
		prev = pp->pp_itw_head;
		next = prev->itw_next;

		while (next && (next != itw)) {
			prev = next;
			next = next->itw_next;
		}

		if (next == itw) {
			prev->itw_next = next->itw_next;

			if (pp->pp_itw_tail == itw) {
				pp->pp_itw_tail = prev;
			}
		}
	}

	/* Free this iTWs dma resources */
	ehci_free_itw_dma(ehcip, pp, itw);

	ehcip->ehci_periodic_req_count--;
	ehci_toggle_scheduler(ehcip);
}


/*
 * ehci_free_itw_dma:
 *
 * Free the Isochronous Transfer Wrapper dma resources.
 */
/*ARGSUSED*/
static void
ehci_free_itw_dma(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_isoc_xwrapper_t	*itw)
{
	int	rval;

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ehcip->ehci_log_hdl,
	    "ehci_free_itw_dma: itw = 0x%p", (void *)itw);

	ASSERT(itw != NULL);
	ASSERT(itw->itw_id != NULL);

	/* Free 32bit ID */
	EHCI_FREE_ID((uint32_t)itw->itw_id);

	rval = ddi_dma_unbind_handle(itw->itw_dmahandle);
	ASSERT(rval == DDI_SUCCESS);

	ddi_dma_mem_free(&itw->itw_accesshandle);
	ddi_dma_free_handle(&itw->itw_dmahandle);

	/* Free transfer wrapper */
	kmem_free(itw, sizeof (ehci_isoc_xwrapper_t));
}


/*
 * transfer descriptor functions
 */
/*
 * ehci_allocate_itd:
 *
 * Allocate a Transfer Descriptor (iTD) from the iTD buffer pool.
 */
static ehci_itd_t *
ehci_allocate_itd(ehci_state_t	*ehcip)
{
	int		i, state;
	ehci_itd_t	*itd;

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/*
	 * Search for a blank Transfer Descriptor (iTD)
	 * in the iTD buffer pool.
	 */
	for (i = 0; i < ehci_itd_pool_size; i ++) {
		state = Get_ITD(ehcip->ehci_itd_pool_addr[i].itd_state);
		if (state == EHCI_ITD_FREE) {
			break;
		}
	}

	if (i >= ehci_itd_pool_size) {
		USB_DPRINTF_L2(PRINT_MASK_ALLOC, ehcip->ehci_log_hdl,
		    "ehci_allocate_itd: ITD exhausted");

		return (NULL);
	}

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ehcip->ehci_log_hdl,
	    "ehci_allocate_itd: Allocated %d", i);

	/* Create a new dummy for the end of the ITD list */
	itd = &ehcip->ehci_itd_pool_addr[i];

	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_allocate_itd: itd 0x%p", (void *)itd);

	/* Mark the newly allocated ITD as a empty */
	Set_ITD(itd->itd_state, EHCI_ITD_DUMMY);

	return (itd);
}


/*
 * ehci_deallocate_itd:
 *
 * Deallocate a Host Controller's (HC) Transfer Descriptor (ITD).
 *
 */
void
ehci_deallocate_itd(
	ehci_state_t		*ehcip,
	ehci_isoc_xwrapper_t	*itw,
	ehci_itd_t		*old_itd)
{
	ehci_itd_t	*itd, *next_itd;

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ehcip->ehci_log_hdl,
	    "ehci_deallocate_itd: old_itd = 0x%p", (void *)old_itd);

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/* If it has been marked RECLAIM it has already been removed */
	if (Get_ITD(old_itd->itd_state) != EHCI_ITD_RECLAIM) {
		ehci_remove_isoc_from_pfl(ehcip, old_itd);
	}

	/* Make sure the ITD is not in the PFL */
	ASSERT(Get_ITD_FRAME(old_itd->itd_frame_number) == 0);

	/* Remove the itd from the itw */
	itd = itw->itw_itd_head;
	if (old_itd != itd) {
		next_itd = ehci_itd_iommu_to_cpu(ehcip,
		    Get_ITD(itd->itd_itw_next_itd));

		while (next_itd != old_itd) {
			itd = next_itd;
			next_itd = ehci_itd_iommu_to_cpu(ehcip,
			    Get_ITD(itd->itd_itw_next_itd));
		}

		Set_ITD(itd->itd_itw_next_itd, old_itd->itd_itw_next_itd);

		if (itd->itd_itw_next_itd == NULL) {
			itw->itw_itd_tail = itd;
		}
	} else {
		itw->itw_itd_head = ehci_itd_iommu_to_cpu(
		    ehcip, Get_ITD(old_itd->itd_itw_next_itd));

		if (itw->itw_itd_head == NULL) {
			itw->itw_itd_tail = NULL;
		}
	}

	bzero((char *)old_itd, sizeof (ehci_itd_t));
	Set_ITD(old_itd->itd_state, EHCI_ITD_FREE);

	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "Dealloc_itd: itd 0x%p", (void *)old_itd);
}


/*
 * ehci_calc_num_itds:
 *
 * Calculates how many ITDs are needed for this request.
 * The calculation is based on weather it is an HIGH speed
 * transaction of a FULL/LOW transaction.
 *
 * For FULL/LOW transaction more itds are necessary if it
 * spans frames.
 */
uint_t
ehci_calc_num_itds(
	ehci_isoc_xwrapper_t	*itw,
	size_t			pkt_count)
{
	uint_t			multiplier, itd_count;

	/* Allocate the appropriate isoc resources */
	if (itw->itw_port_status == USBA_HIGH_SPEED_DEV) {
		/* Multiplier needs to be passed in somehow */
		multiplier = 1 * 8;
		itd_count = pkt_count / multiplier;
		if (pkt_count % multiplier) {
			itd_count++;
		}
	} else {
		itd_count = (uint_t)pkt_count;
	}

	return (itd_count);
}

/*
 * ehci_allocate_itds_for_itw:
 *
 * Allocate n Transfer Descriptors (TD) from the TD buffer pool and places it
 * into the TW.
 *
 * Returns USB_NO_RESOURCES if it was not able to allocate all the requested TD
 * otherwise USB_SUCCESS.
 */
int
ehci_allocate_itds_for_itw(
	ehci_state_t		*ehcip,
	ehci_isoc_xwrapper_t	*itw,
	uint_t			itd_count)
{
	ehci_itd_t		*itd;
	uint32_t		itd_addr;
	int			i;
	int			error = USB_SUCCESS;

	for (i = 0; i < itd_count; i += 1) {
		itd = ehci_allocate_itd(ehcip);
		if (itd == NULL) {
			error = USB_NO_RESOURCES;
			USB_DPRINTF_L2(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
			    "ehci_allocate_itds_for_itw: "
			    "Unable to allocate %d ITDs",
			    itd_count);
			break;
		}
		if (i > 0) {
			itd_addr = ehci_itd_cpu_to_iommu(ehcip,
			    itw->itw_itd_free_list);
			Set_ITD(itd->itd_link_ptr, itd_addr);
		}
		Set_ITD_INDEX(itd, 0, EHCI_ITD_UNUSED_INDEX);
		Set_ITD_INDEX(itd, 1, EHCI_ITD_UNUSED_INDEX);
		Set_ITD_INDEX(itd, 2, EHCI_ITD_UNUSED_INDEX);
		Set_ITD_INDEX(itd, 3, EHCI_ITD_UNUSED_INDEX);
		Set_ITD_INDEX(itd, 4, EHCI_ITD_UNUSED_INDEX);
		Set_ITD_INDEX(itd, 5, EHCI_ITD_UNUSED_INDEX);
		Set_ITD_INDEX(itd, 6, EHCI_ITD_UNUSED_INDEX);
		Set_ITD_INDEX(itd, 7, EHCI_ITD_UNUSED_INDEX);
		itw->itw_itd_free_list = itd;
	}

	return (error);
}


/*
 * ehci_deallocate_itds_for_itw:
 *
 * Free all allocated resources for Transaction Wrapper (TW).
 * Does not free the iTW itself.
 */
static void
ehci_deallocate_itds_for_itw(
	ehci_state_t		*ehcip,
	ehci_isoc_xwrapper_t	*itw)
{
	ehci_itd_t		*itd = NULL;
	ehci_itd_t		*temp_itd = NULL;

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ehcip->ehci_log_hdl,
	    "ehci_free_itw_itd_resources: itw = 0x%p", (void *)itw);

	itd = itw->itw_itd_free_list;
	while (itd != NULL) {
		/* Save the pointer to the next itd before destroying it */
		temp_itd = ehci_itd_iommu_to_cpu(ehcip,
		    Get_ITD(itd->itd_link_ptr));
		ehci_deallocate_itd(ehcip, itw, itd);
		itd = temp_itd;
	}
	itw->itw_itd_free_list = NULL;
}


/*
 * ehci_insert_itd_on_itw:
 *
 * The transfer wrapper keeps a list of all Transfer Descriptors (iTD) that
 * are allocated for this transfer. Insert a iTD onto this list.
 */
void ehci_insert_itd_on_itw(
	ehci_state_t		*ehcip,
	ehci_isoc_xwrapper_t	*itw,
	ehci_itd_t		*itd)
{
	/*
	 * Set the next pointer to NULL because
	 * this is the last ITD on list.
	 */
	Set_ITD(itd->itd_itw_next_itd, NULL);

	if (itw->itw_itd_head == NULL) {
		ASSERT(itw->itw_itd_tail == NULL);
		itw->itw_itd_head = itd;
		itw->itw_itd_tail = itd;
	} else {
		ehci_itd_t *dummy = (ehci_itd_t *)itw->itw_itd_tail;

		ASSERT(dummy != NULL);
		ASSERT(Get_ITD(itd->itd_state) == EHCI_ITD_ACTIVE);

		/* Add the itd to the end of the list */
		Set_ITD(dummy->itd_itw_next_itd,
		    ehci_itd_cpu_to_iommu(ehcip, itd));

		itw->itw_itd_tail = itd;
	}

	Set_ITD(itd->itd_trans_wrapper, (uint32_t)itw->itw_id);
}


/*
 * ehci_insert_itd_into_active_list:
 *
 * Add current ITD into the active ITD list in reverse order.
 * When the done list is created, remove it in the reverse order.
 */
void
ehci_insert_itd_into_active_list(
	ehci_state_t		*ehcip,
	ehci_itd_t		*itd)
{
	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));
	ASSERT(itd != NULL);

	Set_ITD(itd->itd_next_active_itd,
	    ehci_itd_cpu_to_iommu(ehcip, ehcip->ehci_active_itd_list));
	ehcip->ehci_active_itd_list = itd;
}


/*
 * ehci_remove_itd_from_active_list:
 *
 * Remove current ITD from the active ITD list.
 */
void
ehci_remove_itd_from_active_list(
	ehci_state_t		*ehcip,
	ehci_itd_t		*itd)
{
	ehci_itd_t		*curr_itd, *next_itd;

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));
	ASSERT(itd != NULL);

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_remove_itd_from_active_list: "
	    "ehci_active_itd_list = 0x%p itd = 0x%p",
	    (void *)ehcip->ehci_active_itd_list, (void *)itd);

	curr_itd = ehcip->ehci_active_itd_list;

	if (curr_itd == itd) {
		ehcip->ehci_active_itd_list =
		    ehci_itd_iommu_to_cpu(ehcip, itd->itd_next_active_itd);
		itd->itd_next_active_itd = NULL;

		return;
	}

	next_itd = ehci_itd_iommu_to_cpu(ehcip, curr_itd->itd_next_active_itd);
	while (next_itd != itd) {
		curr_itd = next_itd;
		if (curr_itd) {
			next_itd = ehci_itd_iommu_to_cpu(ehcip,
			    curr_itd->itd_next_active_itd);
		} else {
			break;
		}
	}

	if ((curr_itd) && (next_itd == itd)) {
		Set_ITD(curr_itd->itd_next_active_itd,
		    Get_ITD(itd->itd_next_active_itd));
		Set_ITD(itd->itd_next_active_itd, NULL);
	} else {
		USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
		    "ehci_remove_itd_from_active_list: "
		    "Unable to find ITD in active_itd_list");
	}
}


/*
 * ehci_create_done_itd_list:
 *
 * Traverse the active list and create a done list and remove them
 * from the active list.
 */
ehci_itd_t *
ehci_create_done_itd_list(
	ehci_state_t		*ehcip)
{
	usb_frame_number_t	current_frame_number;
	usb_frame_number_t	itd_frame_number, itd_reclaim_number;
	ehci_itd_t		*curr_itd = NULL, *next_itd = NULL;
	ehci_itd_t		*done_itd_list = NULL;
	uint_t			state;

	USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_create_done_itd_list:");

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/*
	 * Get the current frame number.
	 * Only process itd that were inserted before the current
	 * frame number.
	 */
	current_frame_number = ehci_get_current_frame_number(ehcip);

	curr_itd = ehcip->ehci_active_itd_list;

	while (curr_itd) {
		/* Get next itd from the active itd list */
		next_itd = ehci_itd_iommu_to_cpu(ehcip,
		    Get_ITD(curr_itd->itd_next_active_itd));

		/*
		 * If haven't past the frame number that the ITD was
		 * suppose to be executed, don't touch it.  Just in
		 * case it is being processed by the HCD and cause
		 * a race condition.
		 */
		itd_frame_number = Get_ITD_FRAME(curr_itd->itd_frame_number);
		itd_reclaim_number =
		    Get_ITD_FRAME(curr_itd->itd_reclaim_number);

		/* Get the ITD state */
		state = Get_ITD(curr_itd->itd_state);

		if (((state == EHCI_ITD_ACTIVE) &&
		    (itd_frame_number < current_frame_number)) ||
		    ((state == EHCI_ITD_RECLAIM) &&
		    (itd_reclaim_number < current_frame_number))) {

			/* Remove this ITD from active ITD list */
			ehci_remove_itd_from_active_list(ehcip, curr_itd);

			/*
			 * Create the done list in reverse order, since the
			 * active list was also created in reverse order.
			 */
			Set_ITD(curr_itd->itd_next_active_itd,
			    ehci_itd_cpu_to_iommu(ehcip, done_itd_list));
			done_itd_list = curr_itd;
		}

		curr_itd = next_itd;
	}

	return (done_itd_list);
}


/*
 * ehci_insert_isoc_to_pfl:
 *
 * Insert a ITD request into the Host Controller's isochronous list.
 * All the ITDs in the ITW will be added the PFL at once.  Either all
 * of them will make it or none of them will.
 */
int
ehci_insert_isoc_to_pfl(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_isoc_xwrapper_t	*itw)
{
	usb_isoc_req_t		*isoc_reqp = itw->itw_curr_xfer_reqp;
	usb_frame_number_t	current_frame_number, start_frame_number;
	uint_t			ddic, pfl_number;
	ehci_periodic_frame_list_t *periodic_frame_list =
	    ehcip->ehci_periodic_frame_list_tablep;
	uint32_t		addr, port_status;
	ehci_itd_t		*itd;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_insert_isoc_to_pfl: "
	    "isoc flags 0x%x itw = 0x%p",
	    isoc_reqp->isoc_attributes, (void *)itw);

	/*
	 * Enter critical, while programming the usb frame number
	 * and inserting current isochronous TD into the ED's list.
	 */
	ddic = ddi_enter_critical();

	/* Get the current frame number */
	current_frame_number = ehci_get_current_frame_number(ehcip);

	/*
	 * Check the given isochronous flags and get the frame number
	 * to insert the itd into.
	 */
	switch (isoc_reqp->isoc_attributes &
	    (USB_ATTRS_ISOC_START_FRAME | USB_ATTRS_ISOC_XFER_ASAP)) {
	case USB_ATTRS_ISOC_START_FRAME:

		/* Starting frame number is specified */
		if (pp->pp_flag & EHCI_ISOC_XFER_CONTINUE) {
			/* Get the starting usb frame number */
			start_frame_number = pp->pp_next_frame_number;
		} else {
			/* Check for the Starting usb frame number */
			if ((isoc_reqp->isoc_frame_no == 0) ||
			    ((isoc_reqp->isoc_frame_no +
			    isoc_reqp->isoc_pkts_count) <
			    current_frame_number)) {

				/* Exit the critical */
				ddi_exit_critical(ddic);

				USB_DPRINTF_L2(PRINT_MASK_LISTS,
				    ehcip->ehci_log_hdl,
				    "ehci_insert_isoc_to_pfl:"
				    "Invalid starting frame number");

				return (USB_INVALID_START_FRAME);
			}

			/* Get the starting usb frame number */
			start_frame_number = isoc_reqp->isoc_frame_no;

			pp->pp_next_frame_number = 0;
		}
		break;
	case USB_ATTRS_ISOC_XFER_ASAP:
		/* ehci has to specify starting frame number */
		if ((pp->pp_next_frame_number) &&
		    (pp->pp_next_frame_number > current_frame_number)) {
			/*
			 * Get the next usb frame number.
			 */
			start_frame_number = pp->pp_next_frame_number;
		} else {
			/*
			 * Add appropriate offset to the current usb
			 * frame number and use it as a starting frame
			 * number.
			 */
			start_frame_number =
			    current_frame_number + EHCI_FRAME_OFFSET;
		}

		if (!(pp->pp_flag & EHCI_ISOC_XFER_CONTINUE)) {
			isoc_reqp->isoc_frame_no = start_frame_number;
		}
		break;
	default:
		/* Exit the critical */
		ddi_exit_critical(ddic);

		USB_DPRINTF_L2(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
		    "ehci_insert_isoc_to_pfl: Either starting "
		    "frame number or ASAP flags are not set, attrs = 0x%x",
		    isoc_reqp->isoc_attributes);

		return (USB_NO_FRAME_NUMBER);
	}

	if (itw->itw_port_status == USBA_HIGH_SPEED_DEV) {
		port_status = EHCI_ITD_LINK_REF_ITD;
	} else {
		port_status = EHCI_ITD_LINK_REF_SITD;
	}

	itd = itw->itw_itd_head;
	while (itd) {
		/* Find the appropriate frame list to put the itd into */
		pfl_number = start_frame_number % EHCI_NUM_PERIODIC_FRAME_LISTS;

		addr = Get_PFLT(periodic_frame_list->
		    ehci_periodic_frame_list_table[pfl_number]);
		Set_ITD(itd->itd_link_ptr, addr);

		/* Set the link_ref correctly as ITD or SITD. */
		addr = ehci_itd_cpu_to_iommu(ehcip, itd) & EHCI_ITD_LINK_PTR;
		addr |= port_status;

		Set_PFLT(periodic_frame_list->
		    ehci_periodic_frame_list_table[pfl_number], addr);

		/* Save which frame the ITD was inserted into */
		Set_ITD_FRAME(itd->itd_frame_number, start_frame_number);

		ehci_insert_itd_into_active_list(ehcip, itd);

		/* Get the next ITD in the ITW */
		itd = ehci_itd_iommu_to_cpu(ehcip,
		    Get_ITD(itd->itd_itw_next_itd));

		start_frame_number++;
	}

	/* Exit the critical */
	ddi_exit_critical(ddic);

	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_insert_isoc_to_pfl: "
	    "current frame number 0x%llx start frame number 0x%llx num itds %d",
	    (unsigned long long)current_frame_number,
	    (unsigned long long)start_frame_number, itw->itw_num_itds);

	/*
	 * Increment this saved frame number by current number
	 * of data packets needs to be transfer.
	 */
	pp->pp_next_frame_number = start_frame_number;

	/*
	 * Set EHCI_ISOC_XFER_CONTINUE flag in order to send other
	 * isochronous packets,  part of the current isoch request
	 * in the subsequent frames.
	 */
	pp->pp_flag |= EHCI_ISOC_XFER_CONTINUE;

	return (USB_SUCCESS);
}


/*
 * ehci_remove_isoc_to_pfl:
 *
 * Remove an ITD request from the Host Controller's isochronous list.
 * If we can't find it, something has gone wrong.
 */
void
ehci_remove_isoc_from_pfl(
	ehci_state_t		*ehcip,
	ehci_itd_t		*curr_itd)
{
	ehci_periodic_frame_list_t *periodic_frame_list;
	uint_t		pfl_number;
	uint32_t	next_addr, curr_itd_addr;
	uint32_t	link_ref;
	ehci_itd_t	*prev_itd = NULL;

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ehcip->ehci_log_hdl,
	    "ehci_remove_isoc_from_pfl:");

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/* Get the address of the current itd */
	curr_itd_addr = ehci_itd_cpu_to_iommu(ehcip, curr_itd);

	/*
	 * Remove this ITD from the PFL
	 * But first we need to find it in the PFL
	 */
	periodic_frame_list = ehcip->ehci_periodic_frame_list_tablep;
	pfl_number = Get_ITD_FRAME(curr_itd->itd_frame_number) %
	    EHCI_NUM_PERIODIC_FRAME_LISTS;

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ehcip->ehci_log_hdl,
	    "ehci_remove_isoc_from_pfl: itd = 0x%p pfl number 0x%x",
	    (void *)curr_itd, pfl_number);

	next_addr = Get_PFLT(periodic_frame_list->
	    ehci_periodic_frame_list_table[pfl_number]);
	while ((next_addr & EHCI_ITD_LINK_PTR) !=
	    (curr_itd_addr & EHCI_ITD_LINK_PTR)) {

		link_ref = next_addr & EHCI_ITD_LINK_REF;

		if ((link_ref == EHCI_ITD_LINK_REF_ITD) ||
		    (link_ref == EHCI_ITD_LINK_REF_SITD)) {

			prev_itd = ehci_itd_iommu_to_cpu(ehcip,
			    (next_addr & EHCI_ITD_LINK_PTR));
			next_addr = Get_ITD(prev_itd->itd_link_ptr);
		} else {

			break;
		}
	}

	/*
	 * If the next itd is the current itd, that means we found it.
	 * Set the previous's ITD link ptr to the Curr_ITD's link ptr.
	 * But do not touch the Curr_ITD's link ptr.
	 */
	if ((next_addr & EHCI_ITD_LINK_PTR) ==
	    (curr_itd_addr & EHCI_ITD_LINK_PTR)) {

		next_addr = Get_ITD(curr_itd->itd_link_ptr);

		if (prev_itd == NULL) {
			/* This means PFL points to this ITD */
			Set_PFLT(periodic_frame_list->
			    ehci_periodic_frame_list_table[pfl_number],
			    next_addr);
		} else {
			/* Set the previous ITD's itd_link_ptr */
			Set_ITD(prev_itd->itd_link_ptr, next_addr);
		}

		Set_ITD_FRAME(curr_itd->itd_frame_number, 0);
	} else {
		ASSERT((next_addr & EHCI_ITD_LINK_PTR) ==
		    (curr_itd_addr & EHCI_ITD_LINK_PTR));
		USB_DPRINTF_L3(PRINT_MASK_ALLOC, ehcip->ehci_log_hdl,
		    "ehci_remove_isoc_from_pfl: Unable to find ITD in PFL");
	}
}


/*
 * Isochronous in resource functions
 */
/*
 * ehci_allocate_periodic_in_resource
 *
 * Allocate interrupt request structure for the interrupt IN transfer.
 */
int
ehci_allocate_isoc_in_resource(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_isoc_xwrapper_t	*itw,
	usb_flags_t		flags)
{
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;
	usb_isoc_req_t		*orig_isoc_reqp, *clone_isoc_reqp;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_allocate_isoc_in_resource:"
	    "pp = 0x%p itw = 0x%p flags = 0x%x", (void *)pp, (void *)itw,
	    flags);

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));
	ASSERT(itw->itw_curr_xfer_reqp == NULL);

	/* Get the client periodic in request pointer */
	orig_isoc_reqp = (usb_isoc_req_t *)(pp->pp_client_periodic_in_reqp);

	ASSERT(orig_isoc_reqp != NULL);

	clone_isoc_reqp = usba_hcdi_dup_isoc_req(ph->p_dip,
	    orig_isoc_reqp, flags);

	if (clone_isoc_reqp == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
		    "ehci_allocate_isoc_in_resource: Isochronous"
		    "request structure allocation failed");

		return (USB_NO_RESOURCES);
	}

	/*
	 * Save the client's isochronous request pointer and
	 * length of isochronous transfer in transfer wrapper.
	 * The dup'ed request is saved in pp_client_periodic_in_reqp
	 */
	itw->itw_curr_xfer_reqp = orig_isoc_reqp;

	pp->pp_client_periodic_in_reqp = (usb_opaque_t)clone_isoc_reqp;

	mutex_enter(&ph->p_mutex);
	ph->p_req_count++;
	mutex_exit(&ph->p_mutex);

	pp->pp_state = EHCI_PIPE_STATE_ACTIVE;

	return (USB_SUCCESS);
}


/*
 * ehci_deallocate_isoc_in_resource
 *
 * Deallocate interrupt request structure for the interrupt IN transfer.
 */
void
ehci_deallocate_isoc_in_resource(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_isoc_xwrapper_t	*itw)
{
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;
	uchar_t			ep_attr = ph->p_ep.bmAttributes;
	usb_isoc_req_t		*isoc_reqp;

	USB_DPRINTF_L4(PRINT_MASK_LISTS,
	    ehcip->ehci_log_hdl,
	    "ehci_deallocate_isoc_in_resource: "
	    "pp = 0x%p itw = 0x%p", (void *)pp, (void *)itw);

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));
	ASSERT((ep_attr & USB_EP_ATTR_MASK) == USB_EP_ATTR_ISOCH);

	isoc_reqp = itw->itw_curr_xfer_reqp;

	/* Check the current periodic in request pointer */
	if (isoc_reqp) {
		itw->itw_curr_xfer_reqp = NULL;
		itw->itw_curr_isoc_pktp = NULL;

		mutex_enter(&ph->p_mutex);
		ph->p_req_count--;
		mutex_exit(&ph->p_mutex);

		usb_free_isoc_req(isoc_reqp);

		/* Set periodic in pipe state to idle */
		pp->pp_state = EHCI_PIPE_STATE_IDLE;
	}
}


/*
 * ehci_itd_cpu_to_iommu:
 *
 * This function converts for the given Transfer Descriptor (ITD) CPU address
 * to IO address.
 */
uint32_t
ehci_itd_cpu_to_iommu(
	ehci_state_t	*ehcip,
	ehci_itd_t	*addr)
{
	uint32_t	td;

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	if (addr == NULL) {

		return (NULL);
	}

	td = (uint32_t)ehcip->ehci_itd_pool_cookie.dmac_address +
	    (uint32_t)((uintptr_t)addr -
	    (uintptr_t)(ehcip->ehci_itd_pool_addr));

	ASSERT(((uint32_t) (sizeof (ehci_itd_t) *
	    (addr - ehcip->ehci_itd_pool_addr))) ==
	    ((uint32_t)((uintptr_t)addr - (uintptr_t)
	    (ehcip->ehci_itd_pool_addr))));

	ASSERT(td >= ehcip->ehci_itd_pool_cookie.dmac_address);
	ASSERT(td <= ehcip->ehci_itd_pool_cookie.dmac_address +
	    sizeof (ehci_itd_t) * ehci_itd_pool_size);

	return (td);
}


/*
 * ehci_itd_iommu_to_cpu:
 *
 * This function converts for the given Transfer Descriptor (ITD) IO address
 * to CPU address.
 */
ehci_itd_t *
ehci_itd_iommu_to_cpu(
	ehci_state_t	*ehcip,
	uintptr_t	addr)
{
	ehci_itd_t	*itd;

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	if (addr == NULL) {

		return (NULL);
	}

	itd = (ehci_itd_t *)((uintptr_t)
	    (addr - ehcip->ehci_itd_pool_cookie.dmac_address) +
	    (uintptr_t)ehcip->ehci_itd_pool_addr);

	ASSERT(itd >= ehcip->ehci_itd_pool_addr);
	ASSERT((uintptr_t)itd <= (uintptr_t)ehcip->ehci_itd_pool_addr +
	    (uintptr_t)(sizeof (ehci_itd_t) * ehci_itd_pool_size));

	return (itd);
}


/*
 * Error parsing functions
 */
void ehci_parse_isoc_error(
	ehci_state_t		*ehcip,
	ehci_isoc_xwrapper_t	*itw,
	ehci_itd_t		*itd)
{
	usb_isoc_req_t		*isoc_reqp;
	usb_cr_t		error;

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	isoc_reqp = itw->itw_curr_xfer_reqp;

	if (itw->itw_port_status == USBA_HIGH_SPEED_DEV) {
		error = ehci_parse_itd_error(ehcip, itw, itd);
	} else {
		error = ehci_parse_sitd_error(ehcip, itw, itd);

		if (error != USB_CR_OK) {
			isoc_reqp->isoc_error_count++;

			USB_DPRINTF_L2(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
			    "ehci_parse_sitd_error: Error %d Device Address %d"
			    " Endpoint number %d", error, itw->itw_device_addr,
			    itw->itw_endpoint_num);
		}

	}
}


/* ARGSUSED */
static usb_cr_t ehci_parse_itd_error(
	ehci_state_t		*ehcip,
	ehci_isoc_xwrapper_t	*itw,
	ehci_itd_t		*itd)
{
	uint32_t		status, index;
	usb_cr_t		error = USB_CR_OK;
	uint32_t		i;
	usb_isoc_req_t		*isoc_reqp;

	isoc_reqp = itw->itw_curr_xfer_reqp;

	for (i = 0; i < EHCI_ITD_CTRL_LIST_SIZE; i++) {
		index = Get_ITD_INDEX(itd, i);
		if (index == 0xffffffff) {

			continue;
		}

		error = USB_CR_OK;

		status = Get_ITD_BODY(itd, EHCI_ITD_CTRL0 + i) &
		    EHCI_ITD_XFER_STATUS_MASK;

		if (status & EHCI_ITD_XFER_DATA_BUFFER_ERR) {
			if (itw->itw_direction == USB_EP_DIR_OUT) {
				USB_DPRINTF_L3(PRINT_MASK_INTR,
				    ehcip->ehci_log_hdl,
				    "ehci_parse_itd_error: BUFFER Underrun");

				error = USB_CR_BUFFER_UNDERRUN;
			} else {
				USB_DPRINTF_L3(PRINT_MASK_INTR,
				    ehcip->ehci_log_hdl,
				    "ehci_parse_itd_error: BUFFER Overrun");

				error = USB_CR_BUFFER_OVERRUN;
			}
		}

		if (status & EHCI_ITD_XFER_BABBLE) {
			USB_DPRINTF_L3(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
			    "ehci_parse_itd_error: BABBLE DETECTED");

			error = USB_CR_DATA_OVERRUN;
		}

		if (status & EHCI_ITD_XFER_ERROR) {
			USB_DPRINTF_L3(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
			    "ehci_parse_itd_error: XACT ERROR");

			error = USB_CR_DEV_NOT_RESP;
		}

		if (status & EHCI_ITD_XFER_ACTIVE) {
			USB_DPRINTF_L3(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
			    "ehci_parse_itd_error: NOT ACCESSED");

			error = USB_CR_NOT_ACCESSED;
		}

		itw->itw_curr_isoc_pktp->isoc_pkt_actual_length = 0;

		/* Write the status of isoc data packet */
		itw->itw_curr_isoc_pktp->isoc_pkt_status = error;

		/* counts total number of error packets in this req */
		if (error != USB_CR_OK) {
			isoc_reqp->isoc_error_count++;
			USB_DPRINTF_L3(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
			    "ehci_parse_itd_error: Error %d Device Address %d "
			    "Endpoint number %d", error, itw->itw_device_addr,
			    itw->itw_endpoint_num);
		}

		itw->itw_curr_isoc_pktp++;
	}

	return (error);
}

static usb_cr_t ehci_parse_sitd_error(
	ehci_state_t		*ehcip,
	ehci_isoc_xwrapper_t	*itw,
	ehci_itd_t		*itd)
{
	uint32_t		status;
	usb_cr_t		error;
	usb_isoc_pkt_descr_t	*isoc_pkt_descr;
	uint32_t		residue;

	isoc_pkt_descr = itw->itw_curr_isoc_pktp;

	status = Get_ITD_BODY(itd, EHCI_SITD_XFER_STATE) &
	    EHCI_SITD_XFER_STATUS_MASK;

	switch (status) {
	case EHCI_SITD_XFER_ACTIVE:
		USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_check_for_sitd_error: NOT ACCESSED");
		error = USB_CR_NOT_ACCESSED;

		break;
	case EHCI_SITD_XFER_ERROR:
		USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_check_for_sitd_error: TT ERROR");

		error = USB_CR_UNSPECIFIED_ERR;

		break;
	case EHCI_SITD_XFER_DATA_BUFFER_ERR:
		if (itw->itw_direction == USB_EP_DIR_OUT) {
			USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
			    "ehci_check_for_sitd_error: BUFFER Underrun");
			error = USB_CR_BUFFER_UNDERRUN;
		} else {
			USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
			    "ehci_check_for_sitd_error: BUFFER Overrun");
			error = USB_CR_BUFFER_OVERRUN;
		}

		break;
	case EHCI_SITD_XFER_BABBLE:
		USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_check_for_sitd_error: BABBLE");
		error = USB_CR_DATA_OVERRUN;

		break;
	case EHCI_SITD_XFER_XACT_ERROR:
		USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_check_for_sitd_error: XACT ERROR");

		error = USB_CR_DEV_NOT_RESP;
		break;
	case EHCI_SITD_XFER_MISSED_UFRAME:
		USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_check_for_sitd_error: MISSED UFRAME");

		error = USB_CR_NOT_ACCESSED;
		break;
	default:
		USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_check_for_sitd_error: NO ERROR");
		error = USB_CR_OK;

		break;
	}

	/* This is HCD specific and may not have this information */
	residue =
	    (Get_ITD_BODY(itd, EHCI_SITD_XFER_STATE) &
	    EHCI_SITD_XFER_TOTAL_MASK) >>
	    EHCI_SITD_XFER_TOTAL_SHIFT;

	/*
	 * Subtract the residue from the isoc_pkt_descr that
	 * was set when this ITD was inserted.
	 */
	isoc_pkt_descr->isoc_pkt_actual_length -= residue;

	/* Write the status of isoc data packet */
	isoc_pkt_descr->isoc_pkt_status = error;

	itw->itw_curr_isoc_pktp++;

	return (error);
}


/*
 * debug print functions
 */
void
ehci_print_itd(
	ehci_state_t	*ehcip,
	ehci_itd_t	*itd)
{
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_print_itd: itd = 0x%p", (void *)itd);

	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\titd_link_ptr: 0x%x ", Get_ITD(itd->itd_link_ptr));

	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\titd_ctrl0: 0x%x ",
	    Get_ITD(itd->itd_body[EHCI_ITD_CTRL0]));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\titd_ctrl1: 0x%x ",
	    Get_ITD(itd->itd_body[EHCI_ITD_CTRL1]));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\titd_ctrl2: 0x%x ",
	    Get_ITD(itd->itd_body[EHCI_ITD_CTRL2]));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\titd_ctrl3: 0x%x ",
	    Get_ITD(itd->itd_body[EHCI_ITD_CTRL3]));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\titd_ctrl4: 0x%x ",
	    Get_ITD(itd->itd_body[EHCI_ITD_CTRL4]));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\titd_ctrl5: 0x%x ",
	    Get_ITD(itd->itd_body[EHCI_ITD_CTRL5]));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\titd_ctrl6: 0x%x ",
	    Get_ITD(itd->itd_body[EHCI_ITD_CTRL6]));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\titd_ctrl7: 0x%x ",
	    Get_ITD(itd->itd_body[EHCI_ITD_CTRL7]));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\titd_buffer0: 0x%x ",
	    Get_ITD(itd->itd_body[EHCI_ITD_BUFFER0]));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\titd_buffer1: 0x%x ",
	    Get_ITD(itd->itd_body[EHCI_ITD_BUFFER1]));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\titd_buffer2: 0x%x ",
	    Get_ITD(itd->itd_body[EHCI_ITD_BUFFER2]));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\titd_buffer3: 0x%x ",
	    Get_ITD(itd->itd_body[EHCI_ITD_BUFFER3]));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\titd_buffer4: 0x%x ",
	    Get_ITD(itd->itd_body[EHCI_ITD_BUFFER4]));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\titd_buffer5: 0x%x ",
	    Get_ITD(itd->itd_body[EHCI_ITD_BUFFER5]));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\titd_buffer6: 0x%x ",
	    Get_ITD(itd->itd_body[EHCI_ITD_BUFFER6]));

	/* HCD private fields */
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\titd_trans_wrapper: 0x%x ",
	    Get_ITD(itd->itd_trans_wrapper));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\titd_itw_next_itd: 0x%x ",
	    Get_ITD(itd->itd_itw_next_itd));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\titd_state: 0x%x ",
	    Get_ITD(itd->itd_state));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\titd_index: 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x ",
	    Get_ITD_INDEX(itd, 0), Get_ITD_INDEX(itd, 1),
	    Get_ITD_INDEX(itd, 2), Get_ITD_INDEX(itd, 3),
	    Get_ITD_INDEX(itd, 4), Get_ITD_INDEX(itd, 5),
	    Get_ITD_INDEX(itd, 6), Get_ITD_INDEX(itd, 7));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\titd_frame_number: 0x%x ",
	    Get_ITD(itd->itd_frame_number));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\titd_reclaim_number: 0x%x ",
	    Get_ITD(itd->itd_reclaim_number));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\titd_next_active_itd: 0x%x ",
	    Get_ITD(itd->itd_next_active_itd));
}


void
ehci_print_sitd(
	ehci_state_t	*ehcip,
	ehci_itd_t	*itd)
{
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_print_itd: itd = 0x%p", (void *)itd);

	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\titd_link_ptr: 0x%x ", Get_ITD(itd->itd_link_ptr));

	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\tsitd_ctrl: 0x%x ",
	    Get_ITD(itd->itd_body[EHCI_SITD_CTRL]));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\tsitd_uframe_sched: 0x%x ",
	    Get_ITD(itd->itd_body[EHCI_SITD_UFRAME_SCHED]));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\tsitd_xfer_state: 0x%x ",
	    Get_ITD(itd->itd_body[EHCI_SITD_XFER_STATE]));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\tsitd_buffer0: 0x%x ",
	    Get_ITD(itd->itd_body[EHCI_SITD_BUFFER0]));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\tsitd_buffer1: 0x%x ",
	    Get_ITD(itd->itd_body[EHCI_SITD_BUFFER1]));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\tsitd_prev_sitd: 0x%x ",
	    Get_ITD(itd->itd_body[EHCI_SITD_PREV_SITD]));

	/* HCD private fields */
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\titd_trans_wrapper: 0x%x ",
	    Get_ITD(itd->itd_trans_wrapper));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\titd_itw_next_itd: 0x%x ",
	    Get_ITD(itd->itd_itw_next_itd));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\titd_state: 0x%x ",
	    Get_ITD(itd->itd_state));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\titd_frame_number: 0x%x ",
	    Get_ITD(itd->itd_frame_number));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\titd_reclaim_number: 0x%x ",
	    Get_ITD(itd->itd_reclaim_number));
	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "\titd_next_active_itd: 0x%x ",
	    Get_ITD(itd->itd_next_active_itd));
}
