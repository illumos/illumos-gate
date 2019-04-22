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
#include <sys/usb/hcd/ehci/ehci_isoch.h>
#include <sys/usb/hcd/ehci/ehci_isoch_util.h>
#include <sys/strsun.h>

/*
 * Isochronous initialization functions
 */
int ehci_isoc_init(
	ehci_state_t		*ehcip);
void ehci_isoc_cleanup(
	ehci_state_t		*ehcip);
void ehci_isoc_pipe_cleanup(
	ehci_state_t		*ehcip,
	usba_pipe_handle_data_t *ph);
static void ehci_wait_for_isoc_completion(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp);

/*
 * Isochronous request functions
 */
ehci_isoc_xwrapper_t *ehci_allocate_isoc_resources(
	ehci_state_t		*ehcip,
	usba_pipe_handle_data_t *ph,
	usb_isoc_req_t		*isoc_reqp,
	usb_flags_t		usb_flags);
int ehci_insert_isoc_req(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_isoc_xwrapper_t	*itw,
	usb_flags_t		usb_flags);
static int ehci_insert_itd_req(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_isoc_xwrapper_t	*itw,
	usb_flags_t		usb_flags);
static int ehci_insert_sitd_req(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_isoc_xwrapper_t	*itw,
	usb_flags_t		usb_flags);
static void ehci_remove_isoc_itds(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp);
static void ehci_mark_reclaim_isoc(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp);
static void ehci_reclaim_isoc(
	ehci_state_t		*ehcip,
	ehci_isoc_xwrapper_t	*itw,
	ehci_itd_t		*itd,
	ehci_pipe_private_t	*pp);
int	ehci_start_isoc_polling(
	ehci_state_t		*ehcip,
	usba_pipe_handle_data_t	*ph,
	usb_flags_t		flags);

/*
 * Isochronronous handling functions.
 */
void ehci_traverse_active_isoc_list(
	ehci_state_t		*ehcip);
static void ehci_handle_isoc(
	ehci_state_t		*ehcip,
	ehci_isoc_xwrapper_t	*itw,
	ehci_itd_t		*itd);
static void ehci_handle_itd(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_isoc_xwrapper_t	*itw,
	ehci_itd_t		*itd,
	void			*tw_handle_callback_value);
static void ehci_sendup_itd_message(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_isoc_xwrapper_t	*itw,
	ehci_itd_t		*td,
	usb_cr_t		error);
void ehci_hcdi_isoc_callback(
	usba_pipe_handle_data_t	*ph,
	ehci_isoc_xwrapper_t	*itw,
	usb_cr_t		completion_reason);


/*
 * Isochronous initialization functions
 */
/*
 * Initialize all the needed resources needed by isochronous pipes.
 */
int
ehci_isoc_init(
	ehci_state_t		*ehcip)
{
	return (ehci_allocate_isoc_pools(ehcip));
}


/*
 * Cleanup isochronous resources.
 */
void
ehci_isoc_cleanup(
	ehci_state_t		*ehcip)
{
	ehci_isoc_xwrapper_t	*itw;
	ehci_pipe_private_t	*pp;
	ehci_itd_t		*itd;
	int			i, ctrl, rval;

	/* Free all the buffers */
	if (ehcip->ehci_itd_pool_addr && ehcip->ehci_itd_pool_mem_handle) {
		for (i = 0; i < ehci_get_itd_pool_size(); i ++) {
			itd = &ehcip->ehci_itd_pool_addr[i];
			ctrl = Get_ITD(ehcip->
			    ehci_itd_pool_addr[i].itd_state);

			if ((ctrl != EHCI_ITD_FREE) &&
			    (ctrl != EHCI_ITD_DUMMY) &&
			    (itd->itd_trans_wrapper)) {

				mutex_enter(&ehcip->ehci_int_mutex);

				itw = (ehci_isoc_xwrapper_t *)
				    EHCI_LOOKUP_ID((uint32_t)
				    Get_ITD(itd->itd_trans_wrapper));

				/* Obtain the pipe private structure */
				pp = itw->itw_pipe_private;

				ehci_deallocate_itd(ehcip, itw, itd);
				ehci_deallocate_itw(ehcip, pp, itw);

				mutex_exit(&ehcip->ehci_int_mutex);
			}
		}

		/*
		 * If EHCI_ITD_POOL_BOUND flag is set, then unbind
		 * the handle for ITD pools.
		 */
		if ((ehcip->ehci_dma_addr_bind_flag &
		    EHCI_ITD_POOL_BOUND) == EHCI_ITD_POOL_BOUND) {

			rval = ddi_dma_unbind_handle(
			    ehcip->ehci_itd_pool_dma_handle);

			ASSERT(rval == DDI_SUCCESS);
		}
		ddi_dma_mem_free(&ehcip->ehci_itd_pool_mem_handle);
	}

	/* Free the ITD pool */
	if (ehcip->ehci_itd_pool_dma_handle) {
		ddi_dma_free_handle(&ehcip->ehci_itd_pool_dma_handle);
	}
}


/*
 * ehci_isoc_pipe_cleanup
 *
 * Cleanup ehci isoc pipes.
 */
void ehci_isoc_pipe_cleanup(
	ehci_state_t		*ehcip,
	usba_pipe_handle_data_t *ph)
{
	ehci_pipe_private_t	*pp = (ehci_pipe_private_t *)ph->p_hcd_private;
	uint_t			pipe_state = pp->pp_state;
	usb_cr_t		completion_reason;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_isoc_pipe_cleanup: ph = 0x%p", (void *)ph);

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/* Stop all further processing */
	ehci_mark_reclaim_isoc(ehcip, pp);

	/*
	 * Wait for processing all completed transfers
	 * and send result upstream/
	 */
	ehci_wait_for_isoc_completion(ehcip, pp);

	/* Go ahead and remove all remaining itds if there are any */
	ehci_remove_isoc_itds(ehcip, pp);

	switch (pipe_state) {
	case EHCI_PIPE_STATE_CLOSE:
		completion_reason = USB_CR_PIPE_CLOSING;
		break;
	case EHCI_PIPE_STATE_RESET:
	case EHCI_PIPE_STATE_STOP_POLLING:
		/* Set completion reason */
		completion_reason = (pipe_state ==
		    EHCI_PIPE_STATE_RESET) ?
		    USB_CR_PIPE_RESET: USB_CR_STOPPED_POLLING;

		/* Set pipe state to idle */
		pp->pp_state = EHCI_PIPE_STATE_IDLE;

		break;
	}

	/*
	 * Do the callback for the original client
	 * periodic IN request.
	 */
	if ((ph->p_ep.bEndpointAddress & USB_EP_DIR_MASK) ==
	    USB_EP_DIR_IN) {

		ehci_do_client_periodic_in_req_callback(
		    ehcip, pp, completion_reason);
	}
}


/*
 * ehci_wait_for_transfers_completion:
 *
 * Wait for processing all completed transfers and to send results
 * to upstream.
 */
static void
ehci_wait_for_isoc_completion(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp)
{
	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	if (pp->pp_itw_head == NULL) {

		return;
	}

	(void) cv_reltimedwait(&pp->pp_xfer_cmpl_cv, &ehcip->ehci_int_mutex,
	    drv_usectohz(EHCI_XFER_CMPL_TIMEWAIT * 1000000), TR_CLOCK_TICK);

	if (pp->pp_itw_head) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
		    "ehci_wait_for_isoc_completion: "
		    "No transfers completion confirmation received");
	}
}


/*
 *  Isochronous request functions
 */
/*
 * ehci_allocate_isoc_resources:
 *
 * Calculates the number of tds necessary for a isoch transfer, and
 * allocates all the necessary resources.
 *
 * Returns NULL if there is insufficient resources otherwise ITW.
 */
ehci_isoc_xwrapper_t *
ehci_allocate_isoc_resources(
	ehci_state_t		*ehcip,
	usba_pipe_handle_data_t *ph,
	usb_isoc_req_t		*isoc_reqp,
	usb_flags_t		usb_flags)
{
	ehci_pipe_private_t	*pp = (ehci_pipe_private_t *)ph->p_hcd_private;
	int			pipe_dir, i;
	uint_t			max_ep_pkt_size, max_isoc_xfer_size;
	usb_isoc_pkt_descr_t	*isoc_pkt_descr;
	size_t			isoc_pkt_count, isoc_pkts_length;
	size_t			itw_xfer_size = 0;
	ehci_isoc_xwrapper_t	*itw;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_allocate_isoc_resources: flags = 0x%x", usb_flags);

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/*
	 * Check whether pipe is in halted state.
	 */
	if (pp->pp_state == EHCI_PIPE_STATE_ERROR) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
		    "ehci_allocate_isoc_resources:"
		    "Pipe is in error state, need pipe reset to continue");

		return (NULL);
	}

	/* Calculate the maximum isochronous transfer size we allow */
	max_ep_pkt_size = (ph->p_ep.wMaxPacketSize &
	    EHCI_ITD_CTRL_MAX_PACKET_MASK) *
	    CalculateITDMultiField(ph->p_ep.wMaxPacketSize);

	max_isoc_xfer_size = EHCI_MAX_ISOC_PKTS_PER_XFER * max_ep_pkt_size;

	/* Get the packet descriptor and number of packets to send */
	if (isoc_reqp) {
		isoc_pkt_descr = isoc_reqp->isoc_pkt_descr;
		isoc_pkt_count = isoc_reqp->isoc_pkts_count;
		isoc_pkts_length = isoc_reqp->isoc_pkts_length;
	} else {
		isoc_pkt_descr = ((usb_isoc_req_t *)
		    pp->pp_client_periodic_in_reqp)->isoc_pkt_descr;

		isoc_pkt_count = ((usb_isoc_req_t *)
		    pp->pp_client_periodic_in_reqp)->isoc_pkts_count;

		isoc_pkts_length = ((usb_isoc_req_t *)
		    pp->pp_client_periodic_in_reqp)->isoc_pkts_length;
	}

	/* Calculate the size of the transfer. */
	pipe_dir = ph->p_ep.bEndpointAddress & USB_EP_DIR_MASK;
	if (pipe_dir == USB_EP_DIR_IN) {
		for (i = 0; i < isoc_pkt_count; i++) {
			/*
			 * isoc_pkt_length is used as Transaction Length and
			 * according to EHCI spec Table 3-3, the maximum value
			 * allowed is 3072
			 */
			if (isoc_pkt_descr->isoc_pkt_length > 3072) {

				return (NULL);
			}

			itw_xfer_size += isoc_pkt_descr->isoc_pkt_length;

			isoc_pkt_descr++;
		}

		if ((isoc_pkts_length) &&
		    (isoc_pkts_length != itw_xfer_size)) {

			USB_DPRINTF_L2(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
			    "ehci_allocate_isoc_resources: "
			    "isoc_pkts_length 0x%lx is not equal to the sum of "
			    "all pkt lengths 0x%lx in an isoc request",
			    isoc_pkts_length, itw_xfer_size);

			return (NULL);
		}

	} else {
		ASSERT(isoc_reqp != NULL);
		itw_xfer_size = MBLKL(isoc_reqp->isoc_data);
	}

	/* Check the size of isochronous request */
	if (itw_xfer_size > max_isoc_xfer_size) {

		USB_DPRINTF_L2(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
		    "ehci_allocate_isoc_resources: Maximum isoc request "
		    "size 0x%x Given isoc request size 0x%lx",
		    max_isoc_xfer_size, itw_xfer_size);

		return (NULL);
	}

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_allocate_isoc_resources: length = 0x%lx", itw_xfer_size);

	/* Allocate the itw for this request */
	if ((itw = ehci_allocate_itw_resources(ehcip, pp, itw_xfer_size,
	    usb_flags, isoc_pkt_count)) == NULL) {

		return (NULL);
	}

	itw->itw_handle_callback_value = NULL;

	if (pipe_dir == USB_EP_DIR_IN) {
		if (ehci_allocate_isoc_in_resource(ehcip, pp, itw, usb_flags) !=
		    USB_SUCCESS) {

			ehci_deallocate_itw(ehcip, pp, itw);

			return (NULL);
		}
	} else {
		if (itw->itw_length) {
			ASSERT(isoc_reqp->isoc_data != NULL);

			/* Copy the data into the buffer */
			bcopy(isoc_reqp->isoc_data->b_rptr,
			    itw->itw_buf, itw->itw_length);

			Sync_IO_Buffer_for_device(itw->itw_dmahandle,
			    itw->itw_length);
		}
		itw->itw_curr_xfer_reqp = isoc_reqp;
	}

	return (itw);
}


/*
 * ehci_insert_isoc_req:
 *
 * Insert an isochronous request into the Host Controller's
 * isochronous list.
 */
int
ehci_insert_isoc_req(
	ehci_state_t			*ehcip,
	ehci_pipe_private_t		*pp,
	ehci_isoc_xwrapper_t		*itw,
	usb_flags_t			usb_flags)
{
	int			error;
	ehci_itd_t		*new_itd, *temp_itd;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_insert_isoc_req: flags = 0x%x port status = 0x%x",
	    usb_flags, itw->itw_port_status);

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	ASSERT(itw->itw_curr_xfer_reqp != NULL);
	ASSERT(itw->itw_curr_xfer_reqp->isoc_pkt_descr != NULL);

	/*
	 * Save address of first usb isochronous packet descriptor.
	 */
	itw->itw_curr_isoc_pktp = itw->itw_curr_xfer_reqp->isoc_pkt_descr;

	if (itw->itw_port_status == USBA_HIGH_SPEED_DEV) {
		error = ehci_insert_itd_req(ehcip, pp, itw, usb_flags);
	} else {
		error = ehci_insert_sitd_req(ehcip, pp, itw, usb_flags);
	}

	/* Either all the isocs will be added or none of them will */
	error = ehci_insert_isoc_to_pfl(ehcip, pp, itw);

	if (error != USB_SUCCESS) {
		/*
		 * Deallocate all the ITDs, otherwise they will be
		 * lost forever.
		 */
		new_itd = itw->itw_itd_head;
		while (new_itd) {
			temp_itd = ehci_itd_iommu_to_cpu(ehcip,
			    Get_ITD(new_itd->itd_itw_next_itd));
			ehci_deallocate_itd(ehcip, itw, new_itd);
			new_itd = temp_itd;
		}
		if ((itw->itw_direction == USB_EP_DIR_IN)) {
			ehci_deallocate_isoc_in_resource(ehcip, pp, itw);

			if (pp->pp_cur_periodic_req_cnt) {
				/*
				 * Set pipe state to stop polling and
				 * error to no resource. Don't insert
				 * any more isoch polling requests.
				 */
				pp->pp_state =
				    EHCI_PIPE_STATE_STOP_POLLING;
				pp->pp_error = error;
			} else {
				/* Set periodic in pipe state to idle */
				pp->pp_state = EHCI_PIPE_STATE_IDLE;
			}

			return (error);
		}

		/* Save how many packets and data actually went */
		itw->itw_num_itds = 0;
		itw->itw_length  = 0;
	}

	/*
	 * Reset back to the address of first usb isochronous
	 * packet descriptor.
	 */
	itw->itw_curr_isoc_pktp = itw->itw_curr_xfer_reqp->isoc_pkt_descr;

	/* Reset the CONTINUE flag */
	pp->pp_flag &= ~EHCI_ISOC_XFER_CONTINUE;

	return (error);
}


/*
 * ehci_insert_itd_req:
 *
 * Insert an ITD request into the Host Controller's isochronous list.
 */
/* ARGSUSED */
static int
ehci_insert_itd_req(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_isoc_xwrapper_t	*itw,
	usb_flags_t		usb_flags)
{
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;
	usb_isoc_req_t		*curr_isoc_reqp;
	usb_isoc_pkt_descr_t	*curr_isoc_pkt_descr;
	size_t			curr_isoc_xfer_offset;
	size_t			isoc_pkt_length;
	uint_t			count, xactcount;
	uint32_t		xact_status;
	uint32_t		page, pageselected;
	uint32_t		buf[EHCI_ITD_BUFFER_LIST_SIZE];
	uint16_t		index = 0;
	uint16_t		multi = 0;
	ehci_itd_t		*new_itd;

	/*
	 * Get the current isochronous request and packet
	 * descriptor pointers.
	 */
	curr_isoc_reqp = (usb_isoc_req_t *)itw->itw_curr_xfer_reqp;

	page = itw->itw_cookie.dmac_address;
	ASSERT((page % EHCI_4K_ALIGN) == 0);

	USB_DPRINTF_L3(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_insert_itd_req: itw_curr_xfer_reqp = 0x%p page = 0x%x,"
	    " pagesize = 0x%lx", (void *)itw->itw_curr_xfer_reqp, page,
	    itw->itw_cookie.dmac_size);

	/* Insert all the isochronous TDs */
	count = 0;
	curr_isoc_xfer_offset = 0;

	while (count < curr_isoc_reqp->isoc_pkts_count) {

		/* Grab a new itd */
		new_itd = itw->itw_itd_free_list;

		ASSERT(new_itd != NULL);

		itw->itw_itd_free_list = ehci_itd_iommu_to_cpu(ehcip,
		    Get_ITD(new_itd->itd_link_ptr));
		Set_ITD(new_itd->itd_link_ptr, 0);

		bzero(buf, EHCI_ITD_BUFFER_LIST_SIZE * sizeof (uint32_t));

		multi = CalculateITDMultiField(ph->p_ep.wMaxPacketSize);

		if (multi > EHCI_ITD_CTRL_MULTI_MASK) {
			USB_DPRINTF_L2(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
			    "ehci_insert_itd_req: Wrong multi value.");

			return (USB_FAILURE);
		}

		/* Fill 8 transaction for every iTD */
		for (xactcount = 0, pageselected = 0;
		    xactcount < EHCI_ITD_CTRL_LIST_SIZE; xactcount++) {

			curr_isoc_pkt_descr = itw->itw_curr_isoc_pktp;

			isoc_pkt_length =
			    curr_isoc_pkt_descr->isoc_pkt_length;

			curr_isoc_pkt_descr->isoc_pkt_actual_length
			    = (ushort_t)isoc_pkt_length;

			xact_status = 0;

			if (pageselected < EHCI_ITD_BUFFER_LIST_SIZE) {

				buf[pageselected] |= page;
			} else {
				USB_DPRINTF_L2(PRINT_MASK_INTR,
				    ehcip->ehci_log_hdl,
				    "ehci_insert_itd_req: "
				    "Error in buffer pointer.");

				return (USB_FAILURE);
			}

			xact_status = (uint32_t)curr_isoc_xfer_offset;
			xact_status |= (pageselected << 12);
			xact_status |= isoc_pkt_length << 16;
			xact_status |= EHCI_ITD_XFER_ACTIVE;

			/* Set IOC on the last TD. */
			if (count == (curr_isoc_reqp->isoc_pkts_count - 1)) {
				xact_status |= EHCI_ITD_XFER_IOC_ON;
			}

			USB_DPRINTF_L3(PRINT_MASK_INTR,
			    ehcip->ehci_log_hdl,
			    "ehci_insert_itd_req: count = 0x%x multi = %d"
			    "status = 0x%x page = 0x%x index = %d "
			    "pageselected = %d isoc_pkt_length = 0x%lx",
			    xactcount, multi, xact_status, page,
			    index, pageselected, isoc_pkt_length);

			/* Fill in the new itd */
			Set_ITD_BODY(new_itd, xactcount, xact_status);

			itw->itw_curr_isoc_pktp++;
			Set_ITD_INDEX(new_itd, xactcount, index++);

			curr_isoc_xfer_offset += isoc_pkt_length;

			if (curr_isoc_xfer_offset >= EHCI_4K_ALIGN) {
				pageselected ++;
				page += EHCI_4K_ALIGN;
				curr_isoc_xfer_offset -= EHCI_4K_ALIGN;
			}

			count ++;
			if (count >= curr_isoc_reqp->isoc_pkts_count) {

				break;
			}
		}

		buf[0] |= (itw->itw_endpoint_num << 8);
		buf[0] |= itw->itw_device_addr;
		buf[1] |= ph->p_ep.wMaxPacketSize &
		    EHCI_ITD_CTRL_MAX_PACKET_MASK;

		if (itw->itw_direction == USB_EP_DIR_IN) {
			buf[1] |= EHCI_ITD_CTRL_DIR_IN;
		}
		buf[2] |= multi;

		Set_ITD_BODY(new_itd, EHCI_ITD_BUFFER0, buf[0]);
		Set_ITD_BODY(new_itd, EHCI_ITD_BUFFER1, buf[1]);
		Set_ITD_BODY(new_itd, EHCI_ITD_BUFFER2, buf[2]);
		Set_ITD_BODY(new_itd, EHCI_ITD_BUFFER3, buf[3]);
		Set_ITD_BODY(new_itd, EHCI_ITD_BUFFER4, buf[4]);
		Set_ITD_BODY(new_itd, EHCI_ITD_BUFFER5, buf[5]);
		Set_ITD_BODY(new_itd, EHCI_ITD_BUFFER6, buf[6]);

		Set_ITD(new_itd->itd_state, EHCI_ITD_ACTIVE);
		ehci_print_itd(ehcip, new_itd);

		/*
		 * Add this itd to the itw before we add it in the PFL
		 * If adding it to the PFL fails, we will have to cleanup.
		 */
		ehci_insert_itd_on_itw(ehcip, itw, new_itd);

	}

	return (USB_SUCCESS);
}


/*
 * ehci_insert_sitd_req:
 *
 * Insert an SITD request into the Host Controller's isochronous list.
 */
/* ARGSUSED */
static int
ehci_insert_sitd_req(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_isoc_xwrapper_t	*itw,
	usb_flags_t		usb_flags)
{
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;
	usb_isoc_req_t		*curr_isoc_reqp;
	usb_isoc_pkt_descr_t	*curr_isoc_pkt_descr;
	size_t			curr_isoc_xfer_offset;
	size_t			isoc_pkt_length;
	uint_t			count;
	uint32_t		ctrl, uframe_sched, xfer_state;
	uint32_t		page0, page1, prev_sitd;
	uint32_t		ssplit_count;
	ehci_itd_t		*new_sitd;

	/*
	 * Get the current isochronous request and packet
	 * descriptor pointers.
	 */
	curr_isoc_reqp = (usb_isoc_req_t *)itw->itw_curr_xfer_reqp;

	/* Set the ctrl field */
	ctrl = 0;
	if (itw->itw_direction == USB_EP_DIR_IN) {
		ctrl |= EHCI_SITD_CTRL_DIR_IN;
	} else {
		ctrl |= EHCI_SITD_CTRL_DIR_OUT;
	}

	ctrl |= (itw->itw_hub_port << EHCI_SITD_CTRL_PORT_SHIFT) &
	    EHCI_SITD_CTRL_PORT_MASK;
	ctrl |= (itw->itw_hub_addr << EHCI_SITD_CTRL_HUB_SHIFT) &
	    EHCI_SITD_CTRL_HUB_MASK;
	ctrl |= (itw->itw_endpoint_num << EHCI_SITD_CTRL_END_PT_SHIFT) &
	    EHCI_SITD_CTRL_END_PT_MASK;
	ctrl |= (itw->itw_device_addr << EHCI_SITD_CTRL_DEVICE_SHIFT) &
	    EHCI_SITD_CTRL_DEVICE_MASK;

	/* Set the micro frame schedule */
	uframe_sched = 0;
	uframe_sched |= (pp->pp_smask << EHCI_SITD_UFRAME_SMASK_SHIFT) &
	    EHCI_SITD_UFRAME_SMASK_MASK;
	uframe_sched |= (pp->pp_cmask << EHCI_SITD_UFRAME_CMASK_SHIFT) &
	    EHCI_SITD_UFRAME_CMASK_MASK;

	/* Set the default page information */
	page0 = itw->itw_cookie.dmac_address;
	page1 = 0;

	prev_sitd = EHCI_ITD_LINK_PTR_INVALID;

	/*
	 * Save the number of isochronous TDs needs
	 * to be insert to complete current isochronous request.
	 */
	itw->itw_num_itds = curr_isoc_reqp->isoc_pkts_count;

	/* Insert all the isochronous TDs */
	for (count = 0, curr_isoc_xfer_offset = 0;
	    count < itw->itw_num_itds; count++) {

		curr_isoc_pkt_descr = itw->itw_curr_isoc_pktp;

		isoc_pkt_length = curr_isoc_pkt_descr->isoc_pkt_length;
		curr_isoc_pkt_descr->isoc_pkt_actual_length =
		    (ushort_t)isoc_pkt_length;

		/* Set the transfer state information */
		xfer_state = 0;

		if (itw->itw_direction == USB_EP_DIR_IN) {
			/* Set the size to the max packet size */
			xfer_state |= (ph->p_ep.wMaxPacketSize <<
			    EHCI_SITD_XFER_TOTAL_SHIFT) &
			    EHCI_SITD_XFER_TOTAL_MASK;
		} else {
			/* Set the size to the packet length */
			xfer_state |= (isoc_pkt_length <<
			    EHCI_SITD_XFER_TOTAL_SHIFT) &
			    EHCI_SITD_XFER_TOTAL_MASK;
		}
		xfer_state |=  EHCI_SITD_XFER_ACTIVE;

		/* Set IOC on the last TD. */
		if (count == (itw->itw_num_itds - 1)) {
			xfer_state |= EHCI_SITD_XFER_IOC_ON;
		}

		ssplit_count = isoc_pkt_length / MAX_UFRAME_SITD_XFER;
		if (isoc_pkt_length % MAX_UFRAME_SITD_XFER) {
			ssplit_count++;
		}

		page1 = (ssplit_count & EHCI_SITD_XFER_TCOUNT_MASK) <<
		    EHCI_SITD_XFER_TCOUNT_SHIFT;
		if (ssplit_count > 1) {
			page1 |= EHCI_SITD_XFER_TP_BEGIN;
		} else {
			page1 |= EHCI_SITD_XFER_TP_ALL;
		}

		/* Grab a new sitd */
		new_sitd = itw->itw_itd_free_list;

		ASSERT(new_sitd != NULL);

		itw->itw_itd_free_list = ehci_itd_iommu_to_cpu(ehcip,
		    Get_ITD(new_sitd->itd_link_ptr));
		Set_ITD(new_sitd->itd_link_ptr, 0);

		/* Fill in the new sitd */
		Set_ITD_BODY(new_sitd, EHCI_SITD_CTRL, ctrl);
		Set_ITD_BODY(new_sitd, EHCI_SITD_UFRAME_SCHED, uframe_sched);
		Set_ITD_BODY(new_sitd, EHCI_SITD_XFER_STATE, xfer_state);
		Set_ITD_BODY(new_sitd, EHCI_SITD_BUFFER0,
		    page0 + curr_isoc_xfer_offset);
		Set_ITD_BODY(new_sitd, EHCI_SITD_BUFFER1, page1);
		Set_ITD_BODY(new_sitd, EHCI_SITD_PREV_SITD, prev_sitd);

		Set_ITD(new_sitd->itd_state, EHCI_ITD_ACTIVE);

		/*
		 * Add this itd to the itw before we add it in the PFL
		 * If adding it to the PFL fails, we will have to cleanup.
		 */
		ehci_insert_itd_on_itw(ehcip, itw, new_sitd);

		itw->itw_curr_isoc_pktp++;
		curr_isoc_xfer_offset += isoc_pkt_length;
	}

	return (USB_SUCCESS);
}


/*
 * ehci_remove_isoc_itds:
 *
 * Remove all itds from the PFL.
 */
static void
ehci_remove_isoc_itds(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp)
{
	ehci_isoc_xwrapper_t	*curr_itw, *next_itw;
	ehci_itd_t		*curr_itd, *next_itd;

	USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_remove_isoc_itds: pp = 0x%p", (void *)pp);

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	curr_itw = pp->pp_itw_head;
	while (curr_itw) {
		USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_remove_isoc_itds: itw = 0x%p num itds = %d",
		    (void *)curr_itw, curr_itw->itw_num_itds);

		next_itw = curr_itw->itw_next;

		curr_itd = curr_itw->itw_itd_head;
		while (curr_itd) {
			next_itd = ehci_itd_iommu_to_cpu(ehcip,
			    Get_ITD(curr_itd->itd_itw_next_itd));

			ehci_reclaim_isoc(ehcip, curr_itw, curr_itd, pp);

			curr_itd = next_itd;
		}

		ehci_deallocate_itw(ehcip, pp, curr_itw);

		curr_itw = next_itw;
	}
}


/*
 * ehci_mark_reclaim_isoc:
 *
 * Set active ITDs to RECLAIM.
 * Return number of ITD that need to be processed.
 */
static void
ehci_mark_reclaim_isoc(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp)
{
	usb_frame_number_t	current_frame_number;
	ehci_isoc_xwrapper_t	*curr_itw, *next_itw;
	ehci_itd_t		*curr_itd, *next_itd;
	uint_t			ctrl;
	uint_t			isActive;
	int			i;

	USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_mark_reclaim_isoc: pp = 0x%p", (void *)pp);

	if (pp->pp_itw_head == NULL) {

		return;
	}

	/* Get the current frame number. */
	current_frame_number = ehci_get_current_frame_number(ehcip);

	/* Traverse the list of transfer descriptors */
	curr_itw = pp->pp_itw_head;
	while (curr_itw) {
		next_itw = curr_itw->itw_next;

		USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_mark_reclaim_isoc: itw = 0x%p num itds = %d",
		    (void *)curr_itw, curr_itw->itw_num_itds);

		curr_itd = curr_itw->itw_itd_head;
		while (curr_itd) {
			next_itd = ehci_itd_iommu_to_cpu(ehcip,
			    Get_ITD(curr_itd->itd_itw_next_itd));

			if (curr_itw->itw_port_status == USBA_HIGH_SPEED_DEV) {

				for (i = 0; i < EHCI_ITD_CTRL_LIST_SIZE; i++) {
					ctrl = Get_ITD_BODY(curr_itd,
					    EHCI_ITD_CTRL0 + i);
					isActive = ctrl & EHCI_ITD_XFER_ACTIVE;
					/* If still active, deactivate it */
					if (isActive) {
						ctrl &= ~EHCI_ITD_XFER_ACTIVE;
						Set_ITD_BODY(curr_itd,
						    EHCI_ITD_CTRL0 + i,
						    ctrl);
						break;
					}
				}
			} else {
				ctrl = Get_ITD_BODY(curr_itd,
				    EHCI_SITD_XFER_STATE);
				isActive = ctrl & EHCI_SITD_XFER_ACTIVE;
				/* If it is still active deactivate it */
				if (isActive) {
					ctrl &= ~EHCI_SITD_XFER_ACTIVE;
					Set_ITD_BODY(curr_itd,
					    EHCI_SITD_XFER_STATE,
					    ctrl);
				}
			}

			/*
			 * If the itd was active put it on the reclaim status,
			 * so the interrupt handler will know not to process it.
			 * Otherwise leave it alone and let the interrupt
			 * handler process it normally.
			 */
			if (isActive) {
				Set_ITD(curr_itd->itd_state, EHCI_ITD_RECLAIM);
				Set_ITD_FRAME(curr_itd->itd_reclaim_number,
				    current_frame_number);
				ehci_remove_isoc_from_pfl(ehcip, curr_itd);
			}
			curr_itd = next_itd;
		}
		curr_itw = next_itw;
	}
}


/*
 * ehci_reclaim_isoc:
 *
 * "Reclaim" itds that were marked as RECLAIM.
 */
static void
ehci_reclaim_isoc(
	ehci_state_t		*ehcip,
	ehci_isoc_xwrapper_t	*itw,
	ehci_itd_t		*itd,
	ehci_pipe_private_t	*pp)
{
	USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_reclaim_isoc: itd = 0x%p", (void *)itd);

	/*
	 * These are itds that were marked "RECLAIM"
	 * by the pipe cleanup.
	 *
	 * Decrement the num_itds and the periodic in
	 * request count if necessary.
	 */
	if ((--itw->itw_num_itds == 0) && (itw->itw_curr_xfer_reqp)) {
		if (itw->itw_direction == USB_EP_DIR_IN) {

			pp->pp_cur_periodic_req_cnt--;

			ehci_deallocate_isoc_in_resource(ehcip, pp, itw);
		} else {
			ehci_hcdi_isoc_callback(pp->pp_pipe_handle, itw,
			    USB_CR_FLUSHED);
		}
	}

	/* Deallocate this transfer descriptor */
	ehci_deallocate_itd(ehcip, itw, itd);
}


/*
 * ehci_start_isoc_polling:
 *
 * Insert the number of periodic requests corresponding to polling
 * interval as calculated during pipe open.
 */
int
ehci_start_isoc_polling(
	ehci_state_t		*ehcip,
	usba_pipe_handle_data_t	*ph,
	usb_flags_t		flags)
{
	ehci_pipe_private_t	*pp = (ehci_pipe_private_t *)ph->p_hcd_private;
	ehci_isoc_xwrapper_t	*itw_list, *itw;
	int			i, total_itws;
	int			error = USB_SUCCESS;

	USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_start_isoc_polling:");

	/* Allocate all the necessary resources for the IN transfer */
	itw_list = NULL;
	total_itws = pp->pp_max_periodic_req_cnt - pp->pp_cur_periodic_req_cnt;
	for (i = 0; i < total_itws; i += 1) {
		itw = ehci_allocate_isoc_resources(ehcip, ph, NULL, flags);
		if (itw == NULL) {
			error = USB_NO_RESOURCES;
			/* There are not enough resources deallocate the ITWs */
			itw = itw_list;
			while (itw != NULL) {
				itw_list = itw->itw_next;
				ehci_deallocate_isoc_in_resource(
				    ehcip, pp, itw);
				ehci_deallocate_itw(ehcip, pp, itw);
				itw = itw_list;
			}

			return (error);
		} else {
			if (itw_list == NULL) {
				itw_list = itw;
			}
		}
	}

	i = 0;
	while (pp->pp_cur_periodic_req_cnt < pp->pp_max_periodic_req_cnt) {

		USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
		    "ehci_start_isoc_polling: max = %d curr = %d itw = %p:",
		    pp->pp_max_periodic_req_cnt, pp->pp_cur_periodic_req_cnt,
		    (void *)itw_list);

		itw = itw_list;
		itw_list = itw->itw_next;

		error = ehci_insert_isoc_req(ehcip, pp, itw, flags);

		if (error == USB_SUCCESS) {
			pp->pp_cur_periodic_req_cnt++;
		} else {
			/*
			 * Deallocate the remaining tw
			 * The current tw should have already been deallocated
			 */
			itw = itw_list;
			while (itw != NULL) {
				itw_list = itw->itw_next;
				ehci_deallocate_isoc_in_resource(
				    ehcip, pp, itw);
				ehci_deallocate_itw(ehcip, pp, itw);
				itw = itw_list;
			}
			/*
			 * If this is the first req return an error.
			 * Otherwise return success.
			 */
			if (i != 0) {
				error = USB_SUCCESS;
			}

			break;
		}
		i++;
	}

	return (error);
}


/*
 * Isochronronous handling functions.
 */
/*
 * ehci_traverse_active_isoc_list:
 */
void
ehci_traverse_active_isoc_list(
	ehci_state_t		*ehcip)
{
	ehci_isoc_xwrapper_t	*curr_itw;
	ehci_itd_t		*curr_itd, *next_itd;
	uint_t			state;
	ehci_pipe_private_t	*pp;

	USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_traverse_active_isoc_list:");

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/* Sync ITD pool */
	Sync_ITD_Pool(ehcip);

	/* Traverse the list of done itds */
	curr_itd = ehci_create_done_itd_list(ehcip);
	USB_DPRINTF_L3(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_traverse_active_isoc_list: current itd = 0x%p",
	    (void *)curr_itd);

	while (curr_itd) {
		/* Save the next_itd */
		next_itd = ehci_itd_iommu_to_cpu(ehcip,
		    Get_ITD(curr_itd->itd_next_active_itd));

		/* Get the transfer wrapper and the pp */
		curr_itw = (ehci_isoc_xwrapper_t *)EHCI_LOOKUP_ID(
		    (uint32_t)Get_ITD(curr_itd->itd_trans_wrapper));
		pp = curr_itw->itw_pipe_private;

		if (curr_itw->itw_port_status == USBA_HIGH_SPEED_DEV) {
			ehci_print_itd(ehcip, curr_itd);
		} else {
			ehci_print_sitd(ehcip, curr_itd);
		}

		/* Get the ITD state */
		state = Get_ITD(curr_itd->itd_state);

		/* Only process the ITDs marked as active. */
		if (state == EHCI_ITD_ACTIVE) {
			ehci_parse_isoc_error(ehcip, curr_itw, curr_itd);
			ehci_handle_isoc(ehcip, curr_itw, curr_itd);
		} else {
			ASSERT(state == EHCI_ITD_RECLAIM);
			ehci_reclaim_isoc(ehcip, curr_itw, curr_itd, pp);
		}

		/*
		 * Deallocate the transfer wrapper if there are no more
		 * ITD's for the transfer wrapper.  ehci_deallocate_itw()
		 * will  not deallocate the tw for a periodic in endpoint
		 * since it will always have a ITD attached to it.
		 */
		ehci_deallocate_itw(ehcip, pp, curr_itw);

		/* Check any ISOC is waiting for transfers completion event */
		if (pp->pp_itw_head == NULL) {
			USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
			    "ehci_traverse_active_isoc_list: "
			    "Sent transfers completion event pp = 0x%p",
			    (void *)pp);
			cv_signal(&pp->pp_xfer_cmpl_cv);
		}

		curr_itd = next_itd;

		USB_DPRINTF_L3(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_traverse_active_isoc_list: state = 0x%x "
		    "pp = 0x%p itw = 0x%p itd = 0x%p next_itd = 0x%p",
		    state, (void *)pp, (void *)curr_itw, (void *)curr_itd,
		    (void *)next_itd);
	}
}


static void
ehci_handle_isoc(
	ehci_state_t		*ehcip,
	ehci_isoc_xwrapper_t	*itw,
	ehci_itd_t		*itd)
{
	ehci_pipe_private_t	*pp;	/* Pipe private field */

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_handle_isoc:");

	/* Obtain the pipe private structure */
	pp = itw->itw_pipe_private;

	ehci_handle_itd(ehcip, pp, itw, itd, itw->itw_handle_callback_value);
}


/*
 * ehci_handle_itd:
 *
 * Handle an (split) isochronous transfer descriptor.
 * This function will deallocate the itd from the list as well.
 */
/* ARGSUSED */
static void
ehci_handle_itd(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_isoc_xwrapper_t	*itw,
	ehci_itd_t		*itd,
	void			*tw_handle_callback_value)
{
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;
	usb_isoc_req_t		*curr_isoc_reqp =
	    (usb_isoc_req_t *)itw->itw_curr_xfer_reqp;
	int			error = USB_SUCCESS;
	int			i, index;

	USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_handle_itd: pp=0x%p itw=0x%p itd=0x%p "
	    "isoc_reqp=0%p data=0x%p", (void *)pp, (void *)itw, (void *)itd,
	    (void *)curr_isoc_reqp, (void *)curr_isoc_reqp->isoc_data);

	if (itw->itw_port_status == USBA_HIGH_SPEED_DEV &&
	    curr_isoc_reqp != NULL) {

		for (i = 0; i < EHCI_ITD_CTRL_LIST_SIZE; i++) {

			index = Get_ITD_INDEX(itd, i);
			if (index == EHCI_ITD_UNUSED_INDEX) {

				continue;
			}
			curr_isoc_reqp->
			    isoc_pkt_descr[index].isoc_pkt_actual_length =
			    (Get_ITD_BODY(itd, i) & EHCI_ITD_XFER_LENGTH) >> 16;
		}
	}

	/*
	 * Decrement the ITDs counter and check whether all the isoc
	 * data has been send or received. If ITDs counter reaches
	 * zero then inform client driver about completion current
	 * isoc request. Otherwise wait for completion of other isoc
	 * ITDs or transactions on this pipe.
	 */
	if (--itw->itw_num_itds != 0) {
		/* Deallocate this transfer descriptor */
		ehci_deallocate_itd(ehcip, itw, itd);

		return;
	}

	/*
	 * If this is a isoc in pipe, return the data to the client.
	 * For a isoc out pipe, there is no need to do anything.
	 */
	if (itw->itw_direction == USB_EP_DIR_OUT) {
		USB_DPRINTF_L3(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_handle_itd: Isoc out pipe, isoc_reqp=0x%p, data=0x%p",
		    (void *)curr_isoc_reqp, (void *)curr_isoc_reqp->isoc_data);

		/* Do the callback */
		ehci_hcdi_isoc_callback(ph, itw, USB_CR_OK);

		/* Deallocate this transfer descriptor */
		ehci_deallocate_itd(ehcip, itw, itd);

		return;
	}

	/* Decrement number of IN isochronous request count */
	pp->pp_cur_periodic_req_cnt--;

	USB_DPRINTF_L3(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_handle_itd: pp_cur_periodic_req_cnt = 0x%x ",
	    pp->pp_cur_periodic_req_cnt);

	/* Call ehci_sendup_itd_message to send message to upstream */
	ehci_sendup_itd_message(ehcip, pp, itw, itd, USB_CR_OK);

	/* Deallocate this transfer descriptor */
	ehci_deallocate_itd(ehcip, itw, itd);

	/*
	 * If isochronous pipe state is still active, insert next isochronous
	 * request into the Host Controller's isochronous list.
	 */
	if (pp->pp_state != EHCI_PIPE_STATE_ACTIVE) {

		return;
	}

	if ((error = ehci_allocate_isoc_in_resource(ehcip, pp, itw, 0)) ==
	    USB_SUCCESS) {
		curr_isoc_reqp = (usb_isoc_req_t *)itw->itw_curr_xfer_reqp;

		ASSERT(curr_isoc_reqp != NULL);

		itw->itw_num_itds = ehci_calc_num_itds(itw,
		    curr_isoc_reqp->isoc_pkts_count);

		if (ehci_allocate_itds_for_itw(ehcip, itw, itw->itw_num_itds) !=
		    USB_SUCCESS) {
			ehci_deallocate_isoc_in_resource(ehcip, pp, itw);
			itw->itw_num_itds = 0;
			error = USB_FAILURE;
		}
	}

	if ((error != USB_SUCCESS) ||
	    (ehci_insert_isoc_req(ehcip, pp, itw, 0) != USB_SUCCESS)) {
		/*
		 * Set pipe state to stop polling and error to no
		 * resource. Don't insert any more isoch polling
		 * requests.
		 */
		pp->pp_state = EHCI_PIPE_STATE_STOP_POLLING;
		pp->pp_error = USB_CR_NO_RESOURCES;

	} else {
		/* Increment number of IN isochronous request count */
		pp->pp_cur_periodic_req_cnt++;

		ASSERT(pp->pp_cur_periodic_req_cnt ==
		    pp->pp_max_periodic_req_cnt);
	}
}


/*
 * ehci_sendup_qtd_message:
 *	copy data, if necessary and do callback
 */
/* ARGSUSED */
static void
ehci_sendup_itd_message(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_isoc_xwrapper_t	*itw,
	ehci_itd_t		*td,
	usb_cr_t		error)
{
	usb_isoc_req_t		*isoc_reqp = itw->itw_curr_xfer_reqp;
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;
	size_t			length;
	uchar_t			*buf;
	mblk_t			*mp;

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_sendup_itd_message:");

	ASSERT(itw != NULL);

	length = itw->itw_length;

	/* Copy the data into the mblk_t */
	buf = (uchar_t *)itw->itw_buf;

	USB_DPRINTF_L3(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_sendup_itd_message: length %ld error %d", length, error);

	/* Get the message block */
	mp = isoc_reqp->isoc_data;

	ASSERT(mp != NULL);

	if (length) {
		/* Sync IO buffer */
		Sync_IO_Buffer(itw->itw_dmahandle, length);

		/* Copy the data into the message */
		ddi_rep_get8(itw->itw_accesshandle,
		    mp->b_rptr, buf, length, DDI_DEV_AUTOINCR);

		/* Increment the write pointer */
		mp->b_wptr = mp->b_wptr + length;
	} else {
		USB_DPRINTF_L3(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_sendup_itd_message: Zero length packet");
	}

	ehci_hcdi_isoc_callback(ph, itw, error);
}


/*
 * ehci_hcdi_isoc_callback:
 *
 * Convenience wrapper around usba_hcdi_cb() other than root hub.
 */
void
ehci_hcdi_isoc_callback(
	usba_pipe_handle_data_t	*ph,
	ehci_isoc_xwrapper_t	*itw,
	usb_cr_t		completion_reason)
{
	ehci_state_t		*ehcip = ehci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	ehci_pipe_private_t	*pp = (ehci_pipe_private_t *)ph->p_hcd_private;
	usb_opaque_t		curr_xfer_reqp;
	uint_t			pipe_state = 0;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ehcip->ehci_log_hdl,
	    "ehci_hcdi_isoc_callback: ph = 0x%p, itw = 0x%p, cr = 0x%x",
	    (void *)ph, (void *)itw, completion_reason);

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/* Set the pipe state as per completion reason */
	switch (completion_reason) {
	case USB_CR_OK:
		pipe_state = pp->pp_state;
		break;
	case USB_CR_NO_RESOURCES:
	case USB_CR_NOT_SUPPORTED:
	case USB_CR_PIPE_RESET:
	case USB_CR_STOPPED_POLLING:
		pipe_state = EHCI_PIPE_STATE_IDLE;
		break;
	case USB_CR_PIPE_CLOSING:
		break;
	}

	pp->pp_state = pipe_state;

	if (itw && itw->itw_curr_xfer_reqp) {
		curr_xfer_reqp = (usb_opaque_t)itw->itw_curr_xfer_reqp;
		itw->itw_curr_xfer_reqp = NULL;
	} else {
		ASSERT(pp->pp_client_periodic_in_reqp != NULL);

		curr_xfer_reqp = pp->pp_client_periodic_in_reqp;
		pp->pp_client_periodic_in_reqp = NULL;
	}

	ASSERT(curr_xfer_reqp != NULL);

	mutex_exit(&ehcip->ehci_int_mutex);

	usba_hcdi_cb(ph, curr_xfer_reqp, completion_reason);

	mutex_enter(&ehcip->ehci_int_mutex);
}
