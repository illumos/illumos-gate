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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * EHCI Host Controller Driver (EHCI)
 *
 * The EHCI driver is a software driver which interfaces to the Universal
 * Serial Bus layer (USBA) and the Host Controller (HC). The interface to
 * the Host Controller is defined by the EHCI Host Controller Interface.
 *
 * This module contains the main EHCI driver code which handles all USB
 * transfers, bandwidth allocations and other general functionalities.
 */

#include <sys/usb/hcd/ehci/ehcid.h>
#include <sys/usb/hcd/ehci/ehci_intr.h>
#include <sys/usb/hcd/ehci/ehci_util.h>
#include <sys/usb/hcd/ehci/ehci_isoch.h>

/* Adjustable variables for the size of the pools */
extern int ehci_qh_pool_size;
extern int ehci_qtd_pool_size;


/* Endpoint Descriptor (QH) related functions */
ehci_qh_t	*ehci_alloc_qh(
				ehci_state_t		*ehcip,
				usba_pipe_handle_data_t	*ph,
				uint_t			flag);
static void	ehci_unpack_endpoint(
				ehci_state_t		*ehcip,
				usba_pipe_handle_data_t	*ph,
				ehci_qh_t		*qh);
void		ehci_insert_qh(
				ehci_state_t		*ehcip,
				usba_pipe_handle_data_t	*ph);
static void	ehci_insert_async_qh(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp);
static void	ehci_insert_intr_qh(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp);
static void	ehci_modify_qh_status_bit(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				halt_bit_t		action);
static void	ehci_halt_hs_qh(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				ehci_qh_t		*qh);
static void	ehci_halt_fls_ctrl_and_bulk_qh(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				ehci_qh_t		*qh);
static void	ehci_clear_tt_buffer(
				ehci_state_t		*ehcip,
				usba_pipe_handle_data_t	*ph,
				ehci_qh_t		*qh);
static void	ehci_halt_fls_intr_qh(
				ehci_state_t		*ehcip,
				ehci_qh_t		*qh);
void		ehci_remove_qh(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				boolean_t		reclaim);
static void	ehci_remove_async_qh(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				boolean_t		reclaim);
static void	ehci_remove_intr_qh(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				boolean_t		reclaim);
static void	ehci_insert_qh_on_reclaim_list(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp);
void		ehci_deallocate_qh(
				ehci_state_t		*ehcip,
				ehci_qh_t		*old_qh);
uint32_t	ehci_qh_cpu_to_iommu(
				ehci_state_t		*ehcip,
				ehci_qh_t		*addr);
ehci_qh_t	*ehci_qh_iommu_to_cpu(
				ehci_state_t		*ehcip,
				uintptr_t		addr);

/* Transfer Descriptor (QTD) related functions */
static int	ehci_initialize_dummy(
				ehci_state_t		*ehcip,
				ehci_qh_t		*qh);
ehci_trans_wrapper_t *ehci_allocate_ctrl_resources(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				usb_ctrl_req_t		*ctrl_reqp,
				usb_flags_t		usb_flags);
void		ehci_insert_ctrl_req(
				ehci_state_t		*ehcip,
				usba_pipe_handle_data_t	*ph,
				usb_ctrl_req_t		*ctrl_reqp,
				ehci_trans_wrapper_t	*tw,
				usb_flags_t		usb_flags);
ehci_trans_wrapper_t *ehci_allocate_bulk_resources(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				usb_bulk_req_t		*bulk_reqp,
				usb_flags_t		usb_flags);
void		ehci_insert_bulk_req(
				ehci_state_t		*ehcip,
				usba_pipe_handle_data_t	*ph,
				usb_bulk_req_t		*bulk_reqp,
				ehci_trans_wrapper_t	*tw,
				usb_flags_t		flags);
int		ehci_start_periodic_pipe_polling(
				ehci_state_t		*ehcip,
				usba_pipe_handle_data_t	*ph,
				usb_opaque_t		periodic_in_reqp,
				usb_flags_t		flags);
static int	ehci_start_pipe_polling(
				ehci_state_t		*ehcip,
				usba_pipe_handle_data_t	*ph,
				usb_flags_t		flags);
static int	ehci_start_intr_polling(
				ehci_state_t		*ehcip,
				usba_pipe_handle_data_t	*ph,
				usb_flags_t		flags);
static void	ehci_set_periodic_pipe_polling(
				ehci_state_t		*ehcip,
				usba_pipe_handle_data_t	*ph);
ehci_trans_wrapper_t *ehci_allocate_intr_resources(
				ehci_state_t		*ehcip,
				usba_pipe_handle_data_t	*ph,
				usb_intr_req_t		*intr_reqp,
				usb_flags_t		usb_flags);
void		ehci_insert_intr_req(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				ehci_trans_wrapper_t	*tw,
				usb_flags_t		flags);
int		ehci_stop_periodic_pipe_polling(
				ehci_state_t		*ehcip,
				usba_pipe_handle_data_t	*ph,
				usb_flags_t		flags);
int		ehci_insert_qtd(
				ehci_state_t		*ehcip,
				uint32_t		qtd_ctrl,
				size_t			qtd_dma_offs,
				size_t			qtd_length,
				uint32_t		qtd_ctrl_phase,
				ehci_pipe_private_t	*pp,
				ehci_trans_wrapper_t	*tw);
static ehci_qtd_t *ehci_allocate_qtd_from_pool(
				ehci_state_t		*ehcip);
static void	ehci_fill_in_qtd(
				ehci_state_t		*ehcip,
				ehci_qtd_t		*qtd,
				uint32_t		qtd_ctrl,
				size_t			qtd_dma_offs,
				size_t			qtd_length,
				uint32_t		qtd_ctrl_phase,
				ehci_pipe_private_t	*pp,
				ehci_trans_wrapper_t	*tw);
static void	ehci_insert_qtd_on_tw(
				ehci_state_t		*ehcip,
				ehci_trans_wrapper_t	*tw,
				ehci_qtd_t		*qtd);
static void	ehci_insert_qtd_into_active_qtd_list(
				ehci_state_t		*ehcip,
				ehci_qtd_t		*curr_qtd);
void		ehci_remove_qtd_from_active_qtd_list(
				ehci_state_t		*ehcip,
				ehci_qtd_t		*curr_qtd);
static void	ehci_traverse_qtds(
				ehci_state_t		*ehcip,
				usba_pipe_handle_data_t	*ph);
void		ehci_deallocate_qtd(
				ehci_state_t		*ehcip,
				ehci_qtd_t		*old_qtd);
uint32_t	ehci_qtd_cpu_to_iommu(
				ehci_state_t		*ehcip,
				ehci_qtd_t		*addr);
ehci_qtd_t	*ehci_qtd_iommu_to_cpu(
				ehci_state_t		*ehcip,
				uintptr_t		addr);

/* Transfer Wrapper (TW) functions */
static ehci_trans_wrapper_t  *ehci_create_transfer_wrapper(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				size_t			length,
				uint_t			usb_flags);
int		ehci_allocate_tds_for_tw(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				ehci_trans_wrapper_t	*tw,
				size_t			qtd_count);
static ehci_trans_wrapper_t  *ehci_allocate_tw_resources(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				size_t			length,
				usb_flags_t		usb_flags,
				size_t			td_count);
static void	ehci_free_tw_td_resources(
				ehci_state_t		*ehcip,
				ehci_trans_wrapper_t	*tw);
static void	ehci_start_xfer_timer(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				ehci_trans_wrapper_t	*tw);
void		ehci_stop_xfer_timer(
				ehci_state_t		*ehcip,
				ehci_trans_wrapper_t	*tw,
				uint_t			flag);
static void	ehci_xfer_timeout_handler(void		*arg);
static void	ehci_remove_tw_from_timeout_list(
				ehci_state_t		*ehcip,
				ehci_trans_wrapper_t	*tw);
static void	ehci_start_timer(ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp);
void		ehci_deallocate_tw(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				ehci_trans_wrapper_t	*tw);
void		ehci_free_dma_resources(
				ehci_state_t		*ehcip,
				usba_pipe_handle_data_t	*ph);
static void	ehci_free_tw(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				ehci_trans_wrapper_t	*tw);

/* Miscellaneous functions */
int		ehci_allocate_intr_in_resource(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				ehci_trans_wrapper_t	*tw,
				usb_flags_t		flags);
void		ehci_pipe_cleanup(
				ehci_state_t		*ehcip,
				usba_pipe_handle_data_t	*ph);
static void	ehci_wait_for_transfers_completion(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp);
void		ehci_check_for_transfers_completion(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp);
static void	ehci_save_data_toggle(
				ehci_state_t		*ehcip,
				usba_pipe_handle_data_t	*ph);
void		ehci_restore_data_toggle(
				ehci_state_t		*ehcip,
				usba_pipe_handle_data_t	*ph);
void		ehci_handle_outstanding_requests(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp);
void		ehci_deallocate_intr_in_resource(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				ehci_trans_wrapper_t	*tw);
void		ehci_do_client_periodic_in_req_callback(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp,
				usb_cr_t		completion_reason);
void		ehci_hcdi_callback(
				usba_pipe_handle_data_t	*ph,
				ehci_trans_wrapper_t	*tw,
				usb_cr_t		completion_reason);


/*
 * Endpoint Descriptor (QH) manipulations functions
 */

/*
 * ehci_alloc_qh:
 *
 * Allocate an endpoint descriptor (QH)
 *
 * NOTE: This function is also called from POLLED MODE.
 */
ehci_qh_t *
ehci_alloc_qh(
	ehci_state_t		*ehcip,
	usba_pipe_handle_data_t	*ph,
	uint_t			flag)
{
	int			i, state;
	ehci_qh_t		*qh;

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ehcip->ehci_log_hdl,
	    "ehci_alloc_qh: ph = 0x%p flag = 0x%x", (void *)ph, flag);

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/*
	 * If this is for a ISOC endpoint return null.
	 * Isochronous uses ITD put directly onto the PFL.
	 */
	if (ph) {
		if (EHCI_ISOC_ENDPOINT((&ph->p_ep))) {

			return (NULL);
		}
	}

	/*
	 * The first 63 endpoints in the Endpoint Descriptor (QH)
	 * buffer pool are reserved for building interrupt lattice
	 * tree. Search for a blank endpoint descriptor in the QH
	 * buffer pool.
	 */
	for (i = EHCI_NUM_STATIC_NODES; i < ehci_qh_pool_size; i ++) {
		state = Get_QH(ehcip->ehci_qh_pool_addr[i].qh_state);

		if (state == EHCI_QH_FREE) {
			break;
		}
	}

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ehcip->ehci_log_hdl,
	    "ehci_alloc_qh: Allocated %d", i);

	if (i == ehci_qh_pool_size) {
		USB_DPRINTF_L2(PRINT_MASK_ALLOC,  ehcip->ehci_log_hdl,
		    "ehci_alloc_qh: QH exhausted");

		return (NULL);
	} else {
		qh = &ehcip->ehci_qh_pool_addr[i];
		bzero((void *)qh, sizeof (ehci_qh_t));

		USB_DPRINTF_L4(PRINT_MASK_ALLOC, ehcip->ehci_log_hdl,
		    "ehci_alloc_qh: Allocated address 0x%p", (void *)qh);

		/* Check polled mode flag */
		if (flag == EHCI_POLLED_MODE_FLAG) {
			Set_QH(qh->qh_link_ptr, EHCI_QH_LINK_PTR_VALID);
			Set_QH(qh->qh_ctrl, EHCI_QH_CTRL_ED_INACTIVATE);
		}

		/* Unpack the endpoint descriptor into a control field */
		if (ph) {
			if ((ehci_initialize_dummy(ehcip,
			    qh)) == USB_NO_RESOURCES) {

				Set_QH(qh->qh_state, EHCI_QH_FREE);

				return (NULL);
			}

			ehci_unpack_endpoint(ehcip, ph, qh);

			Set_QH(qh->qh_curr_qtd, 0);
			Set_QH(qh->qh_alt_next_qtd,
			    EHCI_QH_ALT_NEXT_QTD_PTR_VALID);

			/* Change QH's state Active */
			Set_QH(qh->qh_state, EHCI_QH_ACTIVE);
		} else {
			Set_QH(qh->qh_status, EHCI_QH_STS_HALTED);

			/* Change QH's state Static */
			Set_QH(qh->qh_state, EHCI_QH_STATIC);
		}

		ehci_print_qh(ehcip, qh);

		return (qh);
	}
}


/*
 * ehci_unpack_endpoint:
 *
 * Unpack the information in the pipe handle and create the first byte
 * of the Host Controller's (HC) Endpoint Descriptor (QH).
 */
static void
ehci_unpack_endpoint(
	ehci_state_t		*ehcip,
	usba_pipe_handle_data_t	*ph,
	ehci_qh_t		*qh)
{
	usb_ep_descr_t		*endpoint = &ph->p_ep;
	uint_t			maxpacketsize, addr, xactions;
	uint_t			ctrl = 0, status = 0, split_ctrl = 0;
	usb_port_status_t	usb_port_status;
	usba_device_t		*usba_device = ph->p_usba_device;
	ehci_pipe_private_t	*pp = (ehci_pipe_private_t *)ph->p_hcd_private;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_unpack_endpoint:");

	mutex_enter(&usba_device->usb_mutex);
	ctrl = usba_device->usb_addr;
	usb_port_status = usba_device->usb_port_status;
	mutex_exit(&usba_device->usb_mutex);

	addr = endpoint->bEndpointAddress;

	/* Assign the endpoint's address */
	ctrl |= ((addr & USB_EP_NUM_MASK) << EHCI_QH_CTRL_ED_NUMBER_SHIFT);

	/* Assign the speed */
	switch (usb_port_status) {
	case USBA_LOW_SPEED_DEV:
		ctrl |= EHCI_QH_CTRL_ED_LOW_SPEED;
		break;
	case USBA_FULL_SPEED_DEV:
		ctrl |= EHCI_QH_CTRL_ED_FULL_SPEED;
		break;
	case USBA_HIGH_SPEED_DEV:
		ctrl |= EHCI_QH_CTRL_ED_HIGH_SPEED;
		break;
	}

	switch (endpoint->bmAttributes & USB_EP_ATTR_MASK) {
	case USB_EP_ATTR_CONTROL:
		/* Assign data toggle information */
		ctrl |= EHCI_QH_CTRL_DATA_TOGGLE;

		if (usb_port_status != USBA_HIGH_SPEED_DEV) {
			ctrl |= EHCI_QH_CTRL_CONTROL_ED_FLAG;
		}
		/* FALLTHRU */
	case USB_EP_ATTR_BULK:
		/* Maximum nak counter */
		ctrl |= EHCI_QH_CTRL_MAX_NC;

		if (usb_port_status == USBA_HIGH_SPEED_DEV) {
			/*
			 * Perform ping before executing control
			 * and bulk transactions.
			 */
			status = EHCI_QH_STS_DO_PING;
		}
		break;
	case USB_EP_ATTR_INTR:
		/* Set start split mask */
		split_ctrl = (pp->pp_smask & EHCI_QH_SPLIT_CTRL_INTR_MASK);

		/*
		 * Set complete split mask for low/full speed
		 * usb devices.
		 */
		if (usb_port_status != USBA_HIGH_SPEED_DEV) {
			split_ctrl |= ((pp->pp_cmask <<
			    EHCI_QH_SPLIT_CTRL_COMP_SHIFT) &
			    EHCI_QH_SPLIT_CTRL_COMP_MASK);
		}
		break;
	}

	/* Get the max transactions per microframe */
	xactions = (endpoint->wMaxPacketSize &
	    USB_EP_MAX_XACTS_MASK) >>  USB_EP_MAX_XACTS_SHIFT;

	switch (xactions) {
	case 0:
		split_ctrl |= EHCI_QH_SPLIT_CTRL_1_XACTS;
		break;
	case 1:
		split_ctrl |= EHCI_QH_SPLIT_CTRL_2_XACTS;
		break;
	case 2:
		split_ctrl |= EHCI_QH_SPLIT_CTRL_3_XACTS;
		break;
	default:
		split_ctrl |= EHCI_QH_SPLIT_CTRL_1_XACTS;
		break;
	}

	/*
	 * For low/full speed devices, program high speed hub
	 * address and port number.
	 */
	if (usb_port_status != USBA_HIGH_SPEED_DEV) {
		mutex_enter(&usba_device->usb_mutex);
		split_ctrl |= ((usba_device->usb_hs_hub_addr
		    << EHCI_QH_SPLIT_CTRL_HUB_ADDR_SHIFT) &
		    EHCI_QH_SPLIT_CTRL_HUB_ADDR);

		split_ctrl |= ((usba_device->usb_hs_hub_port
		    << EHCI_QH_SPLIT_CTRL_HUB_PORT_SHIFT) &
		    EHCI_QH_SPLIT_CTRL_HUB_PORT);

		mutex_exit(&usba_device->usb_mutex);

		/* Set start split transaction state */
		status = EHCI_QH_STS_DO_START_SPLIT;
	}

	/* Assign endpoint's maxpacketsize */
	maxpacketsize = endpoint->wMaxPacketSize & USB_EP_MAX_PKTSZ_MASK;
	maxpacketsize = maxpacketsize << EHCI_QH_CTRL_MAXPKTSZ_SHIFT;
	ctrl |= (maxpacketsize & EHCI_QH_CTRL_MAXPKTSZ);

	Set_QH(qh->qh_ctrl, ctrl);
	Set_QH(qh->qh_split_ctrl, split_ctrl);
	Set_QH(qh->qh_status, status);
}


/*
 * ehci_insert_qh:
 *
 * Add the Endpoint Descriptor (QH) into the Host Controller's
 * (HC) appropriate endpoint list.
 */
void
ehci_insert_qh(
	ehci_state_t		*ehcip,
	usba_pipe_handle_data_t	*ph)
{
	ehci_pipe_private_t	*pp = (ehci_pipe_private_t *)ph->p_hcd_private;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_insert_qh: qh=0x%p", (void *)pp->pp_qh);

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	switch (ph->p_ep.bmAttributes & USB_EP_ATTR_MASK) {
	case USB_EP_ATTR_CONTROL:
	case USB_EP_ATTR_BULK:
		ehci_insert_async_qh(ehcip, pp);
		ehcip->ehci_open_async_count++;
		break;
	case USB_EP_ATTR_INTR:
		ehci_insert_intr_qh(ehcip, pp);
		ehcip->ehci_open_periodic_count++;
		break;
	case USB_EP_ATTR_ISOCH:
		/* ISOCH does not use QH, don't do anything but update count */
		ehcip->ehci_open_periodic_count++;
		break;
	}
}


/*
 * ehci_insert_async_qh:
 *
 * Insert a control/bulk endpoint into the Host Controller's (HC)
 * Asynchronous schedule endpoint list.
 */
static void
ehci_insert_async_qh(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp)
{
	ehci_qh_t		*qh = pp->pp_qh;
	ehci_qh_t		*async_head_qh;
	ehci_qh_t		*next_qh;
	uintptr_t		qh_addr;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_insert_async_qh:");

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/* Make sure this QH is not already in the list */
	ASSERT((Get_QH(qh->qh_prev) & EHCI_QH_LINK_PTR) == 0);

	qh_addr = ehci_qh_cpu_to_iommu(ehcip, qh);

	/* Obtain a ptr to the head of the Async schedule list */
	async_head_qh = ehcip->ehci_head_of_async_sched_list;

	if (async_head_qh == NULL) {
		/* Set this QH to be the "head" of the circular list */
		Set_QH(qh->qh_ctrl,
		    (Get_QH(qh->qh_ctrl) | EHCI_QH_CTRL_RECLAIM_HEAD));

		/* Set new QH's link and previous pointer to itself */
		Set_QH(qh->qh_link_ptr, qh_addr | EHCI_QH_LINK_REF_QH);
		Set_QH(qh->qh_prev, qh_addr);

		ehcip->ehci_head_of_async_sched_list = qh;

		/* Set the head ptr to the new endpoint */
		Set_OpReg(ehci_async_list_addr, qh_addr);

		/*
		 * For some reason this register might get nulled out by
		 * the Uli M1575 South Bridge. To workaround the hardware
		 * problem, check the value after write and retry if the
		 * last write fails.
		 *
		 * If the ASYNCLISTADDR remains "stuck" after
		 * EHCI_MAX_RETRY retries, then the M1575 is broken
		 * and is stuck in an inconsistent state and is about
		 * to crash the machine with a trn_oor panic when it
		 * does a DMA read from 0x0.  It is better to panic
		 * now rather than wait for the trn_oor crash; this
		 * way Customer Service will have a clean signature
		 * that indicts the M1575 chip rather than a
		 * mysterious and hard-to-diagnose trn_oor panic.
		 */
		if ((ehcip->ehci_vendor_id == PCI_VENDOR_ULi_M1575) &&
		    (ehcip->ehci_device_id == PCI_DEVICE_ULi_M1575) &&
		    (qh_addr != Get_OpReg(ehci_async_list_addr))) {
			int retry = 0;

			Set_OpRegRetry(ehci_async_list_addr, qh_addr, retry);
			if (retry >= EHCI_MAX_RETRY)
				cmn_err(CE_PANIC, "ehci_insert_async_qh:"
				    " ASYNCLISTADDR write failed.");

			USB_DPRINTF_L2(PRINT_MASK_ATTA, ehcip->ehci_log_hdl,
			    "ehci_insert_async_qh: ASYNCLISTADDR "
			    "write failed, retry=%d", retry);
		}
	} else {
		ASSERT(Get_QH(async_head_qh->qh_ctrl) &
		    EHCI_QH_CTRL_RECLAIM_HEAD);

		/* Ensure this QH's "H" bit is not set */
		Set_QH(qh->qh_ctrl,
		    (Get_QH(qh->qh_ctrl) & ~EHCI_QH_CTRL_RECLAIM_HEAD));

		next_qh = ehci_qh_iommu_to_cpu(ehcip,
		    Get_QH(async_head_qh->qh_link_ptr) & EHCI_QH_LINK_PTR);

		/* Set new QH's link and previous pointers */
		Set_QH(qh->qh_link_ptr,
		    Get_QH(async_head_qh->qh_link_ptr) | EHCI_QH_LINK_REF_QH);
		Set_QH(qh->qh_prev, ehci_qh_cpu_to_iommu(ehcip, async_head_qh));

		/* Set next QH's prev pointer */
		Set_QH(next_qh->qh_prev, ehci_qh_cpu_to_iommu(ehcip, qh));

		/* Set QH Head's link pointer points to new QH */
		Set_QH(async_head_qh->qh_link_ptr,
		    qh_addr | EHCI_QH_LINK_REF_QH);
	}
}


/*
 * ehci_insert_intr_qh:
 *
 * Insert a interrupt endpoint into the Host Controller's (HC) interrupt
 * lattice tree.
 */
static void
ehci_insert_intr_qh(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp)
{
	ehci_qh_t		*qh = pp->pp_qh;
	ehci_qh_t		*next_lattice_qh, *lattice_qh;
	uint_t			hnode;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_insert_intr_qh:");

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/* Make sure this QH is not already in the list */
	ASSERT((Get_QH(qh->qh_prev) & EHCI_QH_LINK_PTR) == 0);

	/*
	 * The appropriate high speed node was found
	 * during the opening of the pipe.
	 */
	hnode = pp->pp_pnode;

	/* Find the lattice endpoint */
	lattice_qh = &ehcip->ehci_qh_pool_addr[hnode];

	/* Find the next lattice endpoint */
	next_lattice_qh = ehci_qh_iommu_to_cpu(
	    ehcip, (Get_QH(lattice_qh->qh_link_ptr) & EHCI_QH_LINK_PTR));

	/* Update the previous pointer */
	Set_QH(qh->qh_prev, ehci_qh_cpu_to_iommu(ehcip, lattice_qh));

	/* Check next_lattice_qh value */
	if (next_lattice_qh) {
		/* Update this qh to point to the next one in the lattice */
		Set_QH(qh->qh_link_ptr, Get_QH(lattice_qh->qh_link_ptr));

		/* Update the previous pointer of qh->qh_link_ptr */
		if (Get_QH(next_lattice_qh->qh_state) != EHCI_QH_STATIC) {
			Set_QH(next_lattice_qh->qh_prev,
			    ehci_qh_cpu_to_iommu(ehcip, qh));
		}
	} else {
		/* Update qh's link pointer to terminate periodic list */
		Set_QH(qh->qh_link_ptr,
		    (Get_QH(lattice_qh->qh_link_ptr) | EHCI_QH_LINK_PTR_VALID));
	}

	/* Insert this endpoint into the lattice */
	Set_QH(lattice_qh->qh_link_ptr,
	    (ehci_qh_cpu_to_iommu(ehcip, qh) | EHCI_QH_LINK_REF_QH));
}


/*
 * ehci_modify_qh_status_bit:
 *
 * Modify the halt bit on the Host Controller (HC) Endpoint Descriptor (QH).
 *
 * If several threads try to halt the same pipe, they will need to wait on
 * a condition variable.  Only one thread is allowed to halt or unhalt the
 * pipe at a time.
 *
 * Usually after a halt pipe, an unhalt pipe will follow soon after.  There
 * is an assumption that an Unhalt pipe will never occur without a halt pipe.
 */
static void
ehci_modify_qh_status_bit(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	halt_bit_t		action)
{
	ehci_qh_t		*qh = pp->pp_qh;
	uint_t			smask, eps, split_intr_qh;
	uint_t			status;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_modify_qh_status_bit: action=0x%x qh=0x%p",
	    action, (void *)qh);

	ehci_print_qh(ehcip, qh);

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/*
	 * If this pipe is in the middle of halting don't allow another
	 * thread to come in and modify the same pipe.
	 */
	while (pp->pp_halt_state & EHCI_HALT_STATE_HALTING) {

		cv_wait(&pp->pp_halt_cmpl_cv,
		    &ehcip->ehci_int_mutex);
	}

	/* Sync the QH QTD pool to get up to date information */
	Sync_QH_QTD_Pool(ehcip);


	if (action == CLEAR_HALT) {
		/*
		 * If the halt bit is to be cleared, just clear it.
		 * there shouldn't be any race condition problems.
		 * If the host controller reads the bit before the
		 * driver has a chance to set the bit, the bit will
		 * be reread on the next frame.
		 */
		Set_QH(qh->qh_ctrl,
		    (Get_QH(qh->qh_ctrl) & ~EHCI_QH_CTRL_ED_INACTIVATE));
		Set_QH(qh->qh_status,
		    Get_QH(qh->qh_status) & ~(EHCI_QH_STS_XACT_STATUS));

		goto success;
	}

	/* Halt the the QH, but first check to see if it is already halted */
	status = Get_QH(qh->qh_status);
	if (!(status & EHCI_QH_STS_HALTED)) {
		/* Indicate that this pipe is in the middle of halting. */
		pp->pp_halt_state |= EHCI_HALT_STATE_HALTING;

		/*
		 * Find out if this is an full/low speed interrupt endpoint.
		 * A non-zero Cmask indicates that this QH is an interrupt
		 * endpoint.  Check the endpoint speed to see if it is either
		 * FULL or LOW .
		 */
		smask = Get_QH(qh->qh_split_ctrl) &
		    EHCI_QH_SPLIT_CTRL_INTR_MASK;
		eps = Get_QH(qh->qh_ctrl) & EHCI_QH_CTRL_ED_SPEED;
		split_intr_qh = ((smask != 0) &&
		    (eps != EHCI_QH_CTRL_ED_HIGH_SPEED));

		if (eps == EHCI_QH_CTRL_ED_HIGH_SPEED) {
			ehci_halt_hs_qh(ehcip, pp, qh);
		} else {
			if (split_intr_qh) {
				ehci_halt_fls_intr_qh(ehcip, qh);
			} else {
				ehci_halt_fls_ctrl_and_bulk_qh(ehcip, pp, qh);
			}
		}

		/* Indicate that this pipe is not in the middle of halting. */
		pp->pp_halt_state &= ~EHCI_HALT_STATE_HALTING;
	}

	/* Sync the QH QTD pool again to get the most up to date information */
	Sync_QH_QTD_Pool(ehcip);

	ehci_print_qh(ehcip, qh);

	status = Get_QH(qh->qh_status);
	if (!(status & EHCI_QH_STS_HALTED)) {
		USB_DPRINTF_L1(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
		    "ehci_modify_qh_status_bit: Failed to halt qh=0x%p",
		    (void *)qh);

		ehci_print_qh(ehcip, qh);

		/* Set host controller soft state to error */
		ehcip->ehci_hc_soft_state = EHCI_CTLR_ERROR_STATE;

		ASSERT(status & EHCI_QH_STS_HALTED);
	}

success:
	/* Wake up threads waiting for this pipe to be halted. */
	cv_signal(&pp->pp_halt_cmpl_cv);
}


/*
 * ehci_halt_hs_qh:
 *
 * Halts all types of HIGH SPEED QHs.
 */
static void
ehci_halt_hs_qh(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_qh_t		*qh)
{
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_halt_hs_qh:");

	/* Remove this qh from the HCD's view, but do not reclaim it */
	ehci_remove_qh(ehcip, pp, B_FALSE);
	ehci_toggle_scheduler_on_pipe(ehcip);

	/*
	 * Wait for atleast one SOF, just in case the HCD is in the
	 * middle accessing this QH.
	 */
	(void) ehci_wait_for_sof(ehcip);

	/* Sync the QH QTD pool to get up to date information */
	Sync_QH_QTD_Pool(ehcip);

	/* Modify the status bit and halt this QH. */
	Set_QH(qh->qh_status,
	    ((Get_QH(qh->qh_status) &
	    ~(EHCI_QH_STS_ACTIVE)) | EHCI_QH_STS_HALTED));

	/* Insert this QH back into the HCD's view */
	ehci_insert_qh(ehcip, ph);
	ehci_toggle_scheduler_on_pipe(ehcip);
}


/*
 * ehci_halt_fls_ctrl_and_bulk_qh:
 *
 * Halts FULL/LOW Ctrl and Bulk QHs only.
 */
static void
ehci_halt_fls_ctrl_and_bulk_qh(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_qh_t		*qh)
{
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;
	uint_t			status, split_status, bytes_left;


	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_halt_fls_ctrl_and_bulk_qh:");

	/* Remove this qh from the HCD's view, but do not reclaim it */
	ehci_remove_qh(ehcip, pp, B_FALSE);
	ehci_toggle_scheduler_on_pipe(ehcip);

	/*
	 * Wait for atleast one SOF, just in case the HCD is in the
	 * middle accessing this QH.
	 */
	(void) ehci_wait_for_sof(ehcip);

	/* Sync the QH QTD pool to get up to date information */
	Sync_QH_QTD_Pool(ehcip);

	/* Modify the status bit and halt this QH. */
	Set_QH(qh->qh_status,
	    ((Get_QH(qh->qh_status) &
	    ~(EHCI_QH_STS_ACTIVE)) | EHCI_QH_STS_HALTED));

	/* Check to see if the QH was in the middle of a transaction */
	status = Get_QH(qh->qh_status);
	split_status = status & EHCI_QH_STS_SPLIT_XSTATE;
	bytes_left = status & EHCI_QH_STS_BYTES_TO_XFER;
	if ((split_status == EHCI_QH_STS_DO_COMPLETE_SPLIT) &&
	    (bytes_left != 0)) {
		/* send ClearTTBuffer to this device's parent 2.0 hub */
		ehci_clear_tt_buffer(ehcip, ph, qh);
	}

	/* Insert this QH back into the HCD's view */
	ehci_insert_qh(ehcip, ph);
	ehci_toggle_scheduler_on_pipe(ehcip);
}


/*
 * ehci_clear_tt_buffer
 *
 * This function will sent a Clear_TT_Buffer request to the pipe's
 * parent 2.0 hub.
 */
static void
ehci_clear_tt_buffer(
	ehci_state_t		*ehcip,
	usba_pipe_handle_data_t	*ph,
	ehci_qh_t		*qh)
{
	usba_device_t		*usba_device;
	usba_device_t		*hub_usba_device;
	usb_pipe_handle_t	hub_def_ph;
	usb_ep_descr_t		*eptd;
	uchar_t			attributes;
	uint16_t		wValue;
	usb_ctrl_setup_t	setup;
	usb_cr_t		completion_reason;
	usb_cb_flags_t		cb_flags;
	int			retry;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_clear_tt_buffer: ");

	/* Get some information about the current pipe */
	usba_device = ph->p_usba_device;
	eptd = &ph->p_ep;
	attributes = eptd->bmAttributes & USB_EP_ATTR_MASK;

	/*
	 * Create the wIndex for this request (usb spec 11.24.2.3)
	 * 3..0		Endpoint Number
	 * 10..4	Device Address
	 * 12..11	Endpoint Type
	 * 14..13	Reserved (must be 0)
	 * 15		Direction 1 = IN, 0 = OUT
	 */
	wValue = 0;
	if ((eptd->bEndpointAddress & USB_EP_DIR_MASK) == USB_EP_DIR_IN) {
		wValue |= 0x8000;
	}
	wValue |= attributes << 11;
	wValue |= (Get_QH(qh->qh_ctrl) & EHCI_QH_CTRL_DEVICE_ADDRESS) << 4;
	wValue |= (Get_QH(qh->qh_ctrl) & EHCI_QH_CTRL_ED_HIGH_SPEED) >>
	    EHCI_QH_CTRL_ED_NUMBER_SHIFT;

	mutex_exit(&ehcip->ehci_int_mutex);

	/* Manually fill in the request. */
	setup.bmRequestType = EHCI_CLEAR_TT_BUFFER_REQTYPE;
	setup.bRequest = EHCI_CLEAR_TT_BUFFER_BREQ;
	setup.wValue = wValue;
	setup.wIndex = 1;
	setup.wLength = 0;
	setup.attrs = USB_ATTRS_NONE;

	/* Get the usba_device of the parent 2.0 hub. */
	mutex_enter(&usba_device->usb_mutex);
	hub_usba_device = usba_device->usb_hs_hub_usba_dev;
	mutex_exit(&usba_device->usb_mutex);

	/* Get the default ctrl pipe for the parent 2.0 hub */
	mutex_enter(&hub_usba_device->usb_mutex);
	hub_def_ph = (usb_pipe_handle_t)&hub_usba_device->usb_ph_list[0];
	mutex_exit(&hub_usba_device->usb_mutex);

	for (retry = 0; retry < 3; retry++) {

		/* sync send the request to the default pipe */
		if (usb_pipe_ctrl_xfer_wait(
		    hub_def_ph,
		    &setup,
		    NULL,
		    &completion_reason, &cb_flags, 0) == USB_SUCCESS) {

			break;
		}

		USB_DPRINTF_L2(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
		    "ehci_clear_tt_buffer: Failed to clear tt buffer,"
		    "retry = %d, cr = %d, cb_flags = 0x%x\n",
		    retry, completion_reason, cb_flags);
	}

	if (retry >= 3) {
		char *path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		dev_info_t *dip = hub_usba_device->usb_dip;

		/*
		 * Ask the user to hotplug the 2.0 hub, to make sure that
		 * all the buffer is in sync since this command has failed.
		 */
		USB_DPRINTF_L0(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
		    "Error recovery failure: Please hotplug the 2.0 hub at"
		    "%s", ddi_pathname(dip, path));

		kmem_free(path, MAXPATHLEN);
	}

	mutex_enter(&ehcip->ehci_int_mutex);
}

/*
 * ehci_halt_fls_intr_qh:
 *
 * Halts FULL/LOW speed Intr QHs.
 */
static void
ehci_halt_fls_intr_qh(
	ehci_state_t		*ehcip,
	ehci_qh_t		*qh)
{
	usb_frame_number_t	starting_frame;
	usb_frame_number_t	frames_past;
	uint_t			status, i;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_halt_fls_intr_qh:");

	/*
	 * Ask the HC to deactivate the QH in a
	 * full/low periodic QH.
	 */
	Set_QH(qh->qh_ctrl,
	    (Get_QH(qh->qh_ctrl) | EHCI_QH_CTRL_ED_INACTIVATE));

	starting_frame = ehci_get_current_frame_number(ehcip);

	/*
	 * Wait at least EHCI_NUM_INTR_QH_LISTS+2 frame or until
	 * the QH has been halted.
	 */
	Sync_QH_QTD_Pool(ehcip);
	frames_past = 0;
	status = Get_QH(qh->qh_status) & EHCI_QTD_CTRL_ACTIVE_XACT;

	while ((frames_past <= (EHCI_NUM_INTR_QH_LISTS + 2)) &&
	    (status != 0)) {

		(void) ehci_wait_for_sof(ehcip);

		Sync_QH_QTD_Pool(ehcip);
		status = Get_QH(qh->qh_status) & EHCI_QTD_CTRL_ACTIVE_XACT;
		frames_past = ehci_get_current_frame_number(ehcip) -
		    starting_frame;
	}

	/* Modify the status bit and halt this QH. */
	Sync_QH_QTD_Pool(ehcip);

	status = Get_QH(qh->qh_status);

	for (i = 0; i < EHCI_NUM_INTR_QH_LISTS; i++) {
		Set_QH(qh->qh_status,
		    ((Get_QH(qh->qh_status) &
		    ~(EHCI_QH_STS_ACTIVE)) | EHCI_QH_STS_HALTED));

		Sync_QH_QTD_Pool(ehcip);

		(void) ehci_wait_for_sof(ehcip);
		Sync_QH_QTD_Pool(ehcip);

		if (Get_QH(qh->qh_status) & EHCI_QH_STS_HALTED) {

			break;
		}
	}

	Sync_QH_QTD_Pool(ehcip);

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_halt_fls_intr_qh: qh=0x%p frames past=%llu,"
	    " status=0x%x, 0x%x", (void *)qh,
	    (unsigned long long)(ehci_get_current_frame_number(ehcip) -
	    starting_frame), status, Get_QH(qh->qh_status));
}


/*
 * ehci_remove_qh:
 *
 * Remove the Endpoint Descriptor (QH) from the Host Controller's appropriate
 * endpoint list.
 */
void
ehci_remove_qh(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	boolean_t		reclaim)
{
	uchar_t			attributes;

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_remove_qh: qh=0x%p", (void *)pp->pp_qh);

	attributes = pp->pp_pipe_handle->p_ep.bmAttributes & USB_EP_ATTR_MASK;

	switch (attributes) {
	case USB_EP_ATTR_CONTROL:
	case USB_EP_ATTR_BULK:
		ehci_remove_async_qh(ehcip, pp, reclaim);
		ehcip->ehci_open_async_count--;
		break;
	case USB_EP_ATTR_INTR:
		ehci_remove_intr_qh(ehcip, pp, reclaim);
		ehcip->ehci_open_periodic_count--;
		break;
	case USB_EP_ATTR_ISOCH:
		/* ISOCH does not use QH, don't do anything but update count */
		ehcip->ehci_open_periodic_count--;
		break;
	}
}


/*
 * ehci_remove_async_qh:
 *
 * Remove a control/bulk endpoint into the Host Controller's (HC)
 * Asynchronous schedule endpoint list.
 */
static void
ehci_remove_async_qh(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	boolean_t		reclaim)
{
	ehci_qh_t		*qh = pp->pp_qh; /* qh to be removed */
	ehci_qh_t		*prev_qh, *next_qh;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_remove_async_qh:");

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	prev_qh = ehci_qh_iommu_to_cpu(ehcip,
	    Get_QH(qh->qh_prev) & EHCI_QH_LINK_PTR);
	next_qh = ehci_qh_iommu_to_cpu(ehcip,
	    Get_QH(qh->qh_link_ptr) & EHCI_QH_LINK_PTR);

	/* Make sure this QH is in the list */
	ASSERT(prev_qh != NULL);

	/*
	 * If next QH and current QH are the same, then this is the last
	 * QH on the Asynchronous Schedule list.
	 */
	if (qh == next_qh) {
		ASSERT(Get_QH(qh->qh_ctrl) & EHCI_QH_CTRL_RECLAIM_HEAD);
		/*
		 * Null our pointer to the async sched list, but do not
		 * touch the host controller's list_addr.
		 */
		ehcip->ehci_head_of_async_sched_list = NULL;
		ASSERT(ehcip->ehci_open_async_count == 1);
	} else {
		/* If this QH is the HEAD then find another one to replace it */
		if (ehcip->ehci_head_of_async_sched_list == qh) {

			ASSERT(Get_QH(qh->qh_ctrl) & EHCI_QH_CTRL_RECLAIM_HEAD);
			ehcip->ehci_head_of_async_sched_list = next_qh;
			Set_QH(next_qh->qh_ctrl,
			    Get_QH(next_qh->qh_ctrl) |
			    EHCI_QH_CTRL_RECLAIM_HEAD);
		}
		Set_QH(prev_qh->qh_link_ptr, Get_QH(qh->qh_link_ptr));
		Set_QH(next_qh->qh_prev, Get_QH(qh->qh_prev));
	}

	/* qh_prev to indicate it is no longer in the circular list */
	Set_QH(qh->qh_prev, 0);

	if (reclaim) {
		ehci_insert_qh_on_reclaim_list(ehcip, pp);
	}
}


/*
 * ehci_remove_intr_qh:
 *
 * Set up an interrupt endpoint to be removed from the Host Controller's (HC)
 * interrupt lattice tree. The Endpoint Descriptor (QH) will be freed in the
 * interrupt handler.
 */
static void
ehci_remove_intr_qh(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	boolean_t		reclaim)
{
	ehci_qh_t		*qh = pp->pp_qh; /* qh to be removed */
	ehci_qh_t		*prev_qh, *next_qh;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_remove_intr_qh:");

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	prev_qh = ehci_qh_iommu_to_cpu(ehcip, Get_QH(qh->qh_prev));
	next_qh = ehci_qh_iommu_to_cpu(ehcip,
	    Get_QH(qh->qh_link_ptr) & EHCI_QH_LINK_PTR);

	/* Make sure this QH is in the list */
	ASSERT(prev_qh != NULL);

	if (next_qh) {
		/* Update previous qh's link pointer */
		Set_QH(prev_qh->qh_link_ptr, Get_QH(qh->qh_link_ptr));

		if (Get_QH(next_qh->qh_state) != EHCI_QH_STATIC) {
			/* Set the previous pointer of the next one */
			Set_QH(next_qh->qh_prev, Get_QH(qh->qh_prev));
		}
	} else {
		/* Update previous qh's link pointer */
		Set_QH(prev_qh->qh_link_ptr,
		    (Get_QH(qh->qh_link_ptr) | EHCI_QH_LINK_PTR_VALID));
	}

	/* qh_prev to indicate it is no longer in the circular list */
	Set_QH(qh->qh_prev, 0);

	if (reclaim) {
		ehci_insert_qh_on_reclaim_list(ehcip, pp);
	}
}


/*
 * ehci_insert_qh_on_reclaim_list:
 *
 * Insert Endpoint onto the reclaim list
 */
static void
ehci_insert_qh_on_reclaim_list(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp)
{
	ehci_qh_t		*qh = pp->pp_qh; /* qh to be removed */
	ehci_qh_t		*next_qh, *prev_qh;
	usb_frame_number_t	frame_number;

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/*
	 * Read current usb frame number and add appropriate number of
	 * usb frames needs to wait before reclaiming current endpoint.
	 */
	frame_number =
	    ehci_get_current_frame_number(ehcip) + MAX_SOF_WAIT_COUNT;

	/* Store 32-bit ID */
	Set_QH(qh->qh_reclaim_frame,
	    ((uint32_t)(EHCI_GET_ID((void *)(uintptr_t)frame_number))));

	/* Insert the endpoint onto the reclamation list */
	if (ehcip->ehci_reclaim_list) {
		next_qh = ehcip->ehci_reclaim_list;

		while (next_qh) {
			prev_qh = next_qh;
			next_qh = ehci_qh_iommu_to_cpu(ehcip,
			    Get_QH(next_qh->qh_reclaim_next));
		}

		Set_QH(prev_qh->qh_reclaim_next,
		    ehci_qh_cpu_to_iommu(ehcip, qh));
	} else {
		ehcip->ehci_reclaim_list = qh;
	}

	ASSERT(Get_QH(qh->qh_reclaim_next) == 0);
}


/*
 * ehci_deallocate_qh:
 *
 * Deallocate a Host Controller's (HC) Endpoint Descriptor (QH).
 *
 * NOTE: This function is also called from POLLED MODE.
 */
void
ehci_deallocate_qh(
	ehci_state_t	*ehcip,
	ehci_qh_t	*old_qh)
{
	ehci_qtd_t	*first_dummy_qtd, *second_dummy_qtd;

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ehcip->ehci_log_hdl,
	    "ehci_deallocate_qh:");

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	first_dummy_qtd = ehci_qtd_iommu_to_cpu(ehcip,
	    (Get_QH(old_qh->qh_next_qtd) & EHCI_QH_NEXT_QTD_PTR));

	if (first_dummy_qtd) {
		ASSERT(Get_QTD(first_dummy_qtd->qtd_state) == EHCI_QTD_DUMMY);

		second_dummy_qtd = ehci_qtd_iommu_to_cpu(ehcip,
		    Get_QTD(first_dummy_qtd->qtd_next_qtd));

		if (second_dummy_qtd) {
			ASSERT(Get_QTD(second_dummy_qtd->qtd_state) ==
			    EHCI_QTD_DUMMY);

			ehci_deallocate_qtd(ehcip, second_dummy_qtd);
		}

		ehci_deallocate_qtd(ehcip, first_dummy_qtd);
	}

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ehcip->ehci_log_hdl,
	    "ehci_deallocate_qh: Deallocated 0x%p", (void *)old_qh);

	Set_QH(old_qh->qh_state, EHCI_QH_FREE);
}


/*
 * ehci_qh_cpu_to_iommu:
 *
 * This function converts for the given Endpoint Descriptor (QH) CPU address
 * to IO address.
 *
 * NOTE: This function is also called from POLLED MODE.
 */
uint32_t
ehci_qh_cpu_to_iommu(
	ehci_state_t	*ehcip,
	ehci_qh_t	*addr)
{
	uint32_t	qh;

	qh = (uint32_t)ehcip->ehci_qh_pool_cookie.dmac_address +
	    (uint32_t)((uintptr_t)addr - (uintptr_t)(ehcip->ehci_qh_pool_addr));

	ASSERT(qh >= ehcip->ehci_qh_pool_cookie.dmac_address);
	ASSERT(qh <= ehcip->ehci_qh_pool_cookie.dmac_address +
	    sizeof (ehci_qh_t) * ehci_qh_pool_size);

	return (qh);
}


/*
 * ehci_qh_iommu_to_cpu:
 *
 * This function converts for the given Endpoint Descriptor (QH) IO address
 * to CPU address.
 */
ehci_qh_t *
ehci_qh_iommu_to_cpu(
	ehci_state_t	*ehcip,
	uintptr_t	addr)
{
	ehci_qh_t	*qh;

	if (addr == 0)
		return (NULL);

	qh = (ehci_qh_t *)((uintptr_t)
	    (addr - ehcip->ehci_qh_pool_cookie.dmac_address) +
	    (uintptr_t)ehcip->ehci_qh_pool_addr);

	ASSERT(qh >= ehcip->ehci_qh_pool_addr);
	ASSERT((uintptr_t)qh <= (uintptr_t)ehcip->ehci_qh_pool_addr +
	    (uintptr_t)(sizeof (ehci_qh_t) * ehci_qh_pool_size));

	return (qh);
}


/*
 * Transfer Descriptor manipulations functions
 */

/*
 * ehci_initialize_dummy:
 *
 * An Endpoint Descriptor (QH) has a  dummy Transfer Descriptor (QTD) on the
 * end of its QTD list. Initially, both the head and tail pointers of the QH
 * point to the dummy QTD.
 */
static int
ehci_initialize_dummy(
	ehci_state_t	*ehcip,
	ehci_qh_t	*qh)
{
	ehci_qtd_t	*first_dummy_qtd, *second_dummy_qtd;

	/* Allocate first dummy QTD */
	first_dummy_qtd = ehci_allocate_qtd_from_pool(ehcip);

	if (first_dummy_qtd == NULL) {
		return (USB_NO_RESOURCES);
	}

	/* Allocate second dummy QTD */
	second_dummy_qtd = ehci_allocate_qtd_from_pool(ehcip);

	if (second_dummy_qtd == NULL) {
		/* Deallocate first dummy QTD */
		ehci_deallocate_qtd(ehcip, first_dummy_qtd);

		return (USB_NO_RESOURCES);
	}

	/* Next QTD pointer of an QH point to this new dummy QTD */
	Set_QH(qh->qh_next_qtd, ehci_qtd_cpu_to_iommu(ehcip,
	    first_dummy_qtd) & EHCI_QH_NEXT_QTD_PTR);

	/* Set qh's dummy qtd field */
	Set_QH(qh->qh_dummy_qtd, ehci_qtd_cpu_to_iommu(ehcip, first_dummy_qtd));

	/* Set first_dummy's next qtd pointer */
	Set_QTD(first_dummy_qtd->qtd_next_qtd,
	    ehci_qtd_cpu_to_iommu(ehcip, second_dummy_qtd));

	return (USB_SUCCESS);
}

/*
 * ehci_allocate_ctrl_resources:
 *
 * Calculates the number of tds necessary for a ctrl transfer, and allocates
 * all the resources necessary.
 *
 * Returns NULL if there is insufficient resources otherwise TW.
 */
ehci_trans_wrapper_t *
ehci_allocate_ctrl_resources(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	usb_ctrl_req_t		*ctrl_reqp,
	usb_flags_t		usb_flags)
{
	size_t			qtd_count = 2;
	size_t			ctrl_buf_size;
	ehci_trans_wrapper_t	*tw;

	/* Add one more td for data phase */
	if (ctrl_reqp->ctrl_wLength) {
		qtd_count += 1;
	}

	/*
	 * If we have a control data phase, the data buffer starts
	 * on the next 4K page boundary. So the TW buffer is allocated
	 * to be larger than required. The buffer in the range of
	 * [SETUP_SIZE, EHCI_MAX_QTD_BUF_SIZE) is just for padding
	 * and not to be transferred.
	 */
	if (ctrl_reqp->ctrl_wLength) {
		ctrl_buf_size = EHCI_MAX_QTD_BUF_SIZE +
		    ctrl_reqp->ctrl_wLength;
	} else {
		ctrl_buf_size = SETUP_SIZE;
	}

	tw = ehci_allocate_tw_resources(ehcip, pp, ctrl_buf_size,
	    usb_flags, qtd_count);

	return (tw);
}

/*
 * ehci_insert_ctrl_req:
 *
 * Create a Transfer Descriptor (QTD) and a data buffer for a control endpoint.
 */
/* ARGSUSED */
void
ehci_insert_ctrl_req(
	ehci_state_t		*ehcip,
	usba_pipe_handle_data_t	*ph,
	usb_ctrl_req_t		*ctrl_reqp,
	ehci_trans_wrapper_t	*tw,
	usb_flags_t		usb_flags)
{
	ehci_pipe_private_t	*pp = (ehci_pipe_private_t *)ph->p_hcd_private;
	uchar_t			bmRequestType = ctrl_reqp->ctrl_bmRequestType;
	uchar_t			bRequest = ctrl_reqp->ctrl_bRequest;
	uint16_t		wValue = ctrl_reqp->ctrl_wValue;
	uint16_t		wIndex = ctrl_reqp->ctrl_wIndex;
	uint16_t		wLength = ctrl_reqp->ctrl_wLength;
	mblk_t			*data = ctrl_reqp->ctrl_data;
	uint32_t		ctrl = 0;
	uint8_t			setup_packet[8];

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_insert_ctrl_req:");

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/*
	 * Save current control request pointer and timeout values
	 * in transfer wrapper.
	 */
	tw->tw_curr_xfer_reqp = (usb_opaque_t)ctrl_reqp;
	tw->tw_timeout = ctrl_reqp->ctrl_timeout ?
	    ctrl_reqp->ctrl_timeout : EHCI_DEFAULT_XFER_TIMEOUT;

	/*
	 * Initialize the callback and any callback data for when
	 * the qtd completes.
	 */
	tw->tw_handle_qtd = ehci_handle_ctrl_qtd;
	tw->tw_handle_callback_value = NULL;

	/*
	 * swap the setup bytes where necessary since we specified
	 * NEVERSWAP
	 */
	setup_packet[0] = bmRequestType;
	setup_packet[1] = bRequest;
	setup_packet[2] = (uint8_t)wValue;
	setup_packet[3] = wValue >> 8;
	setup_packet[4] = (uint8_t)wIndex;
	setup_packet[5] = wIndex >> 8;
	setup_packet[6] = (uint8_t)wLength;
	setup_packet[7] = wLength >> 8;

	bcopy(setup_packet, tw->tw_buf, SETUP_SIZE);

	Sync_IO_Buffer_for_device(tw->tw_dmahandle, SETUP_SIZE);

	ctrl = (EHCI_QTD_CTRL_DATA_TOGGLE_0 | EHCI_QTD_CTRL_SETUP_PID);

	/*
	 * The QTD's are placed on the QH one at a time.
	 * Once this QTD is placed on the done list, the
	 * data or status phase QTD will be enqueued.
	 */
	(void) ehci_insert_qtd(ehcip, ctrl, 0, SETUP_SIZE,
	    EHCI_CTRL_SETUP_PHASE, pp, tw);

	USB_DPRINTF_L3(PRINT_MASK_ALLOC, ehcip->ehci_log_hdl,
	    "ehci_insert_ctrl_req: pp 0x%p", (void *)pp);

	/*
	 * If this control transfer has a data phase, record the
	 * direction. If the data phase is an OUT transaction,
	 * copy the data into the buffer of the transfer wrapper.
	 */
	if (wLength != 0) {
		/* There is a data stage.  Find the direction */
		if (bmRequestType & USB_DEV_REQ_DEV_TO_HOST) {
			tw->tw_direction = EHCI_QTD_CTRL_IN_PID;
		} else {
			tw->tw_direction = EHCI_QTD_CTRL_OUT_PID;

			/* Copy the data into the message */
			bcopy(data->b_rptr, tw->tw_buf + EHCI_MAX_QTD_BUF_SIZE,
			    wLength);

			Sync_IO_Buffer_for_device(tw->tw_dmahandle,
			    wLength + EHCI_MAX_QTD_BUF_SIZE);
		}

		ctrl = (EHCI_QTD_CTRL_DATA_TOGGLE_1 | tw->tw_direction);

		/*
		 * Create the QTD.  If this is an OUT transaction,
		 * the data is already in the buffer of the TW.
		 * The transfer should start from EHCI_MAX_QTD_BUF_SIZE
		 * which is 4K aligned, though the ctrl phase only
		 * transfers a length of SETUP_SIZE. The padding data
		 * in the TW buffer are discarded.
		 */
		(void) ehci_insert_qtd(ehcip, ctrl, EHCI_MAX_QTD_BUF_SIZE,
		    tw->tw_length - EHCI_MAX_QTD_BUF_SIZE,
		    EHCI_CTRL_DATA_PHASE, pp, tw);

		/*
		 * The direction of the STATUS QTD depends  on
		 * the direction of the transfer.
		 */
		if (tw->tw_direction == EHCI_QTD_CTRL_IN_PID) {
			ctrl = (EHCI_QTD_CTRL_DATA_TOGGLE_1|
			    EHCI_QTD_CTRL_OUT_PID |
			    EHCI_QTD_CTRL_INTR_ON_COMPLETE);
		} else {
			ctrl = (EHCI_QTD_CTRL_DATA_TOGGLE_1|
			    EHCI_QTD_CTRL_IN_PID |
			    EHCI_QTD_CTRL_INTR_ON_COMPLETE);
		}
	} else {
		/*
		 * There is no data stage,  then initiate
		 * status phase from the host.
		 */
		ctrl = (EHCI_QTD_CTRL_DATA_TOGGLE_1 |
		    EHCI_QTD_CTRL_IN_PID |
		    EHCI_QTD_CTRL_INTR_ON_COMPLETE);
	}


	(void) ehci_insert_qtd(ehcip, ctrl, 0, 0,
	    EHCI_CTRL_STATUS_PHASE, pp,  tw);

	/* Start the timer for this control transfer */
	ehci_start_xfer_timer(ehcip, pp, tw);
}


/*
 * ehci_allocate_bulk_resources:
 *
 * Calculates the number of tds necessary for a ctrl transfer, and allocates
 * all the resources necessary.
 *
 * Returns NULL if there is insufficient resources otherwise TW.
 */
ehci_trans_wrapper_t *
ehci_allocate_bulk_resources(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	usb_bulk_req_t		*bulk_reqp,
	usb_flags_t		usb_flags)
{
	size_t			qtd_count = 0;
	ehci_trans_wrapper_t	*tw;

	/* Check the size of bulk request */
	if (bulk_reqp->bulk_len > EHCI_MAX_BULK_XFER_SIZE) {

		USB_DPRINTF_L2(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
		    "ehci_allocate_bulk_resources: Bulk request size 0x%x is "
		    "more than 0x%x", bulk_reqp->bulk_len,
		    EHCI_MAX_BULK_XFER_SIZE);

		return (NULL);
	}

	/* Get the required bulk packet size */
	qtd_count = bulk_reqp->bulk_len / EHCI_MAX_QTD_XFER_SIZE;
	if (bulk_reqp->bulk_len % EHCI_MAX_QTD_XFER_SIZE ||
	    bulk_reqp->bulk_len == 0) {
		qtd_count += 1;
	}

	tw = ehci_allocate_tw_resources(ehcip, pp, bulk_reqp->bulk_len,
	    usb_flags, qtd_count);

	return (tw);
}

/*
 * ehci_insert_bulk_req:
 *
 * Create a Transfer Descriptor (QTD) and a data buffer for a bulk
 * endpoint.
 */
/* ARGSUSED */
void
ehci_insert_bulk_req(
	ehci_state_t		*ehcip,
	usba_pipe_handle_data_t	*ph,
	usb_bulk_req_t		*bulk_reqp,
	ehci_trans_wrapper_t	*tw,
	usb_flags_t		flags)
{
	ehci_pipe_private_t	*pp = (ehci_pipe_private_t *)ph->p_hcd_private;
	uint_t			bulk_pkt_size, count;
	size_t			residue = 0, len = 0;
	uint32_t		ctrl = 0;
	int			pipe_dir;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_insert_bulk_req: bulk_reqp = 0x%p flags = 0x%x",
	    (void *)bulk_reqp, flags);

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/* Get the bulk pipe direction */
	pipe_dir = ph->p_ep.bEndpointAddress & USB_EP_DIR_MASK;

	/* Get the required bulk packet size */
	bulk_pkt_size = min(bulk_reqp->bulk_len, EHCI_MAX_QTD_XFER_SIZE);

	if (bulk_pkt_size) {
		residue = tw->tw_length % bulk_pkt_size;
	}

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_insert_bulk_req: bulk_pkt_size = %d", bulk_pkt_size);

	/*
	 * Save current bulk request pointer and timeout values
	 * in transfer wrapper.
	 */
	tw->tw_curr_xfer_reqp = (usb_opaque_t)bulk_reqp;
	tw->tw_timeout = bulk_reqp->bulk_timeout;

	/*
	 * Initialize the callback and any callback
	 * data required when the qtd completes.
	 */
	tw->tw_handle_qtd = ehci_handle_bulk_qtd;
	tw->tw_handle_callback_value = NULL;

	tw->tw_direction = (pipe_dir == USB_EP_DIR_OUT) ?
	    EHCI_QTD_CTRL_OUT_PID : EHCI_QTD_CTRL_IN_PID;

	if (tw->tw_direction == EHCI_QTD_CTRL_OUT_PID) {

		if (bulk_reqp->bulk_len) {
			ASSERT(bulk_reqp->bulk_data != NULL);

			bcopy(bulk_reqp->bulk_data->b_rptr, tw->tw_buf,
			    bulk_reqp->bulk_len);

			Sync_IO_Buffer_for_device(tw->tw_dmahandle,
			    bulk_reqp->bulk_len);
		}
	}

	ctrl = tw->tw_direction;

	/* Insert all the bulk QTDs */
	for (count = 0; count < tw->tw_num_qtds; count++) {

		/* Check for last qtd */
		if (count == (tw->tw_num_qtds - 1)) {

			ctrl |= EHCI_QTD_CTRL_INTR_ON_COMPLETE;

			/* Check for inserting residue data */
			if (residue) {
				bulk_pkt_size = (uint_t)residue;
			}
		}

		/* Insert the QTD onto the endpoint */
		(void) ehci_insert_qtd(ehcip, ctrl, len, bulk_pkt_size,
		    0, pp, tw);

		len = len + bulk_pkt_size;
	}

	/* Start the timer for this bulk transfer */
	ehci_start_xfer_timer(ehcip, pp, tw);
}


/*
 * ehci_start_periodic_pipe_polling:
 *
 * NOTE: This function is also called from POLLED MODE.
 */
int
ehci_start_periodic_pipe_polling(
	ehci_state_t		*ehcip,
	usba_pipe_handle_data_t	*ph,
	usb_opaque_t		periodic_in_reqp,
	usb_flags_t		flags)
{
	ehci_pipe_private_t	*pp = (ehci_pipe_private_t *)ph->p_hcd_private;
	usb_ep_descr_t		*eptd = &ph->p_ep;
	int			error = USB_SUCCESS;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ehcip->ehci_log_hdl,
	    "ehci_start_periodic_pipe_polling: ep%d",
	    ph->p_ep.bEndpointAddress & USB_EP_NUM_MASK);

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/*
	 * Check and handle start polling on root hub interrupt pipe.
	 */
	if ((ph->p_usba_device->usb_addr == ROOT_HUB_ADDR) &&
	    ((eptd->bmAttributes & USB_EP_ATTR_MASK) ==
	    USB_EP_ATTR_INTR)) {

		error = ehci_handle_root_hub_pipe_start_intr_polling(ph,
		    (usb_intr_req_t *)periodic_in_reqp, flags);

		return (error);
	}

	switch (pp->pp_state) {
	case EHCI_PIPE_STATE_IDLE:
		/* Save the Original client's Periodic IN request */
		pp->pp_client_periodic_in_reqp = periodic_in_reqp;

		/*
		 * This pipe is uninitialized or if a valid QTD is
		 * not found then insert a QTD on the interrupt IN
		 * endpoint.
		 */
		error = ehci_start_pipe_polling(ehcip, ph, flags);

		if (error != USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_INTR,
			    ehcip->ehci_log_hdl,
			    "ehci_start_periodic_pipe_polling: "
			    "Start polling failed");

			pp->pp_client_periodic_in_reqp = NULL;

			return (error);
		}

		USB_DPRINTF_L3(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
		    "ehci_start_periodic_pipe_polling: PP = 0x%p", (void *)pp);

#ifdef DEBUG
		switch (eptd->bmAttributes & USB_EP_ATTR_MASK) {
		case USB_EP_ATTR_INTR:
			ASSERT((pp->pp_tw_head != NULL) &&
			    (pp->pp_tw_tail != NULL));
			break;
		case USB_EP_ATTR_ISOCH:
			ASSERT((pp->pp_itw_head != NULL) &&
			    (pp->pp_itw_tail != NULL));
			break;
		}
#endif

		break;
	case EHCI_PIPE_STATE_ACTIVE:
		USB_DPRINTF_L2(PRINT_MASK_INTR,
		    ehcip->ehci_log_hdl,
		    "ehci_start_periodic_pipe_polling: "
		    "Polling is already in progress");

		error = USB_FAILURE;
		break;
	case EHCI_PIPE_STATE_ERROR:
		USB_DPRINTF_L2(PRINT_MASK_INTR,
		    ehcip->ehci_log_hdl,
		    "ehci_start_periodic_pipe_polling: "
		    "Pipe is halted and perform reset"
		    "before restart polling");

		error = USB_FAILURE;
		break;
	default:
		USB_DPRINTF_L2(PRINT_MASK_INTR,
		    ehcip->ehci_log_hdl,
		    "ehci_start_periodic_pipe_polling: "
		    "Undefined state");

		error = USB_FAILURE;
		break;
	}

	return (error);
}


/*
 * ehci_start_pipe_polling:
 *
 * Insert the number of periodic requests corresponding to polling
 * interval as calculated during pipe open.
 */
static int
ehci_start_pipe_polling(
	ehci_state_t		*ehcip,
	usba_pipe_handle_data_t	*ph,
	usb_flags_t		flags)
{
	ehci_pipe_private_t	*pp = (ehci_pipe_private_t *)ph->p_hcd_private;
	usb_ep_descr_t		*eptd = &ph->p_ep;
	int			error = USB_FAILURE;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_start_pipe_polling:");

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/*
	 * For the start polling, pp_max_periodic_req_cnt will be zero
	 * and for the restart polling request, it will be non zero.
	 *
	 * In case of start polling request, find out number of requests
	 * required for the Interrupt IN endpoints corresponding to the
	 * endpoint polling interval. For Isochronous IN endpoints, it is
	 * always fixed since its polling interval will be one ms.
	 */
	if (pp->pp_max_periodic_req_cnt == 0) {

		ehci_set_periodic_pipe_polling(ehcip, ph);
	}

	ASSERT(pp->pp_max_periodic_req_cnt != 0);

	switch (eptd->bmAttributes & USB_EP_ATTR_MASK) {
	case USB_EP_ATTR_INTR:
		error = ehci_start_intr_polling(ehcip, ph, flags);
		break;
	case USB_EP_ATTR_ISOCH:
		error = ehci_start_isoc_polling(ehcip, ph, flags);
		break;
	}

	return (error);
}

static int
ehci_start_intr_polling(
	ehci_state_t		*ehcip,
	usba_pipe_handle_data_t	*ph,
	usb_flags_t		flags)
{
	ehci_pipe_private_t	*pp = (ehci_pipe_private_t *)ph->p_hcd_private;
	ehci_trans_wrapper_t	*tw_list, *tw;
	int			i, total_tws;
	int			error = USB_SUCCESS;

	/* Allocate all the necessary resources for the IN transfer */
	tw_list = NULL;
	total_tws = pp->pp_max_periodic_req_cnt - pp->pp_cur_periodic_req_cnt;
	for (i = 0; i < total_tws; i += 1) {
		tw = ehci_allocate_intr_resources(ehcip, ph, NULL, flags);
		if (tw == NULL) {
			error = USB_NO_RESOURCES;
			/* There are not enough resources, deallocate the TWs */
			tw = tw_list;
			while (tw != NULL) {
				tw_list = tw->tw_next;
				ehci_deallocate_intr_in_resource(
				    ehcip, pp, tw);
				ehci_deallocate_tw(ehcip, pp, tw);
				tw = tw_list;
			}

			return (error);
		} else {
			if (tw_list == NULL) {
				tw_list = tw;
			}
		}
	}

	while (pp->pp_cur_periodic_req_cnt < pp->pp_max_periodic_req_cnt) {

		USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
		    "ehci_start_pipe_polling: max = %d curr = %d tw = %p:",
		    pp->pp_max_periodic_req_cnt, pp->pp_cur_periodic_req_cnt,
		    (void *)tw_list);

		tw = tw_list;
		tw_list = tw->tw_next;

		ehci_insert_intr_req(ehcip, pp, tw, flags);

		pp->pp_cur_periodic_req_cnt++;
	}

	return (error);
}


/*
 * ehci_set_periodic_pipe_polling:
 *
 * Calculate the number of periodic requests needed corresponding to the
 * interrupt IN endpoints polling interval. Table below gives the number
 * of periodic requests needed for the interrupt IN endpoints  according
 * to endpoint polling interval.
 *
 * Polling interval		Number of periodic requests
 *
 * 1ms				4
 * 2ms				2
 * 4ms to 32ms			1
 */
static void
ehci_set_periodic_pipe_polling(
	ehci_state_t		*ehcip,
	usba_pipe_handle_data_t	*ph)
{
	ehci_pipe_private_t	*pp = (ehci_pipe_private_t *)ph->p_hcd_private;
	usb_ep_descr_t		*endpoint = &ph->p_ep;
	uchar_t			ep_attr = endpoint->bmAttributes;
	uint_t			interval;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_set_periodic_pipe_polling:");

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	pp->pp_cur_periodic_req_cnt = 0;

	/*
	 * Check usb flag whether USB_FLAGS_ONE_TIME_POLL flag is
	 * set and if so, set pp->pp_max_periodic_req_cnt to one.
	 */
	if (((ep_attr & USB_EP_ATTR_MASK) == USB_EP_ATTR_INTR) &&
	    (pp->pp_client_periodic_in_reqp)) {
		usb_intr_req_t *intr_reqp = (usb_intr_req_t *)
		    pp->pp_client_periodic_in_reqp;

		if (intr_reqp->intr_attributes &
		    USB_ATTRS_ONE_XFER) {

			pp->pp_max_periodic_req_cnt = EHCI_INTR_XMS_REQS;

			return;
		}
	}

	mutex_enter(&ph->p_usba_device->usb_mutex);

	/*
	 * The ehci_adjust_polling_interval function will not fail
	 * at this instance since bandwidth allocation is already
	 * done. Here we are getting only the periodic interval.
	 */
	interval = ehci_adjust_polling_interval(ehcip, endpoint,
	    ph->p_usba_device->usb_port_status);

	mutex_exit(&ph->p_usba_device->usb_mutex);

	switch (interval) {
	case EHCI_INTR_1MS_POLL:
		pp->pp_max_periodic_req_cnt = EHCI_INTR_1MS_REQS;
		break;
	case EHCI_INTR_2MS_POLL:
		pp->pp_max_periodic_req_cnt = EHCI_INTR_2MS_REQS;
		break;
	default:
		pp->pp_max_periodic_req_cnt = EHCI_INTR_XMS_REQS;
		break;
	}

	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_set_periodic_pipe_polling: Max periodic requests = %d",
	    pp->pp_max_periodic_req_cnt);
}

/*
 * ehci_allocate_intr_resources:
 *
 * Calculates the number of tds necessary for a intr transfer, and allocates
 * all the necessary resources.
 *
 * Returns NULL if there is insufficient resources otherwise TW.
 */
ehci_trans_wrapper_t *
ehci_allocate_intr_resources(
	ehci_state_t		*ehcip,
	usba_pipe_handle_data_t	*ph,
	usb_intr_req_t		*intr_reqp,
	usb_flags_t		flags)
{
	ehci_pipe_private_t	*pp = (ehci_pipe_private_t *)ph->p_hcd_private;
	int			pipe_dir;
	size_t			qtd_count = 1;
	size_t			tw_length;
	ehci_trans_wrapper_t	*tw;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_allocate_intr_resources:");

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	pipe_dir = ph->p_ep.bEndpointAddress & USB_EP_DIR_MASK;

	/* Get the length of interrupt transfer & alloc data */
	if (intr_reqp) {
		tw_length = intr_reqp->intr_len;
	} else {
		ASSERT(pipe_dir == USB_EP_DIR_IN);
		tw_length = (pp->pp_client_periodic_in_reqp) ?
		    (((usb_intr_req_t *)pp->
		    pp_client_periodic_in_reqp)->intr_len) :
		    ph->p_ep.wMaxPacketSize;
	}

	/* Check the size of interrupt request */
	if (tw_length > EHCI_MAX_QTD_XFER_SIZE) {

		USB_DPRINTF_L2(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
		    "ehci_allocate_intr_resources: Intr request size 0x%lx is "
		    "more than 0x%x", tw_length, EHCI_MAX_QTD_XFER_SIZE);

		return (NULL);
	}

	if ((tw = ehci_allocate_tw_resources(ehcip, pp, tw_length, flags,
	    qtd_count)) == NULL) {

		return (NULL);
	}

	if (pipe_dir == USB_EP_DIR_IN) {
		if (ehci_allocate_intr_in_resource(ehcip, pp, tw, flags) !=
		    USB_SUCCESS) {
			ehci_deallocate_tw(ehcip, pp, tw);
		}
		tw->tw_direction = EHCI_QTD_CTRL_IN_PID;
	} else {
		if (tw_length) {
			ASSERT(intr_reqp->intr_data != NULL);

			/* Copy the data into the buffer */
			bcopy(intr_reqp->intr_data->b_rptr, tw->tw_buf,
			    intr_reqp->intr_len);

			Sync_IO_Buffer_for_device(tw->tw_dmahandle,
			    intr_reqp->intr_len);
		}

		tw->tw_curr_xfer_reqp = (usb_opaque_t)intr_reqp;
		tw->tw_direction = EHCI_QTD_CTRL_OUT_PID;
	}

	if (intr_reqp) {
		tw->tw_timeout = intr_reqp->intr_timeout;
	}

	/*
	 * Initialize the callback and any callback
	 * data required when the qtd completes.
	 */
	tw->tw_handle_qtd = ehci_handle_intr_qtd;
	tw->tw_handle_callback_value = NULL;

	return (tw);
}


/*
 * ehci_insert_intr_req:
 *
 * Insert an Interrupt request into the Host Controller's periodic list.
 */
/* ARGSUSED */
void
ehci_insert_intr_req(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_trans_wrapper_t	*tw,
	usb_flags_t		flags)
{
	uint_t			ctrl = 0;

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	ASSERT(tw->tw_curr_xfer_reqp != NULL);

	ctrl = (tw->tw_direction | EHCI_QTD_CTRL_INTR_ON_COMPLETE);

	/* Insert another interrupt QTD */
	(void) ehci_insert_qtd(ehcip, ctrl, 0, tw->tw_length, 0, pp, tw);

	/* Start the timer for this Interrupt transfer */
	ehci_start_xfer_timer(ehcip, pp, tw);
}


/*
 * ehci_stop_periodic_pipe_polling:
 */
/* ARGSUSED */
int
ehci_stop_periodic_pipe_polling(
	ehci_state_t		*ehcip,
	usba_pipe_handle_data_t	*ph,
	usb_flags_t		flags)
{
	ehci_pipe_private_t	*pp = (ehci_pipe_private_t *)ph->p_hcd_private;
	usb_ep_descr_t		*eptd = &ph->p_ep;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ehcip->ehci_log_hdl,
	    "ehci_stop_periodic_pipe_polling: Flags = 0x%x", flags);

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/*
	 * Check and handle stop polling on root hub interrupt pipe.
	 */
	if ((ph->p_usba_device->usb_addr == ROOT_HUB_ADDR) &&
	    ((eptd->bmAttributes & USB_EP_ATTR_MASK) ==
	    USB_EP_ATTR_INTR)) {

		ehci_handle_root_hub_pipe_stop_intr_polling(ph, flags);

		return (USB_SUCCESS);
	}

	if (pp->pp_state != EHCI_PIPE_STATE_ACTIVE) {

		USB_DPRINTF_L2(PRINT_MASK_HCDI, ehcip->ehci_log_hdl,
		    "ehci_stop_periodic_pipe_polling: "
		    "Polling already stopped");

		return (USB_SUCCESS);
	}

	/* Set pipe state to pipe stop polling */
	pp->pp_state = EHCI_PIPE_STATE_STOP_POLLING;

	ehci_pipe_cleanup(ehcip, ph);

	return (USB_SUCCESS);
}


/*
 * ehci_insert_qtd:
 *
 * Insert a Transfer Descriptor (QTD) on an Endpoint Descriptor (QH).
 * Always returns USB_SUCCESS for now.	Once Isoch has been implemented,
 * it may return USB_FAILURE.
 */
int
ehci_insert_qtd(
	ehci_state_t		*ehcip,
	uint32_t		qtd_ctrl,
	size_t			qtd_dma_offs,
	size_t			qtd_length,
	uint32_t		qtd_ctrl_phase,
	ehci_pipe_private_t	*pp,
	ehci_trans_wrapper_t	*tw)
{
	ehci_qtd_t		*curr_dummy_qtd, *next_dummy_qtd;
	ehci_qtd_t		*new_dummy_qtd;
	ehci_qh_t		*qh = pp->pp_qh;
	int			error = USB_SUCCESS;

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/* Allocate new dummy QTD */
	new_dummy_qtd = tw->tw_qtd_free_list;

	ASSERT(new_dummy_qtd != NULL);
	tw->tw_qtd_free_list = ehci_qtd_iommu_to_cpu(ehcip,
	    Get_QTD(new_dummy_qtd->qtd_tw_next_qtd));
	Set_QTD(new_dummy_qtd->qtd_tw_next_qtd, 0);

	/* Get the current and next dummy QTDs */
	curr_dummy_qtd = ehci_qtd_iommu_to_cpu(ehcip,
	    Get_QH(qh->qh_dummy_qtd));
	next_dummy_qtd = ehci_qtd_iommu_to_cpu(ehcip,
	    Get_QTD(curr_dummy_qtd->qtd_next_qtd));

	/* Update QH's dummy qtd field */
	Set_QH(qh->qh_dummy_qtd, ehci_qtd_cpu_to_iommu(ehcip, next_dummy_qtd));

	/* Update next dummy's next qtd pointer */
	Set_QTD(next_dummy_qtd->qtd_next_qtd,
	    ehci_qtd_cpu_to_iommu(ehcip, new_dummy_qtd));

	/*
	 * Fill in the current dummy qtd and
	 * add the new dummy to the end.
	 */
	ehci_fill_in_qtd(ehcip, curr_dummy_qtd, qtd_ctrl,
	    qtd_dma_offs, qtd_length, qtd_ctrl_phase, pp, tw);

	/* Insert this qtd onto the tw */
	ehci_insert_qtd_on_tw(ehcip, tw, curr_dummy_qtd);

	/*
	 * Insert this qtd onto active qtd list.
	 * Don't insert polled mode qtd here.
	 */
	if (pp->pp_flag != EHCI_POLLED_MODE_FLAG) {
		/* Insert this qtd onto active qtd list */
		ehci_insert_qtd_into_active_qtd_list(ehcip, curr_dummy_qtd);
	}

	/* Print qh and qtd */
	ehci_print_qh(ehcip, qh);
	ehci_print_qtd(ehcip, curr_dummy_qtd);

	return (error);
}


/*
 * ehci_allocate_qtd_from_pool:
 *
 * Allocate a Transfer Descriptor (QTD) from the QTD buffer pool.
 */
static ehci_qtd_t *
ehci_allocate_qtd_from_pool(ehci_state_t	*ehcip)
{
	int		i, ctrl;
	ehci_qtd_t	*qtd;

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/*
	 * Search for a blank Transfer Descriptor (QTD)
	 * in the QTD buffer pool.
	 */
	for (i = 0; i < ehci_qtd_pool_size; i ++) {
		ctrl = Get_QTD(ehcip->ehci_qtd_pool_addr[i].qtd_state);
		if (ctrl == EHCI_QTD_FREE) {
			break;
		}
	}

	if (i >= ehci_qtd_pool_size) {
		USB_DPRINTF_L2(PRINT_MASK_ALLOC, ehcip->ehci_log_hdl,
		    "ehci_allocate_qtd_from_pool: QTD exhausted");

		return (NULL);
	}

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ehcip->ehci_log_hdl,
	    "ehci_allocate_qtd_from_pool: Allocated %d", i);

	/* Create a new dummy for the end of the QTD list */
	qtd = &ehcip->ehci_qtd_pool_addr[i];

	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_allocate_qtd_from_pool: qtd 0x%p", (void *)qtd);

	/* Mark the newly allocated QTD as a dummy */
	Set_QTD(qtd->qtd_state, EHCI_QTD_DUMMY);

	/* Mark the status of this new QTD to halted state */
	Set_QTD(qtd->qtd_ctrl, EHCI_QTD_CTRL_HALTED_XACT);

	/* Disable dummy QTD's next and alternate next pointers */
	Set_QTD(qtd->qtd_next_qtd, EHCI_QTD_NEXT_QTD_PTR_VALID);
	Set_QTD(qtd->qtd_alt_next_qtd, EHCI_QTD_ALT_NEXT_QTD_PTR_VALID);

	return (qtd);
}


/*
 * ehci_fill_in_qtd:
 *
 * Fill in the fields of a Transfer Descriptor (QTD).
 * The "Buffer Pointer" fields of a QTD are retrieved from the TW
 * it is associated with.
 *
 * Note:
 * qtd_dma_offs - the starting offset into the TW buffer, where the QTD
 *		  should transfer from. It should be 4K aligned. And when
 *		  a TW has more than one QTDs, the QTDs must be filled in
 *		  increasing order.
 * qtd_length - the total bytes to transfer.
 */
/*ARGSUSED*/
static void
ehci_fill_in_qtd(
	ehci_state_t		*ehcip,
	ehci_qtd_t		*qtd,
	uint32_t		qtd_ctrl,
	size_t			qtd_dma_offs,
	size_t			qtd_length,
	uint32_t		qtd_ctrl_phase,
	ehci_pipe_private_t	*pp,
	ehci_trans_wrapper_t	*tw)
{
	uint32_t		buf_addr;
	size_t			buf_len = qtd_length;
	uint32_t		ctrl = qtd_ctrl;
	uint_t			i = 0;
	int			rem_len;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_fill_in_qtd: qtd 0x%p ctrl 0x%x bufoffs 0x%lx "
	    "len 0x%lx", (void *)qtd, qtd_ctrl, qtd_dma_offs, qtd_length);

	/* Assert that the qtd to be filled in is a dummy */
	ASSERT(Get_QTD(qtd->qtd_state) == EHCI_QTD_DUMMY);

	/* Change QTD's state Active */
	Set_QTD(qtd->qtd_state, EHCI_QTD_ACTIVE);

	/* Set the total length data transfer */
	ctrl |= (((qtd_length << EHCI_QTD_CTRL_BYTES_TO_XFER_SHIFT)
	    & EHCI_QTD_CTRL_BYTES_TO_XFER) | EHCI_QTD_CTRL_MAX_ERR_COUNTS);

	/*
	 * QTDs must be filled in increasing DMA offset order.
	 * tw_dma_offs is initialized to be 0 at TW creation and
	 * is only increased in this function.
	 */
	ASSERT(buf_len == 0 || qtd_dma_offs >= tw->tw_dma_offs);

	/*
	 * Save the starting dma buffer offset used and
	 * length of data that will be transfered in
	 * the current QTD.
	 */
	Set_QTD(qtd->qtd_xfer_offs, qtd_dma_offs);
	Set_QTD(qtd->qtd_xfer_len, buf_len);

	while (buf_len) {
		/*
		 * Advance to the next DMA cookie until finding the cookie
		 * that qtd_dma_offs falls in.
		 * It is very likely this loop will never repeat more than
		 * once. It is here just to accommodate the case qtd_dma_offs
		 * is increased by multiple cookies during two consecutive
		 * calls into this function. In that case, the interim DMA
		 * buffer is allowed to be skipped.
		 */
		while ((tw->tw_dma_offs + tw->tw_cookie.dmac_size) <=
		    qtd_dma_offs) {
			/*
			 * tw_dma_offs always points to the starting offset
			 * of a cookie
			 */
			tw->tw_dma_offs += tw->tw_cookie.dmac_size;
			ddi_dma_nextcookie(tw->tw_dmahandle, &tw->tw_cookie);
			tw->tw_cookie_idx++;
			ASSERT(tw->tw_cookie_idx < tw->tw_ncookies);
		}

		/*
		 * Counting the remained buffer length to be filled in
		 * the QTD for current DMA cookie
		 */
		rem_len = (tw->tw_dma_offs + tw->tw_cookie.dmac_size) -
		    qtd_dma_offs;

		/* Update the beginning of the buffer */
		buf_addr = (qtd_dma_offs - tw->tw_dma_offs) +
		    tw->tw_cookie.dmac_address;
		ASSERT((buf_addr % EHCI_4K_ALIGN) == 0);
		Set_QTD(qtd->qtd_buf[i], buf_addr);

		USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
		    "ehci_fill_in_qtd: dmac_addr 0x%x dmac_size "
		    "0x%lx idx %d", buf_addr, tw->tw_cookie.dmac_size,
		    tw->tw_cookie_idx);

		if (buf_len <= EHCI_MAX_QTD_BUF_SIZE) {
			ASSERT(buf_len <= rem_len);
			break;
		} else {
			ASSERT(rem_len >= EHCI_MAX_QTD_BUF_SIZE);
			buf_len -= EHCI_MAX_QTD_BUF_SIZE;
			qtd_dma_offs += EHCI_MAX_QTD_BUF_SIZE;
		}

		i++;
	}

	/*
	 * Setup the alternate next qTD pointer if appropriate.  The alternate
	 * qtd is currently pointing to a QTD that is not yet linked, but will
	 * be in the very near future.	If a short_xfer occurs in this
	 * situation , the HC will automatically skip this QH.	Eventually
	 * everything will be placed and the alternate_qtd will be valid QTD.
	 * For more information on alternate qtds look at section 3.5.2 in the
	 * EHCI spec.
	 */
	if (tw->tw_alt_qtd != NULL) {
		Set_QTD(qtd->qtd_alt_next_qtd,
		    (ehci_qtd_cpu_to_iommu(ehcip, tw->tw_alt_qtd) &
		    EHCI_QTD_ALT_NEXT_QTD_PTR));
	}

	/*
	 * For control, bulk and interrupt QTD, now
	 * enable current QTD by setting active bit.
	 */
	Set_QTD(qtd->qtd_ctrl, (ctrl | EHCI_QTD_CTRL_ACTIVE_XACT));

	/*
	 * For Control Xfer, qtd_ctrl_phase is a valid filed.
	 */
	if (qtd_ctrl_phase) {
		Set_QTD(qtd->qtd_ctrl_phase, qtd_ctrl_phase);
	}

	/* Set the transfer wrapper */
	ASSERT(tw != NULL);
	ASSERT(tw->tw_id != 0);

	Set_QTD(qtd->qtd_trans_wrapper, (uint32_t)tw->tw_id);
}


/*
 * ehci_insert_qtd_on_tw:
 *
 * The transfer wrapper keeps a list of all Transfer Descriptors (QTD) that
 * are allocated for this transfer. Insert a QTD  onto this list. The  list
 * of QTD's does not include the dummy QTD that is at the end of the list of
 * QTD's for the endpoint.
 */
static void
ehci_insert_qtd_on_tw(
	ehci_state_t		*ehcip,
	ehci_trans_wrapper_t	*tw,
	ehci_qtd_t		*qtd)
{
	/*
	 * Set the next pointer to NULL because
	 * this is the last QTD on list.
	 */
	Set_QTD(qtd->qtd_tw_next_qtd, 0);

	if (tw->tw_qtd_head == NULL) {
		ASSERT(tw->tw_qtd_tail == NULL);
		tw->tw_qtd_head = qtd;
		tw->tw_qtd_tail = qtd;
	} else {
		ehci_qtd_t *dummy = (ehci_qtd_t *)tw->tw_qtd_tail;

		ASSERT(dummy != NULL);
		ASSERT(dummy != qtd);
		ASSERT(Get_QTD(qtd->qtd_state) != EHCI_QTD_DUMMY);

		/* Add the qtd to the end of the list */
		Set_QTD(dummy->qtd_tw_next_qtd,
		    ehci_qtd_cpu_to_iommu(ehcip, qtd));

		tw->tw_qtd_tail = qtd;

		ASSERT(Get_QTD(qtd->qtd_tw_next_qtd) == 0);
	}
}


/*
 * ehci_insert_qtd_into_active_qtd_list:
 *
 * Insert current QTD into active QTD list.
 */
static void
ehci_insert_qtd_into_active_qtd_list(
	ehci_state_t		*ehcip,
	ehci_qtd_t		*qtd)
{
	ehci_qtd_t		*curr_qtd, *next_qtd;

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	curr_qtd = ehcip->ehci_active_qtd_list;

	/* Insert this QTD into QTD Active List */
	if (curr_qtd) {
		next_qtd = ehci_qtd_iommu_to_cpu(ehcip,
		    Get_QTD(curr_qtd->qtd_active_qtd_next));

		while (next_qtd) {
			curr_qtd = next_qtd;
			next_qtd = ehci_qtd_iommu_to_cpu(ehcip,
			    Get_QTD(curr_qtd->qtd_active_qtd_next));
		}

		Set_QTD(qtd->qtd_active_qtd_prev,
		    ehci_qtd_cpu_to_iommu(ehcip, curr_qtd));

		Set_QTD(curr_qtd->qtd_active_qtd_next,
		    ehci_qtd_cpu_to_iommu(ehcip, qtd));
	} else {
		ehcip->ehci_active_qtd_list = qtd;
		Set_QTD(qtd->qtd_active_qtd_next, 0);
		Set_QTD(qtd->qtd_active_qtd_prev, 0);
	}
}


/*
 * ehci_remove_qtd_from_active_qtd_list:
 *
 * Remove current QTD from the active QTD list.
 *
 * NOTE: This function is also called from POLLED MODE.
 */
void
ehci_remove_qtd_from_active_qtd_list(
	ehci_state_t		*ehcip,
	ehci_qtd_t		*qtd)
{
	ehci_qtd_t		*curr_qtd, *prev_qtd, *next_qtd;

	ASSERT(qtd != NULL);

	curr_qtd = ehcip->ehci_active_qtd_list;

	while ((curr_qtd) && (curr_qtd != qtd)) {
		curr_qtd = ehci_qtd_iommu_to_cpu(ehcip,
		    Get_QTD(curr_qtd->qtd_active_qtd_next));
	}

	if ((curr_qtd) && (curr_qtd == qtd)) {
		prev_qtd = ehci_qtd_iommu_to_cpu(ehcip,
		    Get_QTD(curr_qtd->qtd_active_qtd_prev));
		next_qtd = ehci_qtd_iommu_to_cpu(ehcip,
		    Get_QTD(curr_qtd->qtd_active_qtd_next));

		if (prev_qtd) {
			Set_QTD(prev_qtd->qtd_active_qtd_next,
			    Get_QTD(curr_qtd->qtd_active_qtd_next));
		} else {
			ehcip->ehci_active_qtd_list = next_qtd;
		}

		if (next_qtd) {
			Set_QTD(next_qtd->qtd_active_qtd_prev,
			    Get_QTD(curr_qtd->qtd_active_qtd_prev));
		}
	} else {
		USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
		    "ehci_remove_qtd_from_active_qtd_list: "
		    "Unable to find QTD in active_qtd_list");
	}
}


/*
 * ehci_traverse_qtds:
 *
 * Traverse the list of QTDs for given pipe using transfer wrapper.  Since
 * the endpoint is marked as Halted, the Host Controller (HC) is no longer
 * accessing these QTDs. Remove all the QTDs that are attached to endpoint.
 */
static void
ehci_traverse_qtds(
	ehci_state_t		*ehcip,
	usba_pipe_handle_data_t	*ph)
{
	ehci_pipe_private_t	*pp = (ehci_pipe_private_t *)ph->p_hcd_private;
	ehci_trans_wrapper_t	*next_tw;
	ehci_qtd_t		*qtd;
	ehci_qtd_t		*next_qtd;

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_traverse_qtds:");

	/* Process the transfer wrappers for this pipe */
	next_tw = pp->pp_tw_head;

	while (next_tw) {
		/* Stop the the transfer timer */
		ehci_stop_xfer_timer(ehcip, next_tw, EHCI_REMOVE_XFER_ALWAYS);

		qtd = (ehci_qtd_t *)next_tw->tw_qtd_head;

		/* Walk through each QTD for this transfer wrapper */
		while (qtd) {
			/* Remove this QTD from active QTD list */
			ehci_remove_qtd_from_active_qtd_list(ehcip, qtd);

			next_qtd = ehci_qtd_iommu_to_cpu(ehcip,
			    Get_QTD(qtd->qtd_tw_next_qtd));

			/* Deallocate this QTD */
			ehci_deallocate_qtd(ehcip, qtd);

			qtd = next_qtd;
		}

		next_tw = next_tw->tw_next;
	}

	/* Clear current qtd pointer */
	Set_QH(pp->pp_qh->qh_curr_qtd, (uint32_t)0x00000000);

	/* Update the next qtd pointer in the QH */
	Set_QH(pp->pp_qh->qh_next_qtd, Get_QH(pp->pp_qh->qh_dummy_qtd));
}


/*
 * ehci_deallocate_qtd:
 *
 * Deallocate a Host Controller's (HC) Transfer Descriptor (QTD).
 *
 * NOTE: This function is also called from POLLED MODE.
 */
void
ehci_deallocate_qtd(
	ehci_state_t		*ehcip,
	ehci_qtd_t		*old_qtd)
{
	ehci_trans_wrapper_t	*tw = NULL;

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ehcip->ehci_log_hdl,
	    "ehci_deallocate_qtd: old_qtd = 0x%p", (void *)old_qtd);

	/*
	 * Obtain the transaction wrapper and tw will be
	 * NULL for the dummy QTDs.
	 */
	if (Get_QTD(old_qtd->qtd_state) != EHCI_QTD_DUMMY) {
		tw = (ehci_trans_wrapper_t *)
		    EHCI_LOOKUP_ID((uint32_t)
		    Get_QTD(old_qtd->qtd_trans_wrapper));

		ASSERT(tw != NULL);
	}

	/*
	 * If QTD's transfer wrapper is NULL, don't access its TW.
	 * Just free the QTD.
	 */
	if (tw) {
		ehci_qtd_t	*qtd, *next_qtd;

		qtd = tw->tw_qtd_head;

		if (old_qtd != qtd) {
			next_qtd = ehci_qtd_iommu_to_cpu(
			    ehcip, Get_QTD(qtd->qtd_tw_next_qtd));

			while (next_qtd != old_qtd) {
				qtd = next_qtd;
				next_qtd = ehci_qtd_iommu_to_cpu(
				    ehcip, Get_QTD(qtd->qtd_tw_next_qtd));
			}

			Set_QTD(qtd->qtd_tw_next_qtd, old_qtd->qtd_tw_next_qtd);

			if (qtd->qtd_tw_next_qtd == 0) {
				tw->tw_qtd_tail = qtd;
			}
		} else {
			tw->tw_qtd_head = ehci_qtd_iommu_to_cpu(
			    ehcip, Get_QTD(old_qtd->qtd_tw_next_qtd));

			if (tw->tw_qtd_head == NULL) {
				tw->tw_qtd_tail = NULL;
			}
		}
	}

	bzero((void *)old_qtd, sizeof (ehci_qtd_t));
	Set_QTD(old_qtd->qtd_state, EHCI_QTD_FREE);

	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "Dealloc_qtd: qtd 0x%p", (void *)old_qtd);
}


/*
 * ehci_qtd_cpu_to_iommu:
 *
 * This function converts for the given Transfer Descriptor (QTD) CPU address
 * to IO address.
 *
 * NOTE: This function is also called from POLLED MODE.
 */
uint32_t
ehci_qtd_cpu_to_iommu(
	ehci_state_t	*ehcip,
	ehci_qtd_t	*addr)
{
	uint32_t	td;

	td  = (uint32_t)ehcip->ehci_qtd_pool_cookie.dmac_address +
	    (uint32_t)((uintptr_t)addr -
	    (uintptr_t)(ehcip->ehci_qtd_pool_addr));

	ASSERT((ehcip->ehci_qtd_pool_cookie.dmac_address +
	    (uint32_t) (sizeof (ehci_qtd_t) *
	    (addr - ehcip->ehci_qtd_pool_addr))) ==
	    (ehcip->ehci_qtd_pool_cookie.dmac_address +
	    (uint32_t)((uintptr_t)addr - (uintptr_t)
	    (ehcip->ehci_qtd_pool_addr))));

	ASSERT(td >= ehcip->ehci_qtd_pool_cookie.dmac_address);
	ASSERT(td <= ehcip->ehci_qtd_pool_cookie.dmac_address +
	    sizeof (ehci_qtd_t) * ehci_qtd_pool_size);

	return (td);
}


/*
 * ehci_qtd_iommu_to_cpu:
 *
 * This function converts for the given Transfer Descriptor (QTD) IO address
 * to CPU address.
 *
 * NOTE: This function is also called from POLLED MODE.
 */
ehci_qtd_t *
ehci_qtd_iommu_to_cpu(
	ehci_state_t	*ehcip,
	uintptr_t	addr)
{
	ehci_qtd_t	*qtd;

	if (addr == 0)
		return (NULL);

	qtd = (ehci_qtd_t *)((uintptr_t)
	    (addr - ehcip->ehci_qtd_pool_cookie.dmac_address) +
	    (uintptr_t)ehcip->ehci_qtd_pool_addr);

	ASSERT(qtd >= ehcip->ehci_qtd_pool_addr);
	ASSERT((uintptr_t)qtd <= (uintptr_t)ehcip->ehci_qtd_pool_addr +
	    (uintptr_t)(sizeof (ehci_qtd_t) * ehci_qtd_pool_size));

	return (qtd);
}

/*
 * ehci_allocate_tds_for_tw_resources:
 *
 * Allocate n Transfer Descriptors (TD) from the TD buffer pool and places it
 * into the TW.  Also chooses the correct alternate qtd when required.	It is
 * used for hardware short transfer support.  For more information on
 * alternate qtds look at section 3.5.2 in the EHCI spec.
 * Here is how each alternate qtd's are used:
 *
 * Bulk: used fully.
 * Intr: xfers only require 1 QTD, so alternate qtds are never used.
 * Ctrl: Should not use alternate QTD
 * Isoch: Doesn't support short_xfer nor does it use QTD
 *
 * Returns USB_NO_RESOURCES if it was not able to allocate all the requested TD
 * otherwise USB_SUCCESS.
 */
int
ehci_allocate_tds_for_tw(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_trans_wrapper_t	*tw,
	size_t			qtd_count)
{
	usb_ep_descr_t		*eptd = &pp->pp_pipe_handle->p_ep;
	uchar_t			attributes;
	ehci_qtd_t		*qtd;
	uint32_t		qtd_addr;
	int			i;
	int			error = USB_SUCCESS;

	attributes = eptd->bmAttributes & USB_EP_ATTR_MASK;

	for (i = 0; i < qtd_count; i += 1) {
		qtd = ehci_allocate_qtd_from_pool(ehcip);
		if (qtd == NULL) {
			error = USB_NO_RESOURCES;
			USB_DPRINTF_L2(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
			    "ehci_allocate_qtds_for_tw: "
			    "Unable to allocate %lu QTDs",
			    qtd_count);
			break;
		}
		if (i > 0) {
			qtd_addr = ehci_qtd_cpu_to_iommu(ehcip,
			    tw->tw_qtd_free_list);
			Set_QTD(qtd->qtd_tw_next_qtd, qtd_addr);
		}
		tw->tw_qtd_free_list = qtd;

		/*
		 * Save the second one as a pointer to the new dummy 1.
		 * It is used later for the alt_qtd_ptr.  Xfers with only
		 * one qtd do not need alt_qtd_ptr.
		 * The tds's are allocated and put into a stack, that is
		 * why the second qtd allocated will turn out to be the
		 * new dummy 1.
		 */
		if ((i == 1) && (attributes == USB_EP_ATTR_BULK)) {
			tw->tw_alt_qtd = qtd;
		}
	}

	return (error);
}

/*
 * ehci_allocate_tw_resources:
 *
 * Allocate a Transaction Wrapper (TW) and n Transfer Descriptors (QTD)
 * from the QTD buffer pool and places it into the TW.	It does an all
 * or nothing transaction.
 *
 * Returns NULL if there is insufficient resources otherwise TW.
 */
static ehci_trans_wrapper_t *
ehci_allocate_tw_resources(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	size_t			tw_length,
	usb_flags_t		usb_flags,
	size_t			qtd_count)
{
	ehci_trans_wrapper_t	*tw;

	tw = ehci_create_transfer_wrapper(ehcip, pp, tw_length, usb_flags);

	if (tw == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
		    "ehci_allocate_tw_resources: Unable to allocate TW");
	} else {
		if (ehci_allocate_tds_for_tw(ehcip, pp, tw, qtd_count) ==
		    USB_SUCCESS) {
			tw->tw_num_qtds = (uint_t)qtd_count;
		} else {
			ehci_deallocate_tw(ehcip, pp, tw);
			tw = NULL;
		}
	}

	return (tw);
}


/*
 * ehci_free_tw_td_resources:
 *
 * Free all allocated resources for Transaction Wrapper (TW).
 * Does not free the TW itself.
 *
 * Returns NULL if there is insufficient resources otherwise TW.
 */
static void
ehci_free_tw_td_resources(
	ehci_state_t		*ehcip,
	ehci_trans_wrapper_t	*tw)
{
	ehci_qtd_t		*qtd = NULL;
	ehci_qtd_t		*temp_qtd = NULL;

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ehcip->ehci_log_hdl,
	    "ehci_free_tw_td_resources: tw = 0x%p", (void *)tw);

	qtd = tw->tw_qtd_free_list;
	while (qtd != NULL) {
		/* Save the pointer to the next qtd before destroying it */
		temp_qtd = ehci_qtd_iommu_to_cpu(ehcip,
		    Get_QTD(qtd->qtd_tw_next_qtd));
		ehci_deallocate_qtd(ehcip, qtd);
		qtd = temp_qtd;
	}
	tw->tw_qtd_free_list = NULL;
}

/*
 * Transfer Wrapper functions
 *
 * ehci_create_transfer_wrapper:
 *
 * Create a Transaction Wrapper (TW) and this involves the allocating of DMA
 * resources.
 */
static ehci_trans_wrapper_t *
ehci_create_transfer_wrapper(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	size_t			length,
	uint_t			usb_flags)
{
	ddi_device_acc_attr_t	dev_attr;
	ddi_dma_attr_t		dma_attr;
	int			result;
	size_t			real_length;
	ehci_trans_wrapper_t	*tw;
	int			kmem_flag;
	int			(*dmamem_wait)(caddr_t);
	usb_ep_descr_t		*eptd = &pp->pp_pipe_handle->p_ep;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_create_transfer_wrapper: length = 0x%lx flags = 0x%x",
	    length, usb_flags);

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/* SLEEP flag should not be used while holding mutex */
	kmem_flag = KM_NOSLEEP;
	dmamem_wait = DDI_DMA_DONTWAIT;

	/* Allocate space for the transfer wrapper */
	tw = kmem_zalloc(sizeof (ehci_trans_wrapper_t), kmem_flag);

	if (tw == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS,  ehcip->ehci_log_hdl,
		    "ehci_create_transfer_wrapper: kmem_zalloc failed");

		return (NULL);
	}

	/* zero-length packet doesn't need to allocate dma memory */
	if (length == 0) {

		goto dmadone;
	}

	/* allow sg lists for transfer wrapper dma memory */
	bcopy(&ehcip->ehci_dma_attr, &dma_attr, sizeof (ddi_dma_attr_t));
	dma_attr.dma_attr_sgllen = EHCI_DMA_ATTR_TW_SGLLEN;
	dma_attr.dma_attr_align = EHCI_DMA_ATTR_ALIGNMENT;

	/* Allocate the DMA handle */
	result = ddi_dma_alloc_handle(ehcip->ehci_dip,
	    &dma_attr, dmamem_wait, 0, &tw->tw_dmahandle);

	if (result != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
		    "ehci_create_transfer_wrapper: Alloc handle failed");

		kmem_free(tw, sizeof (ehci_trans_wrapper_t));

		return (NULL);
	}

	dev_attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;

	/* no need for swapping the raw data */
	dev_attr.devacc_attr_endian_flags  = DDI_NEVERSWAP_ACC;
	dev_attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	/* Allocate the memory */
	result = ddi_dma_mem_alloc(tw->tw_dmahandle, length,
	    &dev_attr, DDI_DMA_CONSISTENT, dmamem_wait, NULL,
	    (caddr_t *)&tw->tw_buf, &real_length, &tw->tw_accesshandle);

	if (result != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
		    "ehci_create_transfer_wrapper: dma_mem_alloc fail");

		ddi_dma_free_handle(&tw->tw_dmahandle);
		kmem_free(tw, sizeof (ehci_trans_wrapper_t));

		return (NULL);
	}

	ASSERT(real_length >= length);

	/* Bind the handle */
	result = ddi_dma_addr_bind_handle(tw->tw_dmahandle, NULL,
	    (caddr_t)tw->tw_buf, real_length, DDI_DMA_RDWR|DDI_DMA_CONSISTENT,
	    dmamem_wait, NULL, &tw->tw_cookie, &tw->tw_ncookies);

	if (result != DDI_DMA_MAPPED) {
		ehci_decode_ddi_dma_addr_bind_handle_result(ehcip, result);

		ddi_dma_mem_free(&tw->tw_accesshandle);
		ddi_dma_free_handle(&tw->tw_dmahandle);
		kmem_free(tw, sizeof (ehci_trans_wrapper_t));

		return (NULL);
	}

	tw->tw_cookie_idx = 0;
	tw->tw_dma_offs = 0;

dmadone:
	/*
	 * Only allow one wrapper to be added at a time. Insert the
	 * new transaction wrapper into the list for this pipe.
	 */
	if (pp->pp_tw_head == NULL) {
		pp->pp_tw_head = tw;
		pp->pp_tw_tail = tw;
	} else {
		pp->pp_tw_tail->tw_next = tw;
		pp->pp_tw_tail = tw;
	}

	/* Store the transfer length */
	tw->tw_length = length;

	/* Store a back pointer to the pipe private structure */
	tw->tw_pipe_private = pp;

	/* Store the transfer type - synchronous or asynchronous */
	tw->tw_flags = usb_flags;

	/* Get and Store 32bit ID */
	tw->tw_id = EHCI_GET_ID((void *)tw);

	ASSERT(tw->tw_id != 0);

	/* isoc ep will not come here */
	if (EHCI_INTR_ENDPOINT(eptd)) {
		ehcip->ehci_periodic_req_count++;
	} else {
		ehcip->ehci_async_req_count++;
	}
	ehci_toggle_scheduler(ehcip);

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ehcip->ehci_log_hdl,
	    "ehci_create_transfer_wrapper: tw = 0x%p, ncookies = %u",
	    (void *)tw, tw->tw_ncookies);

	return (tw);
}


/*
 * ehci_start_xfer_timer:
 *
 * Start the timer for the control, bulk and for one time interrupt
 * transfers.
 */
/* ARGSUSED */
static void
ehci_start_xfer_timer(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_trans_wrapper_t	*tw)
{
	USB_DPRINTF_L3(PRINT_MASK_LISTS,  ehcip->ehci_log_hdl,
	    "ehci_start_xfer_timer: tw = 0x%p", (void *)tw);

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/*
	 * The timeout handling is done only for control, bulk and for
	 * one time Interrupt transfers.
	 *
	 * NOTE: If timeout is zero; Assume infinite timeout and don't
	 * insert this transfer on the timeout list.
	 */
	if (tw->tw_timeout) {
		/*
		 * Add this transfer wrapper to the head of the pipe's
		 * tw timeout list.
		 */
		if (pp->pp_timeout_list) {
			tw->tw_timeout_next = pp->pp_timeout_list;
		}

		pp->pp_timeout_list = tw;
		ehci_start_timer(ehcip, pp);
	}
}


/*
 * ehci_stop_xfer_timer:
 *
 * Start the timer for the control, bulk and for one time interrupt
 * transfers.
 */
void
ehci_stop_xfer_timer(
	ehci_state_t		*ehcip,
	ehci_trans_wrapper_t	*tw,
	uint_t			flag)
{
	ehci_pipe_private_t	*pp;
	timeout_id_t		timer_id;

	USB_DPRINTF_L3(PRINT_MASK_LISTS,  ehcip->ehci_log_hdl,
	    "ehci_stop_xfer_timer: tw = 0x%p", (void *)tw);

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/* Obtain the pipe private structure */
	pp = tw->tw_pipe_private;

	/* check if the timeout tw list is empty */
	if (pp->pp_timeout_list == NULL) {

		return;
	}

	switch (flag) {
	case EHCI_REMOVE_XFER_IFLAST:
		if (tw->tw_qtd_head != tw->tw_qtd_tail) {
			break;
		}

		/* FALLTHRU */
	case EHCI_REMOVE_XFER_ALWAYS:
		ehci_remove_tw_from_timeout_list(ehcip, tw);

		if ((pp->pp_timeout_list == NULL) &&
		    (pp->pp_timer_id)) {

			timer_id = pp->pp_timer_id;

			/* Reset the timer id to zero */
			pp->pp_timer_id = 0;

			mutex_exit(&ehcip->ehci_int_mutex);

			(void) untimeout(timer_id);

			mutex_enter(&ehcip->ehci_int_mutex);
		}
		break;
	default:
		break;
	}
}


/*
 * ehci_xfer_timeout_handler:
 *
 * Control or bulk transfer timeout handler.
 */
static void
ehci_xfer_timeout_handler(void *arg)
{
	usba_pipe_handle_data_t	*ph = (usba_pipe_handle_data_t *)arg;
	ehci_state_t		*ehcip = ehci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	ehci_pipe_private_t	*pp = (ehci_pipe_private_t *)ph->p_hcd_private;
	ehci_trans_wrapper_t	*tw, *next;
	ehci_trans_wrapper_t	*expire_xfer_list = NULL;
	ehci_qtd_t		*qtd;

	USB_DPRINTF_L4(PRINT_MASK_LISTS,  ehcip->ehci_log_hdl,
	    "ehci_xfer_timeout_handler: ehcip = 0x%p, ph = 0x%p",
	    (void *)ehcip, (void *)ph);

	mutex_enter(&ehcip->ehci_int_mutex);

	/*
	 * Check whether still timeout handler is valid.
	 */
	if (pp->pp_timer_id != 0) {

		/* Reset the timer id to zero */
		pp->pp_timer_id = 0;
	} else {
		mutex_exit(&ehcip->ehci_int_mutex);

		return;
	}

	/* Get the transfer timeout list head */
	tw = pp->pp_timeout_list;

	while (tw) {

		/* Get the transfer on the timeout list */
		next = tw->tw_timeout_next;

		tw->tw_timeout--;

		if (tw->tw_timeout <= 0) {

			/* remove the tw from the timeout list */
			ehci_remove_tw_from_timeout_list(ehcip, tw);

			/* remove QTDs from active QTD list */
			qtd = tw->tw_qtd_head;
			while (qtd) {
				ehci_remove_qtd_from_active_qtd_list(
				    ehcip, qtd);

				/* Get the next QTD from the wrapper */
				qtd = ehci_qtd_iommu_to_cpu(ehcip,
				    Get_QTD(qtd->qtd_tw_next_qtd));
			}

			/*
			 * Preserve the order to the requests
			 * started time sequence.
			 */
			tw->tw_timeout_next = expire_xfer_list;
			expire_xfer_list = tw;
		}

		tw = next;
	}

	/*
	 * The timer should be started before the callbacks.
	 * There is always a chance that ehci interrupts come
	 * in when we release the mutex while calling the tw back.
	 * To keep an accurate timeout it should be restarted
	 * as soon as possible.
	 */
	ehci_start_timer(ehcip, pp);

	/* Get the expired transfer timeout list head */
	tw = expire_xfer_list;

	while (tw) {

		/* Get the next tw on the expired transfer timeout list */
		next = tw->tw_timeout_next;

		/*
		 * The error handle routine will release the mutex when
		 * calling back to USBA. But this will not cause any race.
		 * We do the callback and are relying on ehci_pipe_cleanup()
		 * to halt the queue head and clean up since we should not
		 * block in timeout context.
		 */
		ehci_handle_error(ehcip, tw->tw_qtd_head, USB_CR_TIMEOUT);

		tw = next;
	}
	mutex_exit(&ehcip->ehci_int_mutex);
}


/*
 * ehci_remove_tw_from_timeout_list:
 *
 * Remove Control or bulk transfer from the timeout list.
 */
static void
ehci_remove_tw_from_timeout_list(
	ehci_state_t		*ehcip,
	ehci_trans_wrapper_t	*tw)
{
	ehci_pipe_private_t	*pp;
	ehci_trans_wrapper_t	*prev, *next;

	USB_DPRINTF_L3(PRINT_MASK_LISTS,  ehcip->ehci_log_hdl,
	    "ehci_remove_tw_from_timeout_list: tw = 0x%p", (void *)tw);

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/* Obtain the pipe private structure */
	pp = tw->tw_pipe_private;

	if (pp->pp_timeout_list) {
		if (pp->pp_timeout_list == tw) {
			pp->pp_timeout_list = tw->tw_timeout_next;

			tw->tw_timeout_next = NULL;
		} else {
			prev = pp->pp_timeout_list;
			next = prev->tw_timeout_next;

			while (next && (next != tw)) {
				prev = next;
				next = next->tw_timeout_next;
			}

			if (next == tw) {
				prev->tw_timeout_next =
				    next->tw_timeout_next;
				tw->tw_timeout_next = NULL;
			}
		}
	}
}


/*
 * ehci_start_timer:
 *
 * Start the pipe's timer
 */
static void
ehci_start_timer(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp)
{
	USB_DPRINTF_L4(PRINT_MASK_LISTS,  ehcip->ehci_log_hdl,
	    "ehci_start_timer: ehcip = 0x%p, pp = 0x%p",
	    (void *)ehcip, (void *)pp);

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/*
	 * Start the pipe's timer only if currently timer is not
	 * running and if there are any transfers on the timeout
	 * list. This timer will be per pipe.
	 */
	if ((!pp->pp_timer_id) && (pp->pp_timeout_list)) {
		pp->pp_timer_id = timeout(ehci_xfer_timeout_handler,
		    (void *)(pp->pp_pipe_handle), drv_usectohz(1000000));
	}
}

/*
 * ehci_deallocate_tw:
 *
 * Deallocate of a Transaction Wrapper (TW) and this involves the freeing of
 * of DMA resources.
 */
void
ehci_deallocate_tw(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_trans_wrapper_t	*tw)
{
	ehci_trans_wrapper_t	*prev, *next;

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ehcip->ehci_log_hdl,
	    "ehci_deallocate_tw: tw = 0x%p", (void *)tw);

	/*
	 * If the transfer wrapper has no Host Controller (HC)
	 * Transfer Descriptors (QTD) associated with it,  then
	 * remove the transfer wrapper.
	 */
	if (tw->tw_qtd_head) {
		ASSERT(tw->tw_qtd_tail != NULL);

		return;
	}

	ASSERT(tw->tw_qtd_tail == NULL);

	/* Make sure we return all the unused qtd's to the pool as well */
	ehci_free_tw_td_resources(ehcip, tw);

	/*
	 * If pp->pp_tw_head and pp->pp_tw_tail are pointing to
	 * given TW then set the head and  tail  equal to NULL.
	 * Otherwise search for this TW in the linked TW's list
	 * and then remove this TW from the list.
	 */
	if (pp->pp_tw_head == tw) {
		if (pp->pp_tw_tail == tw) {
			pp->pp_tw_head = NULL;
			pp->pp_tw_tail = NULL;
		} else {
			pp->pp_tw_head = tw->tw_next;
		}
	} else {
		prev = pp->pp_tw_head;
		next = prev->tw_next;

		while (next && (next != tw)) {
			prev = next;
			next = next->tw_next;
		}

		if (next == tw) {
			prev->tw_next = next->tw_next;

			if (pp->pp_tw_tail == tw) {
				pp->pp_tw_tail = prev;
			}
		}
	}

	/*
	 * Make sure that, this TW has been removed
	 * from the timeout list.
	 */
	ehci_remove_tw_from_timeout_list(ehcip, tw);

	/* Deallocate this TW */
	ehci_free_tw(ehcip, pp, tw);
}


/*
 * ehci_free_dma_resources:
 *
 * Free dma resources of a Transfer Wrapper (TW) and also free the TW.
 *
 * NOTE: This function is also called from POLLED MODE.
 */
void
ehci_free_dma_resources(
	ehci_state_t		*ehcip,
	usba_pipe_handle_data_t	*ph)
{
	ehci_pipe_private_t	*pp = (ehci_pipe_private_t *)ph->p_hcd_private;
	ehci_trans_wrapper_t	*head_tw = pp->pp_tw_head;
	ehci_trans_wrapper_t	*next_tw, *tw;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_free_dma_resources: ph = 0x%p", (void *)ph);

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/* Process the Transfer Wrappers */
	next_tw = head_tw;
	while (next_tw) {
		tw = next_tw;
		next_tw = tw->tw_next;

		USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
		    "ehci_free_dma_resources: Free TW = 0x%p", (void *)tw);

		ehci_free_tw(ehcip, pp, tw);
	}

	/* Adjust the head and tail pointers */
	pp->pp_tw_head = NULL;
	pp->pp_tw_tail = NULL;
}


/*
 * ehci_free_tw:
 *
 * Free the Transfer Wrapper (TW).
 */
/*ARGSUSED*/
static void
ehci_free_tw(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_trans_wrapper_t	*tw)
{
	int	rval;
	usb_ep_descr_t	*eptd = &pp->pp_pipe_handle->p_ep;

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ehcip->ehci_log_hdl,
	    "ehci_free_tw: tw = 0x%p", (void *)tw);

	ASSERT(tw != NULL);
	ASSERT(tw->tw_id != 0);

	/* Free 32bit ID */
	EHCI_FREE_ID((uint32_t)tw->tw_id);

	if (tw->tw_dmahandle != NULL) {
		rval = ddi_dma_unbind_handle(tw->tw_dmahandle);
		ASSERT(rval == DDI_SUCCESS);

		ddi_dma_mem_free(&tw->tw_accesshandle);
		ddi_dma_free_handle(&tw->tw_dmahandle);
	}

	/* interrupt ep will come to this point */
	if (EHCI_INTR_ENDPOINT(eptd)) {
		ehcip->ehci_periodic_req_count--;
	} else {
		ehcip->ehci_async_req_count--;
	}
	ehci_toggle_scheduler(ehcip);

	/* Free transfer wrapper */
	kmem_free(tw, sizeof (ehci_trans_wrapper_t));
}


/*
 * Miscellaneous functions
 */

/*
 * ehci_allocate_intr_in_resource
 *
 * Allocate interrupt request structure for the interrupt IN transfer.
 */
/*ARGSUSED*/
int
ehci_allocate_intr_in_resource(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_trans_wrapper_t	*tw,
	usb_flags_t		flags)
{
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;
	usb_intr_req_t		*curr_intr_reqp;
	usb_opaque_t		client_periodic_in_reqp;
	size_t			length = 0;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_allocate_intr_in_resource:"
	    "pp = 0x%p tw = 0x%p flags = 0x%x", (void *)pp, (void *)tw, flags);

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));
	ASSERT(tw->tw_curr_xfer_reqp == NULL);

	/* Get the client periodic in request pointer */
	client_periodic_in_reqp = pp->pp_client_periodic_in_reqp;

	/*
	 * If it a periodic IN request and periodic request is NULL,
	 * allocate corresponding usb periodic IN request for the
	 * current periodic polling request and copy the information
	 * from the saved periodic request structure.
	 */
	if (client_periodic_in_reqp) {

		/* Get the interrupt transfer length */
		length = ((usb_intr_req_t *)
		    client_periodic_in_reqp)->intr_len;

		curr_intr_reqp = usba_hcdi_dup_intr_req(ph->p_dip,
		    (usb_intr_req_t *)client_periodic_in_reqp, length, flags);
	} else {
		curr_intr_reqp = usb_alloc_intr_req(ph->p_dip, length, flags);
	}

	if (curr_intr_reqp == NULL) {

		USB_DPRINTF_L2(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
		    "ehci_allocate_intr_in_resource: Interrupt"
		    "request structure allocation failed");

		return (USB_NO_RESOURCES);
	}

	/* For polled mode */
	if (client_periodic_in_reqp == NULL) {
		curr_intr_reqp->intr_attributes = USB_ATTRS_SHORT_XFER_OK;
		curr_intr_reqp->intr_len = ph->p_ep.wMaxPacketSize;
	} else {
		/* Check and save the timeout value */
		tw->tw_timeout = (curr_intr_reqp->intr_attributes &
		    USB_ATTRS_ONE_XFER) ? curr_intr_reqp->intr_timeout: 0;
	}

	tw->tw_curr_xfer_reqp = (usb_opaque_t)curr_intr_reqp;
	tw->tw_length = curr_intr_reqp->intr_len;

	mutex_enter(&ph->p_mutex);
	ph->p_req_count++;
	mutex_exit(&ph->p_mutex);

	pp->pp_state = EHCI_PIPE_STATE_ACTIVE;

	return (USB_SUCCESS);
}

/*
 * ehci_pipe_cleanup
 *
 * Cleanup ehci pipe.
 */
void
ehci_pipe_cleanup(
	ehci_state_t		*ehcip,
	usba_pipe_handle_data_t	*ph)
{
	ehci_pipe_private_t	*pp = (ehci_pipe_private_t *)ph->p_hcd_private;
	uint_t			pipe_state = pp->pp_state;
	usb_cr_t		completion_reason;
	usb_ep_descr_t		*eptd = &ph->p_ep;

	USB_DPRINTF_L4(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_pipe_cleanup: ph = 0x%p", (void *)ph);

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	if (EHCI_ISOC_ENDPOINT(eptd)) {
		ehci_isoc_pipe_cleanup(ehcip, ph);

		return;
	}

	ASSERT(!servicing_interrupt());

	/*
	 * Set the QH's status to Halt condition.
	 * If another thread is halting this function will automatically
	 * wait. If a pipe close happens at this time
	 * we will be in lots of trouble.
	 * If we are in an interrupt thread, don't halt, because it may
	 * do a wait_for_sof.
	 */
	ehci_modify_qh_status_bit(ehcip, pp, SET_HALT);

	/*
	 * Wait for processing all completed transfers and
	 * to send results to upstream.
	 */
	ehci_wait_for_transfers_completion(ehcip, pp);

	/* Save the data toggle information */
	ehci_save_data_toggle(ehcip, ph);

	/*
	 * Traverse the list of QTDs for this pipe using transfer
	 * wrapper. Process these QTDs depending on their status.
	 * And stop the timer of this pipe.
	 */
	ehci_traverse_qtds(ehcip, ph);

	/* Make sure the timer is not running */
	ASSERT(pp->pp_timer_id == 0);

	/* Do callbacks for all unfinished requests */
	ehci_handle_outstanding_requests(ehcip, pp);

	/* Free DMA resources */
	ehci_free_dma_resources(ehcip, ph);

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

		/* Restore the data toggle information */
		ehci_restore_data_toggle(ehcip, ph);

		/*
		 * Clear the halt bit to restart all the
		 * transactions on this pipe.
		 */
		ehci_modify_qh_status_bit(ehcip, pp, CLEAR_HALT);

		/* Set pipe state to idle */
		pp->pp_state = EHCI_PIPE_STATE_IDLE;

		break;
	}

	/*
	 * Do the callback for the original client
	 * periodic IN request.
	 */
	if ((EHCI_PERIODIC_ENDPOINT(eptd)) &&
	    ((ph->p_ep.bEndpointAddress & USB_EP_DIR_MASK) ==
	    USB_EP_DIR_IN)) {

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
ehci_wait_for_transfers_completion(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp)
{
	ehci_trans_wrapper_t	*next_tw = pp->pp_tw_head;
	ehci_qtd_t		*qtd;

	USB_DPRINTF_L4(PRINT_MASK_LISTS,
	    ehcip->ehci_log_hdl,
	    "ehci_wait_for_transfers_completion: pp = 0x%p", (void *)pp);

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	if ((ehci_state_is_operational(ehcip)) != USB_SUCCESS) {

		return;
	}

	pp->pp_count_done_qtds = 0;

	/* Process the transfer wrappers for this pipe */
	while (next_tw) {
		qtd = (ehci_qtd_t *)next_tw->tw_qtd_head;

		/*
		 * Walk through each QTD for this transfer wrapper.
		 * If a QTD still exists, then it is either on done
		 * list or on the QH's list.
		 */
		while (qtd) {
			if (!(Get_QTD(qtd->qtd_ctrl) &
			    EHCI_QTD_CTRL_ACTIVE_XACT)) {
				pp->pp_count_done_qtds++;
			}

			qtd = ehci_qtd_iommu_to_cpu(ehcip,
			    Get_QTD(qtd->qtd_tw_next_qtd));
		}

		next_tw = next_tw->tw_next;
	}

	USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
	    "ehci_wait_for_transfers_completion: count_done_qtds = 0x%x",
	    pp->pp_count_done_qtds);

	if (!pp->pp_count_done_qtds) {

		return;
	}

	(void) cv_reltimedwait(&pp->pp_xfer_cmpl_cv, &ehcip->ehci_int_mutex,
	    drv_usectohz(EHCI_XFER_CMPL_TIMEWAIT * 1000000), TR_CLOCK_TICK);

	if (pp->pp_count_done_qtds) {

		USB_DPRINTF_L2(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
		    "ehci_wait_for_transfers_completion:"
		    "No transfers completion confirmation received");
	}
}

/*
 * ehci_check_for_transfers_completion:
 *
 * Check whether anybody is waiting for transfers completion event. If so, send
 * this event and also stop initiating any new transfers on this pipe.
 */
void
ehci_check_for_transfers_completion(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp)
{
	USB_DPRINTF_L4(PRINT_MASK_LISTS,
	    ehcip->ehci_log_hdl,
	    "ehci_check_for_transfers_completion: pp = 0x%p", (void *)pp);

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	if ((pp->pp_state == EHCI_PIPE_STATE_STOP_POLLING) &&
	    (pp->pp_error == USB_CR_NO_RESOURCES) &&
	    (pp->pp_cur_periodic_req_cnt == 0)) {

		/* Reset pipe error to zero */
		pp->pp_error = 0;

		/* Do callback for original request */
		ehci_do_client_periodic_in_req_callback(
		    ehcip, pp, USB_CR_NO_RESOURCES);
	}

	if (pp->pp_count_done_qtds) {

		USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
		    "ehci_check_for_transfers_completion:"
		    "count_done_qtds = 0x%x", pp->pp_count_done_qtds);

		/* Decrement the done qtd count */
		pp->pp_count_done_qtds--;

		if (!pp->pp_count_done_qtds) {

			USB_DPRINTF_L3(PRINT_MASK_LISTS, ehcip->ehci_log_hdl,
			    "ehci_check_for_transfers_completion:"
			    "Sent transfers completion event pp = 0x%p",
			    (void *)pp);

			/* Send the transfer completion signal */
			cv_signal(&pp->pp_xfer_cmpl_cv);
		}
	}
}


/*
 * ehci_save_data_toggle:
 *
 * Save the data toggle information.
 */
static void
ehci_save_data_toggle(
	ehci_state_t		*ehcip,
	usba_pipe_handle_data_t	*ph)
{
	ehci_pipe_private_t	*pp = (ehci_pipe_private_t *)ph->p_hcd_private;
	usb_ep_descr_t		*eptd = &ph->p_ep;
	uint_t			data_toggle;
	usb_cr_t		error = pp->pp_error;
	ehci_qh_t		*qh = pp->pp_qh;

	USB_DPRINTF_L4(PRINT_MASK_LISTS,
	    ehcip->ehci_log_hdl,
	    "ehci_save_data_toggle: ph = 0x%p", (void *)ph);

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/* Reset the pipe error value */
	pp->pp_error = USB_CR_OK;

	/* Return immediately if it is a control pipe */
	if ((eptd->bmAttributes & USB_EP_ATTR_MASK) ==
	    USB_EP_ATTR_CONTROL) {

		return;
	}

	/* Get the data toggle information from the endpoint (QH) */
	data_toggle = (Get_QH(qh->qh_status) &
	    EHCI_QH_STS_DATA_TOGGLE)? DATA1:DATA0;

	/*
	 * If error is STALL, then, set
	 * data toggle to zero.
	 */
	if (error == USB_CR_STALL) {
		data_toggle = DATA0;
	}

	/*
	 * Save the data toggle information
	 * in the usb device structure.
	 */
	mutex_enter(&ph->p_mutex);
	usba_hcdi_set_data_toggle(ph->p_usba_device, ph->p_ep.bEndpointAddress,
	    data_toggle);
	mutex_exit(&ph->p_mutex);
}


/*
 * ehci_restore_data_toggle:
 *
 * Restore the data toggle information.
 */
void
ehci_restore_data_toggle(
	ehci_state_t		*ehcip,
	usba_pipe_handle_data_t	*ph)
{
	ehci_pipe_private_t	*pp = (ehci_pipe_private_t *)ph->p_hcd_private;
	usb_ep_descr_t		*eptd = &ph->p_ep;
	uint_t			data_toggle = 0;

	USB_DPRINTF_L4(PRINT_MASK_LISTS,
	    ehcip->ehci_log_hdl,
	    "ehci_restore_data_toggle: ph = 0x%p", (void *)ph);

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/* Return immediately if it is a control pipe */
	if ((eptd->bmAttributes & USB_EP_ATTR_MASK) ==
	    USB_EP_ATTR_CONTROL) {

		return;
	}

	mutex_enter(&ph->p_mutex);

	data_toggle = usba_hcdi_get_data_toggle(ph->p_usba_device,
	    ph->p_ep.bEndpointAddress);
	usba_hcdi_set_data_toggle(ph->p_usba_device, ph->p_ep.bEndpointAddress,
	    0);

	mutex_exit(&ph->p_mutex);

	/*
	 * Restore the data toggle bit depending on the
	 * previous data toggle information.
	 */
	if (data_toggle) {
		Set_QH(pp->pp_qh->qh_status,
		    Get_QH(pp->pp_qh->qh_status) | EHCI_QH_STS_DATA_TOGGLE);
	} else {
		Set_QH(pp->pp_qh->qh_status,
		    Get_QH(pp->pp_qh->qh_status) & (~EHCI_QH_STS_DATA_TOGGLE));
	}
}


/*
 * ehci_handle_outstanding_requests
 *
 * Deallocate interrupt request structure for the interrupt IN transfer.
 * Do the callbacks for all unfinished requests.
 *
 * NOTE: This function is also called from POLLED MODE.
 */
void
ehci_handle_outstanding_requests(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp)
{
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;
	usb_ep_descr_t		*eptd = &ph->p_ep;
	ehci_trans_wrapper_t	*curr_tw;
	ehci_trans_wrapper_t	*next_tw;
	usb_opaque_t		curr_xfer_reqp;

	USB_DPRINTF_L4(PRINT_MASK_LISTS,
	    ehcip->ehci_log_hdl,
	    "ehci_handle_outstanding_requests: pp = 0x%p", (void *)pp);

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/* Deallocate all pre-allocated interrupt requests */
	next_tw = pp->pp_tw_head;

	while (next_tw) {
		curr_tw = next_tw;
		next_tw = curr_tw->tw_next;

		curr_xfer_reqp = curr_tw->tw_curr_xfer_reqp;

		/* Deallocate current interrupt request */
		if (curr_xfer_reqp) {

			if ((EHCI_PERIODIC_ENDPOINT(eptd)) &&
			    (curr_tw->tw_direction == EHCI_QTD_CTRL_IN_PID)) {

				/* Decrement periodic in request count */
				pp->pp_cur_periodic_req_cnt--;

				ehci_deallocate_intr_in_resource(
				    ehcip, pp, curr_tw);
			} else {
				ehci_hcdi_callback(ph, curr_tw, USB_CR_FLUSHED);
			}
		}
	}
}


/*
 * ehci_deallocate_intr_in_resource
 *
 * Deallocate interrupt request structure for the interrupt IN transfer.
 */
void
ehci_deallocate_intr_in_resource(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_trans_wrapper_t	*tw)
{
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;
	uchar_t			ep_attr = ph->p_ep.bmAttributes;
	usb_opaque_t		curr_xfer_reqp;

	USB_DPRINTF_L4(PRINT_MASK_LISTS,
	    ehcip->ehci_log_hdl,
	    "ehci_deallocate_intr_in_resource: "
	    "pp = 0x%p tw = 0x%p", (void *)pp, (void *)tw);

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));
	ASSERT((ep_attr & USB_EP_ATTR_MASK) == USB_EP_ATTR_INTR);

	curr_xfer_reqp = tw->tw_curr_xfer_reqp;

	/* Check the current periodic in request pointer */
	if (curr_xfer_reqp) {

		tw->tw_curr_xfer_reqp = NULL;

		mutex_enter(&ph->p_mutex);
		ph->p_req_count--;
		mutex_exit(&ph->p_mutex);

		/* Free pre-allocated interrupt requests */
		usb_free_intr_req((usb_intr_req_t *)curr_xfer_reqp);

		/* Set periodic in pipe state to idle */
		pp->pp_state = EHCI_PIPE_STATE_IDLE;
	}
}


/*
 * ehci_do_client_periodic_in_req_callback
 *
 * Do callback for the original client periodic IN request.
 */
void
ehci_do_client_periodic_in_req_callback(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	usb_cr_t		completion_reason)
{
	usba_pipe_handle_data_t	*ph = pp->pp_pipe_handle;
	usb_ep_descr_t		*eptd = &ph->p_ep;

	USB_DPRINTF_L4(PRINT_MASK_LISTS,
	    ehcip->ehci_log_hdl,
	    "ehci_do_client_periodic_in_req_callback: "
	    "pp = 0x%p cc = 0x%x", (void *)pp, completion_reason);

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/*
	 * Check for Interrupt/Isochronous IN, whether we need to do
	 * callback for the original client's periodic IN request.
	 */
	if (pp->pp_client_periodic_in_reqp) {
		ASSERT(pp->pp_cur_periodic_req_cnt == 0);
		if (EHCI_ISOC_ENDPOINT(eptd)) {
			ehci_hcdi_isoc_callback(ph, NULL, completion_reason);
		} else {
			ehci_hcdi_callback(ph, NULL, completion_reason);
		}
	}
}


/*
 * ehci_hcdi_callback()
 *
 * Convenience wrapper around usba_hcdi_cb() other than root hub.
 */
void
ehci_hcdi_callback(
	usba_pipe_handle_data_t	*ph,
	ehci_trans_wrapper_t	*tw,
	usb_cr_t		completion_reason)
{
	ehci_state_t		*ehcip = ehci_obtain_state(
	    ph->p_usba_device->usb_root_hub_dip);
	ehci_pipe_private_t	*pp = (ehci_pipe_private_t *)ph->p_hcd_private;
	usb_opaque_t		curr_xfer_reqp;
	uint_t			pipe_state = 0;

	USB_DPRINTF_L4(PRINT_MASK_HCDI, ehcip->ehci_log_hdl,
	    "ehci_hcdi_callback: ph = 0x%p, tw = 0x%p, cr = 0x%x",
	    (void *)ph, (void *)tw, completion_reason);

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
	default:
		/* Set the pipe state to error */
		pipe_state = EHCI_PIPE_STATE_ERROR;
		pp->pp_error = completion_reason;
		break;

	}

	pp->pp_state = pipe_state;

	if (tw && tw->tw_curr_xfer_reqp) {
		curr_xfer_reqp = tw->tw_curr_xfer_reqp;
		tw->tw_curr_xfer_reqp = NULL;
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
