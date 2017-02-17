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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*
 * Open Host Controller Driver (OHCI)
 *
 * The USB Open Host Controller driver is a software driver which interfaces
 * to the Universal Serial Bus layer (USBA) and the USB Open Host Controller.
 * The interface to USB Open Host Controller is defined by the OpenHCI	Host
 * Controller Interface.
 *
 * This module contains the specific ohci code used in POLLED mode and this
 * code is in a separate file since it will never become part of ohci driver.
 */
#include <sys/usb/hcd/openhci/ohcid.h>
#include <sys/usb/hcd/openhci/ohci_polled.h>

/*
 * Internal Function Prototypes
 */

/* Polled initialization routines */
static int	ohci_polled_init(
				usba_pipe_handle_data_t	*ph,
				ohci_state_t		*ohcip,
				usb_console_info_impl_t	*console_input_info);

/* Polled deinitialization routines */
static int	ohci_polled_fini(ohci_polled_t		*ohci_polledp);

/* Polled save state routines */
static void	ohci_polled_save_state(ohci_polled_t	*ohci_polledp);
static void	ohci_polled_stop_processing(
				ohci_polled_t		*ohci_polledp);

/* Polled restore state routines */
static void	ohci_polled_restore_state(ohci_polled_t	*ohci_polledp);
static void	ohci_polled_start_processing(
				ohci_polled_t		*ohci_polledp);

/* Polled read routines */
static ohci_td_t *ohci_polled_pickup_done_list(
				ohci_polled_t		*ohci_polledp,
				ohci_td_t		*done_head);
static int	ohci_polled_check_done_list(
				ohci_polled_t		*ohci_polledp);
static void	ohci_polled_create_input_list(
				ohci_polled_t		*ohci_polledp,
				ohci_td_t		*head_done_list);
static int	ohci_polled_process_input_list(
				ohci_polled_t		*ohci_polledp);
static int	ohci_polled_handle_normal_td(
				ohci_polled_t		*ohci_polledp,
				ohci_td_t		*td);
static void	ohci_polled_insert_td(ohci_state_t	*ohcip,
				ohci_td_t		*td);
static void	ohci_polled_fill_in_td(ohci_state_t	*ohcip,
				ohci_td_t		*td,
				ohci_td_t		*new_dummy,
				uint_t			hctd_ctrl,
				uint32_t		hctd_iommu_cbp,
				size_t			hctd_length,
				ohci_trans_wrapper_t	*tw);
static void	ohci_polled_insert_td_on_tw(
				ohci_state_t		*ohcip,
				ohci_trans_wrapper_t	*tw,
				ohci_td_t		*td);
static void	ohci_polled_handle_frame_number_overflow(
				ohci_state_t		*ohcip);
static void	ohci_polled_finish_interrupt(
				ohci_state_t		*ohcip,
				uint_t			intr);
static void	ohci_polled_insert_bulk_td(
				ohci_polled_t		*ohci_polledp);
static int 	ohci_polled_create_tw(
				ohci_state_t		*ohcip,
				usba_pipe_handle_data_t	*ph,
				usb_flags_t		usb_flags);
static int	ohci_polled_insert_hc_td(
				ohci_state_t		*ohcip,
				uint_t			hctd_ctrl,
				uint32_t		hctd_dma_offs,
				size_t			hctd_length,
				ohci_pipe_private_t	*pp,
				ohci_trans_wrapper_t	*tw);
/*
 * POLLED entry points
 *
 * These functions are entry points into the POLLED code.
 */

/*
 * ohci_hcdi_polled_input_init:
 *
 * This is the initialization routine for handling the USB input device
 * in POLLED mode.  This routine is not called from POLLED mode, so
 * it is OK to acquire mutexes.
 */
int
ohci_hcdi_polled_input_init(
	usba_pipe_handle_data_t	*ph,
	uchar_t			**polled_buf,
	usb_console_info_impl_t	*console_input_info)
{
	ohci_polled_t		*ohci_polledp;
	ohci_state_t		*ohcip;
	int			pipe_attr, ret;

	ohcip = ohci_obtain_state(ph->p_usba_device->usb_root_hub_dip);

	/*
	 * Grab the ohci_int_mutex so that things don't change on us
	 * if an interrupt comes in.
	 */
	mutex_enter(&ohcip->ohci_int_mutex);

	ret = ohci_polled_init(ph, ohcip, console_input_info);

	if (ret != USB_SUCCESS) {

		/* Allow interrupts to continue */
		mutex_exit(&ohcip->ohci_int_mutex);

		return (ret);
	}

	ohci_polledp = (ohci_polled_t *)console_input_info->uci_private;
	/*
	 * Mark the structure so that if we are using it, we don't free
	 * the structures if one of them is unplugged.
	 */
	ohci_polledp->ohci_polled_flags |= POLLED_INPUT_MODE;

	/* increase the polled kbd counter for keyboard connected */
	ohcip->ohci_polled_kbd_count ++;

	/*
	 * This is the buffer we will copy characters into. It will be
	 * copied into at this layer, so we need to keep track of it.
	 */
	ohci_polledp->ohci_polled_buf =
	    (uchar_t *)kmem_zalloc(POLLED_RAW_BUF_SIZE, KM_SLEEP);

	*polled_buf = ohci_polledp->ohci_polled_buf;

	/* Insert bulkin td into endpoint's tds list */
	pipe_attr = ohci_polledp->ohci_polled_input_pipe_handle->
	    p_ep.bmAttributes & USB_EP_ATTR_MASK;

	if (pipe_attr == USB_EP_ATTR_BULK) {
		ohci_polled_insert_bulk_td(ohci_polledp);
	}
	/*
	 * This is a software workaround to fix schizo hardware bug.
	 * Existence of "no-prom-cdma-sync"  property means consistent
	 * dma sync should not be done while in prom or polled mode.
	 */
	if (ddi_prop_exists(DDI_DEV_T_ANY, ohcip->ohci_dip,
	    DDI_PROP_NOTPROM, "no-prom-cdma-sync")) {
		ohci_polledp->ohci_polled_no_sync_flag = B_TRUE;
	}

	/* Allow interrupts to continue */
	mutex_exit(&ohcip->ohci_int_mutex);

	return (USB_SUCCESS);
}


/*
 * ohci_hcdi_polled_input_fini:
 */
int
ohci_hcdi_polled_input_fini(usb_console_info_impl_t *info)
{
	ohci_polled_t		*ohci_polledp;
	ohci_state_t		*ohcip;
	int			ret;

	ohci_polledp = (ohci_polled_t *)info->uci_private;

	ohcip = ohci_polledp->ohci_polled_ohcip;

	mutex_enter(&ohcip->ohci_int_mutex);

	/*
	 * Reset the POLLED_INPUT_MODE flag so that we can tell if
	 * this structure is in use in the ohci_polled_fini routine.
	 */
	ohci_polledp->ohci_polled_flags &= ~POLLED_INPUT_MODE;

	/* Decrease the polled kbd counter for keyboard disconnected */
	ohcip->ohci_polled_kbd_count --;

	/* Free the buffer that we copied data into */
	kmem_free(ohci_polledp->ohci_polled_buf, POLLED_RAW_BUF_SIZE);

	ret = ohci_polled_fini(ohci_polledp);

	mutex_exit(&ohcip->ohci_int_mutex);

	return (ret);
}


/*
 * ohci_hcdi_polled_input_enter:
 *
 * This is where we enter into POLLED mode.  This routine sets up
 * everything so that calls to	ohci_hcdi_polled_read will return
 * characters.
 */
int
ohci_hcdi_polled_input_enter(usb_console_info_impl_t *info)
{
	ohci_polled_t		*ohci_polledp;

	ohci_polledp = (ohci_polled_t *)info->uci_private;
	ohci_polledp->ohci_polled_entry++;
	/*
	 * If the controller is already switched over, just return
	 */
	if (ohci_polledp->ohci_polled_entry > 1) {

		return (USB_SUCCESS);
	}
	ohci_polled_save_state(ohci_polledp);

	ohci_polledp->ohci_polled_flags |= POLLED_INPUT_MODE_INUSE;

	return (USB_SUCCESS);
}


/*
 * ohci_hcdi_polled_input_exit:
 *
 * This is where we exit POLLED mode. This routine restores
 * everything that is needed to continue operation.
 */
int
ohci_hcdi_polled_input_exit(usb_console_info_impl_t *info)
{
	ohci_polled_t		*ohci_polledp;

	ohci_polledp = (ohci_polled_t *)info->uci_private;

	ohci_polledp->ohci_polled_entry--;

	/*
	 * If there are still outstanding "enters", just return
	 */
	if (ohci_polledp->ohci_polled_entry > 0)
		return (USB_SUCCESS);

	ohci_polledp->ohci_polled_flags &= ~POLLED_INPUT_MODE_INUSE;
	ohci_polled_restore_state(ohci_polledp);

	return (USB_SUCCESS);
}


/*
 * ohci_hcdi_polled_read:
 *
 * Get a key character
 */
int
ohci_hcdi_polled_read(
	usb_console_info_impl_t	*info,
	uint_t			*num_characters)
{
	ohci_state_t		*ohcip;
	ohci_polled_t		*ohci_polledp;
	uint_t			intr;
	ohci_polledp = (ohci_polled_t *)info->uci_private;

	ohcip = ohci_polledp->ohci_polled_ohcip;

#ifndef lint
	_NOTE(NO_COMPETING_THREADS_NOW);
#endif
	*num_characters = 0;
	intr = (Get_OpReg(hcr_intr_status) & Get_OpReg(hcr_intr_enable));

	/*
	 * Check whether any Frame Number Overflow interrupt is pending
	 * and if it is pending, process this interrupt.
	 */
	if (intr & HCR_INTR_FNO) {
		ohci_handle_frame_number_overflow(ohcip);

		/* Acknowledge the FNO interrupt */
		ohci_polled_finish_interrupt(ohcip, HCR_INTR_FNO);
	}

	/* Check to see if there are any TD's for this input device */
	if (ohci_polled_check_done_list(ohci_polledp) == USB_SUCCESS) {

		/* Process any TD's on the input done list */
		*num_characters =
		    ohci_polled_process_input_list(ohci_polledp);
	}

	/*
	 * To make sure after we get the done list from DoneHead,
	 * every input device gets its own TD's in the
	 * ohci_polled_done_list and then clear the interrupt status.
	 */
	if (intr & HCR_INTR_WDH) {

		/* Acknowledge the WDH interrupt */
		ohci_polled_finish_interrupt(ohcip, HCR_INTR_WDH);
	}
#ifndef lint
	_NOTE(COMPETING_THREADS_NOW);
#endif

	return (USB_SUCCESS);
}


/*
 * ohci_hcdi_polled_output_init:
 *
 * This is the initialization routine for handling the USB serial output
 * in POLLED mode.  This routine is not called from POLLED mode, so
 * it is OK to acquire mutexes.
 */
int
ohci_hcdi_polled_output_init(
	usba_pipe_handle_data_t	*ph,
	usb_console_info_impl_t	*console_output_info)
{
	ohci_polled_t		*ohci_polledp;
	ohci_state_t		*ohcip;
	int			ret;

	ohcip = ohci_obtain_state(ph->p_usba_device->usb_root_hub_dip);

	/*
	 * Grab the ohci_int_mutex so that things don't change on us
	 * if an interrupt comes in.
	 */
	mutex_enter(&ohcip->ohci_int_mutex);

	ret = ohci_polled_init(ph, ohcip, console_output_info);

	if (ret != USB_SUCCESS) {

		/* Allow interrupts to continue */
		mutex_exit(&ohcip->ohci_int_mutex);

		return (ret);
	}

	ohci_polledp = (ohci_polled_t *)console_output_info->uci_private;
	/*
	 * Mark the structure so that if we are using it, we don't free
	 * the structures if one of them is unplugged.
	 */
	ohci_polledp->ohci_polled_flags |= POLLED_OUTPUT_MODE;

	/*
	 * This is a software workaround to fix schizo hardware bug.
	 * Existence of "no-prom-cdma-sync"  property means consistent
	 * dma sync should not be done while in prom or polled mode.
	 */
	if (ddi_prop_exists(DDI_DEV_T_ANY, ohcip->ohci_dip,
	    DDI_PROP_NOTPROM, "no-prom-cdma-sync")) {
		ohci_polledp->ohci_polled_no_sync_flag = B_TRUE;
	}

	/* Allow interrupts to continue */
	mutex_exit(&ohcip->ohci_int_mutex);

	return (USB_SUCCESS);
}

/*
 * ohci_hcdi_polled_output_fini:
 */
int
ohci_hcdi_polled_output_fini(usb_console_info_impl_t *info)
{
	ohci_polled_t		*ohci_polledp;
	ohci_state_t		*ohcip;
	int			ret;

	ohci_polledp = (ohci_polled_t *)info->uci_private;

	ohcip = ohci_polledp->ohci_polled_ohcip;

	mutex_enter(&ohcip->ohci_int_mutex);

	/*
	 * Reset the POLLED_INPUT_MODE flag so that we can tell if
	 * this structure is in use in the ohci_polled_fini routine.
	 */
	ohci_polledp->ohci_polled_flags &= ~POLLED_OUTPUT_MODE;

	ret = ohci_polled_fini(ohci_polledp);

	info->uci_private = NULL;

	mutex_exit(&ohcip->ohci_int_mutex);

	return (ret);
}


/*
 * ohci_hcdi_polled_output_enter:
 *
 * everything is done in input enter
 */
/*ARGSUSED*/
int
ohci_hcdi_polled_output_enter(usb_console_info_impl_t *info)
{
	return (USB_SUCCESS);
}


/*
 * ohci_hcdi_polled_output_exit:
 *
 * everything is done in input exit
 */
/*ARGSUSED*/
int
ohci_hcdi_polled_output_exit(usb_console_info_impl_t *info)
{
	return (USB_SUCCESS);
}


/*
 * ohci_hcdi_polled_write:
 *	Put a key character -- rewrite this!
 */
int
ohci_hcdi_polled_write(usb_console_info_impl_t *info, uchar_t *buf,
    uint_t num_characters, uint_t *num_characters_written)
{
	ohci_state_t		*ohcip;
	ohci_polled_t		*ohci_polledp;
	ohci_trans_wrapper_t	*tw;
	ohci_pipe_private_t	*pp;
	usba_pipe_handle_data_t	*ph;
	uint32_t		ctrl;
	uint_t			intr, bulk_pkg_size;
	int			i;

#ifndef lint
	_NOTE(NO_COMPETING_THREADS_NOW);
#endif

	ohci_polledp = (ohci_polled_t *)info->uci_private;
	ohcip = ohci_polledp->ohci_polled_ohcip;

	/* Disable periodic list processing */
	Set_OpReg(hcr_control,
	    (Get_OpReg(hcr_control) & (~HCR_CONTROL_PLE)));

	/* Add the endpoint to the lattice */
	for (i = ohcip->ohci_polled_enter_count; i < NUM_INTR_ED_LISTS;
	    i = i + MIN_LOW_SPEED_POLL_INTERVAL) {
		Set_HCCA(ohcip->ohci_hccap->HccaIntTble[i],
		    ohci_ed_cpu_to_iommu(ohcip,
		    ohci_polledp->ohci_polled_ed));
	}

	ph = ohci_polledp->ohci_polled_input_pipe_handle;
	pp = (ohci_pipe_private_t *)ph->p_hcd_private;
	tw = pp->pp_tw_head;

	ASSERT(tw != NULL);
	if (tw->tw_hctd_free_list == NULL) {
#ifndef lint
	_NOTE(COMPETING_THREADS_NOW);
#endif
		return (USB_SUCCESS);
	}

	/* Copy transmit buffer */
	if (num_characters > POLLED_RAW_BUF_SIZE) {
		cmn_err(CE_NOTE, "polled write size %d bigger than %d",
		    num_characters, POLLED_RAW_BUF_SIZE);
		num_characters = POLLED_RAW_BUF_SIZE;
	}
	tw->tw_length = num_characters;

	ddi_rep_put8(tw->tw_accesshandle,
	    buf, (uint8_t *)tw->tw_buf,
	    tw->tw_length, DDI_DEV_AUTOINCR);
	Sync_IO_Buffer_for_device(tw->tw_dmahandle, tw->tw_length);

	/* Insert td into endpoint's tds list */
	ctrl = tw->tw_direction | HC_TD_DT_0|HC_TD_1I | HC_TD_R;
	bulk_pkg_size = min(tw->tw_length, OHCI_MAX_TD_XFER_SIZE);

	(void) ohci_polled_insert_hc_td(ohcip, ctrl, 0, bulk_pkg_size, pp, tw);

	/* Enable periodic list processing */
	Set_OpReg(hcr_control,
	    (Get_OpReg(hcr_control) | HCR_CONTROL_PLE));

	/* Wait for bulk out tds transfer completion */
	for (;;) {
		intr = Get_OpReg(hcr_intr_status);

		if (intr & HCR_INTR_FNO) {
			ohci_handle_frame_number_overflow(ohcip);
			ohci_polled_finish_interrupt(ohcip, HCR_INTR_FNO);
		}

		if (intr & HCR_INTR_WDH) {
			if (ohci_polled_check_done_list(ohci_polledp) ==
			    USB_SUCCESS) {
				*num_characters_written =
				    ohci_polled_process_input_list(
				    ohci_polledp);
				break;
			}
		}

		Set_OpReg(hcr_intr_status, intr);
		(void) Get_OpReg(hcr_intr_status);
	}

	/* Remove the endpoint from the lattice */
	for (i = ohcip->ohci_polled_enter_count; i < NUM_INTR_ED_LISTS;
	    i = i + MIN_LOW_SPEED_POLL_INTERVAL) {
		Set_HCCA(ohcip->ohci_hccap->HccaIntTble[i],
		    ohci_ed_cpu_to_iommu(ohcip,
		    ohci_polledp->ohci_polled_dummy_ed));
	}

	Set_OpReg(hcr_intr_status, intr);
	(void) Get_OpReg(hcr_intr_status);
#ifndef lint
	_NOTE(COMPETING_THREADS_NOW);
#endif
	return (USB_SUCCESS);
}


/*
 * Internal Functions
 */

/*
 * Polled initialization routines
 */


/*
 * ohci_polled_init:
 *
 * Initialize generic information Uthat is needed to provide USB/POLLED
 * support.
 */
static int
ohci_polled_init(
	usba_pipe_handle_data_t	*ph,
	ohci_state_t		*ohcip,
	usb_console_info_impl_t	*console_info)
{
	ohci_polled_t		*ohci_polledp;
	ohci_pipe_private_t	*pp;
	int			pipe_attr;

	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/*
	 * We have already initialized this structure. If the structure
	 * has already been initialized, then we don't need to redo it.
	 */
	if (console_info->uci_private) {

		return (USB_SUCCESS);
	}

	/* Allocate and intitialize a state structure */
	ohci_polledp = (ohci_polled_t *)
	    kmem_zalloc(sizeof (ohci_polled_t), KM_SLEEP);

	console_info->uci_private = (usb_console_info_private_t)ohci_polledp;

	/*
	 * Store away the ohcip so that we can get to it when we are in
	 * POLLED mode. We don't want to have to call ohci_obtain_state
	 * every time we want to access this structure. Also save ohci
	 * polled state information in ohcip.
	 */
	ohci_polledp->ohci_polled_ohcip = ohcip;

	/*
	 * Save usb device and endpoint number information from the usb
	 * pipe handle.
	 */
	mutex_enter(&ph->p_mutex);
	ohci_polledp->ohci_polled_usb_dev = ph->p_usba_device;
	ohci_polledp->ohci_polled_ep_addr = ph->p_ep.bEndpointAddress;
	mutex_exit(&ph->p_mutex);

	/*
	 * Allocate memory to make duplicate of original usb pipe handle.
	 */
	ohci_polledp->ohci_polled_input_pipe_handle =
	    kmem_zalloc(sizeof (usba_pipe_handle_data_t), KM_SLEEP);

	/*
	 * Copy the USB handle into the new pipe handle. Also
	 * create new lock for the new pipe handle.
	 */
	bcopy((void *)ph,
	    (void *)ohci_polledp->ohci_polled_input_pipe_handle,
	    sizeof (usba_pipe_handle_data_t));

	/*
	 * uint64_t typecast to make sure amd64 can compile
	 */
	mutex_init(&ohci_polledp->ohci_polled_input_pipe_handle->p_mutex,
	    NULL, MUTEX_DRIVER, DDI_INTR_PRI(ohcip->ohci_intr_pri));

	/* Create a new ohci pipe private structure */
	pp = (ohci_pipe_private_t *)
	    kmem_zalloc(sizeof (ohci_pipe_private_t), KM_SLEEP);

	/*
	 * Store the pointer in the pipe handle. This structure was also
	 * just allocated.
	 */
	mutex_enter(&ohci_polledp->ohci_polled_input_pipe_handle->p_mutex);

	ohci_polledp->ohci_polled_input_pipe_handle->
	    p_hcd_private = (usb_opaque_t)pp;

	mutex_exit(&ohci_polledp->ohci_polled_input_pipe_handle->p_mutex);

	/*
	 * Store a pointer to the pipe handle. This structure was  just
	 * allocated and it is not in use yet.	The locking is there to
	 * satisfy warlock.
	 */
	mutex_enter(&ph->p_mutex);

	bcopy(&ph->p_policy, &pp->pp_policy, sizeof (usb_pipe_policy_t));

	mutex_exit(&ph->p_mutex);

	pp->pp_pipe_handle = ohci_polledp->ohci_polled_input_pipe_handle;

	/*
	 * Allocate a dummy for the interrupt table. This dummy will be
	 * put into the action when we	switch interrupt  tables during
	 * ohci_hcdi_polled_enter. Dummy is placed on the unused lattice
	 * entries. When the ED is allocated we will replace dummy ED by
	 * valid interrupt ED in one or more locations in the interrupt
	 * lattice depending on the requested polling interval. Also we
	 * will hang a dummy TD to the ED & dummy TD is used to indicate
	 * the end of the TD chain.
	 */
	ohci_polledp->ohci_polled_dummy_ed = ohci_alloc_hc_ed(ohcip, NULL);

	if (ohci_polledp->ohci_polled_dummy_ed == NULL) {

		return (USB_NO_RESOURCES);
	}

	/*
	 * Allocate the endpoint. This ED will be inserted in
	 * to the lattice chain for the device. This endpoint
	 * will have the TDs hanging off of it for the processing.
	 */
	ohci_polledp->ohci_polled_ed = ohci_alloc_hc_ed(ohcip,
	    ohci_polledp->ohci_polled_input_pipe_handle);

	if (ohci_polledp->ohci_polled_ed == NULL) {

		return (USB_NO_RESOURCES);
	}

	/* Set the state of pipe as idle */
	pp->pp_state = OHCI_PIPE_STATE_IDLE;

	/* Insert the endpoint onto the pipe handle */
	pp->pp_ept = ohci_polledp->ohci_polled_ed;

	pipe_attr = ph->p_ep.bmAttributes & USB_EP_ATTR_MASK;

	switch (pipe_attr) {
	case USB_EP_ATTR_INTR:
		/*
		 * Set soft interrupt handler flag in the normal mode usb
		 * pipe handle.
		 */
		mutex_enter(&ph->p_mutex);
		ph->p_spec_flag |= USBA_PH_FLAG_USE_SOFT_INTR;
		mutex_exit(&ph->p_mutex);

		/*
		 * Insert a Interrupt polling request onto the endpoint.
		 *
		 * There will now be two TDs on the ED, one is the dummy TD
		 * that was allocated above in the ohci_alloc_hc_ed and
		 * this new one.
		 */
		if ((ohci_start_periodic_pipe_polling(ohcip,
		    ohci_polledp->ohci_polled_input_pipe_handle,
		    NULL, USB_FLAGS_SLEEP)) != USB_SUCCESS) {
			return (USB_NO_RESOURCES);
		}
		break;
	case USB_EP_ATTR_BULK:
		if ((ohci_polled_create_tw(ohcip,
		    ohci_polledp->ohci_polled_input_pipe_handle,
		    USB_FLAGS_SLEEP)) != USB_SUCCESS) {
			return (USB_NO_RESOURCES);
		}
		break;
	default:
		return (USB_FAILURE);
	}
	return (USB_SUCCESS);
}


/*
 * Polled deinitialization routines
 */


/*
 * ohci_polled_fini:
 */
static int
ohci_polled_fini(ohci_polled_t	*ohci_polledp)
{
	ohci_state_t		*ohcip = ohci_polledp->ohci_polled_ohcip;
	ohci_pipe_private_t	*pp;
	ohci_td_t		*curr_td, *next_td;
	ohci_trans_wrapper_t	*curr_tw, *next_tw;
	ASSERT(mutex_owned(&ohcip->ohci_int_mutex));

	/*
	 * If the structure is already in use, then don't free it.
	 */
	if (ohci_polledp->ohci_polled_flags & POLLED_INPUT_MODE) {

		return (USB_SUCCESS);
	}

	pp = (ohci_pipe_private_t *)
	    ohci_polledp->ohci_polled_input_pipe_handle->p_hcd_private;

	/*
	 * Deallocate all the pre-allocated interrupt requests
	 */
	ohci_handle_outstanding_requests(ohcip, pp);

	/*
	 * Traverse the list of TD's on this endpoint and these TD's
	 * have outstanding transfer requests. Since list processing
	 * is stopped, these TDs can be deallocated.
	 */
	ohci_traverse_tds(ohcip, pp->pp_pipe_handle);

	/*
	 * For each transfer wrapper on this pipe, free the TD and
	 * free the TW.  We don't free the last TD in the chain
	 * because it will be freed by ohci_deallocate_ed.  All TD's
	 * on this TW are also on the end point associated with this
	 * pipe.
	 */
	next_tw = pp->pp_tw_head;

	while (next_tw) {
		next_td = (ohci_td_t *)next_tw->tw_hctd_head;

		/*
		 * Walk through each TD for this transfer
		 * wrapper and free that TD.
		 */
		while (next_td) {
			curr_td = next_td;

			next_td = ohci_td_iommu_to_cpu(ohcip,
			    Get_TD(next_td->hctd_tw_next_td));

			ohci_deallocate_td(ohcip, curr_td);
		}

		curr_tw = next_tw;
		next_tw = curr_tw->tw_next;

		/* Free the transfer wrapper */
		ohci_deallocate_tw_resources(ohcip, pp, curr_tw);
	}

	/*
	 * Deallocate the endpoint descriptors that we allocated
	 * with ohci_alloc_hc_ed.
	 */
	if (ohci_polledp->ohci_polled_dummy_ed) {
		ohci_deallocate_ed(ohcip, ohci_polledp->ohci_polled_dummy_ed);
	}

	if (ohci_polledp->ohci_polled_ed) {
		ohci_deallocate_ed(ohcip, ohci_polledp->ohci_polled_ed);
	}

	mutex_destroy(&ohci_polledp->ohci_polled_input_pipe_handle->p_mutex);

	/*
	 * Destroy everything about the pipe that we allocated in
	 * ohci_polled_duplicate_pipe_handle
	 */
	kmem_free(pp, sizeof (ohci_pipe_private_t));

	kmem_free(ohci_polledp->ohci_polled_input_pipe_handle,
	    sizeof (usba_pipe_handle_data_t));

	/*
	 * We use this field to determine if a TD is for input or not,
	 * so NULL the pointer so we don't check deallocated data.
	 */
	ohci_polledp->ohci_polled_input_pipe_handle = NULL;

	/*
	 * Finally, free off the structure that we use to keep track
	 * of all this.
	 */
	kmem_free(ohci_polledp, sizeof (ohci_polled_t));

	return (USB_SUCCESS);
}


/*
 * Polled save state routines
 */


/*
 * ohci_polled_save_state:
 */
static void
ohci_polled_save_state(ohci_polled_t	*ohci_polledp)
{
	ohci_state_t		*ohcip;
	int			i;
	uint_t			polled_toggle;
	uint_t			real_toggle;
	ohci_pipe_private_t	*pp = NULL;	/* Normal mode Pipe */
	ohci_pipe_private_t	*polled_pp;	/* Polled mode Pipe */
	usba_pipe_handle_data_t	*ph;
	uint8_t			ep_addr;
	ohci_save_intr_sts_t	*ohci_intr_sts;
	ohci_regs_t		*ohci_polled_regsp;
	ohci_td_t		*td, *prev_td;
	ohci_td_t		*done_head, **done_list;

#ifndef lint
	_NOTE(NO_COMPETING_THREADS_NOW);
#endif

	/*
	 * If either of these two flags are set, then we have already
	 * saved off the state information and setup the controller.
	 */
	if (ohci_polledp->ohci_polled_flags & POLLED_INPUT_MODE_INUSE) {
#ifndef lint
		_NOTE(COMPETING_THREADS_NOW);
#endif
		return;
	}

	ohcip = ohci_polledp->ohci_polled_ohcip;

	/*
	 * Check if the number of keyboard reach the max number we can
	 * support in polled mode
	 */
	if (++ ohcip->ohci_polled_enter_count > MAX_NUM_FOR_KEYBOARD) {
#ifndef lint
		_NOTE(COMPETING_THREADS_NOW);
#endif
		return;
	}
	/* Get the endpoint addr. */
	ep_addr = ohci_polledp->ohci_polled_ep_addr;

	/* Get the normal mode usb pipe handle */
	ph = usba_hcdi_get_ph_data(ohci_polledp->ohci_polled_usb_dev, ep_addr);
	ohci_intr_sts = &ohcip->ohci_save_intr_sts;
	ohci_polled_regsp = &ohcip->ohci_polled_save_regs;

	/*
	 * Only the first enter keyboard entry disable the interrupt, save the
	 * information of normal mode, stop the processing, initialize the
	 * frame list table.
	 */
	if (ohcip->ohci_polled_enter_count == 1) {
		/*
		 * Prevent the ohci interrupt handler from handling interrupt.
		 * We will turn off interrupts. This  keeps us from generating
		 * a hardware interrupt.This is the useful for testing because
		 * in POLLED  mode we can't get interrupts anyway. We can test
		 * this code by shutting off hardware interrupt generation and
		 * polling  for the interrupts.
		 */
		Set_OpReg(hcr_intr_disable, HCR_INTR_MIE);
		/*
		 * Save the current normal mode ohci registers	and later this
		 * saved register copy is used to replace some of required ohci
		 * registers before switching from polled mode to normal mode.
		 */
		bzero((void *)ohci_polled_regsp, sizeof (ohci_regs_t));

		ohci_polled_regsp->hcr_control = Get_OpReg(hcr_control);
		ohci_polled_regsp->hcr_cmd_status = Get_OpReg(hcr_cmd_status);
		ohci_polled_regsp->hcr_intr_enable = Get_OpReg(hcr_intr_enable);
		ohci_polled_regsp->hcr_HCCA = Get_OpReg(hcr_HCCA);
		ohci_polled_regsp->hcr_done_head = Get_OpReg(hcr_done_head);
		ohci_polled_regsp->hcr_bulk_head = Get_OpReg(hcr_bulk_head);
		ohci_polled_regsp->hcr_ctrl_head = Get_OpReg(hcr_ctrl_head);

		/*
		 * The functionality &	importance of critical code section in
		 * the normal mode ohci interrupt handler and its usage in the
		 * polled mode is explained below.
		 *
		 * (a) Normal mode:
		 *
		 *	- Set the flag indicating that processing critical code
		 *	  in ohci interrupt handler.
		 *
		 *	- Process the missed ohci interrupts by copying missed
		 *	  interrupt events & done head list fields information
		 *	  to the critical interrupt events & done list fields.
		 *
		 *	- Reset the missed ohci interrupt events and done head
		 *	  list fields so that the new missed  interrupt events
		 *	  and done head list information can be saved.
		 *
		 *	- All above steps will be executed within the critical
		 *	  section of the  interrupt handler.  Then ohci missed
		 *	  interrupt handler will be called to service the ohci
		 *	  missed interrupts.
		 *
		 * (b) Polled mode:
		 *
		 *	- On entering the polled code, checks for the critical
		 *	  section code execution within normal	mode interrupt
		 *	  handler.
		 *
		 *	- If critical section code is  executing in the normal
		 *	  mode ohci interrupt handler & if copying of the ohci
		 *	  missed interrupt events and done head list fields to
		 *	  the critical fields is finished then, save the  "any
		 *	  missed interrupt events and done head list"  because
		 *	  of current polled mode switch into "critical	missed
		 *	  interrupt events & done list fields" instead	actual
		 *	  missed events and done list fields.
		 *
		 *	- Otherwise save "any missed interrupt events and done
		 *	  list" because of this  current polled mode switch in
		 *	  the actual missed  interrupt events & done head list
		 *	  fields.
		 */

		/*
		 * Check and save the pending SOF interrupt  condition for the
		 * ohci normal mode. This information will be  saved either in
		 * the critical missed event fields or in actual  missed event
		 * fields depending on the whether the critical code section's
		 * execution flag was set or not when switched to  polled mode
		 * from normal mode.
		 */
		if ((ohci_intr_sts->ohci_intr_flag & OHCI_INTR_CRITICAL) &&
		    (ohci_intr_sts->ohci_critical_intr_sts != 0)) {

			ohci_intr_sts->ohci_critical_intr_sts |=
			    ((Get_OpReg(hcr_intr_status) &
			    Get_OpReg(hcr_intr_enable)) & HCR_INTR_SOF);
		} else {
			ohci_intr_sts->ohci_missed_intr_sts |=
			    ((Get_OpReg(hcr_intr_status) &
			    Get_OpReg(hcr_intr_enable)) & HCR_INTR_SOF);
		}
		ohci_polled_stop_processing(ohci_polledp);

		/* Process any missed Frame Number Overflow (FNO) interrupt */
		ohci_polled_handle_frame_number_overflow(ohcip);

		/*
		 * By this time all list processing has been stopped.Now check
		 * and save the information about the pending HCCA done  list,
		 * done head ohci register and WDH bit in the interrupt status
		 * register. This information will be saved either in critical
		 * missed event fields or in actual missed event fields depend
		 * on the whether the  critical code section's	execution flag
		 * was set or not when switched to polled mode from the normal
		 * mode.
		 */

		/* Read and Save the HCCA DoneHead value */
		done_head = (ohci_td_t *)(uintptr_t)(Get_HCCA(
		    ohcip->ohci_hccap->HccaDoneHead) & HCCA_DONE_HEAD_MASK);

		if ((done_head) &&
		    (done_head != ohci_intr_sts->ohci_curr_done_lst)) {

			if ((ohci_intr_sts->ohci_intr_flag &
			    OHCI_INTR_CRITICAL) &&
			    ((ohci_intr_sts->ohci_critical_done_lst) ||
			    (ohci_intr_sts->ohci_missed_done_lst == NULL))) {

				done_list =
				    &ohci_intr_sts->ohci_critical_done_lst;
				ohci_intr_sts->ohci_critical_intr_sts |=
				    HCR_INTR_WDH;
			} else {
				done_list =
				    &ohci_intr_sts->ohci_missed_done_lst;
				ohci_intr_sts->ohci_missed_intr_sts |=
				    HCR_INTR_WDH;
			}

			if (*done_list) {
				td = (ohci_td_t *)
				    ohci_td_iommu_to_cpu(ohcip,
				    (uintptr_t)done_head);

				while (td) {
					prev_td = td;
					td = ohci_td_iommu_to_cpu(ohcip,
					    Get_TD(td->hctd_next_td));
				}

				Set_TD(prev_td->hctd_next_td, *done_list);

				*done_list = done_head;
			} else {
				*done_list = (ohci_td_t *)done_head;
			}
		}

		/*
		 * Save the latest hcr_done_head ohci register value,  so that
		 * this value can be replaced  when exit from the POLLED mode.
		 */
		ohci_polled_regsp->hcr_done_head = Get_OpReg(hcr_done_head);
		/*
		 * Reset the HCCA done head and ohci done head register.
		 */
		Set_HCCA(ohcip->ohci_hccap->HccaDoneHead, NULL);
		Set_OpReg(hcr_done_head, (uint32_t)0x0);

		/*
		 * Clear the  WriteDoneHead interrupt bit in the ohci interrupt
		 * status register.
		 */
		Set_OpReg(hcr_intr_status, HCR_INTR_WDH);

		/*
		 * Save the current interrupt lattice and  replace this lattice
		 * with an lattice used in POLLED mode. We will restore lattice
		 * back when we exit from the POLLED mode.
		 */
		for (i = 0; i < NUM_INTR_ED_LISTS; i++) {
			ohcip->ohci_polled_save_IntTble[i] =
			    (ohci_ed_t *)(uintptr_t)Get_HCCA(
			    ohcip->ohci_hccap->HccaIntTble[i]);
		}
		/*
		 * Fill in the lattice with dummy EDs. These EDs are used so the
		 * controller can tell that it is at the end of the ED list.
		 */
		for (i = 0; i < NUM_INTR_ED_LISTS; i++) {
			Set_HCCA(ohcip->ohci_hccap->HccaIntTble[i],
			    ohci_ed_cpu_to_iommu(ohcip,
			    ohci_polledp->ohci_polled_dummy_ed));
		}
	}
	/* Get the polled mode ohci pipe private structure */
	polled_pp = (ohci_pipe_private_t *)
	    ohci_polledp->ohci_polled_input_pipe_handle->p_hcd_private;

	/*
	 * Before replacing the lattice, adjust the data togggle on the
	 * on the ohci's interrupt ed
	 */
	polled_toggle = (Get_ED(polled_pp->pp_ept->hced_headp) &
	    HC_EPT_Carry) ? DATA1:DATA0;

	/*
	 * If normal mode interrupt pipe endpoint is active, get the data
	 * toggle from the this interrupt endpoint through the corresponding
	 * interrupt pipe handle. Else get the data toggle information from
	 * the usb device structure and this information is saved during the
	 * normal mode interrupt pipe close. Use this data toggle information
	 * to fix the data toggle of polled mode interrupt endpoint.
	 */
	if (ph) {
		/* Get the normal mode ohci pipe private structure */
		pp = (ohci_pipe_private_t *)ph->p_hcd_private;

		real_toggle = (Get_ED(pp->pp_ept->hced_headp) &
		    HC_EPT_Carry) ? DATA1:DATA0;
	} else {
		real_toggle = usba_hcdi_get_data_toggle(
		    ohci_polledp->ohci_polled_usb_dev, ep_addr);
	}

	if (polled_toggle != real_toggle) {
		if (real_toggle == DATA0) {
			Set_ED(polled_pp->pp_ept->hced_headp,
			    Get_ED(polled_pp->pp_ept->hced_headp) &
			    ~HC_EPT_Carry);
		} else {
			Set_ED(polled_pp->pp_ept->hced_headp,
			    Get_ED(polled_pp->pp_ept->hced_headp) |
			    HC_EPT_Carry);
		}
	}

	/*
	 * Check whether Halt bit is set in the ED and if so  clear the
	 * halt bit.
	 */
	if (polled_pp->pp_ept->hced_headp & HC_EPT_Halt) {

		/* Clear the halt bit */
		Set_ED(polled_pp->pp_ept->hced_headp,
		    (Get_ED(polled_pp->pp_ept->hced_headp) & ~HC_EPT_Halt));
	}

	/*
	 * Now, add the endpoint to the lattice that we will  hang  our
	 * TD's off of.  We need to poll this device at  every 8 ms and
	 * hence add this ED needs 4 entries in interrupt lattice.
	 */
	for (i = (ohcip->ohci_polled_enter_count -1); i < NUM_INTR_ED_LISTS;
	    i = i + MIN_LOW_SPEED_POLL_INTERVAL) {
		Set_HCCA(ohcip->ohci_hccap->HccaIntTble[i],
		    ohci_ed_cpu_to_iommu(ohcip,
		    ohci_polledp->ohci_polled_ed));
	}
	/*
	 * Only the first enter keyboard entry clear the contents of
	 * periodic ED register and enable the WDH interrupt and
	 * start process the periodic list.
	 */
	if (ohcip->ohci_polled_enter_count == 1) {
		/*
		 * Clear the contents of current ohci periodic ED register that
		 * is physical address of current Isochronous or Interrupt ED.
		 */

		Set_OpReg(hcr_periodic_curr, (uint32_t)0x0);

		/* Make sure WriteDoneHead interrupt is enabled */
		Set_OpReg(hcr_intr_enable, HCR_INTR_WDH);

		/*
		 * Enable the periodic list. We will now start processing EDs &
		 * TDs again.
		 */
		Set_OpReg(hcr_control,
		    (Get_OpReg(hcr_control) | HCR_CONTROL_PLE));
	}
#ifndef lint
	_NOTE(COMPETING_THREADS_NOW);
#endif
}


/*
 * ohci_polled_stop_processing:
 */
static void
ohci_polled_stop_processing(ohci_polled_t	*ohci_polledp)
{
	ohci_state_t		*ohcip;
	uint_t			count;
	ohci_regs_t		*ohci_polled_regsp;

	ohcip = ohci_polledp->ohci_polled_ohcip;
	ohci_polled_regsp = &ohcip->ohci_polled_save_regs;

	/*
	 * Turn off all list processing. This will take place starting
	 * at the next frame.
	 */
	Set_OpReg(hcr_control,
	    (ohci_polled_regsp->hcr_control) & ~(HCR_CONTROL_CLE|
	    HCR_CONTROL_PLE| HCR_CONTROL_BLE|HCR_CONTROL_IE));

	/*
	 * Make sure that the  SOF interrupt bit is cleared in the ohci
	 * interrupt status register.
	 */
	Set_OpReg(hcr_intr_status, HCR_INTR_SOF);

	/* Enable SOF interrupt */
	Set_OpReg(hcr_intr_enable, HCR_INTR_SOF);

	/*
	 * According to  OHCI Specification,  we have to wait for eight
	 * start of frames to make sure that the Host Controller writes
	 * contents of done head register to done head filed of HCCA.
	 */
	for (count = 0; count <= DONE_QUEUE_INTR_COUNTER; count++) {
		while (!((Get_OpReg(hcr_intr_status)) & HCR_INTR_SOF)) {
			continue;
		}

		/* Acknowledge the SOF interrupt */
		ohci_polled_finish_interrupt(ohcip, HCR_INTR_SOF);
	}

	Set_OpReg(hcr_intr_disable, HCR_INTR_SOF);
}


/*
 * Polled restore state routines
 */

/*
 * ohci_polled_restore_state:
 */
static void
ohci_polled_restore_state(ohci_polled_t	*ohci_polledp)
{
	ohci_state_t		*ohcip;
	int			i;
	uint_t			polled_toggle;
	uint_t			real_toggle;
	ohci_pipe_private_t	*pp = NULL;	/* Normal mode Pipe */
	ohci_pipe_private_t	*polled_pp;	/* Polled mode Pipe */
	ohci_td_t		*td;
	ohci_td_t		*next_td;	/* TD pointers */
	uint_t			count;
	ohci_save_intr_sts_t	*ohci_intr_sts;
	ohci_regs_t		*ohci_polled_regsp;
	uint32_t		mask;
	usba_pipe_handle_data_t	*ph;
	uint8_t			ep_addr;

#ifndef lint
	_NOTE(NO_COMPETING_THREADS_NOW);
#endif

	/*
	 * If this flag is set, then we are still using this structure,
	 * so don't restore any controller state information yet.
	 */
	if (ohci_polledp->ohci_polled_flags & POLLED_INPUT_MODE_INUSE) {

#ifndef lint
		_NOTE(COMPETING_THREADS_NOW);
#endif

		return;
	}

	ohcip = ohci_polledp->ohci_polled_ohcip;
	ohci_intr_sts = &ohcip->ohci_save_intr_sts;
	ohci_polled_regsp = &ohcip->ohci_polled_save_regs;
	ohcip->ohci_polled_enter_count --;

	/* Get the endpoint addr. */
	ep_addr = ohci_polledp->ohci_polled_ep_addr;
	/* Get the normal mode usb pipe handle */
	ph = usba_hcdi_get_ph_data(ohci_polledp->ohci_polled_usb_dev, ep_addr);

	/*
	 * Only the first leave keyboard entry turn off all list processing.
	 * This will take place starting at the next frame.
	 */
	if (Get_OpReg(hcr_control) & HCR_CONTROL_PLE) {
		Set_OpReg(hcr_control,
		    (Get_OpReg(hcr_control) & ~HCR_CONTROL_PLE));
	}

	/*
	 * Only the last leave keyboard entry restore the info for
	 * normal mode.
	 */
	if (ohcip->ohci_polled_enter_count == 0) {
		Set_OpReg(hcr_intr_enable, HCR_INTR_SOF);

		/*
		 * According to  OHCI Specification,  we have to wait for eight
		 * start of frames to make sure that the Host Controller writes
		 * contents of done head register to done head filed of HCCA.
		 */
		for (count = 0; count <= DONE_QUEUE_INTR_COUNTER; count++) {
			while (!((Get_OpReg(hcr_intr_status)) & HCR_INTR_SOF)) {
				continue;
			}
			/* Acknowledge the SOF interrupt */
			ohci_polled_finish_interrupt(ohcip, HCR_INTR_SOF);
		}

		/*
		 * Check any Frame Number Overflow interrupt (FNO) is pending.
		 */
		ohci_polled_handle_frame_number_overflow(ohcip);

		/*
		 * Before switching back, we have to process last TD in the
		 * POLLED mode. It may be in the hcr_done_head register or
		 * in done list or in the lattice. If it is either on the
		 * hcr_done_head register or in the done list, just re-inserted
		 * into the ED's TD list.
		 *
		 * First look up at the TD's that are in the hcr_done_head
		 * register and re-insert them back into the ED's TD list.
		 */
		td = ohci_td_iommu_to_cpu(ohcip,
		    (uintptr_t)Get_OpReg(hcr_done_head));

		while (td) {

		next_td = ohci_td_iommu_to_cpu(ohcip, Get_TD(td->hctd_next_td));

			/*
			 * Insert valid interrupt TD back into ED's
			 * TD list. No periodic TD's will be processed
			 * since all processing has been stopped.
			 */
			ohci_polled_insert_td(ohcip, td);

			td = next_td;
		}

		/*
		 * Now look up at the TD's that are in the HCCA done head list &
		 * re-insert them back into the ED's TD list.
		 */
		td = ohci_td_iommu_to_cpu(ohcip, (Get_HCCA(
		    ohcip->ohci_hccap->HccaDoneHead) & HCCA_DONE_HEAD_MASK));

		while (td) {

			next_td = ohci_td_iommu_to_cpu(ohcip,
			    Get_TD(td->hctd_next_td));

			/*
			 * Insert valid interrupt TD back into ED's
			 * TD list. No periodic TD's will be processed
			 * since all processing has been stopped.
			 */
			ohci_polled_insert_td(ohcip, td);

			td = next_td;
		}
		/* Reset the HCCA done head list to NULL */
		Set_HCCA(ohcip->ohci_hccap->HccaDoneHead, NULL);

		/*
		 * Replace the hcr_done_head register field with the saved copy
		 * of current normal mode hcr_done_head register contents.
		 */
		Set_OpReg(hcr_done_head,
		    (uint32_t)ohci_polled_regsp->hcr_done_head);

		/*
		 * Clear the WriteDoneHead and SOF interrupt bits in the ohci
		 * interrupt status register.
		 */
		Set_OpReg(hcr_intr_status, (HCR_INTR_WDH | HCR_INTR_SOF));
	}

	/* Get the polled mode ohci pipe private structure */
	polled_pp = (ohci_pipe_private_t *)
	    ohci_polledp->ohci_polled_input_pipe_handle->p_hcd_private;

	/*
	 * Before replacing the lattice, adjust the data togggle
	 * on the on the ohci's interrupt ed
	 */
	polled_toggle = (Get_ED(polled_pp->pp_ept->hced_headp) &
	    HC_EPT_Carry) ? DATA1:DATA0;

	/*
	 * If normal mode interrupt pipe endpoint is active, fix the
	 * data toggle for this interrupt endpoint by getting the data
	 * toggle information from the polled interrupt endpoint. Else
	 * save the data toggle information in usb device structure.
	 */
	if (ph) {
		/* Get the normal mode ohci pipe private structure */
		pp = (ohci_pipe_private_t *)ph->p_hcd_private;

		real_toggle = (Get_ED(pp->pp_ept->hced_headp) &
		    HC_EPT_Carry) ? DATA1:DATA0;

		if (polled_toggle != real_toggle) {
			if (polled_toggle == DATA0) {
				Set_ED(pp->pp_ept->hced_headp,
				    Get_ED(pp->pp_ept->hced_headp) &
				    ~HC_EPT_Carry);
			} else {
				Set_ED(pp->pp_ept->hced_headp,
				    Get_ED(pp->pp_ept->hced_headp) |
				    HC_EPT_Carry);
			}
		}
	} else {
		usba_hcdi_set_data_toggle(ohci_polledp->ohci_polled_usb_dev,
		    ep_addr, polled_toggle);
	}
	/*
	 * Only the last leave keyboard entry restore the Interrupt table,
	 * start processing and enable the interrupt.
	 */
	if (ohcip->ohci_polled_enter_count == 0) {
		/* Replace the lattice */
		for (i = 0; i < NUM_INTR_ED_LISTS; i++) {
			Set_HCCA(ohcip->ohci_hccap->HccaIntTble[i],
			    (uintptr_t)ohcip->ohci_polled_save_IntTble[i]);
		}

		/*
		 * Clear the contents of current ohci periodic ED register that
		 * is physical address of current Isochronous or Interrupt ED.
		 */
		Set_OpReg(hcr_periodic_curr, (uint32_t)0x0);

		ohci_polled_start_processing(ohci_polledp);

		/*
		 * Check and enable required ohci  interrupts before switching
		 * back to normal mode from the POLLED mode.
		 */
		mask = (uint32_t)ohci_polled_regsp->hcr_intr_enable &
		    (HCR_INTR_SOF | HCR_INTR_WDH);

		if (ohci_intr_sts->ohci_intr_flag & OHCI_INTR_HANDLING) {
			Set_OpReg(hcr_intr_enable, mask);
		} else {
			Set_OpReg(hcr_intr_enable, mask | HCR_INTR_MIE);
		}
	}
#ifndef lint
	_NOTE(COMPETING_THREADS_NOW);
#endif
}

/*
 * ohci_polled_start_processing:
 */
static void
ohci_polled_start_processing(ohci_polled_t	*ohci_polledp)
{
	ohci_state_t		*ohcip;
	uint32_t		control;
	uint32_t		mask;
	ohci_regs_t		*ohci_polled_regsp;

	ohcip = ohci_polledp->ohci_polled_ohcip;
	ohci_polled_regsp = &ohcip->ohci_polled_save_regs;

	mask = ((uint32_t)ohci_polled_regsp->hcr_control) & (HCR_CONTROL_CLE |
	    HCR_CONTROL_PLE | HCR_CONTROL_BLE | HCR_CONTROL_IE);

	control = Get_OpReg(hcr_control) & ~(HCR_CONTROL_CLE |
	    HCR_CONTROL_PLE | HCR_CONTROL_BLE | HCR_CONTROL_IE);

	Set_OpReg(hcr_control, (control | mask));
}


/*
 * Polled read routines
 */
/*
 * ohci_polled_check_done_list:
 *
 * Check to see it there are any TD's on the done head.  If there are
 * then reverse the done list and put the TD's on the appropriated list.
 */
static int
ohci_polled_check_done_list(ohci_polled_t	*ohci_polledp)
{
	ohci_state_t	*ohcip = ohci_polledp->ohci_polled_ohcip;
	ohci_td_t	*done_head, *done_list;

	/* Sync HCCA area */
	if (ohci_polledp->ohci_polled_no_sync_flag == B_FALSE) {
		Sync_HCCA(ohcip);
	}

	/* Read and Save the HCCA DoneHead value */
	done_head = (ohci_td_t *)(uintptr_t)
	    (Get_HCCA(ohcip->ohci_hccap->HccaDoneHead) & HCCA_DONE_HEAD_MASK);

	/*
	 * Look at the Done Head and if it is NULL and ohci done list is NULL,
	 * just return; else if ohci done list is not NULL, should check it.
	 */
	if (done_head == NULL) {
		if (ohcip->ohci_polled_done_list) {
			done_head = ohcip->ohci_polled_done_list;
			ohcip->ohci_polled_done_list = NULL;
		} else {

			return (USB_FAILURE);
		}
	} else {
		/* Reset the done head to NULL */
		Set_HCCA(ohcip->ohci_hccap->HccaDoneHead, NULL);
	}

	/* Sync ED and TD pool */
	if (ohci_polledp->ohci_polled_no_sync_flag == B_FALSE) {
		Sync_ED_TD_Pool(ohcip);
	}

	/* Pickup own tds in the done head */
	done_list = ohci_polled_pickup_done_list(ohci_polledp, done_head);

	/*
	 * Look at the own done list which is pickup'ed
	 * and if it is NULL, just return.
	 */
	if (done_list == NULL) {

		return (USB_FAILURE);
	}
	/* Create the input done list */
	ohci_polled_create_input_list(ohci_polledp, done_list);

	return (USB_SUCCESS);
}


/*
 * ohci_polled_pickup_done_list:
 *
 * Pickup the TDs of own in the Done Head List
 */
static ohci_td_t *
ohci_polled_pickup_done_list(
	ohci_polled_t	*ohci_polledp,
	ohci_td_t	*done_head)
{
	ohci_state_t	*ohcip = ohci_polledp->ohci_polled_ohcip;
	ohci_td_t	*create_head = NULL, *current_td, *td;
	ohci_trans_wrapper_t	*tw;
	ohci_pipe_private_t	*pp;

	/*
	 * Current_td pointers point to the done head.
	 */
	current_td = (ohci_td_t *)
	    ohci_td_iommu_to_cpu(ohcip, (uintptr_t)done_head);
	while (current_td) {
		td = (ohci_td_t *)ohci_td_iommu_to_cpu(ohcip,
		    Get_TD(current_td->hctd_next_td));

		Set_TD(current_td->hctd_next_td, NULL);

		/* Obtain the transfer wrapper from the TD */
		tw = (ohci_trans_wrapper_t *)OHCI_LOOKUP_ID(
		    (uint32_t)Get_TD(current_td->hctd_trans_wrapper));

		/* Get the pipe handle for this transfer wrapper. */
		pp = tw->tw_pipe_private;

		/*
		 * Figure  out  which  done list to put this TD on and put it
		 * there.   If  the  pipe handle  of the TD matches the pipe
		 * handle  we  are  using for the input device, then this must
		 * be an input TD, reverse the order and link to the list for
		 * this input device. Else put the TD to the reserve done list
		 * for other input devices.
		 */

		if (pp->pp_pipe_handle ==
		    ohci_polledp->ohci_polled_input_pipe_handle) {
			if (create_head == NULL) {
				create_head = current_td;
			} else {
				Set_TD(current_td->hctd_next_td,
				    ohci_td_cpu_to_iommu(ohcip, create_head));
				create_head = current_td;
			}
		} else {
			if (ohcip->ohci_polled_done_list == NULL) {
				ohcip->ohci_polled_done_list = (ohci_td_t *)
				    (uintptr_t)ohci_td_cpu_to_iommu(ohcip,
				    current_td);
			} else {
				Set_TD(current_td->hctd_next_td,
				    ohcip->ohci_polled_done_list);
				ohcip->ohci_polled_done_list = (ohci_td_t *)
				    (uintptr_t)ohci_td_cpu_to_iommu(ohcip,
				    current_td);
			}
		}
		current_td = td;
	}

	return (create_head);
}


/*
 * ohci_polled_create_input_list:
 *
 * Create the input done list from the actual done head list.
 */
static void
ohci_polled_create_input_list(
	ohci_polled_t		*ohci_polledp,
	ohci_td_t		*head_done_list)
{
	ohci_state_t		*ohcip = ohci_polledp->ohci_polled_ohcip;
	ohci_td_t		*cpu_save, *td;

	ASSERT(head_done_list != NULL);

	/* Get the done head list */
	td = (ohci_td_t *)head_done_list;

	/*
	 * Traverse the done list and create the input done list.
	 */
	while (td) {

		/*
		 * Convert the iommu pointer to a cpu pointer. No point
		 * in doing this over and over, might as well do it once.
		 */
		cpu_save = ohci_td_iommu_to_cpu(ohcip,
		    Get_TD(td->hctd_next_td));

		/*
		 * Terminate this TD by setting its next pointer to NULL.
		 */
		Set_TD(td->hctd_next_td, NULL);

		/* This is an input TD, so put it on the input done list */
		if (ohci_polledp->ohci_polled_input_done_head == NULL) {

			/*
			 * There is nothing on the input done list,
			 * so put this TD on the head.
			 */
			ohci_polledp->ohci_polled_input_done_head = td;
		} else {
			Set_TD(ohci_polledp->
			    ohci_polled_input_done_tail->hctd_next_td,
			    ohci_td_cpu_to_iommu(ohcip, td));
		}

		/* The tail points to the new TD */
		ohci_polledp->ohci_polled_input_done_tail = td;
		td = cpu_save;
	}
}


/*
 * ohci_polled_process_input_list:
 *
 * This routine takes the TD's off of the input done head and processes
 * them.  It returns the number of characters that have been copied for
 * input.
 */
static int
ohci_polled_process_input_list(ohci_polled_t	*ohci_polledp)
{
	ohci_state_t		*ohcip = ohci_polledp->ohci_polled_ohcip;
	ohci_td_t		*td, *next_td;
	uint_t			ctrl;
	uint_t			num_characters;
	ohci_trans_wrapper_t	*tw;
	ohci_pipe_private_t	*pp;
	int 			pipe_dir;

	/*
	 * Get the first TD on the input done head.
	 */
	td = ohci_polledp->ohci_polled_input_done_head;

	ohci_polledp->ohci_polled_input_done_head = NULL;

	num_characters = 0;

	/*
	 * Traverse the list of transfer descriptors. We can't destroy
	 * hctd_next_td pointers of these  TDs because we are using it
	 * to traverse the done list.  Therefore, we can not put these
	 * TDs back on the ED until we are done processing all of them.
	 */
	while (td) {

		/* Get the next TD from the input done list */
		next_td = (ohci_td_t *)
		    ohci_td_iommu_to_cpu(ohcip, Get_TD(td->hctd_next_td));

		/* Look at the status */
		ctrl = (uint_t)Get_TD(td->hctd_ctrl) & (uint32_t)HC_TD_CC;

		/*
		 * Check to see if there is an error. If there is error
		 * clear the halt condition in the Endpoint  Descriptor
		 * (ED) associated with this Transfer  Descriptor (TD).
		 */
		if (ctrl != HC_TD_CC_NO_E) {
			/* Obtain the transfer wrapper from the TD */
			tw = (ohci_trans_wrapper_t *)OHCI_LOOKUP_ID(
			    (uint32_t)Get_TD(td->hctd_trans_wrapper));

			/* Get the pipe handle for this transfer wrapper */
			pp = tw->tw_pipe_private;

			/* Clear the halt bit */
			Set_ED(pp->pp_ept->hced_headp,
			    (Get_ED(pp->pp_ept->hced_headp) & ~HC_EPT_Halt));
		}

		/* Obtain the transfer wrapper from the TD */
		tw = (ohci_trans_wrapper_t *)OHCI_LOOKUP_ID(
		    (uint32_t)Get_TD(td->hctd_trans_wrapper));

		/* Get the pipe direction for this transfer wrapper */
		pipe_dir = tw->tw_pipe_private->pp_pipe_handle->
		    p_ep.bEndpointAddress & USB_EP_DIR_MASK;

		switch (pipe_dir) {
		case USB_EP_DIR_IN:
			num_characters +=
			    ohci_polled_handle_normal_td(ohci_polledp,
			    td);

			/*
			 * Insert this TD back
			 * onto the ED's TD list
			 */
			ohci_polled_insert_td(ohcip, td);
			break;
		case USB_EP_DIR_OUT:
			ASSERT((ohci_td_t *)tw->tw_hctd_head == td);

			tw->tw_hctd_head = (ohci_td_t *)
			    ohci_td_iommu_to_cpu(ohcip,
			    Get_TD(td->hctd_tw_next_td));
			Set_TD(td->hctd_state, HC_TD_DUMMY);

			if (tw->tw_hctd_head == NULL) {
				tw->tw_hctd_tail = NULL;
			}

			if (tw->tw_hctd_free_list != NULL) {
				uint32_t	td_addr;
				td_addr = ohci_td_cpu_to_iommu(ohcip,
				    tw->tw_hctd_free_list);
				Set_TD(td->hctd_tw_next_td, td_addr);
				tw->tw_hctd_free_list = td;
			} else {
				tw->tw_hctd_free_list = td;
				Set_TD(td->hctd_tw_next_td, NULL);
			}
			break;
		}

		td = next_td;
	}

	return (num_characters);
}


/*
 * ohci_polled_handle_normal_td:
 */
static int
ohci_polled_handle_normal_td(
	ohci_polled_t		*ohci_polledp,
	ohci_td_t		*td)
{
	ohci_state_t		*ohcip = ohci_polledp->ohci_polled_ohcip;
	uchar_t			*buf;
	ohci_trans_wrapper_t	*tw;
	size_t			length, residue;

	/* Obtain the transfer wrapper from the TD */
	tw = (ohci_trans_wrapper_t *)OHCI_LOOKUP_ID((uint32_t)
	    Get_TD(td->hctd_trans_wrapper));

	ASSERT(tw != NULL);

	buf = (uchar_t *)tw->tw_buf;

	length = tw->tw_length;
	/*
	 * If "CurrentBufferPointer" of Transfer Descriptor (TD) is
	 * not equal to zero, then we  received less data  from the
	 * device than requested by us. In that  case, get the actual
	 * received data size.
	 */
	if (Get_TD(td->hctd_cbp)) {

		residue = ohci_get_td_residue(ohcip, td);
		length = Get_TD(td->hctd_xfer_offs) +
		    Get_TD(td->hctd_xfer_len) - residue;
	}

	/* Sync IO buffer */
	if (ohci_polledp->ohci_polled_no_sync_flag == B_FALSE) {
		Sync_IO_Buffer(tw->tw_dmahandle, length);
	}

		/* Copy the data into the message */
	ddi_rep_get8(tw->tw_accesshandle,
	    (uint8_t *)ohci_polledp->ohci_polled_buf,
	    (uint8_t *)buf, length, DDI_DEV_AUTOINCR);

	return ((int)length);
}


/*
 * ohci_polled_insert_td:
 *
 * Insert a Transfer Descriptor (TD) on an Endpoint Descriptor (ED).
 */
static void
ohci_polled_insert_td(
	ohci_state_t		*ohcip,
	ohci_td_t		*td)
{
	ohci_pipe_private_t	*pp;
	ohci_ed_t		*ept;
	uint_t			td_control;
	ohci_trans_wrapper_t	*tw;
	ohci_td_t		*cpu_current_dummy;
	usb_intr_req_t		*intr_req;
	usba_pipe_handle_data_t	*ph;
	int			pipe_attr;

	/* Obtain the transfer wrapper from the TD */
	tw = (ohci_trans_wrapper_t *)OHCI_LOOKUP_ID(
	    (uint32_t)Get_TD(td->hctd_trans_wrapper));

	/* Ensure the DMA cookie is valid for reuse */
	ASSERT((tw->tw_cookie_idx == 0) && (tw->tw_dma_offs == 0));

	/*
	 * Take this TD off the transfer wrapper's list since
	 * the pipe is FIFO, this must be the first TD on the
	 * list.
	 */
	ASSERT((ohci_td_t *)tw->tw_hctd_head == td);

	tw->tw_hctd_head = (ohci_td_t *)
	    ohci_td_iommu_to_cpu(ohcip, Get_TD(td->hctd_tw_next_td));

	/*
	 * If the head becomes NULL, then there are no more
	 * active TD's for this transfer wrapper. Also	set
	 * the tail to NULL.
	 */
	if (tw->tw_hctd_head == NULL) {
		tw->tw_hctd_tail = NULL;
	}

	/* Convert current valid TD as new dummy TD */
	bzero((char *)td, sizeof (ohci_td_t));
	Set_TD(td->hctd_state, HC_TD_DUMMY);

	pp = tw->tw_pipe_private;
	ph = pp->pp_pipe_handle;

	/* Obtain the endpoint and the request */
	ept = pp->pp_ept;

	/* Get the pipe attribute */
	pipe_attr = ph->p_ep.bmAttributes & USB_EP_ATTR_MASK;

	switch (pipe_attr) {
	case USB_EP_ATTR_INTR:
		intr_req = (usb_intr_req_t *)tw->tw_curr_xfer_reqp;

		if (intr_req->intr_attributes & USB_ATTRS_SHORT_XFER_OK) {
			td_control = HC_TD_IN|HC_TD_1I|HC_TD_R;
		} else {
			td_control = HC_TD_IN|HC_TD_1I;
		}
		break;
	case USB_EP_ATTR_BULK:
		td_control = tw->tw_direction|HC_TD_DT_0|HC_TD_1I|HC_TD_R;
		break;
	}

	/* Get the current dummy */
	cpu_current_dummy = (ohci_td_t *)
	    (ohci_td_iommu_to_cpu(ohcip, Get_ED(ept->hced_tailp)));

	/*
	 * Fill in the current dummy td and
	 * add the new dummy to the end.
	 */
	ohci_polled_fill_in_td(ohcip, cpu_current_dummy, td,
	    td_control, 0, tw->tw_length, tw);

	/* Insert this td onto the tw */
	ohci_polled_insert_td_on_tw(ohcip, tw, cpu_current_dummy);

	/*
	 * Add the new dummy to the ED's list.	When this occurs,
	 * the Host Controller will see the newly filled in dummy
	 * TD.
	 */
	Set_ED(ept->hced_tailp, (ohci_td_cpu_to_iommu(ohcip, td)));
}


/*
 * ohci_polled_fill_in_td:
 *
 * Fill in the fields of a Transfer Descriptor (TD).
 */
static void
ohci_polled_fill_in_td(
	ohci_state_t		*ohcip,
	ohci_td_t		*td,
	ohci_td_t		*new_dummy,
	uint_t			hctd_ctrl,
	uint32_t		hctd_dma_offs,
	size_t			hctd_length,
	ohci_trans_wrapper_t	*tw)
{
	/* Assert that the td to be filled in is a dummy */
	ASSERT(Get_TD(td->hctd_state) == HC_TD_DUMMY);

	/* Clear the TD */
	bzero((char *)td, sizeof (ohci_td_t));

	/* Update the dummy with control information */
	Set_TD(td->hctd_ctrl, (hctd_ctrl | HC_TD_CC_NA));

	/* Update the beginning and end of the buffer */
	ohci_init_td(ohcip, tw, hctd_dma_offs, hctd_length, td);

	/* The current dummy now points to the new dummy */
	Set_TD(td->hctd_next_td, (ohci_td_cpu_to_iommu(ohcip, new_dummy)));

	/* Fill in the wrapper portion of the TD */
	Set_TD(td->hctd_trans_wrapper, (uint32_t)tw->tw_id);
	Set_TD(td->hctd_tw_next_td, NULL);
}


/*
 * ohci_polled_insert_td_on_tw:
 *
 * The transfer wrapper keeps a list of all Transfer Descriptors (TD) that
 * are allocated for this transfer. Insert a TD  onto this list. The  list
 * of TD's does not include the dummy TD that is at the end of the list of
 * TD's for the endpoint.
 */
static void
ohci_polled_insert_td_on_tw(
	ohci_state_t		*ohcip,
	ohci_trans_wrapper_t	*tw,
	ohci_td_t		*td)
{

	/*
	 * Set the next pointer to NULL because
	 * this is the last TD on list.
	 */
	Set_TD(td->hctd_tw_next_td, NULL);

	if (tw->tw_hctd_head == NULL) {
		ASSERT(tw->tw_hctd_tail == NULL);
		tw->tw_hctd_head = td;
		tw->tw_hctd_tail = td;
	} else {
		ohci_td_t *dummy = (ohci_td_t *)tw->tw_hctd_tail;

		ASSERT(dummy != NULL);
		ASSERT(dummy != td);
		ASSERT(Get_TD(td->hctd_state) == HC_TD_DUMMY);

		/* Add the td to the end of the list */
		Set_TD(dummy->hctd_tw_next_td, ohci_td_cpu_to_iommu(ohcip, td));
		tw->tw_hctd_tail = td;

		ASSERT(Get_TD(td->hctd_tw_next_td) == NULL);
	}
}


/*
 * ohci_polled_handle_frame_number_overflow:
 *
 * Process Frame Number Overflow (FNO) interrupt in polled mode.
 */
static void
ohci_polled_handle_frame_number_overflow(ohci_state_t	*ohcip)
{
	uint_t			intr;

	/* Read the Interrupt Status & Interrupt enable register */
	intr = (Get_OpReg(hcr_intr_status) & Get_OpReg(hcr_intr_enable));

	/*
	 * Check whether any Frame Number Overflow interrupt is pending
	 * and if it is pending, process this interrupt.
	 */
	if (intr & HCR_INTR_FNO) {
		ohci_handle_frame_number_overflow(ohcip);

		/* Acknowledge the FNO interrupt */
		ohci_polled_finish_interrupt(ohcip, HCR_INTR_FNO);
	}
}


/*
 * ohci_polled_finish_interrupt:
 */
static void
ohci_polled_finish_interrupt(
	ohci_state_t	*ohcip,
	uint_t		intr)
{
	/* Acknowledge the interrupt */
	Set_OpReg(hcr_intr_status, intr);

	/*
	 * Read interrupt status register to make sure that any PIO
	 * store to clear the ISR has made it on the PCI bus before
	 * returning from its interrupt handler.
	 */
	(void) Get_OpReg(hcr_intr_status);
}


/*
 * ohci_polled_buikin_start:
 * 	Insert bulkin td into endpoint's td list.
 */
static void
ohci_polled_insert_bulk_td(
	ohci_polled_t	*ohci_polledp)
{
	ohci_state_t		*ohcip;
	ohci_trans_wrapper_t	*tw;
	ohci_pipe_private_t	*pp;
	usba_pipe_handle_data_t	*ph;
	uint32_t		ctrl;
	uint_t			bulk_pkg_size;

	ohcip = ohci_polledp->ohci_polled_ohcip;
	ph = ohci_polledp->ohci_polled_input_pipe_handle;
	pp = (ohci_pipe_private_t *)ph->p_hcd_private;

	tw = pp->pp_tw_head;
	ASSERT(tw != NULL);

	ctrl = tw->tw_direction | HC_TD_DT_0 | HC_TD_1I | HC_TD_R;
	bulk_pkg_size = min(POLLED_RAW_BUF_SIZE, OHCI_MAX_TD_XFER_SIZE);

	(void) ohci_polled_insert_hc_td(ohcip, ctrl, 0, bulk_pkg_size, pp, tw);
}


/*
 * ohci_polled_create_tw:
 *	Create the transfer wrapper used in polled mode.
 */
static int
ohci_polled_create_tw(
	ohci_state_t	*ohcip,
	usba_pipe_handle_data_t	*ph,
	usb_flags_t	usb_flags)
{
	uint_t			ccount;
	ohci_trans_wrapper_t	*tw;
	ddi_device_acc_attr_t	dev_attr;
	ddi_dma_attr_t		dma_attr;
	ohci_pipe_private_t	*pp;
	int			result, pipe_dir, td_count;
	size_t			real_length;

	pp = (ohci_pipe_private_t *)ph->p_hcd_private;
	td_count = (POLLED_RAW_BUF_SIZE - 1) / OHCI_MAX_TD_XFER_SIZE + 1;

	if ((tw = kmem_zalloc(sizeof (ohci_trans_wrapper_t),
	    KM_NOSLEEP)) == NULL) {
		return (USB_FAILURE);
	}

	/* allow sg lists for transfer wrapper dma memory */
	bcopy(&ohcip->ohci_dma_attr, &dma_attr, sizeof (ddi_dma_attr_t));
	dma_attr.dma_attr_sgllen = OHCI_DMA_ATTR_TW_SGLLEN;
	dma_attr.dma_attr_align = OHCI_DMA_ATTR_ALIGNMENT;

	/* Allocate the DMA handle */
	if ((result = ddi_dma_alloc_handle(ohcip->ohci_dip,
	    &dma_attr, DDI_DMA_DONTWAIT, 0, &tw->tw_dmahandle)) !=
	    DDI_SUCCESS) {
		kmem_free(tw, sizeof (ohci_trans_wrapper_t));

		return (USB_FAILURE);
	}

	dev_attr.devacc_attr_version		= DDI_DEVICE_ATTR_V0;
	dev_attr.devacc_attr_endian_flags	= DDI_STRUCTURE_LE_ACC;
	dev_attr.devacc_attr_dataorder		= DDI_STRICTORDER_ACC;

	/* Allocate the memory */
	if ((result = ddi_dma_mem_alloc(tw->tw_dmahandle, POLLED_RAW_BUF_SIZE,
	    &dev_attr, DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT, NULL,
	    &tw->tw_buf, &real_length, &tw->tw_accesshandle)) !=
	    DDI_SUCCESS) {
		ddi_dma_free_handle(&tw->tw_dmahandle);
		kmem_free(tw, sizeof (ohci_trans_wrapper_t));

		return (USB_FAILURE);
	}

	/* Bind the handle */
	if ((result = ddi_dma_addr_bind_handle(tw->tw_dmahandle, NULL,
	    tw->tw_buf, real_length, DDI_DMA_RDWR|DDI_DMA_CONSISTENT,
	    DDI_DMA_DONTWAIT, NULL, &tw->tw_cookie, &ccount)) !=
	    DDI_DMA_MAPPED) {
		ddi_dma_mem_free(&tw->tw_accesshandle);
		ddi_dma_free_handle(&tw->tw_dmahandle);
		kmem_free(tw, sizeof (ohci_trans_wrapper_t));

		return (USB_FAILURE);
	}

	/* The cookie count should be 1 */
	if (ccount != 1) {
		result = ddi_dma_unbind_handle(tw->tw_dmahandle);
		ASSERT(result == DDI_SUCCESS);

		ddi_dma_mem_free(&tw->tw_accesshandle);
		ddi_dma_free_handle(&tw->tw_dmahandle);
		kmem_free(tw, sizeof (ohci_trans_wrapper_t));

		return (USB_FAILURE);
	}

	if (ohci_allocate_tds_for_tw(ohcip, tw, td_count) == USB_SUCCESS) {
		tw->tw_num_tds = td_count;
	} else {
		ohci_deallocate_tw_resources(ohcip, pp, tw);
		return (USB_FAILURE);
	}
	tw->tw_cookie_idx = 0;
	tw->tw_dma_offs = 0;

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
	tw->tw_length = POLLED_RAW_BUF_SIZE;

	/* Store a back pointer to the pipe private structure */
	tw->tw_pipe_private = pp;

	/* Store the transfer type - synchronous or asynchronous */
	tw->tw_flags = usb_flags;

	/* Get and Store 32bit ID */
	tw->tw_id = OHCI_GET_ID((void *)tw);

	ASSERT(tw->tw_id != NULL);

	pipe_dir = ph->p_ep.bEndpointAddress & USB_EP_DIR_MASK;
	tw->tw_direction = (pipe_dir == USB_EP_DIR_IN) ? HC_TD_IN : HC_TD_OUT;

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ohcip->ohci_log_hdl,
	    "ohci_create_transfer_wrapper: tw = 0x%p, ncookies = %u",
	    (void *)tw, tw->tw_ncookies);

	return (USB_SUCCESS);
}


/*
 * ohci_polled_insert_hc_td:
 *
 * Insert a Transfer Descriptor (TD) on an Endpoint Descriptor (ED).
 */
int
ohci_polled_insert_hc_td(
	ohci_state_t		*ohcip,
	uint_t			hctd_ctrl,
	uint32_t		hctd_dma_offs,
	size_t			hctd_length,
	ohci_pipe_private_t	*pp,
	ohci_trans_wrapper_t	*tw)
{
	ohci_td_t		*new_dummy;
	ohci_td_t		*cpu_current_dummy;
	ohci_ed_t		*ept = pp->pp_ept;

	/* Retrieve preallocated td from the TW */
	new_dummy = tw->tw_hctd_free_list;

	ASSERT(new_dummy != NULL);

	tw->tw_hctd_free_list = ohci_td_iommu_to_cpu(ohcip,
	    Get_TD(new_dummy->hctd_tw_next_td));
	Set_TD(new_dummy->hctd_tw_next_td, NULL);

	/* Fill in the current dummy */
	cpu_current_dummy = (ohci_td_t *)
	    (ohci_td_iommu_to_cpu(ohcip, Get_ED(ept->hced_tailp)));

	/*
	 * Fill in the current dummy td and
	 * add the new dummy to the end.
	 */
	ohci_polled_fill_in_td(ohcip, cpu_current_dummy, new_dummy,
	    hctd_ctrl, hctd_dma_offs, hctd_length, tw);

	/*
	 * add the new dummy to the ED's list. When
	 * this occurs, the Host Controller will see
	 * the newly filled in dummy TD.
	 */
	Set_ED(ept->hced_tailp,
	    (ohci_td_cpu_to_iommu(ohcip, new_dummy)));

	/* Insert this td onto the tw */
	ohci_polled_insert_td_on_tw(ohcip, tw, cpu_current_dummy);

	return (USB_SUCCESS);
}
