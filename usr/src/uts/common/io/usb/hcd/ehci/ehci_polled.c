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
 * This module contains the specific EHCI code used in POLLED mode. This
 * code is in a separate file since it will never become part of the EHCI
 * driver.
 */

#include <sys/usb/usba/usbai_version.h>
#include <sys/usb/hcd/ehci/ehcid.h>
#include <sys/usb/hcd/ehci/ehci_xfer.h>
#include <sys/usb/hcd/ehci/ehci_intr.h>
#include <sys/usb/hcd/ehci/ehci_util.h>
#include <sys/usb/hcd/ehci/ehci_polled.h>

#ifndef __sparc
extern void invalidate_cache();
#endif

/*
 * Internal Function Prototypes
 */

/* Polled initialization routines */
static int	ehci_polled_init(
				usba_pipe_handle_data_t	*ph,
				ehci_state_t		*ehcip,
				usb_console_info_impl_t	*console_input_info);

/* Polled deinitialization routines */
static int	ehci_polled_fini(ehci_polled_t		*ehci_polledp);

/* Polled save state routines */
static void	ehci_polled_save_state(ehci_polled_t	*ehci_polledp);

/* Polled restore state routines */
static void	ehci_polled_restore_state(ehci_polled_t	*ehci_polledp);
static void	ehci_polled_stop_processing(
				ehci_polled_t		*ehci_polledp);
static void	ehci_polled_start_processing(
				ehci_polled_t		*ehci_polledp);

/* Polled read routines */
static int	ehci_polled_process_active_intr_qtd_list(
				ehci_polled_t		*ehci_polledp);
static int	ehci_polled_handle_normal_qtd(
				ehci_polled_t		*ehci_polledp,
				ehci_qtd_t		*qtd);
static void	ehci_polled_insert_intr_qtd(
				ehci_polled_t		*ehci_polledp,
				ehci_qtd_t		*qtd);
static void	ehci_polled_insert_bulk_qtd(
				ehci_polled_t		*ehci_polledp);
static void	ehci_polled_fill_in_qtd(
				ehci_state_t		*ehcip,
				ehci_qtd_t		*qtd,
				uint_t			qtd_ctrl,
				size_t			qtd_dma_offs,
				size_t			qtd_length,
				ehci_trans_wrapper_t	*tw);
static void	ehci_polled_insert_qtd_on_tw(
				ehci_state_t		*ehcip,
				ehci_trans_wrapper_t	*tw,
				ehci_qtd_t		*qtd);
static ehci_qtd_t *ehci_polled_create_done_qtd_list(
				ehci_polled_t		*ehci_polledp);
static void	ehci_polled_insert_qtd_into_active_intr_qtd_list(
				ehci_polled_t		*ehci_polledp,
				ehci_qtd_t		*curr_qtd);
static void	ehci_polled_remove_qtd_from_active_intr_qtd_list(
				ehci_polled_t		*ehci_polledp,
				ehci_qtd_t		*curr_qtd);
static void	ehci_polled_traverse_qtds(
				ehci_polled_t		*ehci_polledp,
				usba_pipe_handle_data_t	*ph);
static void	ehci_polled_finish_interrupt(
				ehci_state_t		*ehcip,
				uint_t			intr);
static int	ehci_polled_create_tw(
				ehci_polled_t		*ehci_polledp,
				usba_pipe_handle_data_t	*ph,
				usb_flags_t		usb_flags);
static void	ehci_polled_insert_async_qh(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp);
static void	ehci_polled_remove_async_qh(
				ehci_state_t		*ehcip,
				ehci_pipe_private_t	*pp);

/*
 * POLLED entry points
 *
 * These functions are entry points into the POLLED code.
 */

/*
 * ehci_hcdi_polled_input_init:
 *
 * This is the initialization routine for handling the USB input device
 * in POLLED mode.  This routine is not called from POLLED mode, so
 * it is OK to acquire mutexes.
 */
int
ehci_hcdi_polled_input_init(
	usba_pipe_handle_data_t	*ph,
	uchar_t			**polled_buf,
	usb_console_info_impl_t	*console_input_info)
{
	ehci_polled_t		*ehci_polledp;
	ehci_state_t		*ehcip;
	int			ret;

	ehcip = ehci_obtain_state(ph->p_usba_device->usb_root_hub_dip);

	/*
	 * Grab the ehci_int_mutex so that things don't change on us
	 * if an interrupt comes in.
	 */
	mutex_enter(&ehcip->ehci_int_mutex);

	ret = ehci_polled_init(ph, ehcip, console_input_info);

	if (ret != USB_SUCCESS) {

		/* Allow interrupts to continue */
		mutex_exit(&ehcip->ehci_int_mutex);
		return (ret);
	}

	ehci_polledp = (ehci_polled_t *)console_input_info->uci_private;

	/*
	 * Mark the structure so that if we are using it, we don't free
	 * the structures if one of them is unplugged.
	 */
	ehci_polledp->ehci_polled_flags |= POLLED_INPUT_MODE;

	/* increase the counter for keyboard connected */
	ehcip->ehci_polled_kbd_count ++;

	/*
	 * This is the buffer we will copy characters into. It will be
	 * copied into at this layer, so we need to keep track of it.
	 */
	ehci_polledp->ehci_polled_buf =
	    (uchar_t *)kmem_zalloc(POLLED_RAW_BUF_SIZE, KM_SLEEP);

	*polled_buf = ehci_polledp->ehci_polled_buf;

	/*
	 * This is a software workaround to fix schizo hardware bug.
	 * Existence of "no-prom-cdma-sync"  property means consistent
	 * dma sync should not be done while in prom or polled mode.
	 */
	if (ddi_prop_exists(DDI_DEV_T_ANY, ehcip->ehci_dip,
	    DDI_PROP_NOTPROM, "no-prom-cdma-sync")) {
		ehci_polledp->ehci_polled_no_sync_flag = B_TRUE;
	}

	/* Allow interrupts to continue */
	mutex_exit(&ehcip->ehci_int_mutex);

	return (USB_SUCCESS);
}


/*
 * ehci_hcdi_polled_input_fini:
 */
int
ehci_hcdi_polled_input_fini(usb_console_info_impl_t *info)
{
	ehci_polled_t		*ehci_polledp;
	ehci_state_t		*ehcip;
	int			ret;

	ehci_polledp = (ehci_polled_t *)info->uci_private;

	ehcip = ehci_polledp->ehci_polled_ehcip;

	mutex_enter(&ehcip->ehci_int_mutex);

	/*
	 * Reset the POLLED_INPUT_MODE flag so that we can tell if
	 * this structure is in use in the ehci_polled_fini routine.
	 */
	ehci_polledp->ehci_polled_flags &= ~POLLED_INPUT_MODE;

	/* decrease the counter for keyboard disconnected */
	ehcip->ehci_polled_kbd_count --;

	/* Free the buffer that we copied data into */
	kmem_free(ehci_polledp->ehci_polled_buf, POLLED_RAW_BUF_SIZE);

	ret = ehci_polled_fini(ehci_polledp);

	mutex_exit(&ehcip->ehci_int_mutex);

	return (ret);
}


/*
 * ehci_hcdi_polled_input_enter:
 *
 * This is where we enter into POLLED mode.  This routine sets up
 * everything so that calls to	ehci_hcdi_polled_read will return
 * characters.
 */
int
ehci_hcdi_polled_input_enter(usb_console_info_impl_t *info)
{
	ehci_polled_t		*ehci_polledp;
	ehci_state_t		*ehcip;
	usba_pipe_handle_data_t	*ph;
	ehci_pipe_private_t	*pp;
	int			pipe_attr;

#ifndef lint
	_NOTE(NO_COMPETING_THREADS_NOW);
#endif
	ehci_polledp = (ehci_polled_t *)info->uci_private;
	ehcip = ehci_polledp->ehci_polled_ehcip;
	ph = ehci_polledp->ehci_polled_input_pipe_handle;
	pp = (ehci_pipe_private_t *)ph->p_hcd_private;

	pipe_attr = ph->p_ep.bmAttributes & USB_EP_ATTR_MASK;
#ifndef lint
	_NOTE(COMPETING_THREADS_NOW);
#endif

	ehci_polledp->ehci_polled_entry++;
	/*
	 * If the controller is already switched over, just return
	 */
	if (ehci_polledp->ehci_polled_entry > 1) {

		return (USB_SUCCESS);
	}

	switch (pipe_attr) {
	case USB_EP_ATTR_INTR:
		ehci_polled_save_state(ehci_polledp);
		break;
	case USB_EP_ATTR_BULK:
#ifndef lint
	_NOTE(NO_COMPETING_THREADS_NOW);
#endif
		Set_OpReg(ehci_command, (Get_OpReg(ehci_command) &
		    ~(EHCI_CMD_PERIODIC_SCHED_ENABLE |
		    EHCI_CMD_ASYNC_SCHED_ENABLE)));
		/* Wait for few milliseconds */
		drv_usecwait(EHCI_POLLED_TIMEWAIT);

		ehci_polled_insert_async_qh(ehcip, pp);

		Set_OpReg(ehci_command,
		    (Get_OpReg(ehci_command) | EHCI_CMD_ASYNC_SCHED_ENABLE));
#ifndef lint
	_NOTE(COMPETING_THREADS_NOW);
#endif
		/* Wait for few milliseconds */
		drv_usecwait(EHCI_POLLED_TIMEWAIT);
		break;
	default:
		return (USB_FAILURE);
	}

	ehci_polledp->ehci_polled_flags |= POLLED_INPUT_MODE_INUSE;

	return (USB_SUCCESS);
}


/*
 * ehci_hcdi_polled_input_exit:
 *
 * This is where we exit POLLED mode. This routine restores
 * everything that is needed to continue operation.
 */
int
ehci_hcdi_polled_input_exit(usb_console_info_impl_t *info)
{
	ehci_polled_t		*ehci_polledp;
	ehci_state_t		*ehcip;
	ehci_pipe_private_t	*pp;
	int			pipe_attr;

#ifndef lint
	_NOTE(NO_COMPETING_THREADS_NOW);
#endif
	ehci_polledp = (ehci_polled_t *)info->uci_private;
	ehcip = ehci_polledp->ehci_polled_ehcip;
	pp = (ehci_pipe_private_t *)ehci_polledp->
	    ehci_polled_input_pipe_handle->p_hcd_private;

	pipe_attr = ehci_polledp->ehci_polled_input_pipe_handle->
	    p_ep.bmAttributes & USB_EP_ATTR_MASK;
#ifndef lint
	_NOTE(COMPETING_THREADS_NOW);
#endif

	ehci_polledp->ehci_polled_entry--;

	/*
	 * If there are still outstanding "enters", just return
	 */
	if (ehci_polledp->ehci_polled_entry > 0) {

		return (USB_SUCCESS);
	}

	ehci_polledp->ehci_polled_flags &= ~POLLED_INPUT_MODE_INUSE;

	switch (pipe_attr & USB_EP_ATTR_MASK) {
	case USB_EP_ATTR_INTR:
		ehci_polled_restore_state(ehci_polledp);
		break;
	case USB_EP_ATTR_BULK:
#ifndef lint
	_NOTE(NO_COMPETING_THREADS_NOW);
#endif
		Set_OpReg(ehci_command, (Get_OpReg(ehci_command) &
		    ~(EHCI_CMD_PERIODIC_SCHED_ENABLE |
		    EHCI_CMD_ASYNC_SCHED_ENABLE)));
		/* Wait for few milliseconds */
		drv_usecwait(EHCI_POLLED_TIMEWAIT);

		ehci_polled_remove_async_qh(ehcip, pp);

		Set_OpReg(ehci_command,
		    (Get_OpReg(ehci_command) | EHCI_CMD_ASYNC_SCHED_ENABLE |
		    EHCI_CMD_ASYNC_SCHED_ENABLE));
#ifndef lint
	_NOTE(COMPETING_THREADS_NOW);
#endif
		/* Wait for few milliseconds */
		drv_usecwait(EHCI_POLLED_TIMEWAIT);
		break;
	default:
		return (USB_FAILURE);

	}

	return (USB_SUCCESS);
}


/*
 * ehci_hcdi_polled_read:
 *
 * Get a key character
 */
int
ehci_hcdi_polled_read(
	usb_console_info_impl_t	*info,
	uint_t			*num_characters)
{
	ehci_state_t		*ehcip;
	ehci_polled_t		*ehci_polledp;
	uint_t			intr;
	int			pipe_attr;

	ehci_polledp = (ehci_polled_t *)info->uci_private;

	ehcip = ehci_polledp->ehci_polled_ehcip;

#ifndef lint
	_NOTE(NO_COMPETING_THREADS_NOW);
#endif

	*num_characters = 0;

	pipe_attr = ehci_polledp->ehci_polled_input_pipe_handle->
	    p_ep.bmAttributes & USB_EP_ATTR_MASK;

	if (pipe_attr == USB_EP_ATTR_BULK) {
		ehci_polled_insert_bulk_qtd(ehci_polledp);
	}

	intr = ((Get_OpReg(ehci_status) & Get_OpReg(ehci_interrupt)) &
	    (EHCI_INTR_FRAME_LIST_ROLLOVER |
	    EHCI_INTR_USB | EHCI_INTR_USB_ERROR));

	/*
	 * Check whether any frame list rollover interrupt is pending
	 * and if it is pending, process this interrupt.
	 */
	if (intr & EHCI_INTR_FRAME_LIST_ROLLOVER) {
		/* Check any frame list rollover interrupt is pending */
		ehci_handle_frame_list_rollover(ehcip);
		ehci_polled_finish_interrupt(ehcip,
		    EHCI_INTR_FRAME_LIST_ROLLOVER);
	}

	/* Process any QTD's on the active interrupt qtd list */
	*num_characters =
	    ehci_polled_process_active_intr_qtd_list(ehci_polledp);

#ifndef lint
	_NOTE(COMPETING_THREADS_NOW);
#endif

	return (USB_SUCCESS);
}


/*
 * ehci_hcdi_polled_output_init:
 *
 * This is the initialization routine for handling the USB serial output
 * in POLLED mode.  This routine is not called from POLLED mode, so
 * it is OK to acquire mutexes.
 */
int
ehci_hcdi_polled_output_init(
	usba_pipe_handle_data_t	*ph,
	usb_console_info_impl_t	*console_output_info)
{
	ehci_polled_t		*ehci_polledp;
	ehci_state_t		*ehcip;
	ehci_pipe_private_t	*pp;
	int			ret;

	ehcip = ehci_obtain_state(ph->p_usba_device->usb_root_hub_dip);

	/*
	 * Grab the ehci_int_mutex so that things don't change on us
	 * if an interrupt comes in.
	 */
	mutex_enter(&ehcip->ehci_int_mutex);

	ret = ehci_polled_init(ph, ehcip, console_output_info);

	if (ret != USB_SUCCESS) {

		/* Allow interrupts to continue */
		mutex_exit(&ehcip->ehci_int_mutex);

		return (ret);
	}

	ehci_polledp = (ehci_polled_t *)console_output_info->uci_private;
	/*
	 * Mark the structure so that if we are using it, we don't free
	 * the structures if one of them is unplugged.
	 */
	ehci_polledp->ehci_polled_flags |= POLLED_OUTPUT_MODE;

	/*
	 * Insert the Endpoint Descriptor to appropriate endpoint list.
	 */
	pp = (ehci_pipe_private_t *)ehci_polledp->
	    ehci_polled_input_pipe_handle->p_hcd_private;
	ehci_polled_insert_async_qh(ehcip, pp);

	/*
	 * This is a software workaround to fix schizo hardware bug.
	 * Existence of "no-prom-cdma-sync"  property means consistent
	 * dma sync should not be done while in prom or polled mode.
	 */
	if (ddi_prop_exists(DDI_DEV_T_ANY, ehcip->ehci_dip,
	    DDI_PROP_NOTPROM, "no-prom-cdma-sync")) {
		ehci_polledp->ehci_polled_no_sync_flag = B_TRUE;
	}

	/* Allow interrupts to continue */
	mutex_exit(&ehcip->ehci_int_mutex);

	return (USB_SUCCESS);
}


/*
 * ehci_hcdi_polled_output_fini:
 */
int
ehci_hcdi_polled_output_fini(usb_console_info_impl_t *info)
{
	ehci_polled_t		*ehci_polledp;
	ehci_state_t		*ehcip;
	ehci_pipe_private_t	*pp;
	int			ret;

	ehci_polledp = (ehci_polled_t *)info->uci_private;

	ehcip = ehci_polledp->ehci_polled_ehcip;

	mutex_enter(&ehcip->ehci_int_mutex);

	/* Remove the Endpoint Descriptor. */
	pp = (ehci_pipe_private_t *)ehci_polledp->
	    ehci_polled_input_pipe_handle->p_hcd_private;
	ehci_polled_remove_async_qh(ehcip, pp);

	/*
	 * Reset the POLLED_INPUT_MODE flag so that we can tell if
	 * this structure is in use in the ehci_polled_fini routine.
	 */
	ehci_polledp->ehci_polled_flags &= ~POLLED_OUTPUT_MODE;

	ret = ehci_polled_fini(ehci_polledp);

	info->uci_private = NULL;

	mutex_exit(&ehcip->ehci_int_mutex);

	return (ret);
}


/*
 * ehci_hcdi_polled_output_enter:
 *
 * everything is done in input enter
 */
/*ARGSUSED*/
int
ehci_hcdi_polled_output_enter(usb_console_info_impl_t *info)
{
	return (USB_SUCCESS);
}


/*
 * ehci_hcdi_polled_output_exit:
 *
 * everything is done in input exit
 */
/*ARGSUSED*/
int
ehci_hcdi_polled_output_exit(usb_console_info_impl_t *info)
{
	return (USB_SUCCESS);
}


/*
 * ehci_hcdi_polled_write:
 *	Put a key character.
 */
int
ehci_hcdi_polled_write(usb_console_info_impl_t *info, uchar_t *buf,
    uint_t num_characters, uint_t *num_characters_written)
{
	ehci_state_t		*ehcip;
	ehci_polled_t		*ehci_polledp;
	ehci_trans_wrapper_t	*tw;
	ehci_pipe_private_t	*pp;
	usba_pipe_handle_data_t	*ph;
	int			intr;

#ifndef lint
	_NOTE(NO_COMPETING_THREADS_NOW);
#endif
	ehci_polledp = (ehci_polled_t *)info->uci_private;
	ehcip = ehci_polledp->ehci_polled_ehcip;
	ph = ehci_polledp->ehci_polled_input_pipe_handle;
	pp = (ehci_pipe_private_t *)ph->p_hcd_private;

	/* Disable all list processing */
	Set_OpReg(ehci_command, Get_OpReg(ehci_command) &
	    ~(EHCI_CMD_ASYNC_SCHED_ENABLE |
	    EHCI_CMD_PERIODIC_SCHED_ENABLE));

	/* Wait for few milliseconds */
	drv_usecwait(EHCI_POLLED_TIMEWAIT);

	tw = pp->pp_tw_head;
	ASSERT(tw != NULL);

	/* copy transmit buffer */
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

	ehci_polled_insert_bulk_qtd(ehci_polledp);

	/* Enable async list processing */
	Set_OpReg(ehci_command, (Get_OpReg(ehci_command) |
	    EHCI_CMD_ASYNC_SCHED_ENABLE));

	/* Wait for few milliseconds */
	drv_usecwait(EHCI_POLLED_TIMEWAIT);

	while (!((Get_OpReg(ehci_status)) & (EHCI_INTR_USB
	    |EHCI_INTR_FRAME_LIST_ROLLOVER | EHCI_INTR_USB_ERROR))) {
#ifndef __sparc
		invalidate_cache();
#else
		;
#endif
	}

	intr = (Get_OpReg(ehci_status)) &
	    (EHCI_INTR_FRAME_LIST_ROLLOVER |
	    EHCI_INTR_USB | EHCI_INTR_USB_ERROR);

	/*
	 * Check whether any frame list rollover interrupt is pending
	 * and if it is pending, process this interrupt.
	 */
	if (intr & EHCI_INTR_FRAME_LIST_ROLLOVER) {

		ehci_handle_frame_list_rollover(ehcip);
		ehci_polled_finish_interrupt(ehcip,
		    EHCI_INTR_FRAME_LIST_ROLLOVER);
	}

	/* Check for any USB transaction completion notification */
	if (intr & (EHCI_INTR_USB | EHCI_INTR_USB_ERROR)) {

		(void) ehci_polled_process_active_intr_qtd_list(ehci_polledp);

		/* Acknowledge the USB and USB error interrupt */
		ehci_polled_finish_interrupt(ehcip,
		    intr & (EHCI_INTR_USB | EHCI_INTR_USB_ERROR));

	}

	*num_characters_written = num_characters;

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
 * ehci_polled_init:
 *
 * Initialize generic information Uthat is needed to provide USB/POLLED
 * support.
 */
static int
ehci_polled_init(
	usba_pipe_handle_data_t	*ph,
	ehci_state_t		*ehcip,
	usb_console_info_impl_t	*console_info)
{
	ehci_polled_t		*ehci_polledp;
	ehci_pipe_private_t	*pp;
	ehci_qtd_t		*qtd;
	int			pipe_attr;

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/*
	 * We have already initialized this structure. If the structure
	 * has already been initialized, then we don't need to redo it.
	 */
	if (console_info->uci_private) {

		return (USB_SUCCESS);
	}

	/* Allocate and intitialize a state structure */
	ehci_polledp = (ehci_polled_t *)
	    kmem_zalloc(sizeof (ehci_polled_t), KM_SLEEP);

	console_info->uci_private = (usb_console_info_private_t)ehci_polledp;

	/*
	 * Store away the ehcip so that we can get to it when we are in
	 * POLLED mode. We don't want to have to call ehci_obtain_state
	 * every time we want to access this structure.
	 */
	ehci_polledp->ehci_polled_ehcip = ehcip;
	/*
	 * Save usb device and endpoint number information from the usb
	 * pipe handle.
	 */
	mutex_enter(&ph->p_mutex);
	ehci_polledp->ehci_polled_usb_dev = ph->p_usba_device;
	ehci_polledp->ehci_polled_ep_addr = ph->p_ep.bEndpointAddress;
	mutex_exit(&ph->p_mutex);

	/*
	 * Allocate memory to make duplicate of original usb pipe handle.
	 */
	ehci_polledp->ehci_polled_input_pipe_handle =
	    kmem_zalloc(sizeof (usba_pipe_handle_data_t), KM_SLEEP);

	/*
	 * Copy the USB handle into the new pipe handle. Also
	 * create new lock for the new pipe handle.
	 */
	bcopy((void *)ph,
	    (void *)ehci_polledp->ehci_polled_input_pipe_handle,
	    sizeof (usba_pipe_handle_data_t));

	/*
	 * uint64_t typecast to make sure amd64 can compile
	 */
	mutex_init(&ehci_polledp->ehci_polled_input_pipe_handle->p_mutex,
	    NULL, MUTEX_DRIVER, DDI_INTR_PRI(ehcip->ehci_intr_pri));

	/*
	 * Create a new ehci pipe private structure
	 */
	pp = (ehci_pipe_private_t *)
	    kmem_zalloc(sizeof (ehci_pipe_private_t), KM_SLEEP);

	/*
	 * Store the pointer in the pipe handle. This structure was also
	 * just allocated.
	 */
	mutex_enter(&ehci_polledp->ehci_polled_input_pipe_handle->p_mutex);

	ehci_polledp->ehci_polled_input_pipe_handle->
	    p_hcd_private = (usb_opaque_t)pp;

	mutex_exit(&ehci_polledp->ehci_polled_input_pipe_handle->p_mutex);

	/*
	 * Store a pointer to the pipe handle. This structure was  just
	 * allocated and it is not in use yet.	The locking is there to
	 * satisfy warlock.
	 */
	mutex_enter(&ph->p_mutex);

	bcopy(&ph->p_policy, &pp->pp_policy, sizeof (usb_pipe_policy_t));

	mutex_exit(&ph->p_mutex);

	pp->pp_pipe_handle = ehci_polledp->ehci_polled_input_pipe_handle;

	/*
	 * Allocate a dummy for the interrupt table. This dummy will be
	 * put into the action when we	switch interrupt  tables during
	 * ehci_hcdi_polled_enter. Dummy is placed on the unused lattice
	 * entries. When the QH is allocated we will replace dummy QH by
	 * valid interrupt QH in one or more locations in the interrupt
	 * lattice depending on the requested polling interval. Also we
	 * will hang a dummy QTD to the QH & dummy QTD is used to indicate
	 * the end of the QTD chain.
	 */
	ehci_polledp->ehci_polled_dummy_qh =
	    ehci_alloc_qh(ehcip, NULL, EHCI_POLLED_MODE_FLAG);

	if (ehci_polledp->ehci_polled_dummy_qh == NULL) {

		return (USB_NO_RESOURCES);
	}

	/*
	 * Allocate the endpoint. This QH will be inserted in
	 * to the lattice chain for the device. This endpoint
	 * will have the QTDs hanging off of it for the processing.
	 */
	ehci_polledp->ehci_polled_qh = ehci_alloc_qh(
	    ehcip, ph, EHCI_POLLED_MODE_FLAG);

	if (ehci_polledp->ehci_polled_qh == NULL) {

		return (USB_NO_RESOURCES);
	}

	/* Set the state of pipe as idle */
	pp->pp_state = EHCI_PIPE_STATE_IDLE;

	/* Set polled mode flag */
	pp->pp_flag = EHCI_POLLED_MODE_FLAG;

	/* Insert the endpoint onto the pipe handle */
	pp->pp_qh = ehci_polledp->ehci_polled_qh;

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
		 * There will now be two QTDs on the QH, one is the dummy QTD
		 * that was allocated above in the  ehci_alloc_qh and this
		 * new one.
		 */
		if ((ehci_start_periodic_pipe_polling(ehcip,
		    ehci_polledp->ehci_polled_input_pipe_handle,
		    NULL, USB_FLAGS_SLEEP)) != USB_SUCCESS) {

			return (USB_NO_RESOURCES);
		}
		/* Get the given new interrupt qtd */
		qtd = (ehci_qtd_t *)(ehci_qtd_iommu_to_cpu(ehcip,
		    (Get_QH(pp->pp_qh->qh_next_qtd) & EHCI_QH_NEXT_QTD_PTR)));

		/* Insert this qtd into active interrupt QTD list */
		ehci_polled_insert_qtd_into_active_intr_qtd_list(ehci_polledp,
		    qtd);
		break;
	case USB_EP_ATTR_BULK:
		if ((ehci_polled_create_tw(ehci_polledp,
		    ehci_polledp->ehci_polled_input_pipe_handle,
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
 * ehci_polled_fini:
 */
static int
ehci_polled_fini(ehci_polled_t	*ehci_polledp)
{
	ehci_state_t		*ehcip = ehci_polledp->ehci_polled_ehcip;
	ehci_pipe_private_t	*pp;

	ASSERT(mutex_owned(&ehcip->ehci_int_mutex));

	/* If the structure is already in use, then don't free it */
	if (ehci_polledp->ehci_polled_flags & POLLED_INPUT_MODE) {

		return (USB_SUCCESS);
	}

	pp = (ehci_pipe_private_t *)
	    ehci_polledp->ehci_polled_input_pipe_handle->p_hcd_private;

	/* Deallocate all the pre-allocated interrupt requests */
	ehci_handle_outstanding_requests(ehcip, pp);

	/*
	 * Traverse the list of QTD's on this endpoint and these QTD's
	 * have outstanding transfer requests. Since list processing
	 * is stopped, these QTDs can be deallocated.
	 */
	ehci_polled_traverse_qtds(ehci_polledp, pp->pp_pipe_handle);

	/* Free DMA resources */
	ehci_free_dma_resources(ehcip, pp->pp_pipe_handle);

	/*
	 * Deallocate the endpoint descriptors that we allocated
	 * with ehci_alloc_qh.
	 */
	if (ehci_polledp->ehci_polled_dummy_qh) {
		ehci_deallocate_qh(ehcip, ehci_polledp->ehci_polled_dummy_qh);
	}

	if (ehci_polledp->ehci_polled_qh) {
		ehci_deallocate_qh(ehcip, ehci_polledp->ehci_polled_qh);
	}

	mutex_destroy(&ehci_polledp->ehci_polled_input_pipe_handle->p_mutex);

	/*
	 * Destroy everything about the pipe that we allocated in
	 * ehci_polled_duplicate_pipe_handle
	 */
	kmem_free(pp, sizeof (ehci_pipe_private_t));

	kmem_free(ehci_polledp->ehci_polled_input_pipe_handle,
	    sizeof (usba_pipe_handle_data_t));

	/*
	 * We use this field to determine if a QTD is for input or not,
	 * so NULL the pointer so we don't check deallocated data.
	 */
	ehci_polledp->ehci_polled_input_pipe_handle = NULL;

	/*
	 * Finally, free off the structure that we use to keep track
	 * of all this.
	 */
	kmem_free(ehci_polledp, sizeof (ehci_polled_t));

	return (USB_SUCCESS);
}


/*
 * Polled save state routines
 */


/*
 * ehci_polled_save_state:
 */
static void
ehci_polled_save_state(ehci_polled_t	*ehci_polledp)
{
	int				i;
	ehci_state_t			*ehcip;
	uint_t				polled_toggle;
	uint_t				real_toggle;
	ehci_pipe_private_t		*pp = NULL; /* Normal mode Pipe */
	ehci_pipe_private_t		*polled_pp; /* Polled mode Pipe */
	usba_pipe_handle_data_t		*ph;
	uint8_t				ep_addr;
	ehci_regs_t			*ehci_polled_regsp;
	ehci_qh_t			*qh;

#ifndef lint
	_NOTE(NO_COMPETING_THREADS_NOW);
#endif

	/*
	 * If either of these two flags are set, then we have already
	 * saved off the state information and setup the controller.
	 */
	if (ehci_polledp->ehci_polled_flags & POLLED_INPUT_MODE_INUSE) {
#ifndef lint
		_NOTE(COMPETING_THREADS_NOW);
#endif
		return;
	}

	ehcip = ehci_polledp->ehci_polled_ehcip;

	/*
	 * Check if the number of keyboard reach the max number we can
	 * support in polled mode
	 */
	if (++ ehcip->ehci_polled_enter_count > MAX_NUM_FOR_KEYBOARD) {
#ifndef lint
		_NOTE(COMPETING_THREADS_NOW);
#endif
		return;
	}
	ehci_polled_regsp = &ehcip->ehci_polled_save_regs;

	/* Get the endpoint addr. */
	ep_addr = ehci_polledp->ehci_polled_ep_addr;

	/* Get the normal mode usb pipe handle */
	ph = usba_hcdi_get_ph_data(ehci_polledp->ehci_polled_usb_dev, ep_addr);

	/*
	 * The first enter keyboard entry should save info of the normal mode,
	 * disable all list processing and interrupt, initialize the
	 * frame list table with dummy QHs.
	 */
	if (ehcip->ehci_polled_enter_count == 1) {
		/*
		 * Save the current normal mode ehci registers	and later this
		 * saved register copy is used to replace some of required ehci
		 * registers before switching from polled mode to normal mode.
		 */

		bzero((void *)ehci_polled_regsp, sizeof (ehci_regs_t));

		/* Save current ehci registers */
		ehci_polled_regsp->ehci_command = Get_OpReg(ehci_command);
		ehci_polled_regsp->ehci_interrupt = Get_OpReg(ehci_interrupt);
		ehci_polled_regsp->ehci_ctrl_segment =
		    Get_OpReg(ehci_ctrl_segment);
		ehci_polled_regsp->
		    ehci_async_list_addr = Get_OpReg(ehci_async_list_addr);
		ehci_polled_regsp->ehci_config_flag =
		    Get_OpReg(ehci_config_flag);
		ehci_polled_regsp->ehci_periodic_list_base =
		    Get_OpReg(ehci_periodic_list_base);

		/* Disable all list processing and interrupts */
		Set_OpReg(ehci_command, Get_OpReg(ehci_command) &
		    ~(EHCI_CMD_ASYNC_SCHED_ENABLE |
		    EHCI_CMD_PERIODIC_SCHED_ENABLE));

		/* Wait for few milliseconds */
		drv_usecwait(EHCI_POLLED_TIMEWAIT);

		/* Save any unprocessed normal mode ehci interrupts */
		ehcip->ehci_missed_intr_sts = EHCI_INTR_USB;

		/*
		 * Save the current interrupt lattice and  replace this lattice
		 * with an lattice used in POLLED mode. We will restore lattice
		 * back when we exit from the POLLED mode.
		 */
		for (i = 0; i < EHCI_NUM_PERIODIC_FRAME_LISTS; i++) {
			ehcip->ehci_polled_frame_list_table[i] =
			    (ehci_qh_t *)(uintptr_t)Get_PFLT(ehcip->
			    ehci_periodic_frame_list_tablep->
			    ehci_periodic_frame_list_table[i]);
		}

		/*
		 * Fill in the lattice with dummy QHs. These QHs are used so the
		 * controller can tell that it is at the end of the QH list.
		 */
		for (i = 0; i < EHCI_NUM_PERIODIC_FRAME_LISTS; i++) {
			Set_PFLT(ehcip->ehci_periodic_frame_list_tablep->
			    ehci_periodic_frame_list_table[i],
			    ehci_qh_cpu_to_iommu(ehcip,
			    ehci_polledp->ehci_polled_dummy_qh) |
			    (EHCI_QH_LINK_REF_QH | EHCI_QH_LINK_PTR_VALID));
		}

	}

	/* Get the polled mode ehci pipe private structure */
	polled_pp = (ehci_pipe_private_t *)
	    ehci_polledp->ehci_polled_input_pipe_handle->p_hcd_private;

	/*
	 * Before replacing the lattice, adjust the data togggle on the
	 * on the ehci's interrupt ed
	 */
	polled_toggle = (Get_QH(polled_pp->pp_qh->qh_status) &
	    EHCI_QH_STS_DATA_TOGGLE) ? DATA1:DATA0;

	/*
	 * If normal mode interrupt pipe endpoint is active, get the data
	 * toggle from the this interrupt endpoint through the corresponding
	 * interrupt pipe handle. Else get the data toggle information from
	 * the usb device structure and this information is saved during the
	 * normal mode interrupt pipe close. Use this data toggle information
	 * to fix the data toggle of polled mode interrupt endpoint.
	 */
	if (ph) {
		/* Get the normal mode ehci pipe private structure */
		pp = (ehci_pipe_private_t *)ph->p_hcd_private;

		real_toggle = (Get_QH(pp->pp_qh->qh_status) &
		    EHCI_QH_STS_DATA_TOGGLE) ? DATA1:DATA0;
	} else {
		real_toggle = usba_hcdi_get_data_toggle(
		    ehci_polledp->ehci_polled_usb_dev, ep_addr);
	}

	if (polled_toggle != real_toggle) {
		if (real_toggle == DATA0) {
			Set_QH(polled_pp->pp_qh->qh_status,
			    Get_QH(polled_pp->pp_qh->qh_status) &
			    ~EHCI_QH_STS_DATA_TOGGLE);
		} else {
			Set_QH(polled_pp->pp_qh->qh_status,
			    Get_QH(polled_pp->pp_qh->qh_status) |
			    EHCI_QH_STS_DATA_TOGGLE);
		}
	}

	/*
	 * Check whether Halt bit is set in the QH and if so  clear the
	 * halt bit.
	 */
	if (polled_pp->pp_qh->qh_status & EHCI_QH_STS_HALTED) {

		/* Clear the halt bit */
		Set_QH(polled_pp->pp_qh->qh_status,
		    (Get_QH(polled_pp->pp_qh->qh_status) &
		    ~EHCI_QH_STS_HALTED));
	}

	/*
	 * Initialize the qh overlay area
	 */
	qh = ehci_polledp->ehci_polled_qh;
	for (i = 0; i < 5; i++) {
		Set_QH(qh->qh_buf[i], 0);
		Set_QH(qh->qh_buf_high[i], 0);
	}
	Set_QH(qh->qh_next_qtd, ehci_qtd_cpu_to_iommu(ehcip,
	    ehci_polledp->ehci_polled_active_intr_qtd_list));

	/*
	 * Now, add the endpoint to the lattice that we will  hang  our
	 * QTD's off of.  We need to poll this device at  every 8 ms and
	 * hence add this QH needs 4 entries in interrupt lattice.
	 */
	for (i = ehcip->ehci_polled_enter_count - 1;
	    i < EHCI_NUM_PERIODIC_FRAME_LISTS;
	    i = i + LS_MIN_POLL_INTERVAL) {
		Set_PFLT(ehcip->ehci_periodic_frame_list_tablep->
		    ehci_periodic_frame_list_table[i],
		    ehci_qh_cpu_to_iommu(ehcip,
		    ehci_polledp->ehci_polled_qh) | EHCI_QH_LINK_REF_QH);
	}
	/* The first enter keyboard entry enable interrupts and periodic list */
	if (ehcip->ehci_polled_enter_count == 1) {
		/* Enable USB and Frame list rollover interrupts */
		Set_OpReg(ehci_interrupt, (EHCI_INTR_USB |
		    EHCI_INTR_USB_ERROR | EHCI_INTR_FRAME_LIST_ROLLOVER));

		/* Enable the periodic list */
		Set_OpReg(ehci_command,
		    (Get_OpReg(ehci_command) | EHCI_CMD_PERIODIC_SCHED_ENABLE));

		/* Wait for few milliseconds */
		drv_usecwait(EHCI_POLLED_TIMEWAIT);
	}
#ifndef lint
	_NOTE(COMPETING_THREADS_NOW);
#endif
}


/*
 * Polled restore state routines
 */


/*
 * ehci_polled_restore_state:
 */
static void
ehci_polled_restore_state(ehci_polled_t	*ehci_polledp)
{
	ehci_state_t			*ehcip;
	int				i;
	uint_t				polled_toggle;
	uint_t				real_toggle;
	ehci_pipe_private_t		*pp = NULL; /* Normal mode Pipe */
	ehci_pipe_private_t		*polled_pp; /* Polled mode Pipe */
	usba_pipe_handle_data_t		*ph;
	uint8_t				ep_addr;

#ifndef lint
	_NOTE(NO_COMPETING_THREADS_NOW);
#endif

	/*
	 * If this flag is set, then we are still using this structure,
	 * so don't restore any controller state information yet.
	 */
	if (ehci_polledp->ehci_polled_flags & POLLED_INPUT_MODE_INUSE) {

#ifndef lint
		_NOTE(COMPETING_THREADS_NOW);
#endif

		return;
	}

	ehcip = ehci_polledp->ehci_polled_ehcip;
	ehcip->ehci_polled_enter_count --;

	/* Get the endpoint addr */
	ep_addr = ehci_polledp->ehci_polled_ep_addr;

	/* Get the normal mode usb pipe handle */
	ph = usba_hcdi_get_ph_data(ehci_polledp->ehci_polled_usb_dev, ep_addr);

	/* Disable list processing and other things */
	ehci_polled_stop_processing(ehci_polledp);

	/* Get the polled mode ehci pipe private structure */
	polled_pp = (ehci_pipe_private_t *)
	    ehci_polledp->ehci_polled_input_pipe_handle->p_hcd_private;

	/*
	 * Before replacing the lattice, adjust the data togggle
	 * on the on the ehci's interrupt ed
	 */
	polled_toggle = (Get_QH(polled_pp->pp_qh->qh_status) &
	    EHCI_QH_STS_DATA_TOGGLE) ? DATA1:DATA0;

	/*
	 * If normal mode interrupt pipe endpoint is active, fix the
	 * data toggle for this interrupt endpoint by getting the data
	 * toggle information from the polled interrupt endpoint. Else
	 * save the data toggle information in usb device structure.
	 */
	if (ph) {
		/* Get the normal mode ehci pipe private structure */
		pp = (ehci_pipe_private_t *)ph->p_hcd_private;

		real_toggle = (Get_QH(pp->pp_qh->qh_status) &
		    EHCI_QH_STS_DATA_TOGGLE) ? DATA1:DATA0;

		if (polled_toggle != real_toggle) {
			if (polled_toggle == DATA0) {
				Set_QH(pp->pp_qh->qh_status,
				    Get_QH(pp->pp_qh->qh_status) &
				    ~EHCI_QH_STS_DATA_TOGGLE);
			} else {
				Set_QH(pp->pp_qh->qh_status,
				    Get_QH(pp->pp_qh->qh_status) |
				    EHCI_QH_STS_DATA_TOGGLE);
			}
		}
	} else {
		usba_hcdi_set_data_toggle(ehci_polledp->ehci_polled_usb_dev,
		    ep_addr, polled_toggle);
	}

	/*
	 * Only the last leave keyboard entry restore the save frame
	 * list table and start processing.
	 */
	if (ehcip->ehci_polled_enter_count == 0) {

		/* Replace the lattice */
		for (i = 0; i < EHCI_NUM_PERIODIC_FRAME_LISTS; i++) {
			Set_PFLT(ehcip->ehci_periodic_frame_list_tablep->
			    ehci_periodic_frame_list_table[i],
			    ehcip->ehci_polled_frame_list_table[i]);
		}
		ehci_polled_start_processing(ehci_polledp);
	}

#ifndef lint
	_NOTE(COMPETING_THREADS_NOW);
#endif
}


/*
 * ehci_polled_stop_processing:
 */
static void
ehci_polled_stop_processing(ehci_polled_t	*ehci_polledp)
{
	ehci_state_t		*ehcip;
	ehci_qh_t		*qh = ehci_polledp->ehci_polled_qh;

	ehcip = ehci_polledp->ehci_polled_ehcip;

	/* First inactive this QH */
	Set_QH(qh->qh_ctrl,
	    Get_QH(qh->qh_ctrl) | EHCI_QH_CTRL_ED_INACTIVATE);

	/* Only first leave keyboard entry turn off periodic list processing */
	if (Get_OpReg(ehci_command) & EHCI_CMD_PERIODIC_SCHED_ENABLE) {
		Set_OpReg(ehci_command, (Get_OpReg(ehci_command) &
		    ~EHCI_CMD_PERIODIC_SCHED_ENABLE));

		/* Wait for few milliseconds */
		drv_usecwait(EHCI_POLLED_TIMEWAIT);
	}
	/*
	 * Now clear all required fields of QH
	 * including inactive bit.
	 */
	Set_QH(qh->qh_ctrl,
	    Get_QH(qh->qh_ctrl) & ~(EHCI_QH_CTRL_ED_INACTIVATE));
	Set_QH(qh->qh_status,
	    Get_QH(qh->qh_status) & ~(EHCI_QH_STS_XACT_STATUS));
	Set_QH(qh->qh_curr_qtd, 0);
	Set_QH(qh->qh_alt_next_qtd, EHCI_QH_ALT_NEXT_QTD_PTR_VALID);

	/*
	 * Now look up at the QTD's that are in the active qtd list &
	 * re-insert them back into the QH's QTD list.
	 */
	(void) ehci_polled_process_active_intr_qtd_list(ehci_polledp);
}


/*
 * ehci_polled_start_processing:
 */
static void
ehci_polled_start_processing(ehci_polled_t	*ehci_polledp)
{
	ehci_state_t		*ehcip;
	uint32_t		mask;
	ehci_regs_t		*ehci_polled_regsp;

	ehcip = ehci_polledp->ehci_polled_ehcip;
	ehci_polled_regsp = &ehcip->ehci_polled_save_regs;

	mask = ((uint32_t)ehci_polled_regsp->ehci_interrupt &
	    (EHCI_INTR_HOST_SYSTEM_ERROR | EHCI_INTR_FRAME_LIST_ROLLOVER |
	    EHCI_INTR_USB_ERROR | EHCI_INTR_USB | EHCI_INTR_ASYNC_ADVANCE));

	/* Enable all required EHCI interrupts */
	Set_OpReg(ehci_interrupt, mask);

	mask = ((uint32_t)ehci_polled_regsp->ehci_command &
	    (EHCI_CMD_ASYNC_SCHED_ENABLE | EHCI_CMD_PERIODIC_SCHED_ENABLE));

	/* Enable all reuired list processing */
	Set_OpReg(ehci_command, (Get_OpReg(ehci_command) | mask));

	/* Wait for few milliseconds */
	drv_usecwait(EHCI_POLLED_TIMEWAIT);
}


/*
 * Polled read routines
 */


/*
 * ehci_polled_process_active_intr_qtd_list:
 *
 * This routine takes the QTD's off of the input done head and processes
 * them.  It returns the number of characters that have been copied for
 * input.
 */
static int
ehci_polled_process_active_intr_qtd_list(ehci_polled_t	*ehci_polledp)
{
	ehci_state_t		*ehcip = ehci_polledp->ehci_polled_ehcip;
	ehci_qtd_t		*qtd, *next_qtd;
	uint_t			num_characters = 0;
	uint_t			ctrl;
	ehci_trans_wrapper_t	*tw;
	ehci_pipe_private_t	*pp;
	usb_cr_t		error;
	int			pipe_attr, pipe_dir;

	/* Sync QH and QTD pool */
	if (ehci_polledp->ehci_polled_no_sync_flag == B_FALSE) {
		Sync_QH_QTD_Pool(ehcip);
	}

	/* Create done qtd list */
	qtd = ehci_polled_create_done_qtd_list(ehci_polledp);

	pipe_attr = ehci_polledp->ehci_polled_input_pipe_handle->
	    p_ep.bmAttributes & USB_EP_ATTR_MASK;
	pipe_dir = ehci_polledp->ehci_polled_input_pipe_handle->
	    p_ep.bEndpointAddress & USB_EP_DIR_MASK;
	/*
	 * Traverse the list of transfer descriptors.  We can't destroy
	 * the qtd_next pointers of these QTDs because we are using it
	 * to traverse the done list.  Therefore, we can not put these
	 * QTD's back on the QH until we are done processing all of them.
	 */
	while (qtd) {
		/* Get next active QTD from the active QTD list */
		next_qtd = ehci_qtd_iommu_to_cpu(ehcip,
		    Get_QTD(qtd->qtd_active_qtd_next));

		/* Obtain the transfer wrapper from the QTD */
		tw = (ehci_trans_wrapper_t *)EHCI_LOOKUP_ID(
		    (uint32_t)Get_QTD(qtd->qtd_trans_wrapper));

		/* Get ehci pipe from transfer wrapper */
		pp = tw->tw_pipe_private;

		/* Look at the status */
		ctrl = (uint_t)Get_QTD(qtd->qtd_ctrl) &
		    (uint32_t)EHCI_QTD_CTRL_XACT_STATUS;

		error = ehci_check_for_error(ehcip, pp, tw, qtd, ctrl);

		/*
		 * Check to see if there is an error. If there is error
		 * clear the halt condition in the Endpoint  Descriptor
		 * (QH) associated with this Transfer  Descriptor (QTD).
		 */
		if (error != USB_CR_OK) {
			/* Clear the halt bit */
			Set_QH(pp->pp_qh->qh_status,
			    Get_QH(pp->pp_qh->qh_status) &
			    ~(EHCI_QH_STS_XACT_STATUS));
		} else if (pipe_dir == USB_EP_DIR_IN) {

			num_characters +=
			    ehci_polled_handle_normal_qtd(ehci_polledp,
			    qtd);
		}

		/* Insert this qtd back into QH's qtd list */
		switch (pipe_attr) {
		case USB_EP_ATTR_INTR:
			ehci_polled_insert_intr_qtd(ehci_polledp, qtd);
			break;
		case USB_EP_ATTR_BULK:
			if (tw->tw_qtd_free_list != NULL) {
				uint32_t	td_addr;
				td_addr = ehci_qtd_cpu_to_iommu(ehcip,
				    tw->tw_qtd_free_list);
				Set_QTD(qtd->qtd_tw_next_qtd, td_addr);
				Set_QTD(qtd->qtd_state, EHCI_QTD_DUMMY);
				tw->tw_qtd_free_list = qtd;
			} else {
				tw->tw_qtd_free_list = qtd;
				Set_QTD(qtd->qtd_tw_next_qtd, 0);
				Set_QTD(qtd->qtd_state, EHCI_QTD_DUMMY);
			}
			break;
		}
		qtd = next_qtd;
	}

	return (num_characters);
}


/*
 * ehci_polled_handle_normal_qtd:
 */
static int
ehci_polled_handle_normal_qtd(
	ehci_polled_t		*ehci_polledp,
	ehci_qtd_t		*qtd)
{
	ehci_state_t		*ehcip = ehci_polledp->ehci_polled_ehcip;
	uchar_t			*buf;
	ehci_trans_wrapper_t	*tw;
	size_t			length;
	uint32_t		residue;

	/* Obtain the transfer wrapper from the QTD */
	tw = (ehci_trans_wrapper_t *)EHCI_LOOKUP_ID((uint32_t)
	    Get_QTD(qtd->qtd_trans_wrapper));

	ASSERT(tw != NULL);

	buf = (uchar_t *)tw->tw_buf;

	length = tw->tw_length;

	/*
	 * If "Total bytes of xfer" in control field of qtd is not equal to 0,
	 * then we received less data from the usb device than requested by us.
	 * In that case, get the actual received data size.
	 */
	residue = ((Get_QTD(qtd->qtd_ctrl) &
	    EHCI_QTD_CTRL_BYTES_TO_XFER) >> EHCI_QTD_CTRL_BYTES_TO_XFER_SHIFT);

	if (residue) {

		length = Get_QTD(qtd->qtd_xfer_offs) +
		    Get_QTD(qtd->qtd_xfer_len) - residue;
	}

	/* Sync IO buffer */
	if (ehci_polledp->ehci_polled_no_sync_flag == B_FALSE) {
		Sync_IO_Buffer(tw->tw_dmahandle, length);
	}

	/* Copy the data into the message */
	bcopy(buf, ehci_polledp->ehci_polled_buf, length);

	return ((int)length);
}


/*
 * ehci_polled_insert_intr_qtd:
 *
 * Insert a Transfer Descriptor (QTD) on an Endpoint Descriptor (QH).
 */
static void
ehci_polled_insert_intr_qtd(
	ehci_polled_t		*ehci_polledp,
	ehci_qtd_t		*qtd)
{
	ehci_state_t		*ehcip = ehci_polledp->ehci_polled_ehcip;
	ehci_qtd_t		*curr_dummy_qtd, *next_dummy_qtd;
	ehci_qtd_t		*new_dummy_qtd;
	uint_t			qtd_control;
	ehci_pipe_private_t	*pp;
	ehci_qh_t		*qh;
	ehci_trans_wrapper_t	*tw;

	/* Obtain the transfer wrapper from the QTD */
	tw = (ehci_trans_wrapper_t *)EHCI_LOOKUP_ID(
	    (uint32_t)Get_QTD(qtd->qtd_trans_wrapper));

	pp = tw->tw_pipe_private;

	/* Obtain the endpoint and interrupt request */
	qh = pp->pp_qh;

	/*
	 * Take this QTD off the transfer wrapper's list since
	 * the pipe is FIFO, this must be the first QTD on the
	 * list.
	 */
	ASSERT((ehci_qtd_t *)tw->tw_qtd_head == qtd);

	tw->tw_qtd_head = (ehci_qtd_t *)
	    ehci_qtd_iommu_to_cpu(ehcip, Get_QTD(qtd->qtd_tw_next_qtd));

	/*
	 * If the head becomes NULL, then there are no more
	 * active QTD's for this transfer wrapper. Also	set
	 * the tail to NULL.
	 */
	if (tw->tw_qtd_head == NULL) {
		tw->tw_qtd_tail = NULL;
	}

	/* Convert current valid QTD as new dummy QTD */
	bzero((char *)qtd, sizeof (ehci_qtd_t));
	Set_QTD(qtd->qtd_state, EHCI_QTD_DUMMY);

	/* Rename qtd as new_dummy_qtd */
	new_dummy_qtd = qtd;

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

	qtd_control = (tw->tw_direction | EHCI_QTD_CTRL_INTR_ON_COMPLETE);

	/*
	 * Fill in the current dummy qtd and
	 * add the new dummy to the end.
	 */
	ehci_polled_fill_in_qtd(ehcip, curr_dummy_qtd, qtd_control,
	    0, tw->tw_length, tw);

	/* Insert this qtd onto the tw */
	ehci_polled_insert_qtd_on_tw(ehcip, tw, curr_dummy_qtd);

	/* Insert this qtd into active interrupt QTD list */
	ehci_polled_insert_qtd_into_active_intr_qtd_list(
	    ehci_polledp, curr_dummy_qtd);
}


static void
ehci_polled_insert_bulk_qtd(
	ehci_polled_t	*ehci_polledp)
{
	ehci_state_t		*ehcip;
	ehci_pipe_private_t	*pp;
	ehci_trans_wrapper_t	*tw;
	ehci_qh_t		*qh;
	ehci_qtd_t		*new_dummy_qtd;
	ehci_qtd_t		*curr_dummy_qtd, *next_dummy_qtd;
	uint_t			qtd_control;

	ehcip = ehci_polledp->ehci_polled_ehcip;
	pp = (ehci_pipe_private_t *)ehci_polledp->
	    ehci_polled_input_pipe_handle->p_hcd_private;
	tw = pp->pp_tw_head;
	qh = ehci_polledp->ehci_polled_qh;
	new_dummy_qtd = tw->tw_qtd_free_list;

	if (new_dummy_qtd == NULL) {
		return;
	}

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

	qtd_control = (tw->tw_direction | EHCI_QTD_CTRL_INTR_ON_COMPLETE);

	/*
	 * Fill in the current dummy qtd and
	 * add the new dummy to the end.
	 */
	ehci_polled_fill_in_qtd(ehcip, curr_dummy_qtd, qtd_control,
	    0, tw->tw_length, tw);

	/* Insert this qtd into active interrupt QTD list */
	ehci_polled_insert_qtd_into_active_intr_qtd_list(
	    ehci_polledp, curr_dummy_qtd);
}


/*
 * ehci_polled_fill_in_qtd:
 *
 * Fill in the fields of a Transfer Descriptor (QTD).
 * The "Buffer Pointer" fields of a QTD are retrieved from the TW
 * it is associated with.
 *
 * Unlike the it's ehci_fill_in_qtd counterpart, we do not
 * set the alternative ptr in polled mode.  There is not need
 * for it in polled mode, because it doesn't need to cleanup
 * short xfer conditions.
 *
 * Note:
 * qtd_dma_offs - the starting offset into the TW buffer, where the QTD
 *		  should transfer from. It should be 4K aligned. And when
 *		  a TW has more than one QTDs, the QTDs must be filled in
 *		  increasing order.
 * qtd_length - the total bytes to transfer.
 */
static void
ehci_polled_fill_in_qtd(
	ehci_state_t		*ehcip,
	ehci_qtd_t		*qtd,
	uint_t			qtd_ctrl,
	size_t			qtd_dma_offs,
	size_t			qtd_length,
	ehci_trans_wrapper_t	*tw)
{
	uint32_t		buf_addr;
	size_t			buf_len = qtd_length;
	uint32_t		ctrl = qtd_ctrl;
	uint_t			i = 0;
	int			rem_len;

	/* Assert that the qtd to be filled in is a dummy */
	ASSERT(Get_QTD(qtd->qtd_state) == EHCI_QTD_DUMMY);

	/* Change QTD's state Active */
	Set_QTD(qtd->qtd_state, EHCI_QTD_ACTIVE);

	/* Set the total length data tarnsfer */
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
	 * For control, bulk and interrupt QTD, now
	 * enable current QTD by setting active bit.
	 */
	Set_QTD(qtd->qtd_ctrl, (ctrl | EHCI_QTD_CTRL_ACTIVE_XACT));

	Set_QTD(qtd->qtd_trans_wrapper, (uint32_t)tw->tw_id);
}


/*
 * ehci_polled_insert_qtd_on_tw:
 *
 * The transfer wrapper keeps a list of all Transfer Descriptors (QTD) that
 * are allocated for this transfer. Insert a QTD  onto this list. The  list
 * of QTD's does not include the dummy QTD that is at the end of the list of
 * QTD's for the endpoint.
 */
static void
ehci_polled_insert_qtd_on_tw(
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
 * ehci_polled_create_done_qtd_list:
 *
 * Create done qtd list from active qtd list.
 */
static ehci_qtd_t *
ehci_polled_create_done_qtd_list(
	ehci_polled_t		*ehci_polledp)
{
	ehci_state_t		*ehcip = ehci_polledp->ehci_polled_ehcip;
	ehci_qtd_t		*curr_qtd = NULL, *next_qtd = NULL;
	ehci_qtd_t		*done_qtd_list = NULL, *last_done_qtd = NULL;

	USB_DPRINTF_L4(PRINT_MASK_INTR, ehcip->ehci_log_hdl,
	    "ehci_polled_create_done_qtd_list:");

	curr_qtd = ehci_polledp->ehci_polled_active_intr_qtd_list;

	while (curr_qtd) {

		/* Get next qtd from the active qtd list */
		next_qtd = ehci_qtd_iommu_to_cpu(ehcip,
		    Get_QTD(curr_qtd->qtd_active_qtd_next));

		/* Check this QTD has been processed by Host Controller */
		if (!(Get_QTD(curr_qtd->qtd_ctrl) &
		    EHCI_QTD_CTRL_ACTIVE_XACT)) {

			/* Remove this QTD from active QTD list */
			ehci_polled_remove_qtd_from_active_intr_qtd_list(
			    ehci_polledp, curr_qtd);

			Set_QTD(curr_qtd->qtd_active_qtd_next, 0);

			if (last_done_qtd != NULL) {
				Set_QTD(last_done_qtd->qtd_active_qtd_next,
				    ehci_qtd_cpu_to_iommu(ehcip, curr_qtd));
			} else {
				done_qtd_list = curr_qtd;
			}
			last_done_qtd = curr_qtd;
		}

		curr_qtd = next_qtd;
	}

	return (done_qtd_list);
}


/*
 * ehci_polled_insert_qtd_into_active_intr_qtd_list:
 *
 * Insert current QTD into active interrupt QTD list.
 */
static void
ehci_polled_insert_qtd_into_active_intr_qtd_list(
	ehci_polled_t		*ehci_polledp,
	ehci_qtd_t		*qtd)
{
	ehci_state_t		*ehcip = ehci_polledp->ehci_polled_ehcip;
	ehci_qtd_t		*curr_qtd, *next_qtd;

	curr_qtd = ehci_polledp->ehci_polled_active_intr_qtd_list;

	/* Insert this qtd into active intr qtd list */
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
		ehci_polledp->ehci_polled_active_intr_qtd_list = qtd;
		Set_QTD(qtd->qtd_active_qtd_next, 0);
		Set_QTD(qtd->qtd_active_qtd_prev, 0);
	}
}


/*
 * ehci_polled_remove_qtd_from_active_intr_qtd_list:
 *
 * Remove current QTD from the active QTD list.
 */
void
ehci_polled_remove_qtd_from_active_intr_qtd_list(
	ehci_polled_t		*ehci_polledp,
	ehci_qtd_t		*qtd)
{
	ehci_state_t		*ehcip = ehci_polledp->ehci_polled_ehcip;
	ehci_qtd_t		*curr_qtd, *prev_qtd, *next_qtd;

	ASSERT(qtd != NULL);

	curr_qtd = ehci_polledp->ehci_polled_active_intr_qtd_list;

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
			ehci_polledp->
			    ehci_polled_active_intr_qtd_list = next_qtd;
		}

		if (next_qtd) {
			Set_QTD(next_qtd->qtd_active_qtd_prev,
			    Get_QTD(curr_qtd->qtd_active_qtd_prev));
		}
	}
}


/*
 * ehci_polled_traverse_qtds:
 *
 * Traverse the list of QTDs for given pipe using transfer wrapper.  Since
 * the endpoint is marked as Halted, the Host Controller (HC) is no longer
 * accessing these QTDs. Remove all the QTDs that are attached to endpoint.
 */
static void
ehci_polled_traverse_qtds(
	ehci_polled_t		*ehci_polledp,
	usba_pipe_handle_data_t	*ph)
{
	ehci_state_t		*ehcip = ehci_polledp->ehci_polled_ehcip;
	ehci_pipe_private_t	*pp = (ehci_pipe_private_t *)ph->p_hcd_private;
	ehci_trans_wrapper_t	*next_tw;
	ehci_qtd_t		*qtd;
	ehci_qtd_t		*next_qtd;

	/* Process the transfer wrappers for this pipe */
	next_tw = pp->pp_tw_head;

	while (next_tw) {
		qtd = (ehci_qtd_t *)next_tw->tw_qtd_head;

		/* Walk through each QTD for this transfer wrapper */
		while (qtd) {
			/* Remove this QTD from active QTD list */
			ehci_polled_remove_qtd_from_active_intr_qtd_list(
			    ehci_polledp, qtd);

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
 * ehci_polled_finish_interrupt:
 */
static void
ehci_polled_finish_interrupt(
	ehci_state_t	*ehcip,
	uint_t		intr)
{
	/* Acknowledge the interrupt */
	Set_OpReg(ehci_status, intr);

	/*
	 * Read interrupt status register to make sure that any PIO
	 * store to clear the ISR has made it on the PCI bus before
	 * returning from its interrupt handler.
	 */
	(void) Get_OpReg(ehci_status);
}


static int
ehci_polled_create_tw(
	ehci_polled_t	*ehci_polledp,
	usba_pipe_handle_data_t	*ph,
	usb_flags_t	usb_flags)
{
	uint_t			ccount;
	size_t			real_length;
	ehci_trans_wrapper_t	*tw;
	ddi_device_acc_attr_t	dev_attr;
	int			result, pipe_dir, qtd_count;
	ehci_state_t		*ehcip;
	ehci_pipe_private_t	*pp;
	ddi_dma_attr_t		dma_attr;

	ehcip = ehci_polledp->ehci_polled_ehcip;
	pp = (ehci_pipe_private_t *)ph->p_hcd_private;

	/* Get the required qtd counts */
	qtd_count = (POLLED_RAW_BUF_SIZE - 1) / EHCI_MAX_QTD_XFER_SIZE + 1;

	if ((tw = kmem_zalloc(sizeof (ehci_trans_wrapper_t),
	    KM_NOSLEEP)) == NULL) {
		return (USB_FAILURE);
	}

	/* allow sg lists for transfer wrapper dma memory */
	bcopy(&ehcip->ehci_dma_attr, &dma_attr, sizeof (ddi_dma_attr_t));
	dma_attr.dma_attr_sgllen = EHCI_DMA_ATTR_TW_SGLLEN;
	dma_attr.dma_attr_align = EHCI_DMA_ATTR_ALIGNMENT;

	/* Allocate the DMA handle */
	if ((result = ddi_dma_alloc_handle(ehcip->ehci_dip,
	    &dma_attr, DDI_DMA_DONTWAIT, 0, &tw->tw_dmahandle)) !=
	    DDI_SUCCESS) {
		kmem_free(tw, sizeof (ehci_trans_wrapper_t));

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
		kmem_free(tw, sizeof (ehci_trans_wrapper_t));

		return (USB_FAILURE);
	}

	/* Bind the handle */
	if ((result = ddi_dma_addr_bind_handle(tw->tw_dmahandle, NULL,
	    tw->tw_buf, real_length, DDI_DMA_RDWR|DDI_DMA_CONSISTENT,
	    DDI_DMA_DONTWAIT, NULL, &tw->tw_cookie, &ccount)) !=
	    DDI_DMA_MAPPED) {
		ddi_dma_mem_free(&tw->tw_accesshandle);
		ddi_dma_free_handle(&tw->tw_dmahandle);
		kmem_free(tw, sizeof (ehci_trans_wrapper_t));

		return (USB_FAILURE);
	}

	/* The cookie count should be 1 */
	if (ccount != 1) {
		result = ddi_dma_unbind_handle(tw->tw_dmahandle);
		ASSERT(result == DDI_SUCCESS);

		ddi_dma_mem_free(&tw->tw_accesshandle);
		ddi_dma_free_handle(&tw->tw_dmahandle);
		kmem_free(tw, sizeof (ehci_trans_wrapper_t));

		return (USB_FAILURE);
	}

	if (ehci_allocate_tds_for_tw(ehcip, pp, tw, qtd_count) == USB_SUCCESS) {
		tw->tw_num_qtds = qtd_count;
	} else {
		ehci_deallocate_tw(ehcip, pp, tw);
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
	tw->tw_id = EHCI_GET_ID((void *)tw);

	pipe_dir = ph->p_ep.bEndpointAddress & USB_EP_DIR_MASK;
	tw->tw_direction = (pipe_dir == USB_EP_DIR_OUT)?
	    EHCI_QTD_CTRL_OUT_PID : EHCI_QTD_CTRL_IN_PID;

	USB_DPRINTF_L4(PRINT_MASK_ALLOC, ehcip->ehci_log_hdl,
	    "ehci_create_transfer_wrapper: tw = 0x%p, ncookies = %u",
	    (void *)tw, tw->tw_ncookies);

	return (USB_SUCCESS);
}


/*
 * ehci_polled_insert_async_qh:
 *
 * Insert a bulk endpoint into the Host Controller's (HC)
 * Asynchronous schedule endpoint list.
 */
static void
ehci_polled_insert_async_qh(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp)
{
	ehci_qh_t		*qh = pp->pp_qh;
	ehci_qh_t		*async_head_qh;
	ehci_qh_t		*next_qh;
	uintptr_t		qh_addr;

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
 * ehci_remove_async_qh:
 *
 * Remove a control/bulk endpoint into the Host Controller's (HC)
 * Asynchronous schedule endpoint list.
 */
static void
ehci_polled_remove_async_qh(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp)
{
	ehci_qh_t		*qh = pp->pp_qh; /* qh to be removed */
	ehci_qh_t		*prev_qh, *next_qh;

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

}
