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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * This module contains the specific uhci code used in POLLED mode.
 */
#include <sys/usb/hcd/uhci/uhcid.h>
#include <sys/usb/hcd/uhci/uhcipolled.h>

#ifndef __sparc
extern void invalidate_cache();
#endif
/*
 * Internal Function Prototypes
 */
/* Polled initialization routine */
static int	uhci_polled_init(usba_pipe_handle_data_t *, uhci_state_t *,
		    usb_console_info_impl_t *);

/* Polled fini routine */
static int	uhci_polled_fini(uhci_polled_t *, uhci_state_t *);

/* Polled save state routine */
static void	uhci_polled_save_state(uhci_polled_t *);

/* Polled restore state routine */
static void	uhci_polled_restore_state(uhci_polled_t *);

/* Polled read routines */
static int	uhci_polled_insert_td_on_qh(uhci_polled_t *,
		    usba_pipe_handle_data_t *);
static uhci_trans_wrapper_t
		*uhci_polled_create_tw(uhci_state_t *);


/*
 * POLLED entry points
 *
 * These functions are entry points into the POLLED code.
 */

/*
 * uhci_hcdi_polled_input_init:
 *	This is the initialization routine for handling the USB keyboard
 *	in POLLED mode.  This routine is not called from POLLED mode, so
 *	it is OK to acquire mutexes.
 */
int
uhci_hcdi_polled_input_init(usba_pipe_handle_data_t *ph,
	uchar_t			**polled_buf,
	usb_console_info_impl_t *console_input_info)
{
	int		ret;
	uhci_polled_t	*uhci_polledp;
	uhci_state_t	*uhcip;

	uhcip = uhci_obtain_state(ph->p_usba_device->usb_root_hub_dip);

	/*
	 * Grab the uhci_int_mutex so that things don't change on us
	 * if an interrupt comes in.
	 */
	mutex_enter(&uhcip->uhci_int_mutex);
	ret = uhci_polled_init(ph, uhcip, console_input_info);
	if (ret != USB_SUCCESS) {
		mutex_exit(&uhcip->uhci_int_mutex);

		return (ret);
	}

	uhci_polledp = (uhci_polled_t *)console_input_info->uci_private;
	/*
	 * Mark the structure so that if we are using it, we don't free
	 * the structures if one of them is unplugged.
	 */
	uhci_polledp->uhci_polled_flags |= POLLED_INPUT_MODE;

	/*
	 * This is the buffer we will copy characters into. It will be
	 * copied into at this layer, so we need to keep track of it.
	 */
	uhci_polledp->uhci_polled_buf =
	    (uchar_t *)kmem_zalloc(POLLED_RAW_BUF_SIZE, KM_SLEEP);

	*polled_buf = uhci_polledp->uhci_polled_buf;

	mutex_exit(&uhcip->uhci_int_mutex);
	return (USB_SUCCESS);
}


/*
 * uhci_hcdi_polled_input_fini:
 */
int
uhci_hcdi_polled_input_fini(usb_console_info_impl_t *info)
{
	int			ret;
	uhci_state_t		*uhcip;
	uhci_polled_t		*uhci_polledp;

	uhci_polledp = (uhci_polled_t *)info->uci_private;
	uhcip = uhci_polledp->uhci_polled_uhcip;
	mutex_enter(&uhcip->uhci_int_mutex);

	/* Free the buffer that we copied data into */
	kmem_free(uhci_polledp->uhci_polled_buf, POLLED_RAW_BUF_SIZE);
	ret = uhci_polled_fini(uhci_polledp, uhcip);
	info->uci_private = NULL;
	mutex_exit(&uhcip->uhci_int_mutex);

	return (ret);
}


/*
 * uhci_hcdi_polled_input_enter:
 *	This is where we enter into POLLED mode.  This routine sets up
 *	everything so that calls to  uhci_hcdi_polled_read will return
 *	characters.
 */
int
uhci_hcdi_polled_input_enter(usb_console_info_impl_t *info)
{
	uhci_polled_t	*uhci_polledp;

	uhci_polledp = (uhci_polled_t *)info->uci_private;
	uhci_polledp->uhci_polled_entry++;

	/*
	 * If the controller is already switched over, just return
	 */
	if (uhci_polledp->uhci_polled_entry > 1) {

		return (USB_SUCCESS);
	}

	uhci_polled_save_state(uhci_polledp);
	uhci_polledp->uhci_polled_flags |= POLLED_INPUT_MODE_INUSE;

	return (USB_SUCCESS);
}


/*
 * uhci_hcdi_polled_input_exit:
 *	This is where we exit POLLED mode. This routine restores
 *	everything that is needed to continue operation.
 */
int
uhci_hcdi_polled_input_exit(usb_console_info_impl_t *info)
{
	uhci_polled_t	*uhci_polledp;

	uhci_polledp = (uhci_polled_t *)info->uci_private;
	uhci_polledp->uhci_polled_entry--;

	/*
	 * If there are still outstanding "enters", just return
	 */
	if (uhci_polledp->uhci_polled_entry > 0) {

		return (USB_SUCCESS);
	}

	uhci_polledp->uhci_polled_flags &= ~POLLED_INPUT_MODE_INUSE;
	uhci_polled_restore_state(uhci_polledp);

	return (USB_SUCCESS);
}


/*
 * uhci_hcdi_polled_read:
 *	Get a key character
 */
int
uhci_hcdi_polled_read(usb_console_info_impl_t *info, uint_t *num_characters)
{
	uhci_state_t		*uhcip;
	uhci_polled_t		*uhci_polledp;
	uhci_td_t		*td;
	uhci_trans_wrapper_t	*tw;
	ushort_t		intr_status;

	uhci_polledp = (uhci_polled_t *)info->uci_private;
	uhcip = uhci_polledp->uhci_polled_uhcip;

	/*
	 * This is a temporary work around for halt problem. The upper
	 * layer code does not call the right sequence of entry points
	 * points for reading a character in a polled mode. Once the
	 * upper layer code is fixed, the following code (two lines)
	 * must be removed.
	 */
	if (uhci_polledp->uhci_polled_entry == 0) {
		if (uhci_hcdi_polled_input_enter(info) != USB_SUCCESS) {
			cmn_err(CE_WARN, "Entering Polled Mode failed");
		}
	}

#ifndef lint
	_NOTE(NO_COMPETING_THREADS_NOW);
#endif
#ifndef __sparc
	invalidate_cache();
#endif

	td = uhci_polledp->uhci_polled_td;

	/*
	 * Check to see if there are any TD's on the done head.
	 */
	if (GetTD_status(uhcip, td) & UHCI_TD_ACTIVE) {
		*num_characters = 0;
	} else {

		/*
		 * If the TD does not complete, retry.
		 */
		if ((GetTD_status(uhcip, td) & TD_STATUS_MASK) ||
		    (GetTD_alen(uhcip, td) == ZERO_LENGTH)) {
			*num_characters = 0;
			SetTD_alen(uhcip, td, 0);
		} else {
			*num_characters = GetTD_alen(uhcip, td) + 1;

			tw = td->tw;

			/* Copy the data into the message */
			ddi_rep_get8(tw->tw_accesshandle,
			    (uint8_t *)uhci_polledp->uhci_polled_buf,
			    (uint8_t *)td->tw->tw_buf,
			    *num_characters, DDI_DEV_AUTOINCR);
		}

		/*
		 * Insert the td again into the lattice.
		 */
		SetTD_dtogg(uhcip, td, GetTD_dtogg(uhcip, td) == 0 ? 1 : 0);

		SetTD_status(uhcip, td, UHCI_TD_ACTIVE);
		SetQH32(uhcip, uhci_polledp->uhci_polled_qh->element_ptr,
		    TD_PADDR(td));

		/* Clear the interrupt status register */
		intr_status = Get_OpReg16(USBSTS);
		Set_OpReg16(USBSTS, intr_status);
	}

#ifndef lint
	_NOTE(COMPETING_THREADS_NOW);
#endif

	return (USB_SUCCESS);
}

/*
 * uhci_hcdi_polled_output_init:
 *	This is the initialization routine for handling the USB serial
 *	output in POLLED mode.  This routine is called after input_init
 *	succeeded.
 */
int
uhci_hcdi_polled_output_init(usba_pipe_handle_data_t *ph,
	usb_console_info_impl_t *console_output_info)
{
	int		ret;
	uhci_polled_t	*uhci_polledp;
	uhci_state_t	*uhcip;

	uhcip = uhci_obtain_state(ph->p_usba_device->usb_root_hub_dip);

	/*
	 * Grab the uhci_int_mutex so that things don't change on us
	 * if an interrupt comes in.
	 */
	mutex_enter(&uhcip->uhci_int_mutex);
	ret = uhci_polled_init(ph, uhcip, console_output_info);
	if (ret != USB_SUCCESS) {
		mutex_exit(&uhcip->uhci_int_mutex);

		return (ret);
	}

	uhci_polledp = (uhci_polled_t *)console_output_info->uci_private;
	/*
	 * Mark the structure so that if we are using it, we don't free
	 * the structures if one of them is unplugged.
	 */
	uhci_polledp->uhci_polled_flags |= POLLED_OUTPUT_MODE;

	mutex_exit(&uhcip->uhci_int_mutex);

	return (USB_SUCCESS);
}


/*
 * uhci_hcdi_polled_output_fini:
 */
int
uhci_hcdi_polled_output_fini(usb_console_info_impl_t *info)
{
	int			ret;
	uhci_state_t		*uhcip;
	uhci_polled_t		*uhci_polledp;

	uhci_polledp = (uhci_polled_t *)info->uci_private;
	uhcip = uhci_polledp->uhci_polled_uhcip;
	mutex_enter(&uhcip->uhci_int_mutex);

	ret = uhci_polled_fini(uhci_polledp, uhcip);
	info->uci_private = NULL;
	mutex_exit(&uhcip->uhci_int_mutex);

	return (ret);
}


/*
 * uhci_hcdi_polled_output_enter:
 *	everything is done in input enter
 */
int
uhci_hcdi_polled_output_enter(usb_console_info_impl_t *info)
{
	uhci_state_t		*uhcip;
	uhci_polled_t		*uhci_polledp;

	uhci_polledp = (uhci_polled_t *)info->uci_private;
	uhcip = uhci_polledp->uhci_polled_uhcip;

	/*
	 * Check if the number of devices reaches the max number
	 * we can support in polled mode
	 */
	if (uhcip->uhci_polled_count + 1 > MAX_NUM_FOR_KEYBORAD) {

		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}


/*
 * uhci_hcdi_polled_output_exit:
 *	everything is done in input exit
 */
/*ARGSUSED*/
int
uhci_hcdi_polled_output_exit(usb_console_info_impl_t *info)
{
	return (USB_SUCCESS);
}

/*
 * uhci_hcdi_polled_write:
 *	Put a key character -- rewrite this!
 */
int
uhci_hcdi_polled_write(usb_console_info_impl_t *info, uchar_t *buf,
    uint_t num_characters, uint_t *num_characters_written)
{
	int			i;
	uhci_state_t		*uhcip;
	uhci_polled_t		*uhci_polledp;
	uhci_td_t		*td;
	uhci_trans_wrapper_t	*tw;
	uhci_pipe_private_t	*pp;
	usba_pipe_handle_data_t	*ph;

#ifndef lint
	_NOTE(NO_COMPETING_THREADS_NOW);
#endif

	uhci_polledp = (uhci_polled_t *)info->uci_private;
	uhcip = uhci_polledp->uhci_polled_uhcip;
	ph = uhci_polledp->uhci_polled_ph;
	pp = (uhci_pipe_private_t *)ph->p_hcd_private;

	td = uhci_polledp->uhci_polled_td;
	tw = td->tw;

	/* copy transmit buffer */
	if (num_characters > POLLED_RAW_BUF_SIZE) {
		cmn_err(CE_NOTE, "polled write size %d bigger than %d",
		    num_characters, POLLED_RAW_BUF_SIZE);
		num_characters = POLLED_RAW_BUF_SIZE;
	}
	tw->tw_length = num_characters;
	ddi_put8(tw->tw_accesshandle, (uint8_t *)tw->tw_buf, *buf);
	ddi_rep_put8(tw->tw_accesshandle, buf, (uint8_t *)tw->tw_buf,
	    num_characters, DDI_DEV_AUTOINCR);

	bzero((char *)td, sizeof (uhci_td_t));

	td->tw = tw;
	SetTD_c_err(uhcip, td, UHCI_MAX_ERR_COUNT);
	SetTD_status(uhcip, td, UHCI_TD_ACTIVE);
	SetTD_ioc(uhcip, td, INTERRUPT_ON_COMPLETION);
	SetTD_mlen(uhcip, td, num_characters - 1);
	SetTD_dtogg(uhcip, td, pp->pp_data_toggle);
	ADJ_DATA_TOGGLE(pp);
	SetTD_devaddr(uhcip, td, ph->p_usba_device->usb_addr);
	SetTD_endpt(uhcip, td, ph->p_ep.bEndpointAddress &
	    END_POINT_ADDRESS_MASK);
	SetTD_PID(uhcip, td, PID_OUT);
	SetTD32(uhcip, td->buffer_address, tw->tw_cookie.dmac_address);

	SetQH32(uhcip, uhci_polledp->uhci_polled_qh->element_ptr,
	    TD_PADDR(td));

	/*
	 * Now, add the endpoint to the lattice that we will hang  our
	 * TD's off of.
	 */
	for (i = uhcip->uhci_polled_count; i < NUM_FRAME_LST_ENTRIES;
	    i += MIN_LOW_SPEED_POLL_INTERVAL) {
		SetFL32(uhcip, uhcip->uhci_frame_lst_tablep[i],
		    QH_PADDR(uhci_polledp->uhci_polled_qh) | HC_QUEUE_HEAD);
	}

	/* wait for xfer to finish */
	while (GetTD_status(uhcip, td) & UHCI_TD_ACTIVE)
#ifndef __sparc
		invalidate_cache();
#else
		;
#endif
	*num_characters_written = GetTD_alen(uhcip, td) + 1;

	/* Now, remove the endpoint from the lattice */
	for (i = uhcip->uhci_polled_count; i < NUM_FRAME_LST_ENTRIES;
	    i += MIN_LOW_SPEED_POLL_INTERVAL) {
		SetFL32(uhcip, uhcip->uhci_frame_lst_tablep[i],
		    HC_END_OF_LIST);
	}

#ifndef lint
	_NOTE(COMPETING_THREADS_NOW);
#endif

	return (USB_SUCCESS);
}


/*
 * uhci_polled_init:
 *	Initialize generic information that is needed to provide USB/POLLED
 *	support.
 */
static int
uhci_polled_init(usba_pipe_handle_data_t	*ph,
	uhci_state_t		*uhcip,
	usb_console_info_impl_t	*console_info)
{
	uhci_polled_t	*uhci_polledp;

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	/*
	 * If the structure has already been initialized, then we don't
	 * need to redo it.
	 */
	if (console_info->uci_private != NULL) {

		return (USB_SUCCESS);
	}

	/* Allocate and intitialize a polled mode state structure */
	uhci_polledp = (uhci_polled_t *)kmem_zalloc(sizeof (uhci_polled_t),
	    KM_SLEEP);

	/*
	 * Keep a copy of normal mode state structure and pipe handle.
	 */
	uhci_polledp->uhci_polled_uhcip	= uhcip;
	uhci_polledp->uhci_polled_ph	= ph;

	/*
	 * Allocate a queue head for the device. This queue head wiil be
	 * put in action when we switch to polled mode in _enter point.
	 */
	uhci_polledp->uhci_polled_qh = uhci_alloc_queue_head(uhcip);

	if (uhci_polledp->uhci_polled_qh == NULL) {
		kmem_free(uhci_polledp, sizeof (uhci_polled_t));

		return (USB_NO_RESOURCES);
	}

	/*
	 * Insert a TD onto the queue head.
	 */
	if ((uhci_polled_insert_td_on_qh(uhci_polledp,
	    uhci_polledp->uhci_polled_ph)) != USB_SUCCESS) {
		uhci_polledp->uhci_polled_qh->qh_flag = QUEUE_HEAD_FLAG_FREE;
		kmem_free(uhci_polledp, sizeof (uhci_polled_t));

		return (USB_NO_RESOURCES);
	}

	console_info->uci_private = (usb_console_info_private_t)uhci_polledp;

	return (USB_SUCCESS);
}


/*
 * uhci_polled_fini:
 */
static int
uhci_polled_fini(uhci_polled_t *uhci_polledp, uhci_state_t *uhcip)
{
	uhci_td_t	*td = uhci_polledp->uhci_polled_td;

	ASSERT(mutex_owned(&uhcip->uhci_int_mutex));

	/*
	 * Free the transfer wrapper
	 */
	uhci_free_tw(uhcip, td->tw);

	/*
	 * Free the queue head and transfer descriptor allocated.
	 */
	uhci_polledp->uhci_polled_qh->qh_flag = QUEUE_HEAD_FLAG_FREE;
	uhci_polledp->uhci_polled_td->flag = TD_FLAG_FREE;

	/*
	 * Deallocate the memory for the polled mode state structure.
	 */
	kmem_free(uhci_polledp, sizeof (uhci_polled_t));

	return (USB_SUCCESS);
}


/*
 * uhci_polled_save_state:
 */
static void
uhci_polled_save_state(uhci_polled_t	*uhci_polledp)
{
	int			i;
	uhci_td_t		*td, *polled_td;
	uhci_state_t		*uhcip;
	usba_pipe_handle_data_t	*ph;

#ifndef lint
	_NOTE(NO_COMPETING_THREADS_NOW);
#endif

	/*
	 * If either of these two flags are set, then we have already
	 * saved off the state information and setup the controller.
	 */
	if (uhci_polledp->uhci_polled_flags & POLLED_INPUT_MODE_INUSE) {
#ifndef lint
		_NOTE(COMPETING_THREADS_NOW);
#endif

		return;
	}

	uhcip = uhci_polledp->uhci_polled_uhcip;

	/*
	 * Check if the number of keyboard reaches the max number we can
	 * support in polled mode
	 */
	if (++ uhcip->uhci_polled_count > MAX_NUM_FOR_KEYBORAD) {
#ifndef lint
		_NOTE(COMPETING_THREADS_NOW);
#endif
		return;
	}

	/*
	 * Get the normal mode usb pipe handle.
	 */
	ph = (usba_pipe_handle_data_t *)uhci_polledp->uhci_polled_ph;
	/*
	 * Only the first keyboard enter disable the interrutps, stop the
	 * host controller processing and initialize the interrupt table.
	 */
	if (uhcip->uhci_polled_count == 1) {
		/*
		 * Disable interrupts to prevent the interrupt handler getting
		 * called while we are switing to POLLed mode.
		 */

		Set_OpReg16(USBINTR, DISABLE_ALL_INTRS);

		/*
		 * Stop the HC controller from processing TD's
		 */
		Set_OpReg16(USBCMD, 0);

		/*
		 * Save the current interrupt lattice and  replace this lattice
		 * with an lattice used in POLLED mode. We will restore lattice
		 * back when we exit from the POLLED mode.
		 */
		for (i = 0; i < NUM_FRAME_LST_ENTRIES; i++) {
			uhcip->uhci_polled_save_IntTble[i] =
			    uhcip->uhci_frame_lst_tablep[i];
		}

		/*
		 * Zero out the entire interrupt lattice tree.
		 */
		for (i = 0; i < NUM_FRAME_LST_ENTRIES; i++) {
			SetFL32(uhcip, uhcip->uhci_frame_lst_tablep[i],
			    HC_END_OF_LIST);
		}
	}

	/*
	 * Now, add the endpoint to the lattice that we will hang  our
	 * TD's off of.  We (assume always) need to poll this device at
	 * every 8 ms.
	 */
	for (i = uhcip->uhci_polled_count - 1; i < NUM_FRAME_LST_ENTRIES;
	    i += MIN_LOW_SPEED_POLL_INTERVAL) {
		SetFL32(uhcip, uhcip->uhci_frame_lst_tablep[i],
		    QH_PADDR(uhci_polledp->uhci_polled_qh) | HC_QUEUE_HEAD);
	}

	/*
	 * Adjust the data toggle
	 */
	td = uhcip->uhci_outst_tds_head;
	while (td != NULL) {
		if (td->tw->tw_pipe_private->pp_pipe_handle == ph) {
			polled_td = uhci_polledp->uhci_polled_td;
			if (GetTD_status(uhcip, td) & UHCI_TD_ACTIVE) {
				SetTD_dtogg(uhcip, polled_td,
				    GetTD_dtogg(uhcip, td));
			} else {
				SetTD_dtogg(uhcip, polled_td,
				    (GetTD_dtogg(uhcip, td) ^ 1));
				uhcip->uhci_polled_flag =
				    UHCI_POLLED_FLAG_TD_COMPL;
			}
			break;
		}
		td = td->outst_td_next;
	}
	/*
	 * Only the first keyboard enter reset the frame number and start
	 * the host controler processing.
	 */
	if (uhcip->uhci_polled_count == 1) {
		/* Set the frame number to zero */
		Set_OpReg16(FRNUM, 0);

		/*
		 * Start the Host controller processing
		 */
		Set_OpReg16(USBCMD, (USBCMD_REG_HC_RUN | USBCMD_REG_MAXPKT_64 |
		    USBCMD_REG_CONFIG_FLAG));
	}

#ifndef lint
	_NOTE(COMPETING_THREADS_NOW);
#endif
}


/*
 * uhci_polled_restore_state:
 */
static void
uhci_polled_restore_state(uhci_polled_t	*uhci_polledp)
{
	int			i;
	ushort_t		real_data_toggle;
	uhci_td_t		*td, *polled_td;
	uhci_state_t		*uhcip;
	uhci_pipe_private_t	*pp;

#ifndef lint
	_NOTE(NO_COMPETING_THREADS_NOW);
#endif
	/*
	 * If this flags is set, then we are still using this structure,
	 * so don't restore any controller state information yet.
	 */
	if (uhci_polledp->uhci_polled_flags & POLLED_INPUT_MODE_INUSE) {
#ifndef lint
		_NOTE(COMPETING_THREADS_NOW);
#endif
		return;
	}

	uhcip = uhci_polledp->uhci_polled_uhcip;
	uhcip->uhci_polled_count --;

	/* Just first leave keyboard entry turn off the controller */
	if (Get_OpReg16(USBCMD)) {
		Set_OpReg16(USBCMD, 0x0);
	}
	/* Only the last leave keyboard entry restore the interrupt table */
	if (uhcip->uhci_polled_count == 0) {
		/*
		 * Replace the lattice
		 */
		for (i = 0; i < NUM_FRAME_LST_ENTRIES; i++) {
			uhcip->uhci_frame_lst_tablep[i] =
			    uhcip->uhci_polled_save_IntTble[i];
		}
	}

	/*
	 * Adjust data toggle
	 */
	pp = (uhci_pipe_private_t *)
	    uhci_polledp->uhci_polled_ph->p_hcd_private;

	polled_td = uhci_polledp->uhci_polled_td;
	real_data_toggle = (GetTD_status(uhcip, polled_td) & UHCI_TD_ACTIVE) ?
	    GetTD_dtogg(uhcip, polled_td) :
	    !GetTD_dtogg(uhcip, polled_td);

	td = uhcip->uhci_outst_tds_head;
	while (td != NULL) {
		if (td->tw->tw_pipe_private->pp_pipe_handle ==
		    uhci_polledp->uhci_polled_ph) {
			if (GetTD_status(uhcip, td) & UHCI_TD_ACTIVE) {
				SetTD_dtogg(uhcip, td, real_data_toggle);
				pp->pp_data_toggle =
				    (real_data_toggle == 0) ? 1 : 0;
			} else {
				pp->pp_data_toggle = (uchar_t)real_data_toggle;
			}
		}
		td = td->outst_td_next;
	}

	/*
	 * Only the last leave keyboard entry enable the interrupts,
	 * start Host controller processing.
	 */
	if (uhcip->uhci_polled_count == 0) {
		Set_OpReg16(USBINTR, ENABLE_ALL_INTRS);
		Set_OpReg16(USBCMD, (USBCMD_REG_HC_RUN | USBCMD_REG_MAXPKT_64 |
		    USBCMD_REG_CONFIG_FLAG));
		if (uhcip->uhci_polled_flag == UHCI_POLLED_FLAG_TD_COMPL) {
			uhcip->uhci_polled_flag = UHCI_POLLED_FLAG_TRUE;
		}
	}

#ifndef lint
	_NOTE(COMPETING_THREADS_NOW);
#endif
}


/*
 * uhci_polled_insert_td:
 *	Initializes the transfer descriptor for polling and inserts on the
 *	polled queue head. This will be put in action when entered in to
 *	polled mode.
 */
static int
uhci_polled_insert_td_on_qh(uhci_polled_t *uhci_polledp,
	usba_pipe_handle_data_t *ph)
{
	uhci_td_t		*td;
	uhci_state_t		*uhcip = uhci_polledp->uhci_polled_uhcip;
	usb_ep_descr_t		*eptd;
	uhci_trans_wrapper_t	*tw;
	uint_t			direction;

	/* Create the transfer wrapper */
	if ((tw = uhci_polled_create_tw(uhci_polledp->uhci_polled_uhcip)) ==
	    NULL) {

		return (USB_FAILURE);
	}

	/* Use the dummy TD allocated for the queue head */
	td = uhci_polledp->uhci_polled_qh->td_tailp;
	bzero((char *)td, sizeof (uhci_td_t));

	uhci_polledp->uhci_polled_td = td;
	td->tw = tw;
	td->flag = TD_FLAG_BUSY;
	SetTD32(uhcip, td->link_ptr, HC_END_OF_LIST);

	mutex_enter(&ph->p_usba_device->usb_mutex);
	if (ph->p_usba_device->usb_port_status == USBA_LOW_SPEED_DEV) {
		SetTD_ls(uhcip, td, LOW_SPEED_DEVICE);
	}

	eptd = &ph->p_ep;
	direction = (UHCI_XFER_DIR(eptd) == USB_EP_DIR_OUT) ? PID_OUT : PID_IN;
	SetTD_c_err(uhcip, td, UHCI_MAX_ERR_COUNT);
	SetTD_mlen(uhcip, td, POLLED_RAW_BUF_SIZE - 1);
	SetTD_devaddr(uhcip, td, ph->p_usba_device->usb_addr);
	SetTD_endpt(uhcip, td, eptd->bEndpointAddress & END_POINT_ADDRESS_MASK);
	SetTD_PID(uhcip, td, direction);
	SetTD32(uhcip, td->buffer_address, tw->tw_cookie.dmac_address);
	SetTD_ioc(uhcip, td, INTERRUPT_ON_COMPLETION);
	SetTD_status(uhcip, td, UHCI_TD_ACTIVE);
	mutex_exit(&ph->p_usba_device->usb_mutex);

	SetQH32(uhcip, uhci_polledp->uhci_polled_qh->element_ptr, TD_PADDR(td));

	return (USB_SUCCESS);
}


/*
 * uhci_polled_create_wrapper_t:
 *	Creates the transfer wrapper used in polled mode.
 */
static uhci_trans_wrapper_t *
uhci_polled_create_tw(uhci_state_t *uhcip)
{
	uint_t			result, ccount;
	size_t			real_length;
	uhci_trans_wrapper_t	*tw;
	ddi_device_acc_attr_t	dev_attr;

	/* Allocate space for the transfer wrapper */
	if ((tw = kmem_zalloc(sizeof (uhci_trans_wrapper_t), KM_NOSLEEP)) ==
	    NULL) {

		return (NULL);
	}

	tw->tw_length = POLLED_RAW_BUF_SIZE;

	/* Allocate the DMA handle */
	if ((result = ddi_dma_alloc_handle(uhcip->uhci_dip,
	    &uhcip->uhci_dma_attr, DDI_DMA_DONTWAIT, 0, &tw->tw_dmahandle)) !=
	    DDI_SUCCESS) {
		kmem_free(tw, sizeof (uhci_trans_wrapper_t));

		return (NULL);
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
		kmem_free(tw, sizeof (uhci_trans_wrapper_t));

		return (NULL);
	}

	/* Bind the handle */
	if ((result = ddi_dma_addr_bind_handle(tw->tw_dmahandle, NULL,
	    tw->tw_buf, real_length, DDI_DMA_RDWR|DDI_DMA_CONSISTENT,
	    DDI_DMA_DONTWAIT, NULL, &tw->tw_cookie, &ccount)) !=
	    DDI_DMA_MAPPED) {
		ddi_dma_mem_free(&tw->tw_accesshandle);
		ddi_dma_free_handle(&tw->tw_dmahandle);
		kmem_free(tw, sizeof (uhci_trans_wrapper_t));

		return (NULL);
	}

	/* The cookie count should be 1 */
	if (ccount != 1) {
		result = ddi_dma_unbind_handle(tw->tw_dmahandle);
		ASSERT(result == DDI_SUCCESS);

		ddi_dma_mem_free(&tw->tw_accesshandle);
		ddi_dma_free_handle(&tw->tw_dmahandle);
		kmem_free(tw, sizeof (uhci_trans_wrapper_t));

		return (NULL);
	}

	return (tw);
}
