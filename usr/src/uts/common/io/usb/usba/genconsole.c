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
 * Copyright 2019, Joyent, Inc.
 */

/*
 * USBA: Solaris USB Architecture support
 *
 * ISSUES:
 */
#define	USBA_FRAMEWORK
#include <sys/usb/usba.h>
#include <sys/usb/usba/hcdi.h>
#include <sys/usb/usba/genconsole.h>
#include <sys/usb/usba/usba_types.h>
#include <sys/usb/usba/usba_impl.h>

/*
 * Initialize USB polled support. This routine calls down to the lower
 * layers to initialize any state information.
 */
int
usb_console_input_init(dev_info_t *dip, usb_pipe_handle_t pipe_handle,
    uchar_t **state_buf, usb_console_info_t *console_input_info)
{
	int			ret;
	usba_device_t		*usba_device;
	usba_pipe_handle_data_t	*ph_data;
	usb_console_info_impl_t	*usb_console_input;

	if (dip == NULL) {

		return (USB_INVALID_ARGS);
	}

	if (DEVI_IS_DEVICE_REMOVED(dip)) {

		return (USB_FAILURE);
	}

	usb_console_input = kmem_zalloc(
	    sizeof (struct usb_console_info_impl), KM_SLEEP);

	/*
	 * Save the dip
	 */
	usb_console_input->uci_dip = dip;

	/*
	 * Translate the dip into a device.
	 */
	usba_device = usba_get_usba_device(dip);

	/*
	 * Get ph_data from pipe handle and hold the data
	 */
	if ((ph_data = usba_hold_ph_data(pipe_handle)) == NULL) {
		kmem_free(usb_console_input,
		    sizeof (struct usb_console_info_impl));

		return (USB_INVALID_PIPE);
	}

	/*
	 * Call the lower layer to initialize any state information
	 */
	ret = usba_device->usb_hcdi_ops->usba_hcdi_console_input_init(
	    ph_data, state_buf, usb_console_input);

	if (ret != USB_SUCCESS) {
		kmem_free(usb_console_input,
		    sizeof (struct usb_console_info_impl));
	} else {
		*console_input_info = (usb_console_info_t)usb_console_input;
	}

	usba_release_ph_data((usba_ph_impl_t *)pipe_handle);

	return (ret);
}


/*
 * Free up any resources that we allocated in the above initialization
 * routine.
 */
int
usb_console_input_fini(usb_console_info_t console_input_info)
{
	usb_console_info_impl_t		*usb_console_input;
	usba_device_t			*usba_device;
	int				ret;

	usb_console_input = (usb_console_info_impl_t *)console_input_info;

	/*
	 * Translate the dip into a device.
	 */
	usba_device = usba_get_usba_device(usb_console_input->uci_dip);

	/*
	 * Call the lower layer to free any state information.
	 */
	ret = usba_device->usb_hcdi_ops->usba_hcdi_console_input_fini(
	    usb_console_input);

	if (ret == USB_FAILURE) {

		return (ret);
	}

	/*
	 * We won't be needing this information anymore.
	 */
	kmem_free(usb_console_input, sizeof (struct usb_console_info_impl));

	return (USB_SUCCESS);
}


/*
 * This is the routine that OBP calls to save the USB state information
 * before using the USB keyboard as an input device.  This routine,
 * and all of the routines that it calls, are responsible for saving
 * any state information so that it can be restored when OBP mode is
 * over.  At this layer, this code is mainly just a pass through.
 *
 * Warning:  this code runs in polled mode.
 */
int
usb_console_input_enter(usb_console_info_t console_input_info)
{
	usba_device_t				*usba_device;
	usb_console_info_impl_t			*usb_console_input;

	usb_console_input = (usb_console_info_impl_t *)console_input_info;

	/*
	 * Translate the dip into a device.
	 * Do this by directly looking at the dip, do not call
	 * usba_get_usba_device() because this function calls into the DDI.
	 * The ddi then tries to acquire a mutex and the machine hard hangs.
	 */
	usba_device = usba_polled_get_usba_device(usb_console_input->uci_dip);

	/*
	 * Call the lower layer to save state information.
	 */
	return (usba_device->usb_hcdi_ops->usba_hcdi_console_input_enter(
	    usb_console_input));
}


/*
 * This is the routine that OBP calls when it wants to read a character.
 * We will call to the lower layers to see if there is any input data
 * available.  At this layer, this code is mainly just a pass through.
 *
 * Warning: This code runs in polled mode.
 */
int
usb_console_read(usb_console_info_t console_input_info, uint_t *num_characters)
{
	usba_device_t				*usba_device;
	usb_console_info_impl_t			*usb_console_input;

	usb_console_input = (usb_console_info_impl_t *)console_input_info;

	/*
	 * Translate the dip into a device.
	 * Do this by directly looking at the dip, do not call
	 * usba_get_usba_device() because this function calls into the DDI.
	 * The ddi then tries to acquire a mutex and the machine hard hangs.
	 */
	usba_device = usba_polled_get_usba_device(usb_console_input->uci_dip);

	/*
	 * Call the lower layer to get a a character.  Return the number
	 * of characters read into the buffer.
	 */
	return (usba_device->usb_hcdi_ops->usba_hcdi_console_read(
	    usb_console_input, num_characters));
}


/*
 * This is the routine that OBP calls when it is giving up control of the
 * USB keyboard.  This routine, and the lower layer routines that it calls,
 * are responsible for restoring the controller state to the state it was
 * in before OBP took control. At this layer, this code is mainly just a
 * pass through.
 *
 * Warning: This code runs in polled mode.
 */
int
usb_console_input_exit(usb_console_info_t console_input_info)
{
	usba_device_t				*usba_device;
	usb_console_info_impl_t			*usb_console_input;

	usb_console_input = (usb_console_info_impl_t *)console_input_info;

	/*
	 * Translate the dip into a device.
	 * Do this by directly looking at the dip, do not call
	 * usba_get_usba_device() because this function calls into the DDI.
	 * The ddi then tries to acquire a mutex and the machine hard hangs.
	 */
	usba_device = usba_polled_get_usba_device(usb_console_input->uci_dip);

	/*
	 * Restore the state information.
	 */
	return (usba_device->usb_hcdi_ops->usba_hcdi_console_input_exit(
	    usb_console_input));
}

/*
 * Initialize USB OBP support.	This routine calls down to the lower
 * layers to initialize any state information.
 */
int
usb_console_output_init(
	dev_info_t		*dip,
	usb_pipe_handle_t	pipe_handle,
	usb_console_info_t	*console_output_info)
{
	usba_device_t		*usb_device;
	usb_console_info_impl_t	*usb_console_output;
	int			ret;

	/* Translate the dip into a device and check hcdi ops  */
	usb_device = usba_get_usba_device(dip);
	if (usb_device->usb_hcdi_ops->usba_hcdi_ops_version <
	    HCDI_OPS_VERSION_1 ||
	    usb_device->usb_hcdi_ops->usba_hcdi_console_output_init == NULL)

		return (USB_FAILURE);

	usb_console_output = kmem_zalloc(sizeof (struct usb_console_info_impl),
	    KM_SLEEP);
	usb_console_output->uci_dip = dip;

	/*
	 * Call the lower layer to initialize any state information
	 */
	ret = usb_device->usb_hcdi_ops->usba_hcdi_console_output_init(
	    usba_get_ph_data(pipe_handle), usb_console_output);

	if (ret == USB_FAILURE) {
		kmem_free(usb_console_output,
		    sizeof (struct usb_console_info_impl));

		return (ret);
	}

	*console_output_info = (usb_console_info_t)usb_console_output;

	return (USB_SUCCESS);
}

/*
 * Free up any resources that we allocated in the above initialization
 * routine.
 */
int
usb_console_output_fini(usb_console_info_t console_output_info)
{
	usb_console_info_impl_t	*usb_console_output;
	usba_device_t		*usb_device;
	int			ret;

	usb_console_output = (usb_console_info_impl_t *)console_output_info;

	/*
	 * Translate the dip into a device.
	 */
	usb_device = usba_polled_get_usba_device(usb_console_output->uci_dip);

	/*
	 * Call the lower layer to free any state information.
	 */
	ret = usb_device->usb_hcdi_ops->usba_hcdi_console_output_fini(
	    usb_console_output);

	if (ret == USB_FAILURE) {

		return (ret);
	}

	/*
	 * We won't be needing this information anymore.
	 */
	kmem_free(usb_console_output, sizeof (struct usb_console_info_impl));

	return (USB_SUCCESS);
}

/*
 * This is the routine that OBP calls to save the USB state information
 * before using the USB device as an output device.  This routine,
 * and all of the routines that it calls, are responsible for saving
 * any state information so that it can be restored when OBP mode is
 * over.  At this layer, this code is mainly just a pass through.
 */
int
usb_console_output_enter(usb_console_info_t console_output_info)
{
	usba_device_t			    *usb_device;
	usb_console_info_impl_t		 *usb_console_output;

	usb_console_output = (usb_console_info_impl_t *)console_output_info;

	/*
	 * Translate the dip into a device.
	 */
	usb_device = usba_polled_get_usba_device(usb_console_output->uci_dip);

	/*
	 * Call the lower layer to save state information.
	 */
	return (usb_device->usb_hcdi_ops->usba_hcdi_console_output_enter(
	    usb_console_output));
}

/*
 * This is the routine that OBP calls when it wants to write a character.
 * We will call to the lower layers to write any data
 * At this layer, this code is mainly just a pass through.
 */
int
usb_console_write(usb_console_info_t console_output_info,
    uchar_t *buf, uint_t num_characters, uint_t *num_characters_written)
{
	usba_device_t		*usb_device;
	usb_console_info_impl_t	*usb_console_output;

	usb_console_output = (usb_console_info_impl_t *)console_output_info;

	/*
	 * Translate the dip into a device.
	 */
	usb_device = usba_polled_get_usba_device(usb_console_output->uci_dip);

	/*
	 * Call the lower layer to get a a character.  Return the number
	 * of characters read into the buffer.
	 */
	return (usb_device->usb_hcdi_ops->usba_hcdi_console_write(
	    usb_console_output, buf, num_characters,
	    num_characters_written));
}

/*
 * This is the routine that OBP calls when it is giving up control of the
 * USB output device.  This routine, and the lower layer routines that it
 * calls, are responsible for restoring the controller state to the state
 * it was in before OBP took control. At this layer, this code is mainly
 * just a pass through.
 */
int
usb_console_output_exit(usb_console_info_t console_output_info)
{
	usba_device_t			 *usb_device;
	usb_console_info_impl_t		 *usb_console_output;

	usb_console_output = (usb_console_info_impl_t *)console_output_info;

	/*
	 * Translate the dip into a device.
	 */
	usb_device = usba_polled_get_usba_device(usb_console_output->uci_dip);

	/*
	 * Restore the state information.
	 */
	return (usb_device->usb_hcdi_ops->usba_hcdi_console_output_exit(
	    usb_console_output));
}
