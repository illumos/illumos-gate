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

#ifndef	_SYS_USB_OHCI_POLLED_H
#define	_SYS_USB_OHCI_POLLED_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Open Host Controller Driver (OHCI)
 *
 * The USB Open Host Controller driver is a software driver which interfaces
 * to the Universal Serial Bus layer (USBA) and the USB Open Host Controller.
 * The interface to USB Open Host Controller is defined by the OpenHCI  Host
 * Controller Interface.
 *
 * This header file describes the data structures required for the USB Open
 * Host Controller Driver to work in POLLED mode which will be either OBP
 * mode for Sparc architecture or PC PROM mode for X86 architecture
 */

#define	POLLED_RAW_BUF_SIZE	8

/*
 * These two  flags are used to determine if this structure is already
 * in use.
 */
#define	POLLED_INPUT_MODE		0x01
#define	POLLED_OUTPUT_MODE		0x10

/*
 * These two flags are used to determine if this structure is already in
 * use. We should only save off the controller state information once,
 * restore it once.  These flags are used for the ohci_polled_flags below.
 */
#define	POLLED_INPUT_MODE_INUSE		0x04
#define	POLLED_OUTPUT_MODE_INUSE	0x40

/*
 * For ohci bandwidth of low speed interrupt devices limits,
 * one host controller can support 6 keyboards only.
 */
#define	MAX_NUM_FOR_KEYBOARD		0x6
/*
 * State structure for the POLLED switch off
 */
typedef struct ohci_polled {
	/*
	 * Pointer to the ohcip structure for the device that is to  be
	 * used as input in polled mode.
	 */
	ohci_state_t	*ohci_polled_ohcip;

	/*
	 * Pipe handle for the pipe that is to be used as input device
	 * in POLLED mode.
	 */
	usba_pipe_handle_data_t  *ohci_polled_input_pipe_handle;

	/* Dummy endpoint descriptor */
	ohci_ed_t	*ohci_polled_dummy_ed;

	/* Interrupt Endpoint descriptor */
	ohci_ed_t	*ohci_polled_ed;	/* Interrupt endpoint */

	/*
	 * The buffer that the usb scancodes are copied into.
	 */
	uchar_t		*ohci_polled_buf;

	/*
	 * This flag is used to determine if the state of the controller
	 * has already been saved (enter) or doesn't need to be restored
	 * yet (exit).
	 */
	uint_t		ohci_polled_flags;

	/*
	 * The read or write routines may take TD's of the done head that
	 * are not intended for them.
	 */
	ohci_td_t	*ohci_polled_input_done_head;

	/*
	 * This is the tail for the above ohci_polled_input_done_head;
	 */
	ohci_td_t	*ohci_polled_input_done_tail;

	/*
	 * ohci_hcdi_polled_input_enter() may be called
	 * multiple times before the ohci_hcdi_polled_input_exit() is called.
	 * For example, the system may:
	 *	- go down to kmdb (ohci_hcdi_polled_input_enter())
	 *	- down to the ok prompt, $q (ohci_hcdi_polled_input_enter())
	 *	- back to kmdb, "go" (ohci_hcdi_polled_input_exit())
	 *	- back to the OS, :c at kmdb (ohci_hcdi_polled_input_exit())
	 *
	 * polled_entry keeps track of how  many times
	 * ohci_polled_input_enter/ohci_polled_input_exit have been
	 * called so that the host controller isn't switched back to OS mode
	 * prematurely.
	 */
	uint_t		ohci_polled_entry;

	/*
	 * Save the pointer usb device structure and the endpoint number
	 * during the polled initilization.
	 */
	usba_device_t	*ohci_polled_usb_dev;	/* USB device */

	uint8_t		ohci_polled_ep_addr;

	boolean_t	ohci_polled_no_sync_flag; /* For schizo bug */
} ohci_polled_t;

_NOTE(SCHEME_PROTECTS_DATA("Only accessed in POLLED mode",
	ohci_polled_t::ohci_polled_flags))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ohci_polled_t::ohci_polled_ohcip))
_NOTE(SCHEME_PROTECTS_DATA("Only accessed in POLLED mode",
	ohci_polled_t::ohci_polled_entry))


#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_OHCI_POLLED_H */
