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

#ifndef	_SYS_USB_UHCI_POLLED_H
#define	_SYS_USB_UHCI_POLLED_H


#ifdef __cplusplus
extern "C" {
#endif

/*
 * This header file describes the data structures required for the Host
 * Controller Driver (HCD) to work in POLLED mode which will be  either
 * OBP mode for Sparc architecture or PC PROM mode for X86 architecture
 */
#define	POLLED_RAW_BUF_SIZE	8

/*
 * These two flags are used to determine if this structure is already in
 * use. We should only save off the controller state information once,
 * and restore it once. These flags are used by the uhci_polled_flags below.
 */
#define	POLLED_INPUT_MODE		0x01
#define	POLLED_INPUT_MODE_INUSE		0x04
#define	POLLED_OUTPUT_MODE		0x10
#define	POLLED_OUTPUT_MODE_INUSE	0x40

/*
 * For uhci bandwidth of low speed interrupt devices limits,
 * one host controller can support 7 keyboards only.
 */

#define	MAX_NUM_FOR_KEYBORAD		0x7

/*
 * State structure for the POLLED switch off
 */
typedef struct uhci_polled {
	/*
	 * Pointer to the uhcip structure for the device that is to  be
	 * used as input in polled mode.
	 */
	uhci_state_t *uhci_polled_uhcip;

	/*
	 * Pipe handle for the pipe that is to be used as input device
	 * in POLLED mode.
	 */
	usba_pipe_handle_data_t  *uhci_polled_ph;

	/* Interrupt Endpoint descriptor */
	queue_head_t		*uhci_polled_qh;

	/* Transfer descriptor for polling the device */
	uhci_td_t		*uhci_polled_td;
	/*
	 * The buffer that the usb scancodes are copied into.
	 */
	uchar_t			*uhci_polled_buf;

	/*
	 * This flag is used to determine if the state of the controller
	 * has already been saved (enter) or doesn't need to be restored
	 * yet (exit).
	 */
	uint_t			uhci_polled_flags;
	ushort_t		uhci_polled_entry;
} uhci_polled_t;

_NOTE(SCHEME_PROTECTS_DATA("Only accessed in POLLED mode",
	uhci_polled_t::uhci_polled_flags))
_NOTE(DATA_READABLE_WITHOUT_LOCK(uhci_polled_t::uhci_polled_uhcip))
_NOTE(SCHEME_PROTECTS_DATA("Only accessed in POLLED mode",
	uhci_polled_t::uhci_polled_entry))

/*
 * POLLED entry points
 *	These functions are entry points into the POLLED code.
 */
int	uhci_hcdi_polled_input_init(usba_pipe_handle_data_t *, uchar_t **,
	    usb_console_info_impl_t *);
int	uhci_hcdi_polled_input_fini(usb_console_info_impl_t *);
int	uhci_hcdi_polled_input_enter(usb_console_info_impl_t *);
int	uhci_hcdi_polled_input_exit(usb_console_info_impl_t *);
int	uhci_hcdi_polled_read(usb_console_info_impl_t *, uint_t *);
int	uhci_hcdi_polled_output_init(usba_pipe_handle_data_t *,
	    usb_console_info_impl_t *);
int	uhci_hcdi_polled_output_fini(usb_console_info_impl_t *);
int	uhci_hcdi_polled_output_enter(usb_console_info_impl_t *);
int	uhci_hcdi_polled_output_exit(usb_console_info_impl_t *);
int	uhci_hcdi_polled_write(usb_console_info_impl_t *, uchar_t *,
	    uint_t, uint_t *);

/*
 * External Function Prototypes:
 * These routines are only called from the init and fini functions.
 * They are allowed to acquire locks.
 */
extern uhci_state_t	*uhci_obtain_state(dev_info_t *);
extern queue_head_t	*uhci_alloc_queue_head(uhci_state_t *);
extern void		uhci_free_tw(uhci_state_t *, uhci_trans_wrapper_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_USB_UHCI_POLLED_H */
