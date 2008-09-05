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

#ifndef _SYS_USB_EHCI_ISOCH_H
#define	_SYS_USB_EHCI_ISOCH_H


#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Enchanced Host Controller Driver (EHCI)
 *
 * The EHCI driver is a software driver which interfaces to the Universal
 * Serial Bus layer (USBA) and the Host Controller (HC). The interface to
 * the Host Controller is defined by the EHCI Host Controller Interface.
 *
 * This header file describes the data structures and function prototypes
 * related EHCI driver isochronous support.
 */

extern int
ehci_isoc_init(
	ehci_state_t		*ehcip);

extern void
ehci_isoc_cleanup(
	ehci_state_t		*ehcip);

extern void
ehci_isoc_pipe_cleanup(
	ehci_state_t		*ehcip,
	usba_pipe_handle_data_t *ph);

extern ehci_isoc_xwrapper_t *
ehci_allocate_isoc_resources(
	ehci_state_t		*ehcip,
	usba_pipe_handle_data_t *ph,
	usb_isoc_req_t		*isoc_reqp,
	usb_flags_t		usb_flags);

extern int
ehci_insert_isoc_req(
	ehci_state_t		*ehcip,
	ehci_pipe_private_t	*pp,
	ehci_isoc_xwrapper_t	*itw,
	usb_flags_t		usb_flags);

extern int
ehci_start_isoc_polling(
	ehci_state_t		*ehcip,
	usba_pipe_handle_data_t	*ph,
	usb_flags_t		flags);

extern void
ehci_traverse_active_isoc_list(
	ehci_state_t		*ehcip);

extern void
ehci_hcdi_isoc_callback(
	usba_pipe_handle_data_t	*ph,
	ehci_isoc_xwrapper_t	*itw,
	usb_cr_t		completion_reason);

#define	EHCI_SITD_MAX_XFER_SIZE		1023
#define	EHCI_MAX_ISOC_PKTS_PER_XFER	1024

#ifdef __cplusplus
}
#endif

#endif /* _SYS_USB_EHCI_ISOCH_H */
