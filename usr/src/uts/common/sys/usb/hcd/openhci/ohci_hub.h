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

#ifndef _SYS_USB_OHCI_HUB_H
#define	_SYS_USB_OHCI_HUB_H


#ifdef	__cplusplus
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
 * Host Controller Driver to maintain state of USB Open Host Controller, to
 * perform different USB transfers and for the bandwidth allocations.
 */

/*
 * Root hub information structure
 *
 * The Root hub is a Universal Serial Bus hub attached directly to the
 * Host Controller (HC) and all the internal registers of the root hub
 * are exposed to the Host Controller Driver (HCD) which is responsible
 * for providing the proper hub-class protocol with the  USB driver and
 * proper control of the root hub. This structure contains information
 * about the root hub and its ports.
 */
typedef struct ohci_root_hub {
	usb_hub_descr_t	rh_descr;	/* Copy of rh descriptor */
	uint_t		rh_des_A;	/* Descriptor reg A value */
	uint_t		rh_des_B;	/* Descriptor reg B value */
	uint_t		rh_status;	/* Last root hub status */

	/* Last state & status for each root hub port */
	uint_t		rh_port_status[OHCI_MAX_RH_PORTS];
	uint_t		rh_port_state[OHCI_MAX_RH_PORTS];

	/* Root hub control pipe handle */
	usba_pipe_handle_data_t *rh_ctrl_pipe_handle;

	/* Current control request pointer */
	usb_ctrl_req_t	*rh_curr_ctrl_reqp;

	/* Root hub control pipe state */
	uint_t		rh_ctrl_pipe_state;

	/* Root hub interrupt pipe handle */
	usba_pipe_handle_data_t *rh_intr_pipe_handle;

	/* Current interrupt request pointer */
	usb_intr_req_t	*rh_curr_intr_reqp;

	/* Saved original interrupt request pointer */
	usb_intr_req_t	*rh_client_intr_reqp;

	/* Root hub interrupt pipe state and timer-id */
	uint_t		rh_intr_pipe_state;
	timeout_id_t	rh_intr_pipe_timer_id;
} ohci_root_hub_t;

/* Port States */
#define	UNINIT		0x00		/* Uninitialized port */
#define	POWERED_OFF	0x01		/* Port has no power */
#define	DISCONNECTED	0x02		/* Port has power, no dev */
#define	DISABLED	0x03		/* Dev connected, no downstream data */
#define	ENABLED		0x04		/* Downstream data is enabled */
#define	SUSPEND		0x05		/* Suspended port */

/*
 * Time waits for the different OHCI specific operations.
 * These timeout values are specified in terms of microseconds.
 */
#define	OHCI_RH_POLL_TIME	30000	/* Root hub polling interval */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_USB_OHCI_HUB_H */
