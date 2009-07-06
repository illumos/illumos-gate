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

#ifndef _SYS_USB_EHCI_HUB_H
#define	_SYS_USB_EHCI_HUB_H


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
 * This header file describes the data structures required by the EHCI
 * Driver for the root hub operations.
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
typedef struct ehci_root_hub {
	/* Copy of the Root Hub descriptor */
	usb_hub_descr_t		rh_descr;

	/* Number of Companion Controllers */
	uint_t			rh_companion_controllers;

	/* Last state & status for each root hub port */
	uint_t			rh_port_status[EHCI_MAX_RH_PORTS];
	uint_t			rh_port_state[EHCI_MAX_RH_PORTS];

	/* Root hub control pipe handle */
	usba_pipe_handle_data_t	*rh_ctrl_pipe_handle;

	/* Current control request pointer */
	usb_ctrl_req_t		*rh_curr_ctrl_reqp;

	/* Root hub control pipe state */
	uint_t			rh_ctrl_pipe_state;

	/* Root hub interrupt pipe handle */
	usba_pipe_handle_data_t	*rh_intr_pipe_handle;

	/* Current interrupt request pointer */
	usb_intr_req_t		*rh_curr_intr_reqp;

	/* Saved original interrupt request pointer */
	usb_intr_req_t		*rh_client_intr_reqp;

	/* Root hub interrupt pipe state and timer-id */
	uint_t			rh_intr_pipe_state;
	usb_port_mask_t		rh_intr_pending_status;
	timeout_id_t		rh_intr_pipe_timer_id;
} ehci_root_hub_t;

/* Port States */
#define	UNINIT		0x00	/* Uninitialized port */
#define	POWERED_OFF	0x01	/* Port has no power */
#define	DISCONNECTED	0x02	/* Port has power, no dev */
#define	DISABLED	0x03	/* Dev connected, no data */
#define	ENABLED		0x04	/* Downstream data is enabled */
#define	SUSPEND		0x05	/* Suspended port */

/*
 * Time waits for the different EHCI Root Hub specific operations.
 * These timeout values are specified in terms of microseconds.
 */
#define	EHCI_RH_POLL_TIME		256000	/* RH polling interval */
#define	EHCI_PORT_RESET_TIMEWAIT	50000	/* RH port reset time */
#define	EHCI_PORT_RESET_COMP_TIMEWAIT	2000	/* RH port reset complete */
#define	EHCI_PORT_SUSPEND_TIMEWAIT	10000	/* RH port suspend time */
#define	EHCI_PORT_RESUME_TIMEWAIT	20000	/* RH port resume time */
#define	EHCI_PORT_RESUME_COMP_TIMEWAIT	2000	/* RH port resume complete */
#define	EHCI_PORT_RESET_RETRY_MAX	10	/* RH port reset retry max */
#define	EHCI_PORT_RESUME_RETRY_MAX	10	/* RH port resume retry max */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_USB_EHCI_HUB_H */
