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

#ifndef	_SYS_USB_USB_IA_H
#define	_SYS_USB_USB_IA_H


#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/usb/usba/usbai_private.h>

/*
 * soft	state information for this usb_ia
 */
typedef struct usb_ia {
	int			ia_instance;

	uint_t			ia_init_state;

	kmutex_t		ia_mutex;

	/*
	 * dev_info_t reference
	 */
	dev_info_t		*ia_dip;

	/* pointer to usb_ia_power_t */
	usb_common_power_t	*ia_pm;

	int			ia_dev_state;

	int			ia_first_if;
	int			ia_n_ifs;

	/* track event registration of children */
	uint8_t			*ia_child_events;
	/*
	 * ia_children_dips is a  array for holding
	 * each child dip indexed by interface number
	 */
	dev_info_t		**ia_children_dips;

	size_t			ia_cd_list_length;

	/* logging of messages */
	usb_log_handle_t	ia_log_handle;

	/* usb registration */
	usb_client_dev_data_t	*ia_dev_data;

	/* event support */
	ndi_event_hdl_t		ia_ndi_event_hdl;

} usb_ia_t;

_NOTE(MUTEX_PROTECTS_DATA(usb_ia::ia_mutex, usb_ia))
_NOTE(MUTEX_PROTECTS_DATA(usb_ia::ia_mutex, usb_common_power_t))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_ia::ia_instance
		usb_ia::ia_ndi_event_hdl
		usb_ia::ia_dev_data
		usb_ia::ia_log_handle
		usb_ia::ia_dip
		usb_ia::ia_pm))

/* init state */
#define	USB_IA_LOCK_INIT		0x0001
#define	USB_IA_MINOR_NODE_CREATED	0x0002
#define	USB_IA_EVENTS_REGISTERED	0x0004

/* Tracking events registered by children */
#define	USB_IA_CHILD_EVENT_DISCONNECT	0x01
#define	USB_IA_CHILD_EVENT_PRESUSPEND	0x02

/*
 * Debug printing
 * Masks
 */
#define	DPRINT_MASK_ATTA	0x00000001
#define	DPRINT_MASK_CBOPS	0x00000002
#define	DPRINT_MASK_EVENTS	0x00000004
#define	DPRINT_MASK_PM		0x00000010
#define	DPRINT_MASK_ALL 	0xFFFFFFFF


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_USB_USB_IA_H */
