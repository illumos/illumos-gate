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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_USB_USB_MIDVAR_H
#define	_SYS_USB_USB_MIDVAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/usb/usba/usbai_private.h>


/*
 * soft	state information for this usb_mid
 */
typedef struct usb_mid {
	int			mi_instance;

	uint_t			mi_init_state;
	uint_t			mi_ugen_open_count;

	kmutex_t		mi_mutex;

	/*
	 * dev_info_t reference
	 */
	dev_info_t		*mi_dip;

	/* pointer to usb_common_power_t */
	usb_common_power_t	*mi_pm;

	/*
	 * save the usba_device pointer
	 */
	usba_device_t		*mi_usba_device;

	int			mi_softstate;

	int			mi_dev_state;

	int			mi_n_ifs;

	/* track event registration of children */
	uint8_t			*mi_child_events;

	/* record the interface num of each child node */
	uint_t			*mi_children_ifs;

	/*
	 * mi_children_dips is an array for holding
	 * each child dip indexed by interface number
	 */
	dev_info_t		**mi_children_dips;

	boolean_t		mi_removed_children;

	size_t			mi_cd_list_length;
	int			mi_attach_count;

	/* logging of messages */
	usb_log_handle_t	mi_log_handle;

	/* usb registration */
	usb_client_dev_data_t	*mi_dev_data;

	/* event support */
	ndi_event_hdl_t		mi_ndi_event_hdl;

	/* ugen support */
	usb_ugen_hdl_t		mi_ugen_hdl;

} usb_mid_t;

_NOTE(MUTEX_PROTECTS_DATA(usb_mid::mi_mutex, usb_mid))
_NOTE(MUTEX_PROTECTS_DATA(usb_mid::mi_mutex, usb_common_power_t))
_NOTE(DATA_READABLE_WITHOUT_LOCK(usb_mid::mi_instance
		usb_mid::mi_ndi_event_hdl
		usb_mid::mi_dev_data
		usb_mid::mi_log_handle
		usb_mid::mi_ugen_hdl
		usb_mid::mi_dip
		usb_mid::mi_pm))

#define	USB_MID_MINOR_UGEN_BITS_MASK	0x1ff
#define	USB_MID_MINOR_INSTANCE_SHIFT	9
#define	USB_MID_MINOR_INSTANCE_MASK	~USB_MID_MINOR_UGEN_BITS_MASK
#define	USB_MID_MINOR_TO_INSTANCE(minor) \
		(((minor) & USB_MID_MINOR_INSTANCE_MASK) >> \
		USB_MID_MINOR_INSTANCE_SHIFT)

/* init state */
#define	USB_MID_LOCK_INIT		0x0001
#define	USB_MID_MINOR_NODE_CREATED	0x0002
#define	USB_MID_EVENTS_REGISTERED	0x0004

/* Tracking events registered by children */
#define	USB_MID_CHILD_EVENT_DISCONNECT	0x01
#define	USB_MID_CHILD_EVENT_PRESUSPEND	0x02

/*
 * Debug printing
 * Masks
 */
#define	DPRINT_MASK_ATTA	0x00000001
#define	DPRINT_MASK_CBOPS	0x00000002
#define	DPRINT_MASK_EVENTS	0x00000004
#define	DPRINT_MASK_DUMPING	0x00000008	/* usb_mid dump mask */
#define	DPRINT_MASK_PM		0x00000010
#define	DPRINT_MASK_ALL 	0xFFFFFFFF


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_USB_USB_MIDVAR_H */
