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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_USBA_UGEN_H
#define	_SYS_USBA_UGEN_H


/*
 * UGEN - USB Generic Driver code exported for sharing by USBA
 */
#include <sys/usb/usba/usbai_private.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct usb_ugen_info {
	uint_t		usb_ugen_flags;
	dev_t		usb_ugen_minor_node_ugen_bits_mask;
	dev_t		usb_ugen_minor_node_instance_mask;
} usb_ugen_info_t;

typedef struct usb_ugen_hdl *usb_ugen_hdl_t;

#define	USB_UGEN_ENABLE_PM		0x0001
#define	USB_UGEN_REMOVE_CHILDREN	0x0002

usb_ugen_hdl_t usb_ugen_get_hdl(dev_info_t *, usb_ugen_info_t *);
void	usb_ugen_release_hdl(usb_ugen_hdl_t);
int	usb_ugen_attach(usb_ugen_hdl_t, ddi_attach_cmd_t);
int	usb_ugen_detach(usb_ugen_hdl_t, ddi_detach_cmd_t);
int	usb_ugen_open(usb_ugen_hdl_t, dev_t *, int, int, cred_t *);
int	usb_ugen_close(usb_ugen_hdl_t, dev_t, int, int, cred_t *);
int	usb_ugen_power(usb_ugen_hdl_t, int, int);
int	usb_ugen_read(usb_ugen_hdl_t, dev_t, struct uio *, cred_t *);
int	usb_ugen_write(usb_ugen_hdl_t, dev_t, struct uio *, cred_t *);
int	usb_ugen_poll(usb_ugen_hdl_t, dev_t, short, int,
					short *, struct pollhead **);

int	usb_ugen_disconnect_ev_cb(usb_ugen_hdl_t);
int	usb_ugen_reconnect_ev_cb(usb_ugen_hdl_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_USBA_UGEN_H */
