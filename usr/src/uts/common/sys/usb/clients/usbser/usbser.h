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

#ifndef _SYS_USB_USBSER_H
#define	_SYS_USB_USBSER_H


/*
 * USB-to-serial generic driver functions
 */

#include <sys/usb/clients/usbser/usbser_dsdi.h>

#ifdef	__cplusplus
extern "C" {
#endif

int	usbser_soft_state_size();

/* configuration entry points */
int	usbser_attach(dev_info_t *, ddi_attach_cmd_t, void *, ds_ops_t *);
int	usbser_detach(dev_info_t *, ddi_detach_cmd_t, void *);
int 	usbser_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **, void *);
int 	usbser_power(dev_info_t *, int, int);

/* STREAMS entry points */
int 	usbser_open(queue_t *, dev_t *, int, int, cred_t *, void *);
int	usbser_close(queue_t *, int, cred_t *);
int	usbser_wput(queue_t *, mblk_t *);
int	usbser_wsrv(queue_t *);
int	usbser_rsrv(queue_t *);

/* STREAMS defaults */
enum {
	USBSER_MIN_PKTSZ	= 0,		/* min pkt size */
	USBSER_MAX_PKTSZ	= INFPSZ,	/* max pkt size */
	USBSER_HIWAT		= 32 * 4 * 1024, /* high water mark */
	USBSER_LOWAT		= 4 * 1024	/* low water mark */
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_USB_USBSER_H */
