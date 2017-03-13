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
 *
 * Copyright 2016 Joyent, Inc.
 */

#ifndef	_SYS_USB_HUBDI_H
#define	_SYS_USB_HUBDI_H


#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/usb/usba/usba_types.h>

/* USBA calls these: */
void	usba_hubdi_initialization();
void	usba_hubdi_destruction();

#define	HUBDI_OPS_VERSION_0 	0
#define	HUBD_IS_ROOT_HUB	0x1000


int usba_hubdi_open(dev_info_t *, dev_t *, int, int, cred_t *);
int usba_hubdi_close(dev_info_t *, dev_t, int, int, cred_t *);
int usba_hubdi_ioctl(dev_info_t *, dev_t, int, intptr_t, int,
						cred_t *, int *);
int usba_hubdi_root_hub_power(dev_info_t *, int, int);

extern struct bus_ops usba_hubdi_busops;

/*
 * autoconfiguration data and routines.
 */
int usba_hubdi_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
int usba_hubdi_attach(dev_info_t *, ddi_attach_cmd_t);
int usba_hubdi_probe(dev_info_t *);
int usba_hubdi_detach(dev_info_t *, ddi_detach_cmd_t);
int usba_hubdi_quiesce(dev_info_t *);

int usba_hubdi_bind_root_hub(dev_info_t *, uchar_t *, size_t,
				usb_dev_descr_t *);
int usba_hubdi_unbind_root_hub(dev_info_t *);

int usba_hubdi_reset_device(dev_info_t *, usb_dev_reset_lvl_t);
/* power budget control routines */
void usba_hubdi_incr_power_budget(dev_info_t *, usba_device_t *);
void usba_hubdi_decr_power_budget(dev_info_t *, usba_device_t *);
int usba_hubdi_check_power_budget(dev_info_t *, usba_device_t *, uint_t);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_HUBDI_H */
