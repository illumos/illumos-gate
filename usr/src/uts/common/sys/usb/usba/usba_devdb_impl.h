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

#ifndef	_SYS_USBA_USBA_DEVDB_IMPL_H
#define	_SYS_USBA_USBA_DEVDB_IMPL_H


#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/usb/usba/usba_devdb.h>
#include <sys/kobj.h>
#include <sys/kobj_lex.h>
#include <sys/sysmacros.h>
#include <sys/avl.h>

#define	USBCONF_FILE    "/etc/usb/config_map.conf"

static char usbconf_file[] = USBCONF_FILE;

typedef struct usba_devdb_info {
	usba_configrec_t *usb_dev;
	avl_node_t	avl_link;
} usba_devdb_info_t;


typedef enum {
	USB_SELECTION, USB_VENDOR, USB_PRODUCT, USB_CFGNDX, USB_SRNO,
	USB_PATH, USB_DRIVER, USB_NONE
} config_field_t;

typedef struct usbcfg_var {
	const char	*name;
	config_field_t	field;
} usba_cfg_var_t;

static usba_cfg_var_t usba_cfg_varlist[] = {
	{ "selection",	USB_SELECTION },
	{ "idVendor",   USB_VENDOR },
	{ "idProduct",  USB_PRODUCT },
	{ "cfgndx",	USB_CFGNDX },
	{ "srno",	USB_SRNO },
	{ "pathname",	USB_PATH },
	{ "driver",	USB_DRIVER },
	{ NULL,		USB_NONE },
};

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USBA_USBA_DEVDB_IMPL_H */
