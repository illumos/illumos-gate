/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

#ifndef	_TOPO_USB_H
#define	_TOPO_USB_H

#include <libdevinfo.h>

/*
 * Common USB module header file.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	USB		"usb"
#define	USB_VERSION	1

#define	USB_PCI		"usb-pci"
#define	USB_MOBO	"usb-mobo"
#define	USB_CHASSIS	"usb-chassis"

#ifdef __cplusplus
}
#endif

#endif	/* _TOPO_USB_H */
