/***************************************************************************
 *
 * devinfo_usb.h : definitions for USB devices
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Licensed under the Academic Free License version 2.1
 *
 **************************************************************************/

#ifndef DEVINFO_USB_H
#define	DEVINFO_USB_H

#include "devinfo.h"

#define	bcd(a) ((((a) & 0xf000) >> 12) * 1000 + (((a) & 0xf00) >> 8) * 100 + (((a) & 0xf0) >> 4) * 10 + ((a) & 0xf))

extern DevinfoDevHandler devinfo_usb_handler;

extern const gchar *devinfo_keyboard_get_prober(HalDevice *d, int *timeout);

HalDevice *devinfo_usb_add(HalDevice *parent, di_node_t node, char *devfs_path, char *device_type);

#endif /* DEVINFO_USB_H */
