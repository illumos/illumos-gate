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
 * Copyright 2016 Joyent, Inc.
 */

#ifndef _SYS_USB_XHCI_XHCI_IOCTL_H
#define	_SYS_USB_XHCI_XHCI_IOCTL_H

/*
 * Private ioctls for the xhci driver.
 */

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	XHCI_IOCTL	(('x' << 24) | ('h' << 16 | ('i' << 8)))

#define	XHCI_PORTSC_NPORTS	256
#define	XHCI_IOCTL_PORTSC	(XHCI_IOCTL | 0x01)
#define	XHCI_IOCTL_SETPLS	(XHCI_IOCTL | 0x02)
#define	XHCI_IOCTL_CLEAR	(XHCI_IOCTL | 0x03)

typedef struct xhci_ioctl_portsc {
	uint32_t 	xhi_nports;
	uint32_t	xhi_pad;
	uint32_t	xhi_portsc[XHCI_PORTSC_NPORTS];
} xhci_ioctl_portsc_t;

typedef struct xhci_ioctl_setpls {
	uint32_t	xis_port;
	uint32_t	xis_pls;
} xhci_ioctl_setpls_t;

typedef struct xhci_ioctl_clear {
	uint32_t	xic_port;
	uint32_t 	xic_pad;
} xhci_ioctl_clear_t;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_USB_XHCI_XHCI_IOCTL_H */
