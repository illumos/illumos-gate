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

#ifndef _SYS_USB_UGEND_H
#define	_SYS_USB_UGEND_H


/*
 * UGEN - USB Generic Driver Support
 * This file contains the UGEN specific data structure definitions
 * and UGEN specific macros.
 */
#include <sys/usb/usba/usbai_private.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* UGEN specific macros */
#define	UGEN_INSTANCES		4	/* for softstate init */

typedef struct {
	dev_info_t		*ugen_skel_dip;
	int			ugen_skel_instance;
	usb_ugen_hdl_t		ugen_skel_hdl;
} ugen_skel_state_t;

_NOTE(DATA_READABLE_WITHOUT_LOCK(ugen_skel_state_t))

#define	UGEN_MINOR_UGEN_BITS_MASK	0x1ff
#define	UGEN_MINOR_INSTANCE_SHIFT	9
#define	UGEN_MINOR_INSTANCE_MASK	~UGEN_MINOR_UGEN_BITS_MASK
#define	UGEN_MINOR_TO_INSTANCE(minor) \
		(((minor) & UGEN_MINOR_INSTANCE_MASK) >> \
		UGEN_MINOR_INSTANCE_SHIFT)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_USB_UGEND_H */
