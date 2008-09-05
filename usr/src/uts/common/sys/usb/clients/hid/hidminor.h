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

#ifndef _SYS_USB_HIDMINOR_H
#define	_SYS_USB_HIDMINOR_H


#ifdef	__cplusplus
extern "C" {
#endif

/*
 * In order to support virtual keyboard/mouse, we should distinguish
 * between internal virtual open and external physical open.
 *
 * When the physical devices are opened by application, they will
 * be unlinked from the virtual device and their data stream will
 * not be sent to the virtual device. When the opened physical
 * devices are closed, they will be relinked to the virtual devices.
 *
 * All these automatic switch between virtual and physical are
 * transparent.
 *
 * So we change minor node numbering scheme to be:
 *	external node minor num == instance << 1
 *	internal node minor num == instance << 1 | 0x1
 * (There are only internal nodes for keyboard/mouse now.)
 */
#define	HID_MINOR_BITS_MASK		0x1
#define	HID_MINOR_INSTANCE_MASK		~HID_MINOR_BITS_MASK
#define	HID_MINOR_INSTANCE_SHIFT	1

#define	HID_MINOR_INTERNAL		0x1
#define	HID_MINOR_MAKE_INTERNAL(minor) \
		((minor) | HID_MINOR_INTERNAL)

#define	HID_IS_INTERNAL_OPEN(minor) \
		(((minor) & HID_MINOR_INTERNAL))

#define	HID_MINOR_TO_INSTANCE(minor) \
		(((minor) & HID_MINOR_INSTANCE_MASK) >> \
		HID_MINOR_INSTANCE_SHIFT)

#define	HID_CONSTRUCT_INTERNAL_MINOR(inst) \
		(((inst) << HID_MINOR_INSTANCE_SHIFT) | \
		HID_MINOR_INTERNAL)

#define	HID_CONSTRUCT_EXTERNAL_MINOR(inst) \
		((inst) << HID_MINOR_INSTANCE_SHIFT)

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_HIDMINOR_H */
