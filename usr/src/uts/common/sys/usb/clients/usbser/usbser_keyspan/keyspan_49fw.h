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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_USB_USBSER_KEYSPAN_49FW_H
#define	_SYS_USB_USBSER_KEYSPAN_49FW_H


#define	KEYSPAN_NO_FIRMWARE_SOURCE

/*
 * For the 4-port Keyspan usb-to-serial adapter (usa49wlc) support
 * in the usbsksp(7D) driver, users can download a firmware package
 * from the Keyspan website (http://www.keyspan.com).
 * Please contact Keyspan technical support for questions regarding
 * firmware source access.
 *
 * Users with access to the firmware source code can build the
 * firmware package by copying keyspan_usa49w_fw.h over this
 * header file (keyspan_49fw.h)
 *
 * To build the usbs49_fw module (using x86 platform as an example):
 * $ cd usr/src/uts/intel/usbs49_fw
 * $ make install
 *
 * See usbsksp(7D) for details on using the Solaris USB keyspan
 * driver.
 */

#endif /* _SYS_USB_USBSER_KEYSPAN_49FW_H */
