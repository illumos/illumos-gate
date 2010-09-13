/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_FCTEST_H
#define	_SYS_FCTEST_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * /dev/fctest ioctls ... this is not part of the efcode project.
 * This is a prototype test driver, used to drive the prototype
 * only, and is not needed with hot-plug hardware and real hot-plug
 * capable code.
 */

#define	FCTIOC			(0xfd<<8)

/*
 * FCT_SET_DEBUG_LVL: 'arg' is an intptr_t.
 * Set fcode_debug to the value in intptr_t 'arg'.
 */
#define	FCT_SET_DEBUG_LVL	(FCTIOC | 1)

/*
 * FCT_SET_DEVICE: 'arg' is a pointer to a string.  The string
 * is taken as the pathname of the device to be configured.
 * The driver attempts to locate the device in the device tree,
 * and uses the parent of the device as the attachment point.
 * The device has to exist in the firmware's device tree.
 */
#define	FCT_SET_DEVICE		(FCTIOC | 2)

/*
 * FCT_UNCONFIGURE: 'arg' is ignored. Unconfigures the device
 * given in the FCT_SET_DEVICE ioctl.
 */
#define	FCT_UNCONFIGURE		(FCTIOC | 3)
#define	FCT_CONFIGURE		(FCTIOC | 4)


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FCTEST_H */
