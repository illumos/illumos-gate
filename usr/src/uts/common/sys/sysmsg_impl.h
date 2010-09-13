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
 * Copyright (c) 1996-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_SYSMSG_IMPL_H
#define	_SYS_SYSMSG_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	SYSMSG		"/dev/sysmsg"

/*
 * consadm(1M) uses these ioctls to interface with /dev/sysmsg.
 */

/*
 * When the ioctl is called with a zero length buffer, then the
 * /dev/sysmsg module will return the size of the buffer needed to
 * contain a space separated list of auxiliary device names.
 *
 * When a buffer of the correct size is provided, the ioctl returns
 * a space separated list of auxiliary device names.
 */
#define	CIOCGETCONSOLE	0

/*
 * Set the given device to be an auxiliary console.  This will cause
 * console messages to also appear on that device.
 */
#define	CIOCSETCONSOLE	1

/*
 * Unset the given device as an auxiliary console.  Console
 * messages will not be displayed on that device any longer.
 */
#define	CIOCRMCONSOLE	2

/*
 * Return the dev_t for the controlling tty
 */
#define	CIOCTTYCONSOLE	3

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SYSMSG_IMPL_H */
