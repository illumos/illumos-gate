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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_BALLOON_H
#define	_SYS_BALLOON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define	BALLOON_DEV_NAME	"balloon"
#define	BALLOON_PATHNAME	"xen/" BALLOON_DEV_NAME

#define	BALLOON_DRIVER_NAME	"balloon"

#define	BLN_IOCTL_BASE		('B' << 24) | ('A' << 16)

/*
 * To return the desired value.  These defines are copied in balloon.py
 * in the hypervisor gate, so woe befall anyone who changes these.
 */
#define	BLN_IOCTL_CURRENT	(BLN_IOCTL_BASE | 0x1)
#define	BLN_IOCTL_TARGET	(BLN_IOCTL_BASE | 0x2)
#define	BLN_IOCTL_LOW		(BLN_IOCTL_BASE | 0x3)
#define	BLN_IOCTL_HIGH		(BLN_IOCTL_BASE | 0x4)
#define	BLN_IOCTL_LIMIT		(BLN_IOCTL_BASE | 0x5)

#ifdef __cplusplus
}
#endif

#endif /* _SYS_BALLOON_H */
