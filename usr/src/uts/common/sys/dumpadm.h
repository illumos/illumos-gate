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
 * Copyright (c) 1998, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012 by Delphix. All rights reserved.
 */

#ifndef	_SYS_DUMPADM_H
#define	_SYS_DUMPADM_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * ioctl commands for /dev/dump
 */
#define	DDIOC		(0xdd << 8)
#define	DIOCGETDUMPSIZE	(DDIOC | 0x10)
#define	DIOCGETCONF	(DDIOC | 0x11)
#define	DIOCSETCONF	(DDIOC | 0x12)
#define	DIOCGETDEV	(DDIOC | 0x13)
#define	DIOCSETDEV	(DDIOC | 0x14)
#define	DIOCTRYDEV	(DDIOC | 0x15)
#define	DIOCDUMP	(DDIOC | 0x16)
#define	DIOCSETUUID	(DDIOC | 0x17)
#define	DIOCGETUUID	(DDIOC | 0x18)
#define	DIOCRMDEV	(DDIOC | 0x19)

/*
 * Kernel-controlled dump state flags for dump_conflags
 */
#define	DUMP_EXCL	0x00000001	/* dedicated dump device (not swap) */
#define	DUMP_STATE	0x0000ffff	/* the set of all kernel flags */

/*
 * User-controlled dump content flags (mutually exclusive) for dump_conflags
 */
#define	DUMP_KERNEL	0x00010000	/* dump kernel pages only */
#define	DUMP_ALL	0x00020000	/* dump all pages */
#define	DUMP_CURPROC	0x00040000	/* dump kernel, panicking proc pages */
#define	DUMP_CONTENT	0xffff0000	/* the set of all dump content flags */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DUMPADM_H */
