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
 * Copyright (c) 1995-1996, Sun Microsystems, Inc.  All Rights Reserved.
 */

#ifndef	_SYS_BOOTCMN_H
#define	_SYS_BOOTCMN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*	dummy device names for boot and floppy devices			*/
#define	BOOT_DEV_NAME	"<bootdev>"
#define	FLOPPY0_NAME	"/dev/diskette0"
#define	FLOPPY1_NAME	"/dev/diskette1"

/*	Maximum size (in characters) allotted to DOS volume labels	*/
#define	VOLLABELSIZE	11

#ifdef __cplusplus
}
#endif

#endif /* _SYS_BOOTCMN_H */
