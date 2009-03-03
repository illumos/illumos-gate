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

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc. */

/* 	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T   */
/*	 All Rights Reserved   */

#ifndef _SYS_KD_H
#define	_SYS_KD_H

/*
 * Minimal compatibility support for "kd" ioctls.
 *
 * This file may be deleted or changed without notice.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	KDIOC		('K'<<8)
#define	KDGETMODE	(KDIOC|9)	/* get text/graphics mode */
#define	KDSETMODE	(KDIOC|10)	/* set text/graphics mode */
#define	KD_TEXT		0
#define	KD_GRAPHICS	1
#define	KD_RESETTEXT	2

#ifdef __cplusplus
}
#endif

#endif /* _SYS_KD_H */
