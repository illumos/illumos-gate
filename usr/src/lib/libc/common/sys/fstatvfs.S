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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/


/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

	.file	"fstatvfs.s"

/* C library -- fstatvfs					*/
/* int fstatvfs(int fildes, struct statvfs *buf)		*/

#include <sys/asm_linkage.h>

#if !defined(_LARGEFILE_SOURCE)
	ANSI_PRAGMA_WEAK(fstatvfs,function)
#else
	ANSI_PRAGMA_WEAK(fstatvfs64,function)
#endif

#include "SYS.h"

#if !defined(_LARGEFILE_SOURCE)

	SYSCALL_RVAL1(fstatvfs)
	RETC
	SET_SIZE(fstatvfs)

#else

/* C library -- fstatvfs64					*/
/* int fstatvfs64(int fildes, struct statvfs64 *buf)		*/

	SYSCALL_RVAL1(fstatvfs64)
	RETC
	SET_SIZE(fstatvfs64)

#endif
