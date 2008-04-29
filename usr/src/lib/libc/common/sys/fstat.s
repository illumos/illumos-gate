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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

	.file	"%M%"

/* C library -- fstat						*/
/* int fstat (int fildes, struct stat *buf)			*/

#include <sys/asm_linkage.h>

#if !defined(_LARGEFILE_SOURCE)
	ANSI_PRAGMA_WEAK(fstat,function)
#else
	ANSI_PRAGMA_WEAK(fstat64,function)
#endif

#include "SYS.h"

#if !defined(_LARGEFILE_SOURCE)
	
	SYSCALL_RVAL1(fstat)
	RETC
	SET_SIZE(fstat)

#else

/* C library -- fstat64 transitional large file API		*/
/* int fstat64 (int fildes, struct stat64 *buf)			*/

	SYSCALL_RVAL1(fstat64)
	RETC
	SET_SIZE(fstat64)

#endif
