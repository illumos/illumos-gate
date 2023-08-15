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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

	.file	"getrlimit.s"

/* C library -- getrlimit					*/
/* int getrlimit(int resources, struct rlimit *rlp)		*/

#include <sys/asm_linkage.h>

#if !defined(_LARGEFILE_SOURCE)
	ANSI_PRAGMA_WEAK(getrlimit,function)
#else
	ANSI_PRAGMA_WEAK(getrlimit64,function)
#endif

#include "SYS.h"

#if !defined(_LARGEFILE_SOURCE)

	SYSCALL_RVAL1(getrlimit)
	RETC
	SET_SIZE(getrlimit)

#else

/* C library -- getrlimit64					*/
/* int getrlimit64(int resources, struct rlimit64 *rlp)		*/

	SYSCALL_RVAL1(getrlimit64)
	RETC
	SET_SIZE(getrlimit64)

#endif
