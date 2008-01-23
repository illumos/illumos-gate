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

/* C library -- pread					*/
/* ssize_t __pread(int, void *, size_t, off_t);		*/

#include "SYS.h"

#if !defined(_LARGEFILE_SOURCE)

	SYSCALL2_RESTART_RVAL1(__pread,pread)
	RET
	SET_SIZE(__pread)

#else

/* C library -- pread64 transitional large file API	*/
/* ssize_t __pread(int, void *, size_t, off64_t);	*/

	SYSCALL2_RESTART_RVAL1(__pread64,pread64)
	RET
	SET_SIZE(__pread64)

#endif
