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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

	.file	"%M%"

#include "SYS.h"

#if !defined(_LARGEFILE_SOURCE)

/* C library -- pwrite						*/
/* ssize_t __pwrite(int, const void *, size_t, off_t);		*/

	SYSCALL2_RESTART_RVAL1(__pwrite,pwrite)
	RET
	SET_SIZE(__pwrite)

#else

/* C library -- pwrite64 transitional large file API		*/
/* ssize_t __pwrite64(int, const void *, size_t, off64_t);	*/

	SYSCALL2_RESTART_RVAL1(__pwrite64,pwrite64)
	RET
	SET_SIZE(__pwrite64)

#endif
