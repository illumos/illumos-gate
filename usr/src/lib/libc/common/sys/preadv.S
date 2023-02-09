/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2015, Joyent, Inc.  All rights reserved.
 */

	.file	"preadv.s"

/* C library -- preadv							*/
/* ssize_t __preadv(int, const struct iovec *, int, off_t, off_t);	*/

#include "SYS.h"

#if !defined(_LARGEFILE_SOURCE)

	SYSCALL2_RESTART_RVAL1(__preadv,preadv)
	RET
	SET_SIZE(__preadv)

#else

/* C library -- preadv64 transitional large file API			*/
/* ssize_t __preadv64(int, void *, size_t, off_t, off_t);		*/

	SYSCALL2_RESTART_RVAL1(__preadv64,preadv)
	RET
	SET_SIZE(__preadv64)

#endif
