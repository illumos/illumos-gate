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
 * Copyright 2026 Oxide Computer Company
 */

	.file	"close_range.s"

/*
 * int
 * __close_range(unsigned int low, unsigned int high, int flags);
 *
 * The public close_range() is a C wrapper in port/threads/scalls.c which
 * cancels outstanding user-level asynchronous I/O against the descriptors
 * before invoking this system call.
 */

#include "SYS.h"

	SYSCALL2_RVAL1(__close_range,close_range)
	RETC
	SET_SIZE(__close_range)
