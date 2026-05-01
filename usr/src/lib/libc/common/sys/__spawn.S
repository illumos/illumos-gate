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

	.file	"__spawn.s"

/*
 * pid_t
 * __spawn(const char *path, const void *sp, uint32_t spsize,
 *     const void *sa, uint32_t sasize);
 */

#include "SYS.h"

	SYSCALL2_RVAL1(__spawn, spawn)
	RET
	SET_SIZE(__spawn)
