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
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

/*
 * *xattr() family of functions.
 *
 * These are currently unimplemented.  We return EOPNOTSUPP for now, rather
 * than using NOSYS_NO_EQUIV to avoid unwanted stderr output from ls(1).
 */

#include <errno.h>
#include <sys/types.h>
#include <sys/lx_types.h>
#include <sys/lx_syscall.h>

long
lx_xattr2(uintptr_t p1, uintptr_t p2)
{

	return (-EOPNOTSUPP);
}

long
lx_xattr3(uintptr_t p1, uintptr_t p2, uintptr_t p3)
{

	return (-EOPNOTSUPP);
}

long
lx_xattr4(uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4)
{

	return (-EOPNOTSUPP);
}
