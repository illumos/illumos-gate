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

int
lx_xattr2(uintptr_t p1, uintptr_t p2)
{

	return (-EOPNOTSUPP);
}

int
lx_xattr3(uintptr_t p1, uintptr_t p2, uintptr_t p3)
{

	return (-EOPNOTSUPP);
}

int
lx_xattr4(uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4)
{

	return (-EOPNOTSUPP);
}
