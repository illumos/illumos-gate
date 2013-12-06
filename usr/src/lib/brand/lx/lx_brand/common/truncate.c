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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <errno.h>
#include <unistd.h>
#include <sys/lx_types.h>
#include <sys/lx_misc.h>

/*
 * On Solaris, truncate() and ftruncate() are implemented in libc, so these are
 * layered on those interfaces.
 */

int
lx_truncate(uintptr_t path, uintptr_t length)
{
	return (truncate((const char *)path, (off_t)length) == 0 ? 0 : -errno);
}

int
lx_ftruncate(uintptr_t fd, uintptr_t length)
{
	return (ftruncate((int)fd, (off_t)length) == 0 ? 0 : -errno);
}

int
lx_truncate64(uintptr_t path, uintptr_t length_lo, uintptr_t length_hi)
{
	return (truncate64((const char *)path,
	    LX_32TO64(length_lo, length_hi)) == 0 ? 0 : -errno);
}

int
lx_ftruncate64(uintptr_t fd, uintptr_t length_lo, uintptr_t length_hi)
{
	return (ftruncate64((int)fd,
	    LX_32TO64(length_lo, length_hi)) == 0 ? 0 : -errno);
}
