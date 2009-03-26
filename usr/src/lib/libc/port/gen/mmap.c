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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "lint.h"
#include <sys/feature_tests.h>
#include <sys/mman.h>

extern void unregister_locks(caddr_t, size_t);

#if !defined(_LP64) && _FILE_OFFSET_BITS == 64

extern caddr_t __mmap64(caddr_t, size_t, int, int, int, off64_t);

#pragma weak _mmap64 = mmap64
caddr_t
mmap64(caddr_t addr, size_t len, int prot, int flags, int fildes, off64_t off)
{
	if (flags & MAP_FIXED)
		unregister_locks(addr, len);
	return (__mmap64(addr, len, prot, flags, fildes, off));
}

#else

extern caddr_t __mmap(caddr_t, size_t, int, int, int, off_t);

#pragma weak _mmap = mmap
caddr_t
mmap(caddr_t addr, size_t len, int prot, int flags, int fildes, off_t off)
{
	if (flags & MAP_FIXED)
		unregister_locks(addr, len);
	return (__mmap(addr, len, prot, flags, fildes, off));
}

#endif
