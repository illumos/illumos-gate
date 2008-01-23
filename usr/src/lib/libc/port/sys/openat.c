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

#include "synonyms.h"
#include <stdarg.h>
#include <sys/types.h>
#include <sys/syscall.h>

#if !defined(_LP64) && _FILE_OFFSET_BITS == 64

int
__openat64(int fd, const char *name, int oflag, ...)
{
	va_list ap;
	mode_t mode;

	va_start(ap, oflag);
	mode = va_arg(ap, mode_t);
	va_end(ap);
	return (syscall(SYS_fsat, 1, fd, name, oflag, mode));
}

#else

int
__openat(int fd, const char *name, int oflag, ...)
{
	va_list ap;
	mode_t mode;

	va_start(ap, oflag);
	mode = va_arg(ap, mode_t);
	va_end(ap);
	return (syscall(SYS_fsat, 0, fd, name, oflag, mode));
}

#endif
