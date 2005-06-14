/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2000-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include <errno.h>
#include <sys/syscall.h>

/*
 * __set_errno() takes an error number, maps ERESTART into EINTR, and sets
 * the global (or per-thread) errno.  It returns the mapped error number.
 * __set_errno(error) is designed to be used after calling __systemcall()
 * and getting a non-zero error return value.  (__systemcall() does not
 * set errno and does not deal with ERESTART; it just returns the error
 * number, if any, from the system call.)
 */
int
__set_errno(int error)
{
	if (error == ERESTART)
		error = EINTR;
	errno = error;
	return (error);
}
