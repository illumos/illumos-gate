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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma weak getpagesizes = _getpagesizes
#pragma weak getpagesizes2 = _getpagesizes2

#include "synonyms.h"
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>

/*
 * mman.h contains "#pragma redefine_extname getpagesizes getpagesizes2".
 * Applications that are still calling getpagesizes() instead of
 * getpagesizes2() are 'legacy' applications that have not been recompiled
 * since the #pragma redefine_extname change.
 *
 * Depending on the platform, 'legacy' applications may not be given the full
 * set of supported page sizes to prevent them from inadvertantly using 'new'
 * large pagesizes that might cause application failure or low system memory
 * conditions.
 *
 * The first parameter to the SYS_getpagesizes syscall is effectively
 * a 'legacy' boolean flag used as such in the kernel.
 */
int
getpagesizes(size_t pagesize[], int nelem)
{
	return (syscall(SYS_getpagesizes, 1, pagesize, nelem));
}

int
getpagesizes2(size_t pagesize[], int nelem)
{
	return (syscall(SYS_getpagesizes, 0, pagesize, nelem));
}
