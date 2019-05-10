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

#include "lint.h"

#include <sys/sysmacros.h>

#include <stdlib.h>
#include <errno.h>

/*
 * SUSv3 - aligned memory allocation
 *
 * From the SUSv3 specification:
 *    The value of alignment shall be a power
 *    of two multiple of sizeof (void *).
 * This is enforced below.
 *
 * From the SUSv3 specification:
 *    If the size of the space requested is 0, the behavior
 *    is implementation-defined; the value returned in memptr
 *    shall be either a null pointer or a unique pointer.
 * We choose always to return a null pointer in this case.
 * (Not all implementations of memalign() behave this way.)
 */
int
posix_memalign(void **memptr, size_t alignment, size_t size)
{
	void *ptr = NULL;

	if ((alignment == 0) || !ISP2(alignment) ||
	    (alignment & (sizeof (void *) - 1)) != 0) {
		return (EINVAL);
	} else if (size == 0) {
		*memptr = NULL;
		return (0);
	} else {
		if ((ptr = memalign(alignment, size)) == NULL) {
			return (ENOMEM);
		} else {
			*memptr = ptr;
			return (0);
		}
	}
}
