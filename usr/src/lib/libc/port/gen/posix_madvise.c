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

#include "lint.h"
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>

/*
 * SUSv3 - memory advisory information and alignment control
 *
 * The POSIX_MADV_* constants below are defined in <sys/mman.h>
 * to have the same values as the corresponding MADV_* constants,
 * also defined in <sys/mman.h>, so a direct call to madvise()
 * can be made here without further ado.
 */
int
posix_madvise(void *addr, size_t len, int advice)
{
	switch (advice) {
	case POSIX_MADV_NORMAL:
	case POSIX_MADV_SEQUENTIAL:
	case POSIX_MADV_RANDOM:
	case POSIX_MADV_WILLNEED:
	case POSIX_MADV_DONTNEED:
		break;
	default:
		return (EINVAL);
	}
	if (madvise(addr, len, advice) == 0)
		return (0);
	return (errno);
}
