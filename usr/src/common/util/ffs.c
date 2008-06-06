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

/*
 * Common implementation of ffs for kernel, mdb, and libc.  Note that mdb
 * renames ffs into mdb_ffs to avoid user-space clashes with the signature of
 * ffs(3C).
 */

#if defined(_KERNEL) || defined(ffs)
#include <sys/int_types.h>
#define	arg_t	uintmax_t
#else
#define	arg_t	int
#include "lint.h"
#endif

int
ffs(arg_t bits)
{
	int i;

	if (bits == 0)
		return (0);
	for (i = 1; ; i++, bits >>= 1) {
		if (bits & 1)
			break;
	}
	return (i);
}
