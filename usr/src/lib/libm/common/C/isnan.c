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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma weak isnan = __isnan
#pragma weak _isnan = __isnan
#pragma weak _isnand = __isnan
#pragma weak isnand = __isnan

#include "libm.h"

/*
 * The following implementation assumes fast 64-bit integer arith-
 * metic.  This is fine for sparc because we build libm in v8plus
 * mode.  It's also fine for sparcv9 and amd64.  For x86, it would
 * be better to use 32-bit code, but we have assembly for x86.
 */
int
__isnan(double x) {
	long long	llx;

	llx = *(long long *)&x & ~0x8000000000000000ull;
	return ((unsigned long long)(0x7ff0000000000000ll - llx) >> 63);
}
