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

#pragma weak _fpgetsticky = fpgetsticky

#include "lint.h"
#include <ieeefp.h>

extern int	_sse_hw;
extern void	_getsw(int *), _getmxcsr(int *);

fp_except
fpgetsticky(void)
{
	int	sw, mxcsr;

	_getsw(&sw);
	if (_sse_hw) {
		_getmxcsr(&mxcsr);
		sw |= mxcsr;
	}
	return ((fp_except)(sw & 0x3f));
}
