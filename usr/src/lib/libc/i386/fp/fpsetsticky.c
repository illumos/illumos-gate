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
#include <ieeefp.h>

#pragma weak _fpsetsticky = fpsetsticky

extern int	_sse_hw;
extern void	_getsw(int *), _putsw(int), _getmxcsr(int *), _putmxcsr(int);

fp_except
fpsetsticky(fp_except s)
{
	int		sw, mxcsr;

	_getsw(&sw);
	_putsw((int)s);
	if (_sse_hw) {
		_getmxcsr(&mxcsr);
		sw |= mxcsr;
		mxcsr = (mxcsr & ~0x3f) | ((int)s & 0x3f);
		_putmxcsr(mxcsr);
	}
	return ((fp_except)(sw & 0x3f));
}
