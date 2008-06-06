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

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma weak _fpsetround = fpsetround

#include "lint.h"
#include <ieeefp.h>
#include "fp.h"

extern int	_sse_hw;
extern void	_getmxcsr(int *), _putmxcsr(int);

fp_rnd
fpsetround(fp_rnd newrnd)
{
	struct _cw87 cw;
	fp_rnd oldrnd;
	int	mxcsr;
	extern int __flt_rounds;  /* ANSI value for rounding */

	newrnd &= 0x3;	/* mask off all ubt last 2 bits */
	switch (newrnd) {	/* set ANSI rounding mode */
	case FP_RN:	__flt_rounds = 1;
			break;
	case FP_RM:	__flt_rounds = 3;
			break;
	case FP_RP:	__flt_rounds = 2;
			break;
	case FP_RZ:	__flt_rounds = 0;
			break;
	};
	_getcw(&cw);
	oldrnd = (fp_rnd)cw.rnd;
	cw.rnd = newrnd;
	_putcw(cw);
	if (_sse_hw) {
		_getmxcsr(&mxcsr);
		mxcsr = (mxcsr & ~0x6000) | ((int)newrnd << 13);
		_putmxcsr(mxcsr);
	}
	return (oldrnd);
}
