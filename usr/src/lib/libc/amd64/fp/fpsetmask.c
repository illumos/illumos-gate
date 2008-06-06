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
/*	  All Rights Reserved	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma weak _fpsetmask = fpsetmask

extern void	_getmxcsr(int *), _putmxcsr(int);

#include "lint.h"
#include <ieeefp.h>
#include "fp.h"

fp_except
fpsetmask(fp_except newmask)
{
	struct _cw87 cw;
	fp_except oldmask;
	int	mxcsr;

	_getcw(&cw);
	oldmask = (fp_except)(~cw.mask & EXCPMASK);
	cw.mask = ~((unsigned)newmask) & EXCPMASK;
	_putcw(cw);
	_getmxcsr(&mxcsr);
	mxcsr = (mxcsr & ~0x1f80) | (~((int)newmask << 7) & 0x1f80);
	_putmxcsr(mxcsr);
	return (oldmask);
}
