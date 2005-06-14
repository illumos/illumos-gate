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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include "file64.h"
#include "mse_int.h"
#include "mtlib.h"
#include <stdio.h>
#include <widec.h>
#include <euc.h>
#include <errno.h>
#include "stdiom.h"
#include "mse.h"

wint_t
__fgetwc_xpg5(FILE *iop)
{
	wint_t	result;
	void	*lc;
	wint_t	(*fp_fgetwc)(void *, FILE *);
	rmutex_t	*lk;

	FLOCKFILE(lk, iop);

	if (_set_orientation_wide(iop, &lc,
	    (void (*(*))(void))&fp_fgetwc, FP_FGETWC) == -1) {
		errno = EBADF;
		FUNLOCKFILE(lk);
		return (WEOF);
	}

	result = fp_fgetwc(lc, iop);
	FUNLOCKFILE(lk);
	return (result);
}

wint_t
__getwc_xpg5(FILE *iop)
{
	return (__fgetwc_xpg5(iop));
}
