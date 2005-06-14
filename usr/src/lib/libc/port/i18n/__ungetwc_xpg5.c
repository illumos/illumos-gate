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

/*	Copyright (c) 1986 AT&T	*/
/*	  All Rights Reserved  	*/


/*	This module is created for NLS on Sep.03.86		*/

/*
 * Ungetwc saves the process code c into the one character buffer
 * associated with an input stream "iop". That character, c,
 * will be returned by the next getwc call on that stream.
 */

#include "lint.h"
#include "file64.h"
#include "mse_int.h"
#include <stdio.h>
#include <stdlib.h>
#include <widec.h>
#include <limits.h>
#include <errno.h>
#include "libc.h"
#include "stdiom.h"
#include "mse.h"

wint_t
__ungetwc_xpg5(wint_t wc, FILE *iop)
{
	char	mbs[MB_LEN_MAX];
	unsigned char	*p;
	int	n;
	void	*lc;
	int	(*fp_wctomb)(void *, char *, wchar_t);
	rmutex_t	*lk;

	FLOCKFILE(lk, iop);

	if (_set_orientation_wide(iop, &lc,
	    (void (*(*))(void))&fp_wctomb, FP_WCTOMB) == -1) {
		errno = EBADF;
		FUNLOCKFILE(lk);
		return (WEOF);
	}

	if ((wc == WEOF) || ((iop->_flag & _IOREAD) == 0)) {
		FUNLOCKFILE(lk);
		return (WEOF);
	}

	n = fp_wctomb(lc, mbs, (wchar_t)wc);
	if (n <= 0) {
		FUNLOCKFILE(lk);
		return (WEOF);
	}

	if (iop->_ptr <= iop->_base) {
		if (iop->_base == NULL) {
			FUNLOCKFILE(lk);
			return (WEOF);
		}
		if (iop->_ptr == iop->_base && iop->_cnt == 0) {
			++iop->_ptr;
		} else if ((iop->_ptr - n) < (iop->_base - PUSHBACK)) {
			FUNLOCKFILE(lk);
			return (WEOF);
		}
	}

	p = (unsigned char *)(mbs + n - 1);
	while (n--) {
		*--(iop)->_ptr = (*p--);
		++(iop)->_cnt;
	}
	iop->_flag &= ~_IOEOF;
	FUNLOCKFILE(lk);
	return (wc);
}
