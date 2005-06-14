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


/*
 * Fputwc transforms the wide character c into the multibyte character,
 * and writes it onto the output stream "iop".
 */

#include "lint.h"
#include "file64.h"
#include "mse_int.h"
#include "mtlib.h"
#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>
#include <limits.h>
#include <errno.h>
#include "stdiom.h"
#include "mse.h"

wint_t
__fputwc_xpg5(wint_t wc, FILE *iop)
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

	if (wc == WEOF) {
		FUNLOCKFILE(lk);
		return (WEOF);
	}
	n = fp_wctomb(lc, mbs, (wchar_t)wc);
	if (n <= 0) {
		FUNLOCKFILE(lk);
		return (WEOF);
	}
	p = (unsigned char *)mbs;
	while (n--) {
		/* Can wide I/O functions call byte I/O functions */
		/* because a steam bound to WIDE should not be used */
		/* by byte I/O functions ? */
		/* Anyway, I assume PUTC() macro has appropriate */
		/* definition here. */
		if (PUTC((*p++), iop) == EOF) {
			FUNLOCKFILE(lk);
			return (WEOF);
		}
	}
	FUNLOCKFILE(lk);
	return (wc);
}

wint_t
__putwc_xpg5(wint_t wc, FILE *iop)
{
	return (__fputwc_xpg5(wc, iop));
}
