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
 * Fgetws reads multibyte characters from the "iop", converts
 * them to process codes, and places them in the wchar_t
 * array pointed to by "ptr". Fgetws reads until n-1 process
 * codes are transferred to "ptr", or EOF.
 */

#include "lint.h"
#include "file64.h"
#include "mse_int.h"
#include <stdlib.h>
#include <stdio.h>
#include <widec.h>
#include <errno.h>
#include "mtlib.h"
#include "stdiom.h"
#include "libc.h"
#include "mse.h"

wchar_t *
__fgetws_xpg5(wchar_t *ptr, int size, FILE *iop)
{
	wchar_t	*ptr0 = ptr;
	int	c;
	void	*lc;
	wint_t	(*fp_fgetwc)(void *, FILE *);
	rmutex_t	*lk;

	FLOCKFILE(lk, iop);

	if (_set_orientation_wide(iop, &lc,
	    (void (*(*))(void))&fp_fgetwc, FP_FGETWC) == -1) {
		errno = EBADF;
		FUNLOCKFILE(lk);
		return (NULL);
	}

	for (size--; size > 0; size--) {
		if ((c = fp_fgetwc(lc, iop)) == EOF) {
			if (ptr == ptr0) {
				FUNLOCKFILE(lk);
				return (NULL);
			}
			break;
		}
		*ptr++ = c;
		if (c == '\n')
			break;
	}
	*ptr = 0;
	FUNLOCKFILE(lk);
	return (ptr0);
}
