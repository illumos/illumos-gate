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

/*	Copyright (c) 1986 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * fputws transforms the process code string pointed to by "ptr"
 * into a byte string, and writes the string to the named
 * output "iop".
 *
 * Use an intermediate buffer to transform a string from wchar_t to
 * multibyte char.  In order to not overflow the intermediate buffer,
 * impose a limit on the length of string to output to PC_MAX process
 * codes.  If the input string exceeds PC_MAX process codes, process
 * the string in a series of smaller buffers.
 */

#include "lint.h"
#include "file64.h"
#include "mse_int.h"
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <widec.h>
#include <macros.h>
#include <errno.h>
#include "libc.h"
#include "stdiom.h"
#include "mse.h"

#define	PC_MAX 		256
#define	MBBUFLEN	(PC_MAX * MB_LEN_MAX)

int
__fputws_xpg5(const wchar_t *ptr, FILE *iop)
{
	int	pcsize, ret;
	ssize_t	pclen, pccnt;
	int	nbytes, i;
	char	mbbuf[MBBUFLEN], *mp;
	void	*lc;
	int	(*fp_wctomb)(void *, char *, wchar_t);
	rmutex_t	*lk;

	FLOCKFILE(lk, iop);

	if (_set_orientation_wide(iop, &lc,
	    (void (*(*))(void))&fp_wctomb, FP_WCTOMB) == -1) {
		errno = EBADF;
		FUNLOCKFILE(lk);
		return (EOF);
	}

	pclen = pccnt = wcslen(ptr);
	while (pclen > 0) {
		pcsize = (int)min(pclen, PC_MAX - 1);
		nbytes = 0;
		for (i = 0, mp = mbbuf; i < pcsize; i++, mp += ret) {
			if ((ret = fp_wctomb(lc, mp, *ptr++)) == -1) {
				FUNLOCKFILE(lk);
				return (EOF);
			}
			nbytes += ret;
		}
		*mp = '\0';
		/*
		 * In terms of locking, since libc is using rmutex_t
		 * for locking iop, we can call fputs() with iop that
		 * has been already locked.
		 * But again,
		 * can wide I/O functions call byte I/O functions
		 * because a steam bound to WIDE should not be used
		 * by byte I/O functions ?
		 */
		if (fputs(mbbuf, iop) != nbytes) {
			FUNLOCKFILE(lk);
			return (EOF);
		}
		pclen -= pcsize;
	}
	FUNLOCKFILE(lk);
	if (pccnt <= INT_MAX)
		return ((int)pccnt);
	else
		return (EOF);
}
