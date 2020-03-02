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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Ptr args aren't checked for NULL because the program would be a
 * catastrophic mess anyway.  Better to abort than just to return NULL.
 */
#include "lint.h"
#include "file64.h"
#include "mtlib.h"
#include <stdio.h>
#include <string.h>
#include <thread.h>
#include <synch.h>
#include <sys/types.h>
#include <unistd.h>
#include <limits.h>
#include "stdiom.h"
#include "mse.h"

int
fputs(const char *ptr, FILE *iop)
{
	ssize_t ndone = 0L, n;
	unsigned char *cptr, *bufend;
	rmutex_t *lk;
	size_t	ptrlen;
	size_t	len = 0;
	int	c;

	FLOCKFILE(lk, iop);

	_SET_ORIENTATION_BYTE(iop);

	if (_WRTCHK(iop)) {
		FUNLOCKFILE(lk);
		return (EOF);
	}
	bufend = _bufend(iop);

	ptrlen = strlen(ptr);
	if ((iop->_flag & _IONBF) == 0) {
		for (; ; ptr += len, ptrlen -= len) {
			while ((n = bufend - (cptr = iop->_ptr)) <= 0) {
				/* full buf */
				if (_xflsbuf(iop) == EOF) {
					FUNLOCKFILE(lk);
					return (EOF);
				}
			}
			/*
			 * n: number of available bytes in the buffer of 'iop'
			 * ptrlen: number of remaining bytes in 'ptr' string
			 *
			 * If all remaining bytes in 'ptr' can be copied into
			 * the buffer of 'iop' (ptrlen <= n), 'len' is set to
			 * 'ptrlen'.  Otherwise, 'len' is set to 'n'.
			 * Then, copies 'len' bytes from 'ptr' to the buffer
			 * of 'iop'.
			 */
			len = (c = (ptrlen <= n)) ? ptrlen : n;
			(void) memcpy(cptr, ptr, len);
			iop->_cnt -= len;
			iop->_ptr += len;
			if (_needsync(iop, bufend))
				_bufsync(iop, bufend);
			ndone += len;
			if (c) {
				/*
				 * All bytes in 'ptr' have been copied into
				 * the buffer of 'iop'.
				 * Flush buffer if line-buffered
				 */
				if (iop->_flag & _IOLBF)
					if (_xflsbuf(iop) == EOF) {
						FUNLOCKFILE(lk);
						return (EOF);
					}
				FUNLOCKFILE(lk);
				if (ndone <= INT_MAX)
					return ((int)ndone);
				else
					return (EOF);
			}
		}
	} else {
		/* write out to an unbuffered file */
		ssize_t num_wrote;
		ssize_t count = (ssize_t)ptrlen;

		while ((num_wrote = _xwrite(iop, ptr, (size_t)count)) !=
		    count) {
			if (num_wrote <= 0) {
				if (!cancel_active())
					iop->_flag |= _IOERR;
				FUNLOCKFILE(lk);
				return (EOF);
			}
			count -= num_wrote;
			ptr += num_wrote;
		}
		FUNLOCKFILE(lk);
		if (ptrlen <= INT_MAX)
			return ((int)ptrlen);
		else
			return (EOF);
	}
}
