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
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include "file64.h"
#include "mtlib.h"
#include <sys/types.h>
#include <stdio.h>
#include <memory.h>
#include <thread.h>
#include <synch.h>
#include <limits.h>
#include "stdiom.h"
#include "mse.h"

int
puts(const char *ptr)
{
	ssize_t ndone = 0L, n;
	unsigned char *cptr, *bufend;
	rmutex_t *lk;
	size_t	ptrlen;
	size_t	len = 0;
	int	c;

	FLOCKFILE(lk, stdout);

	_SET_ORIENTATION_BYTE(stdout);

	if (_WRTCHK(stdout)) {
		FUNLOCKFILE(lk);
		return (EOF);
	}

	bufend = _bufend(stdout);

	ptrlen = strlen(ptr) + 1;	/* adding 1 for '\n' */
	for (; ; ptr += len, ptrlen -= len) {
		while ((n = bufend - (cptr = stdout->_ptr)) <= 0) /* full buf */
		{
			if (_xflsbuf(stdout) == EOF) {
				FUNLOCKFILE(lk);
				return (EOF);
			}
		}
		/*
		 * n: number of available bytes in the buffer of stdout
		 * ptrlen: number of remaining bytes in 'ptr' string
		 *
		 * If all remaining bytes in 'ptr' can be copied into
		 * the buffer of stdout (ptrlen <= n), 'len' is set to
		 * 'ptrlen'.  Otherwise, 'len' is set to 'n'.
		 * Then, copies 'len' bytes from 'ptr' to the buffer
		 * of stdout.
		 */
		len = (c = (ptrlen <= n)) ? ptrlen : n;
		(void) memcpy(cptr, ptr, len);
		stdout->_cnt -= len;
		stdout->_ptr += len;
		if (_needsync(stdout, bufend))
			_bufsync(stdout, bufend);
		ndone += len;
		if (c) {
			/*
			 * All bytes in 'ptr' can be copied into
			 * the buffer of stdout.
			 * Terminate the buffer of stdout with '\n'
			 * and flush line buffer
			 */
			stdout->_ptr[-1] = '\n';
			if (stdout->_flag & (_IONBF | _IOLBF)) {
				/* flush line */
				if (_xflsbuf(stdout) == EOF) {
					FUNLOCKFILE(lk);
					return (EOF);
				}
			}
			FUNLOCKFILE(lk);
			if (ndone <= INT_MAX)
				return ((int)ndone);
			else
				return (EOF);
		}
	}
}
