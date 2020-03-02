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

#include "lint.h"
#include "file64.h"
#include "mtlib.h"
#include <sys/types.h>
#include <stdio.h>
#include <values.h>
#include <memory.h>
#include <thread.h>
#include <synch.h>
#include <unistd.h>
#include "stdiom.h"
#include "mse.h"

size_t
_fwrite_unlocked(const void *ptr, size_t size, size_t count, FILE *iop);

size_t
fwrite(const void *ptr, size_t size, size_t count, FILE *iop)
{
	rmutex_t	*lk;
	size_t	retval;

	FLOCKFILE(lk, iop);

	_SET_ORIENTATION_BYTE(iop);

	retval = _fwrite_unlocked(ptr, size, count, iop);
	FUNLOCKFILE(lk);

	return (retval);
}

size_t
_fwrite_unlocked(const void *ptr, size_t size, size_t count, FILE *iop)
{
	ssize_t s, n;
	unsigned char *dptr = (unsigned char *)ptr;
	unsigned char *bufend;

	if (_WRTCHK(iop))
		return (0);

	/*
	 * This test is here to avoid the expensive multiply
	 */
	if (count == 1)
		s = size;
	else if (size == 1)
		s = count;
	else
		s = size * count;

	if (iop->_flag & _IOLBF) {
		bufend = _bufend(iop);
		iop->_cnt = iop->_base - iop->_ptr;
		while (s > 0) {
			ssize_t buflen = bufend - iop->_base;
			if (--iop->_cnt >= (-buflen) && *dptr != '\n')
				*iop->_ptr++ = *dptr++;
			else if (__flsbuf(*dptr++, iop) == EOF)
				break;
			s--;
		}
	} else if (iop->_flag & _IONBF) {
		ssize_t bytes;
		ssize_t written = 0;
		char *data;

		if (size < 1 || count < 1)
			return (0);

		if (iop->_base != iop->_ptr) {
		/*
		 * Flush any existing data. Doesn't count towards return
		 * value.
		 */
			bytes = iop->_ptr - iop->_base;
			data = (char *)iop->_base;

			while ((n = _xwrite(iop, data, (size_t)bytes)) !=
			    bytes) {
				if (n <= 0) {
					if (!cancel_active())
						iop->_flag |= _IOERR;
					return (0);
				} else {
					data += n;
					bytes -= n;
				}
			}
			iop->_cnt = 0;
			iop->_ptr = iop->_base;
		}
		/*
		 * written is in bytes until the return.
		 * Then it is divided by size to produce items.
		 */
		while ((n = _xwrite(iop, dptr, s)) != s) {
			if (n <= 0) {
				if (!cancel_active())
					iop->_flag |= _IOERR;
				return (written / size);
			} else {
				dptr += n;
				s -= n;
				written += n;
			}
		}
		written += n;
		return (written / size);
	} else while (s > 0) {
		if (iop->_cnt < s) {
			if (iop->_cnt > 0) {
				(void) memcpy(iop->_ptr, (void *)dptr,
				    iop->_cnt);
				dptr += iop->_cnt;
				iop->_ptr += iop->_cnt;
				s -= iop->_cnt;
			}
			if (_xflsbuf(iop) == EOF)
				break;
		}
		if (iop->_cnt >= s) {
			char *tmp = (char *)iop->_ptr;

			switch (s) {
			case 8:
				*tmp++ = *dptr++;
				/*FALLTHRU*/
			case 7:
				*tmp++ = *dptr++;
				/*FALLTHRU*/
			case 6:
				*tmp++ = *dptr++;
				/*FALLTHRU*/
			case 5:
				*tmp++ = *dptr++;
				/*FALLTHRU*/
			case 4:
				*tmp++ = *dptr++;
				/*FALLTHRU*/
			case 3:
				*tmp++ = *dptr++;
				/*FALLTHRU*/
			case 2:
				*tmp++ = *dptr++;
				/*FALLTHRU*/
			case 1:
				*tmp++ = *dptr++;
				break;
			case 0:
				return (count);
			default:
				(void) memcpy(iop->_ptr, (void *)dptr, s);
			}
			iop->_ptr += s;
			iop->_cnt -= s;

			return (count);
		}
	}

	return (size != 0 ? count - ((s + size - 1) / size) : 0);
}
