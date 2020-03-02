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

#pragma weak __flsbuf = _flsbuf

#include "lint.h"
#include "file64.h"
#include <mtlib.h>
#include <stdio.h>
#include <thread.h>
#include <synch.h>
#include <unistd.h>
#include <sys/types.h>
#include "stdiom.h"

/*
 * flush (write) buffer, save ch,
 * return EOF on failure
 */
int
_flsbuf(int ch, FILE *iop)
{
	Uchar uch;

	do {	/* only loop if need to use _wrtchk() on non-_IOFBF */
		switch (iop->_flag & (_IOFBF | _IOLBF | _IONBF |
		    _IOWRT | _IOEOF)) {
		case _IOFBF | _IOWRT:	/* okay to do full-buffered case */
			if (iop->_base != 0 && iop->_ptr > iop->_base)
				goto flush_putc;	/* skip _wrtchk() */
			break;
		case _IOLBF | _IOWRT:	/* okay to do line-buffered case */
			if (iop->_ptr >= _bufend(iop))
				/*
				 * which will recursively call
				 * __flsbuf via putc because of no room
				 * in the buffer for the character
				 */
				goto flush_putc;
			if ((*iop->_ptr++ = (unsigned char)ch) == '\n')
				(void) _xflsbuf(iop);
			iop->_cnt = 0;
			goto out;
		case _IONBF | _IOWRT:	/* okay to do no-buffered case */
			iop->_cnt = 0;
			uch = (unsigned char)ch;
			if (_xwrite(iop, (char *)&uch, 1) != 1) {
				if (!cancel_active())
					iop->_flag |= _IOERR;
				return (EOF);
			}
			goto out;
		}
		if (_wrtchk(iop) != 0)	/* check, correct permissions */
			return (EOF);
	} while (iop->_flag & (_IOLBF | _IONBF));
flush_putc:
	(void) _xflsbuf(iop);
	(void) PUTC(ch, iop); /*  recursive call */
out:
	/* necessary for putc() */
	return ((iop->_flag & _IOERR) ? EOF : (unsigned char)ch);
}
