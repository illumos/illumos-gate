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

#pragma weak __filbuf = _filbuf

#include "lint.h"
#include "file64.h"
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include "stdiom.h"


static int
_xpg4_check(void)
{
	extern int	__xpg4;

	return (__xpg4);
}

/* fill buffer, return first character or EOF */
int
_filbuf(FILE *iop)
{
	ssize_t res;
	size_t nbyte;
	Uchar *endbuf;
#ifdef	_LP64
	unsigned int	flag;
#else
	unsigned char	flag;
#endif

	if (!(iop->_flag & _IOREAD)) {	/* check, correct permissions */
		if (iop->_flag & _IORW) {
			iop->_flag |= _IOREAD;  /* change direction */
						/* to read - fseek */
		} else {
			errno = EBADF;
			return (EOF);
		}
	}

	if (iop->_base == 0) {
		/* Get the buffer and end of buffer */
		if ((endbuf = _findbuf(iop)) == 0) {
			return (EOF);
		}
	} else {
		endbuf = _bufend(iop);
	}

	/*
	 * Flush all line-buffered streams before we
	 * read no-buffered or line-buffered input.
	 */
	if (iop->_flag & (_IONBF | _IOLBF))
		_flushlbf();
	/*
	 * Changed the get family fns in Solaris 10 to comply with the
	 * 1990 C Standard and standards based upon it.  If the
	 * end-of-file indicator for the stream is set, or if the stream
	 * is at end-of-file, the function will return EOF, and the file
	 * position indicator for the stream will not be advanced.
	 * Additional bytes appended to the file do not clear the EOF
	 * indicator.
	 */
	if ((flag = iop->_flag) & _IOEOF) {
		if (_xpg4_check()) {
			/*
			 * A previous read() has returned 0 (below),
			 * therefore iop->_cnt was set to 0, and the EOF
			 * indicator was set before returning EOF.  Reset
			 * iop->_cnt to 0; it has likely been changed by
			 * a function such as getc().
			 */
			iop->_cnt = 0;
			return (EOF);
		}
	}

	/*
	 * Fill buffer or read 1 byte for unbuffered, handling any errors.
	 */
	iop->_ptr = iop->_base;
	if (flag & _IONBF)
		nbyte = 1;
	else
		nbyte = endbuf - iop->_base;
	if ((res = _xread(iop, (char *)iop->_base, nbyte)) > 0) {
		iop->_cnt = res - 1;
		return (*iop->_ptr++);
	}

	iop->_cnt = 0;
	if (res == 0)
		iop->_flag |= _IOEOF;
	else if (!cancel_active())
		iop->_flag |= _IOERR;
	return (EOF);
}
