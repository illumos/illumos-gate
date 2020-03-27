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
 * Copyright 2020 Robert Mustacchi
 */


#define	_LARGEFILE64_SOURCE	1

#include "lint.h"
#include "file64.h"
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "stdiom.h"

/*
 * If buffer space has been pre-allocated use it otherwise malloc space.
 * PUSHBACK causes the base pointer to be bumped forward. At least 4 bytes
 * of pushback are required to meet international specifications.
 * Extra space at the end of the buffer allows for synchronization problems.
 * If malloc() fails stdio bails out; assumption being the system is in trouble.
 * Associate a buffer with stream; return NULL on error.
 */
Uchar *
_findbuf(FILE *iop)
{
	int fd = _get_fd(iop);
	Uchar *buf;
	int size = BUFSIZ;
	Uchar *endbuf;
	int tty = -1;

	if (iop->_flag & _IONBF) {	/* need a small buffer, at least */
	trysmall:
		size = _SMBFSZ - PUSHBACK;
		if (fd >= 0 && fd < _NFILE) {
			buf = _smbuf[fd];
		} else if ((buf = (Uchar *)malloc(_SMBFSZ * sizeof (Uchar))) !=
		    NULL) {
			iop->_flag |= _IOMYBUF;
		}
	} else if (fd >= 0 && fd < 2 && (tty = isatty(fd))) {
		/* Use special buffers for standard in and standard out */
		buf = (fd == 0) ? _sibuf : _sobuf;
	} else {

		/*
		 * The operating system can tell us the right size for a buffer;
		 * avoid 0-size buffers as returned for some special files
		 * (doors). Use the default buffer size for memory streams.
		 */
		struct stat64 stbuf;

		if (fd != -1 && fstat64(fd, &stbuf) == 0 && stbuf.st_blksize >
		    0) {
			size = stbuf.st_blksize;
		}

		if ((buf = (Uchar *)malloc(sizeof (Uchar)*(size+_SMBFSZ))) !=
		    NULL) {
			iop->_flag |= _IOMYBUF;
		} else {
			goto trysmall;
		}
	}
	if (buf == NULL)
		return (NULL);	/* malloc() failed */
	iop->_base = buf + PUSHBACK;	/* bytes for pushback */
	iop->_ptr = buf + PUSHBACK;
	endbuf = iop->_base + size;
	_setbufend(iop, endbuf);
	if (!(iop->_flag & _IONBF) && ((tty != -1) ? tty : isatty(fd)))
		iop->_flag |= _IOLBF;
	return (endbuf);
}
