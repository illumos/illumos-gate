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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include <sys/types.h>
#include "file64.h"
#include <stdio.h>
#include "stdiom.h"
#include <stdlib.h>

extern Uchar _smbuf[][_NFILE];

void
setbuffer(FILE *iop, char *abuf, int asize)
{
	Uchar *buf = (Uchar *)abuf;
	int fno = fileno(iop);  /* file number */
	int size = asize - _SMBFSZ;
	Uchar *temp;

	if (iop->_base != 0 && iop->_flag & _IOMYBUF)
		free((char *)iop->_base - PUSHBACK);
	iop->_flag &= ~(_IOMYBUF | _IONBF | _IOLBF);
	if (buf == 0) {
		iop->_flag |= _IONBF;
#ifndef _STDIO_ALLOCATE
		if (fno < 2) {
			/* use special buffer for std{in,out} */
			buf = (fno == 0) ? _sibuf : _sobuf;
			size = BUFSIZ - _SMBFSZ;
		} else /* needed for ifdef */
#endif
		if (fno < _NFILE) {
			buf = _smbuf[fno];
			size = _SMBFSZ - PUSHBACK;
		} else if ((buf = (Uchar *)malloc(_SMBFSZ * sizeof (Uchar))) !=
		    0) {
			iop->_flag |= _IOMYBUF;
			size = _SMBFSZ - PUSHBACK;
		}
	} else /* regular buffered I/O, specified buffer size */ {
		if (size <= 0)
			return;
	}
	if (buf == 0)
		return; /* malloc() failed */
	temp = buf + PUSHBACK;
	iop->_base = temp;
	_setbufend(iop, temp + size);
	iop->_ptr = temp;
	iop->_cnt = 0;
}

/*
 * set line buffering
 */

int
setlinebuf(FILE *iop)
{
	char *buf;

	(void) fflush(iop);
	setbuffer(iop, (char *)NULL, 0);
	buf = (char *)malloc(128);
	if (buf != NULL) {
		setbuffer(iop, buf, 128);
		iop->_flag |= _IOLBF|_IOMYBUF;
	}
	return (0);	/* returns no useful value, keep the same prototype */
}
