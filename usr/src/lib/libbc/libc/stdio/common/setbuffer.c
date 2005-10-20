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
 * Copyright 1986 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <malloc.h>
#include <unistd.h>

extern unsigned char (*_smbuf)[_SBFSIZ];

void
setbuffer(FILE *iop, char *buf, int size)
{
	int fno = fileno(iop);  /* file number */

	if (iop->_base != NULL && iop->_flag&_IOMYBUF)
		free((char *)iop->_base);
	iop->_flag &= ~(_IOMYBUF|_IONBF|_IOLBF);
	if ((iop->_base = (unsigned char *)buf) == NULL) {
		iop->_flag |= _IONBF; /* file unbuffered except in fastio */
		/* use small buffers reserved for this */
		iop->_base = _smbuf[fno];
		iop->_bufsiz = _SBFSIZ;
	} else {
		/* regular buffered I/O, specified buffer size */
		if (size <= 0)
			return;
		iop->_bufsiz = size;
	}
	iop->_ptr = iop->_base;
	iop->_cnt = 0;
}

/*
 * set line buffering
 */
int
setlinebuf(FILE *iop)
{
	char *buf;

	fflush(iop);
	setbuffer(iop, NULL, 0);
	buf = (char *)malloc(128);
	if (buf != NULL) {
		setbuffer(iop, buf, 128);
		iop->_flag |= _IOLBF|_IOMYBUF;
	}
	return (0);
}
