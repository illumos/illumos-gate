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

/*      Copyright (c) 1984 AT&T */
/*        All Rights Reserved   */

#pragma ident	"%Z%%M%	%I%	%E% SMI"  /* from S5R2 2.2 */

/*LINTLIBRARY*/
#include <stdio.h>

extern void free();
extern int isatty();
extern unsigned char (*_smbuf)[_SBFSIZ];
extern void _getsmbuf();

void
setbuf(iop, buf)
register FILE *iop;
char	*buf;
{
	register int fno = fileno(iop);  /* file number */

	if(iop->_base != NULL && iop->_flag & _IOMYBUF)
		free((char*)iop->_base);
	iop->_flag &= ~(_IOMYBUF | _IONBF | _IOLBF);
	if((iop->_base = (unsigned char*)buf) == NULL) {
		iop->_flag |= _IONBF; /* file unbuffered except in fastio */
		/* use small buffers reserved for this */
		iop->_base = _smbuf[fno];
		iop->_bufsiz = _SBFSIZ;
	}
	else {  /* regular buffered I/O, standard buffer size */
		if (isatty(fno))
			iop->_flag |= _IOLBF;
		iop->_bufsiz = BUFSIZ;
	}
	iop->_ptr = iop->_base;
	iop->_cnt = 0;
}
