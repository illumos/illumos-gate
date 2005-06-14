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

#pragma ident	"%Z%%M%	%I%	%E% SMI"  /* from S5R2 1.2 */

/*LINTLIBRARY*/
#include <stdio.h>

extern void free();
extern unsigned char (*_smbuf)[_SBFSIZ];
extern char *malloc();
extern void _getsmbuf();

int
setvbuf(iop, buf, type, size)
register FILE *iop;
register char	*buf;
register int type;
register int size;
{
	register int fno = fileno(iop);  /* file number */

	if(iop->_base != NULL && iop->_flag & _IOMYBUF)
		free((char*)iop->_base);
	iop->_flag &= ~(_IOMYBUF | _IONBF | _IOLBF);
	switch (type)  {
	    /*note that the flags are the same as the possible values for type*/
	    case _IONBF:
		/* file is unbuffered except in fastio */
		iop->_flag |= _IONBF;
		/* use small buffers reserved for this */
		iop->_base = _smbuf[fno];
		iop->_bufsiz = _SBFSIZ;
		break;
	    case _IOLBF:
	    case _IOFBF:
		if (size < 0)
			return -1;
		iop->_flag |= type;
		size = (size == 0) ? BUFSIZ : size;
		/* 
		* need eight characters beyond bufend for stdio slop
		*/
		if (size <= 8) {
		    size = BUFSIZ;
		    buf = NULL;
		}
		if (buf == NULL) {
			size += 8;
			buf = malloc((unsigned)size);
			iop->_flag |= _IOMYBUF;
		}
		iop->_base = (unsigned char *)buf;
		iop->_bufsiz = size - 8;
		break;
	    default:
		return -1;
	}
	iop->_ptr = iop->_base;
	iop->_cnt = 0;
	return 0;
}
