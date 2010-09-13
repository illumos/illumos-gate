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

#pragma ident	"%Z%%M%	%I%	%E% SMI"  /* from S5R2 1.3 */

/*LINTLIBRARY*/
/*
 * Seek for standard library.  Coordinates with buffering.
 */
#include <stdio.h>

extern long lseek();
extern int fflush();

int
fseek(iop, offset, ptrname)
register FILE *iop;
long	offset;
int	ptrname;
{
	register int resync, c;
	long	p = -1;			/* can't happen? */

	iop->_flag &= ~_IOEOF;
	if(iop->_flag & _IOREAD) {
		if(ptrname < 2 && iop->_base && !(iop->_flag&_IONBF)) {
			c = iop->_cnt;
			p = offset;
			if(ptrname == 0) {
				long curpos = lseek(fileno(iop), 0L, 1);
				if (curpos == -1)
					return (-1);
				p += c - curpos;
				resync = offset&01;
			} else {
				offset -= (long)c;
				resync = 0;
			}
			if(!(iop->_flag&_IORW) && c > 0 && p <= c &&
					p >= iop->_base - iop->_ptr) {
				iop->_ptr += (int)p;
				iop->_cnt -= (int)p;
				return(0);
			}
		} else 
			resync = 0;
		if(iop->_flag & _IORW) {
			iop->_ptr = iop->_base;
			iop->_flag &= ~_IOREAD;
			resync = 0;
		}
		p = lseek(fileno(iop), offset-resync, ptrname);
		iop->_cnt = 0;
		if (resync && p != -1)
			if (getc(iop) == EOF)
				p = -1;
	} else if(iop->_flag & (_IOWRT | _IORW)) {
		p = fflush(iop);
		iop->_cnt = 0;
		if(iop->_flag & _IORW) {
			iop->_flag &= ~_IOWRT;
			iop->_ptr = iop->_base;
		}
		return(lseek(fileno(iop), offset, ptrname) == -1 || p == EOF ?
		    -1 : 0);
	}
	return((p == -1)? -1: 0);
}
