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
 * Seek for standard library.  Coordinates with buffering.
 */

#include <sys/feature_tests.h>

#if !defined(_LP64)
#pragma weak _fseeko64 = fseeko64
#endif
#pragma weak _fseeko = fseeko

#include "lint.h"
#include "file64.h"
#include "mtlib.h"
#include <sys/types.h>
#include <unistd.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <thread.h>
#include <synch.h>
#include "stdiom.h"

#if !defined(_LP64)
int
fseeko64(FILE *iop, off64_t offset, int ptrname)
{
	off64_t	p;
	rmutex_t *lk;

	FLOCKFILE(lk, iop);
	iop->_flag &= ~_IOEOF;

	if (!(iop->_flag & _IOREAD) && !(iop->_flag & (_IOWRT | _IORW))) {
		errno = EBADF;
		FUNLOCKFILE(lk);
		return (-1);
	}

	if (iop->_flag & _IOREAD) {
		if (ptrname == 1 && iop->_base && !(iop->_flag&_IONBF)) {
			offset -= iop->_cnt;
		}
	} else if (iop->_flag & (_IOWRT | _IORW)) {
		if (_fflush_u(iop) == EOF) {
			FUNLOCKFILE(lk);
			return (-1);
		}
	}
	iop->_cnt = 0;
	iop->_ptr = iop->_base;
	if (iop->_flag & _IORW) {
		iop->_flag &= ~(_IOREAD | _IOWRT);
	}
	p = _xseek64(iop, offset, ptrname);
	FUNLOCKFILE(lk);
	return ((p == -1)? -1: 0);
}
#endif	/* _LP64 */

int
fseeko(FILE *iop, off_t offset, int ptrname)
{
	return (fseek(iop, offset, ptrname));
}
