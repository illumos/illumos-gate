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
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include "file64.h"
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include "stdiom.h"

#undef _wrtchk

/* check permissions, correct for read & write changes */
int
_wrtchk(FILE *iop)
{
	if ((iop->_flag & (_IOWRT | _IOEOF)) != _IOWRT) {
		if (!(iop->_flag & (_IOWRT | _IORW))) {
			iop->_flag |= _IOERR;
			errno = EBADF;
			return (EOF); /* stream is not writeable */
		}
		iop->_flag = (iop->_flag & ~_IOEOF) | _IOWRT;
	}

	/* if first I/O to the stream get a buffer */
	if (iop->_base == NULL && _findbuf(iop) == NULL)
		return (EOF);
	else if ((iop->_ptr == iop->_base) &&
	    !(iop->_flag & (_IOLBF | _IONBF))) {
		iop->_cnt = _bufend(iop) - iop->_ptr;
	}
	return (0);
}
