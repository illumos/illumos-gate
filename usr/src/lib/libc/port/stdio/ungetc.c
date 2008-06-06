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
#include "mtlib.h"
#include <sys/types.h>
#include <stdio.h>
#include <thread.h>
#include <synch.h>
#include "stdiom.h"

int _ungetc_unlocked(int c, FILE *iop);

int
ungetc(int c, FILE *iop)
{
	FLOCKRETURN(iop, _ungetc_unlocked(c, iop))
}

/*
 * Called internally by the library (instead of the safe "ungetc") when
 * iop->_lock is already held at a higher level - required since we do not
 * have recursive locks.
 */
int
_ungetc_unlocked(int c, FILE *iop)
{
	if (c == EOF)
		return (EOF);
	if (iop->_ptr <= iop->_base) {
		if (iop->_base == 0) {
			if (_findbuf(iop) == 0)
				return (EOF);
		} else if (iop->_ptr <= iop->_base - PUSHBACK)
			return (EOF);
	}
	if ((iop->_flag & _IOREAD) == 0) /* basically a no-op on write stream */
		++iop->_ptr;
	if (*--iop->_ptr != (unsigned char) c)
		*iop->_ptr = (unsigned char) c;  /* was *--iop->_ptr = c; */
	++iop->_cnt;
	iop->_flag &= ~_IOEOF;
	return (c);
}
