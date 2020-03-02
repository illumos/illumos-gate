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

#pragma weak _getc_unlocked = getc_unlocked

#include "lint.h"
#include "file64.h"
#include "mtlib.h"
#include <sys/types.h>
#include <stdio.h>
#include <thread.h>
#include <synch.h>
#include "stdiom.h"
#include "mse.h"

#undef getc
#undef getc_unlocked

int
getc(FILE *iop)
{
	rmutex_t *lk;
	int c;

	FLOCKFILE(lk, iop);
	c = getc_unlocked(iop);
	FUNLOCKFILE(lk);
	return (c);
}


int
getc_unlocked(FILE *iop)
{
	_SET_ORIENTATION_BYTE(iop);
	return ((--iop->_cnt < 0) ? __filbuf(iop) : *iop->_ptr++);
}

int
_getc_internal(FILE *iop)
{
	return ((--iop->_cnt < 0) ? __filbuf(iop) : *iop->_ptr++);
}
