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

#include "lint.h"
#include "file64.h"
#include "mtlib.h"
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <synch.h>
#include <thread.h>
#include "stdiom.h"
#include "libc.h"


void
rewind(FILE *iop)
{
	rmutex_t *lk;

	FLOCKFILE(lk, iop);
	_rewind_unlocked(iop);
	FUNLOCKFILE(lk);
}

void
_rewind_unlocked(FILE *iop)
{
	(void) _fflush_u(iop);
	(void) _xseek64(iop, 0, SEEK_SET);
	iop->_cnt = 0;
	iop->_ptr = iop->_base;
	iop->_flag &= ~(_IOERR | _IOEOF);
	if (iop->_flag & _IORW)
		iop->_flag &= ~(_IOREAD | _IOWRT);
}
