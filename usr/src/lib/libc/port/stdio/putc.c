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

#pragma weak _putc_unlocked = putc_unlocked

#include "lint.h"
#include "file64.h"
#include "mtlib.h"
#include <sys/types.h>
#include <stdio.h>
#include <thread.h>
#include <synch.h>
#include "stdiom.h"
#include "mse.h"

#undef putc
#undef putc_unlocked

int
putc(int ch, FILE *iop)
{
	rmutex_t *lk;
	int ret;

	FLOCKFILE(lk, iop);
	ret = putc_unlocked(ch, iop);
	FUNLOCKFILE(lk);
	return (ret);
}

int
putc_unlocked(int ch, FILE *iop)
{
	_SET_ORIENTATION_BYTE(iop);

	if (--iop->_cnt < 0)
		return (__flsbuf((unsigned char) ch, iop));
	else
		return (*iop->_ptr++ = (unsigned char)ch);
}

int
_putc_internal(int ch, FILE *iop)
{
	if (--iop->_cnt < 0)
		return (__flsbuf((unsigned char) ch, iop));
	else
		return (*iop->_ptr++ = (unsigned char)ch);
}
