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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mt.h"
#include <errno.h>
#include <xti.h>
#include <stropts.h>
#include <sys/timod.h>
#include "tx.h"


int
_tx_getstate(int fd, int api_semantics)
{
	struct _ti_user *tiptr;

	if ((tiptr = _t_checkfd(fd, 0, api_semantics)) == NULL)
		return (-1);

	switch (tiptr->ti_state) {

	case T_UNBND:
	case T_IDLE:
	case T_INCON:
	case T_OUTCON:
	case T_DATAXFER:
	case T_INREL:
	case T_OUTREL:
		return (tiptr->ti_state);
	default:
		t_errno = TSTATECHNG;
		return (-1);
	}
}
