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

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.4.4.1 */

#include "mt.h"
#include <errno.h>
#include <xti.h>
#include <stropts.h>
#include <sys/timod.h>
#include "tx.h"

int
_tx_sync(int fd, int api_semantics)
{
	struct _ti_user *tiptr;
	int force_sync = 0;

	/*
	 * In case of fork/exec'd servers, _t_checkfd() has all
	 * the code to synchronize the tli data structures.
	 *
	 * We do a "forced sync" for XTI and not TLI. Detailed comments
	 * in _utililty.c having to do with rpcgen generated code and
	 * associated risk.
	 *
	 */
	if (_T_IS_XTI(api_semantics))
		force_sync = 1;

	if ((tiptr = _t_checkfd(fd, force_sync, api_semantics)) == NULL)
		return (-1);
	return (tiptr->ti_state);
}
