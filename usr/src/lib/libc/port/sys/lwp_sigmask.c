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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include <signal.h>
#include <sys/syscall.h>

int
__lwp_sigmask(int how, const sigset_t *set, sigset_t *oset)
{
	sysret_t rval;
	uint_t mask0;
	uint_t mask1;

	if (set) {
		mask0 = set->__sigbits[0];
		mask1 = set->__sigbits[1];
	} else {
		how = 0;
		mask0 = mask1 = 0;
	}

	(void) __systemcall(&rval, SYS_lwp_sigmask, how, mask0, mask1);

	if (oset) {
		oset->__sigbits[0] = (uint_t)rval.sys_rval1;
		oset->__sigbits[1] = (uint_t)rval.sys_rval2;
		oset->__sigbits[2] = 0;
		oset->__sigbits[3] = 0;
	}

	return (0);
}
