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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/time.h>
#include <sys/debug.h>
#include <sys/model.h>
#include <sys/msacct.h>

/*
 * Get the time accounting information for the calling LWP.
 */
int
lwp_info(timestruc_t *tvp)
{
	timestruc_t tv[2];
	hrtime_t hrutime, hrstime;
	klwp_t *lwp = ttolwp(curthread);

	hrutime = lwp->lwp_mstate.ms_acct[LMS_USER];
	hrstime = lwp->lwp_mstate.ms_acct[LMS_SYSTEM] +
	    lwp->lwp_mstate.ms_acct[LMS_TRAP];
	scalehrtime(&hrutime);
	scalehrtime(&hrstime);

	hrt2ts(hrutime, &tv[0]);
	hrt2ts(hrstime, &tv[1]);

	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (copyout(tv, tvp, sizeof (tv)))
			return (set_errno(EFAULT));
	} else {
		timestruc32_t tv32[2];

		if (TIMESPEC_OVERFLOW(&tv[0]) ||
		    TIMESPEC_OVERFLOW(&tv[1]))
			return (set_errno(EOVERFLOW));	/* unlikely */

		TIMESPEC_TO_TIMESPEC32(&tv32[0], &tv[0]);
		TIMESPEC_TO_TIMESPEC32(&tv32[1], &tv[1]);

		if (copyout(tv32, tvp, sizeof (tv32)))
			return (set_errno(EFAULT));
	}
	return (0);
}
