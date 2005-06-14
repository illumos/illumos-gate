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
/*	  All Rights Reserved	*/


/*
 * Copyright 1999,2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* from SVr4.0 1.78 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/tuneable.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/time.h>
#include <sys/debug.h>
#include <sys/model.h>
#include <sys/policy.h>

int
adjtime(struct timeval *delta, struct timeval *olddelta)
{
	struct timeval atv, oatv;
	int64_t	ndelta;
	int64_t old_delta;
	int s;
	model_t datamodel = get_udatamodel();

	if (secpolicy_settime(CRED()) != 0)
		return (set_errno(EPERM));

	if (datamodel == DATAMODEL_NATIVE) {
		if (copyin(delta, &atv, sizeof (atv)))
			return (set_errno(EFAULT));
	} else {
		struct timeval32 atv32;

		if (copyin(delta, &atv32, sizeof (atv32)))
			return (set_errno(EFAULT));
		TIMEVAL32_TO_TIMEVAL(&atv, &atv32);
	}

	if (atv.tv_usec <= -MICROSEC || atv.tv_usec >= MICROSEC)
		return (set_errno(EINVAL));

	/*
	 * The SVID specifies that if delta is 0, then there is
	 * no effect upon time correction, just return olddelta.
	 */
	ndelta = (int64_t)atv.tv_sec * NANOSEC + atv.tv_usec * 1000;
	mutex_enter(&tod_lock);
	s = hr_clock_lock();
	old_delta = timedelta;
	if (ndelta)
		timedelta = ndelta;
	/*
	 * Always set tod_needsync on all adjtime() calls, since it implies
	 * someone is watching over us and keeping the local clock in sync.
	 */
	tod_needsync = 1;
	hr_clock_unlock(s);
	mutex_exit(&tod_lock);

	if (olddelta) {
		oatv.tv_sec = old_delta / NANOSEC;
		oatv.tv_usec = (old_delta % NANOSEC) / 1000;
		if (datamodel == DATAMODEL_NATIVE) {
			if (copyout(&oatv, olddelta, sizeof (oatv)))
				return (set_errno(EFAULT));
		} else {
			struct timeval32 oatv32;

			if (TIMEVAL_OVERFLOW(&oatv))
				return (set_errno(EOVERFLOW));

			TIMEVAL_TO_TIMEVAL32(&oatv32, &oatv);

			if (copyout(&oatv32, olddelta, sizeof (oatv32)))
				return (set_errno(EFAULT));
		}
	}
	return (0);
}
