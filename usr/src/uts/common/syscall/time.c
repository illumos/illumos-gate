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
 * Copyright 1994-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	All rights reserved.	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/tuneable.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/time.h>
#include <sys/debug.h>
#include <sys/policy.h>

time_t
gtime(void)
{
	return (gethrestime_sec());
}

int
stime(time_t time)
{
	timestruc_t ts;

	if (secpolicy_settime(CRED()) != 0)
		return (set_errno(EPERM));

	if (time < 0)
		return (set_errno(EINVAL));

	ts.tv_sec = time;
	ts.tv_nsec = 0;
	mutex_enter(&tod_lock);
	tod_set(ts);
	set_hrestime(&ts);
	mutex_exit(&tod_lock);

	return (0);
}

#if defined(_SYSCALL32_IMPL)
int
stime32(time32_t time)
{
	if (time < 0)
		return (set_errno(EINVAL));

	return (stime((time_t)time));
}
#endif
