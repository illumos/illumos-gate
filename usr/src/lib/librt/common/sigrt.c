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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma weak sigwaitinfo = _sigwaitinfo
#pragma weak sigtimedwait = _sigtimedwait
#pragma weak sigqueue = _sigqueue

#include <sys/types.h>
#include "pos4.h"

int
_sigwaitinfo(const sigset_t *set, siginfo_t *info)
{
	return (__sigtimedwait(set, info, NULL));
}

int
_sigtimedwait(const sigset_t *set, siginfo_t *info,
    const struct timespec *timeout)
{
	return (__sigtimedwait(set, info, timeout));
}

int
_sigqueue(pid_t pid, int signo, const union sigval value)
{
	return (__sigqueue(pid, signo, value.sival_ptr, SI_QUEUE));
}
