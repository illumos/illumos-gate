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

#pragma weak _lwp_mutex_lock = __lwp_mutex_lock
#pragma weak _lwp_mutex_trylock = __lwp_mutex_trylock
#pragma weak _lwp_sema_init = __lwp_sema_init
#pragma weak _lwp_sema_wait = __lwp_sema_wait
#pragma weak _lwp_suspend = __lwp_suspend
#if defined(__i386) || defined(__amd64)
#pragma weak _lwp_private = __lwp_private
#endif	/* __i386 || __amd64 */

#include "synonyms.h"
#include "thr_uberdata.h"
#include <sys/types.h>
#include <sys/time.h>
#include <errno.h>
#include <synch.h>
#include <sys/synch32.h>
#include <sys/lwp.h>

extern int ___lwp_mutex_timedlock(mutex_t *, timespec_t *);
extern int ___lwp_sema_timedwait(lwp_sema_t *, timespec_t *, int);

int
_lwp_mutex_lock(mutex_t *mp)
{
	if (set_lock_byte(&mp->mutex_lockw) == 0)
		return (0);
	return (___lwp_mutex_timedlock(mp, NULL));
}

int
_lwp_mutex_trylock(mutex_t *mp)
{
	if (set_lock_byte(&mp->mutex_lockw) == 0)
		return (0);
	return (EBUSY);
}

int
_lwp_sema_init(lwp_sema_t *sp, int count)
{
	sp->sema_count = count;
	sp->sema_waiters = 0;
	sp->type = USYNC_PROCESS;
	return (0);
}

int
_lwp_sema_wait(lwp_sema_t *sp)
{
	return (___lwp_sema_timedwait(sp, NULL, 0));
}

#if defined(__x86)
int
_lwp_private(int cmd, int which, void *sbase)
{
	extern int ___lwp_private(int, int, void *);
	return (___lwp_private(cmd, which, sbase));
}
#endif	/* __x86 */

int
_lwp_suspend(lwpid_t lwpid)
{
	extern int ___lwp_suspend(lwpid_t);
	return (___lwp_suspend(lwpid));
}
