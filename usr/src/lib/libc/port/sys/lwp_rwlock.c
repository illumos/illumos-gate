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

#include "synonyms.h"
#include <synch.h>
#include <time.h>
#include <errno.h>
#include <sys/syscall.h>

#define	SUBSYS_lwp_rwlock_rdlock	0
#define	SUBSYS_lwp_rwlock_wrlock	1
#define	SUBSYS_lwp_rwlock_tryrdlock	2
#define	SUBSYS_lwp_rwlock_trywrlock	3
#define	SUBSYS_lwp_rwlock_unlock	4

int
__lwp_rwlock_rdlock(rwlock_t *rwl, timespec_t *tsp)
{
	int rval;

	do {
		rval = syscall(SYS_lwp_rwlock_sys,
			SUBSYS_lwp_rwlock_rdlock, rwl, tsp);
	} while (rval == -1 && errno == EINTR);

	return (rval == -1 ? errno : 0);
}

int
__lwp_rwlock_wrlock(rwlock_t *rwl, timespec_t *tsp)
{
	int rval;

	do {
		rval = syscall(SYS_lwp_rwlock_sys,
			SUBSYS_lwp_rwlock_wrlock, rwl, tsp);
	} while (rval == -1 && errno == EINTR);

	return (rval == -1 ? errno : 0);
}

int
__lwp_rwlock_tryrdlock(rwlock_t *rwl)
{
	if (syscall(SYS_lwp_rwlock_sys,
	    SUBSYS_lwp_rwlock_tryrdlock, rwl) == -1)
		return (errno);
	return (0);
}

int
__lwp_rwlock_trywrlock(rwlock_t *rwl)
{
	if (syscall(SYS_lwp_rwlock_sys,
	    SUBSYS_lwp_rwlock_trywrlock, rwl) == -1)
		return (errno);
	return (0);
}

int
__lwp_rwlock_unlock(rwlock_t *rwl)
{
	if (syscall(SYS_lwp_rwlock_sys, SUBSYS_lwp_rwlock_unlock, rwl) == -1)
		return (errno);
	return (0);
}
