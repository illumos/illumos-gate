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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mt.h"
#include <stdlib.h>

void *
thr_get_storage(pthread_key_t *keyp, size_t size, void (*destructor)(void *))
{
	void *addr;

	if (pthread_key_create_once_np(keyp, destructor) != 0)
		return (NULL);
	addr = pthread_getspecific(*keyp);
	if (addr == NULL && size != 0) {
		addr = calloc(1, size);
		if (addr != NULL && pthread_setspecific(*keyp, addr) != 0) {
			free(addr);
			return (NULL);
		}
	}

	return (addr);
}

/*
 * sig_mutex_lock() and sig_mutex_unlock() are the same
 * as mutex_lock() and mutex_unlock() except that all
 * signals are deferred while the lock is held.  Likewise
 * for sig_rw_rdlock(), sig_rw_wrlock() and sig_rw_unlock().
 *
 * _sigoff() and _sigon() are consolidation-private
 * interfaces in libc that defer and enable signals.
 * Calls to these can nest but must be balanced, so
 * nested calls to these functions work properly.
 */

void
sig_mutex_lock(mutex_t *mp)
{
	_sigoff();
	(void) mutex_lock(mp);
}

void
sig_mutex_unlock(mutex_t *mp)
{
	(void) mutex_unlock(mp);
	_sigon();
}

void
sig_rw_rdlock(rwlock_t *rwlp)
{
	_sigoff();
	(void) rw_rdlock(rwlp);
}

void
sig_rw_wrlock(rwlock_t *rwlp)
{
	_sigoff();
	(void) rw_wrlock(rwlp);
}

void
sig_rw_unlock(rwlock_t *rwlp)
{
	(void) rw_unlock(rwlp);
	_sigon();
}
