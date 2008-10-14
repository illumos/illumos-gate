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

#include <sys/types.h>
#include <sys/debug.h>
#include <sys/ksynch.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/ddi.h>

#define	__NSC_GEN__
#include "nsc_gen.h"
#include "nsc_mem.h"
#include "nsc_rmspin.h"
#include "../nsctl.h"


static kmutex_t _nsc_rmspin_slp;

nsc_rmlock_t _nsc_lock_top;
kmutex_t _nsc_global_lock;
int _nsc_global_lock_init;

extern nsc_mem_t *_nsc_local_mem;

/*
 * void
 * _nsc_init_rmlock (void)
 *	Initialise global locks.
 *
 * Calling/Exit State:
 *	Called at driver initialisation time to allocate necessary
 *	data structures.
 */
void
_nsc_init_rmlock()
{
	mutex_init(&_nsc_rmspin_slp, NULL, MUTEX_DRIVER, NULL);

	_nsc_lock_top.next = _nsc_lock_top.prev = &_nsc_lock_top;

	mutex_init(&_nsc_global_lock, NULL, MUTEX_DRIVER, NULL);
	_nsc_global_lock_init = 1;
}


/*
 * void
 * _nsc_deinit_rmlock (void)
 *	De-initialise global locks.
 *
 * Calling/Exit State:
 *	Called at driver unload time to de-allocate
 *	resources.
 */
void
_nsc_deinit_rmlock()
{
	_nsc_global_lock_init = 0;
	mutex_destroy(&_nsc_global_lock);

	ASSERT(_nsc_lock_top.next == &_nsc_lock_top);
	ASSERT(_nsc_lock_top.prev == &_nsc_lock_top);

	mutex_destroy(&_nsc_rmspin_slp);
}


/*
 * int
 * _nsc_lock_all_rm (void)
 *	Take all global locks in address order.
 *
 * Calling/Exit State:
 *	Returns 0 if _nsc_unlock_all_rm() should be called, or -1.
 */
int
_nsc_lock_all_rm()
{
	nsc_rmlock_t *lp;

	mutex_enter(&_nsc_rmspin_slp);

	for (lp = _nsc_lock_top.next; lp != &_nsc_lock_top; lp = lp->next) {
		(void) nsc_rm_lock(lp);
	}

	return (0);
}


/*
 * void
 * _nsc_unlock_all_rm (void)
 *	Release all global locks in reverse address order.
 *
 * Calling/Exit State:
 */
void
_nsc_unlock_all_rm()
{
	nsc_rmlock_t *lp;

	for (lp = _nsc_lock_top.prev; lp != &_nsc_lock_top; lp = lp->prev) {
		nsc_rm_unlock(lp);
	}

	mutex_exit(&_nsc_rmspin_slp);
}


/*
 * nsc_rmlock_t *
 * nsc_rm_lock_alloc(char *name, int flag, void *arg)
 *	Allocate and initialise a global lock.
 *
 * Calling/Exit State:
 *	The 'flag' parameter should be either KM_SLEEP or KM_NOSLEEP,
 *	depending on whether the caller is willing to sleep while memory
 *	is allocated or not.
 *
 *	The 'arg' parameter is passed directly to the underlying
 *	mutex_init(9f) function call.
 *
 *	Returns NULL if lock cannot be allocated.
 */
nsc_rmlock_t *
nsc_rm_lock_alloc(char *name, int flag, void *arg)
{
	nsc_rmlock_t *lp, *lk;

	if ((lk = (nsc_rmlock_t *)nsc_kmem_zalloc(sizeof (*lk),
	    flag, _nsc_local_mem)) == NULL)
		return (NULL);

	mutex_init(&lk->lockp, NULL, MUTEX_DRIVER, arg);

	mutex_enter(&_nsc_rmspin_slp);

	for (lp = _nsc_lock_top.next; lp != &_nsc_lock_top; lp = lp->next)
		if (strcmp(lp->name, name) == 0)
			break;

	if (lp != &_nsc_lock_top) {
		mutex_exit(&_nsc_rmspin_slp);

		mutex_destroy(&lk->lockp);
		nsc_kmem_free(lk, sizeof (*lk));

		cmn_err(CE_WARN, "nsctl: rmlock double allocation (%s)", name);
		return (NULL);
	}

	lk->name = name;

	lk->next = _nsc_lock_top.next;
	lk->prev = &_nsc_lock_top;
	_nsc_lock_top.next = lk;
	lk->next->prev = lk;

	mutex_exit(&_nsc_rmspin_slp);

	return (lk);
}


/*
 * void
 * nsc_rm_lock_destroy(nsc_rmlock_t *rmlockp)
 *	Release the global lock.
 *
 * Remarks:
 *	The specified global lock is released and made
 *	available for reallocation.
 */
void
nsc_rm_lock_dealloc(rmlockp)
nsc_rmlock_t *rmlockp;
{
	if (!rmlockp)
		return;

	mutex_enter(&_nsc_rmspin_slp);

	rmlockp->next->prev = rmlockp->prev;
	rmlockp->prev->next = rmlockp->next;

	if (rmlockp->child) {
		cmn_err(CE_WARN, "nsctl: rmlock destroyed when locked (%s)",
		    rmlockp->name);
		nsc_do_unlock(rmlockp->child);
		rmlockp->child = NULL;
	}

	mutex_destroy(&rmlockp->lockp);
	mutex_exit(&_nsc_rmspin_slp);

	nsc_kmem_free(rmlockp, sizeof (*rmlockp));
}


/*
 * void
 * nsc_rm_lock(nsc_rmlock_t *rmlockp)
 * 	Acquire a global lock.
 *
 * Calling/Exit State:
 *	rmlockp is the lock to be acquired.
 *	Returns 0 (success) or errno. Lock is not acquired if rc != 0.
 */
int
nsc_rm_lock(nsc_rmlock_t *rmlockp)
{
	int rc;

	mutex_enter(&rmlockp->lockp);

	ASSERT(! rmlockp->child);

	/* always use a write-lock */
	rc = nsc_do_lock(1, &rmlockp->child);
	if (rc) {
		rmlockp->child = NULL;
		mutex_exit(&rmlockp->lockp);
	}

	return (rc);
}


/*
 * static void
 * nsc_rm_unlock(nsc_rmlock_t *rmlockp)
 * 	Unlock a global lock.
 *
 * Calling/Exit State:
 *	rmlockp is the lock to be released.
 */
void
nsc_rm_unlock(nsc_rmlock_t *rmlockp)
{
	if (rmlockp->child) {
		ASSERT(MUTEX_HELD(&rmlockp->lockp));
		nsc_do_unlock(rmlockp->child);
		rmlockp->child = NULL;
		mutex_exit(&rmlockp->lockp);
	}
#ifdef DEBUG
	else {
		cmn_err(CE_WARN, "nsc_rm_unlock(%s) - not locked",
		    rmlockp->name);
	}
#endif
}
