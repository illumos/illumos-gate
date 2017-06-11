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
 * Copyright (c) 1994, by Sun Microsytems, Inc.
 */

/*
 * Functions to sync up library list with that of the run time linker
 */

#ifndef DEBUG
#define	NDEBUG	1
#endif

#include <assert.h>

#include "tnfctl_int.h"
#include "kernel_int.h"
#include "dbg.h"

tnfctl_errcode_t
tnfctl_check_libs(tnfctl_handle_t *hndl)
{
	tnfctl_errcode_t	prexstat;
	enum event_op_t		dl_evt;
	boolean_t		lmap_ok;

	if (hndl->mode == KERNEL_MODE) {
		prexstat = _tnfctl_refresh_kernel(hndl);
		return (prexstat);
	}

	/* hndl refers to a process */

	/* return value of lmap_ok, dl_evt ignored */
	prexstat = _tnfctl_refresh_process(hndl, &lmap_ok, &dl_evt);
	assert(lmap_ok == B_TRUE);
	return (prexstat);
}

/*
 * _tnfctl_lock_libs() locks the library list maintained in the prex
 * handle against it changing by a dlopen or dlclose.
 *
 * This locking code is between the thread that owns the handle and
 * another thread that may be doing a dlopen/dlclose.  We do not support
 * the situation of having multiple threads operating on the same
 * handle - in effect the code per tnfctl_handle can be thought of as
 * being single-threaded - that is why we can check "hndl->in_objlist"
 * without first obtaining a lock.  "in_objlist" is the re-entrancy
 * protector on the lock i.e. we can call _tnfctl_lock_libs() safely even if
 * this thread has the lock held.  The return value "release_lock" indicates
 * whether the lock should be released or not.  It can be passed into
 * _tnfctl_unlock_libs() which will do the right thing.
 */

tnfctl_errcode_t
_tnfctl_lock_libs(tnfctl_handle_t *hndl, boolean_t *release_lock)
{
	/* this interface is only for INTERNAL_MODE clients */
	assert(hndl->mode == INTERNAL_MODE);

	if (hndl->in_objlist == B_TRUE) {
		/*
		 * already have _tnfctl_lmap_lock held which implies that
		 * the library list has been sync'ed up
		 */
		*release_lock = B_FALSE;
		return (TNFCTL_ERR_NONE);
	}

	/* lock is not currently held, so lock it */
	mutex_lock(&_tnfctl_lmap_lock);
	hndl->in_objlist = B_TRUE;

	*release_lock = B_TRUE;
	return (TNFCTL_ERR_NONE);
}

void
_tnfctl_unlock_libs(tnfctl_handle_t *hndl, boolean_t release_lock)
{
	/* this interface is only for INTERNAL_MODE clients */
	assert(hndl->mode == INTERNAL_MODE);

	if (release_lock) {
		hndl->in_objlist = B_FALSE;
		mutex_unlock(&_tnfctl_lmap_lock);
	}
}

/*
 * _tnfctl_syn_lib_list() syncs up the library list maintained
 * in the prex handle with the libraries in the process (if needed)
 * NOTE: Assumes _tnfctl_lmap_lock is held.
 *
 */
tnfctl_errcode_t
_tnfctl_sync_lib_list(tnfctl_handle_t *hndl)
{
	tnfctl_errcode_t	prexstat = TNFCTL_ERR_NONE;
	enum event_op_t		dl_evt;
	boolean_t		lmap_ok;

	/* this interface is only for INTERNAL_MODE clients */
	assert(hndl->mode == INTERNAL_MODE);

	/* lmap_lock held and in_objlist marked as B_TRUE */
	if (_tnfctl_libs_changed == B_TRUE) {
		prexstat = _tnfctl_refresh_process(hndl, &lmap_ok, &dl_evt);
		if (prexstat) {
			return (prexstat);
		}
	}
	return (TNFCTL_ERR_NONE);
}
