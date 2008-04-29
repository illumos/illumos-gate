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
#include "thr_uberdata.h"
#include <stddef.h>

/*
 * 128 million keys should be enough for anyone.
 * This allocates half a gigabyte of memory for the keys themselves and
 * half a gigabyte of memory for each thread that uses the largest key.
 */
#define	MAX_KEYS	0x08000000U

#pragma weak thr_keycreate = _thr_keycreate
#pragma weak pthread_key_create = _thr_keycreate
#pragma weak _pthread_key_create = _thr_keycreate
int
_thr_keycreate(thread_key_t *pkey, void (*destructor)(void *))
{
	tsd_metadata_t *tsdm = &curthread->ul_uberdata->tsd_metadata;
	void (**old_data)(void *) = NULL;
	void (**new_data)(void *);
	uint_t old_nkeys;
	uint_t new_nkeys;

	lmutex_lock(&tsdm->tsdm_lock);

	/*
	 * Unfortunately, pthread_getspecific() specifies that a
	 * pthread_getspecific() on an allocated key upon which the
	 * calling thread has not performed a pthread_setspecifc()
	 * must return NULL.  Consider the following sequence:
	 *
	 *	pthread_key_create(&key);
	 *	pthread_setspecific(key, datum);
	 *	pthread_key_delete(&key);
	 *	pthread_key_create(&key);
	 *	val = pthread_getspecific(key);
	 *
	 * According to POSIX, if the deleted key is reused for the new
	 * key returned by the second pthread_key_create(), then the
	 * pthread_getspecific() in the above example must return NULL
	 * (and not the stale datum).  The implementation is thus left
	 * with two alternatives:
	 *
	 *  (1)	Reuse deleted keys.  If this is to be implemented optimally,
	 *	it requires that pthread_key_create() somehow associate
	 *	the value NULL with the new (reused) key for each thread.
	 *	Keeping the hot path fast and lock-free induces substantial
	 *	complexity on the implementation.
	 *
	 *  (2)	Never reuse deleted keys. This allows the pthread_getspecific()
	 *	implementation to simply perform a check against the number
	 *	of keys set by the calling thread, returning NULL if the
	 *	specified key is larger than the highest set key.  This has
	 *	the disadvantage of wasting memory (a program which simply
	 *	loops calling pthread_key_create()/pthread_key_delete()
	 *	will ultimately run out of memory), but permits an optimal
	 *	pthread_getspecific() while allowing for simple key creation
	 *	and deletion.
	 *
	 * All Solaris implementations have opted for (2).  Given the
	 * ~10 years that this has been in the field, it is safe to assume
	 * that applications don't loop creating and destroying keys; we
	 * stick with (2).
	 */
	if (tsdm->tsdm_nused == (old_nkeys = tsdm->tsdm_nkeys)) {
		/*
		 * We need to allocate or double the number of keys.
		 * tsdm->tsdm_nused must always be a power of two.
		 */
		if ((new_nkeys = (old_nkeys << 1)) == 0)
			new_nkeys = 8;

		if (new_nkeys > MAX_KEYS) {
			lmutex_unlock(&tsdm->tsdm_lock);
			return (EAGAIN);
		}
		if ((new_data = lmalloc(new_nkeys * sizeof (void *))) == NULL) {
			lmutex_unlock(&tsdm->tsdm_lock);
			return (ENOMEM);
		}
		if ((old_data = tsdm->tsdm_destro) == NULL) {
			/* key == 0 is always invalid */
			new_data[0] = TSD_UNALLOCATED;
			tsdm->tsdm_nused = 1;
		} else {
			(void) memcpy(new_data, old_data,
			    old_nkeys * sizeof (void *));
		}
		tsdm->tsdm_destro = new_data;
		tsdm->tsdm_nkeys = new_nkeys;
	}

	*pkey = tsdm->tsdm_nused;
	tsdm->tsdm_destro[tsdm->tsdm_nused++] = destructor;
	lmutex_unlock(&tsdm->tsdm_lock);

	if (old_data != NULL)
		lfree(old_data, old_nkeys * sizeof (void *));

	return (0);
}

/*
 * Same as _thr_keycreate(), above, except that the key creation
 * is performed only once.  This relies upon the fact that a key
 * value of THR_ONCE_KEY is invalid, and requires that the key be
 * allocated with a value of THR_ONCE_KEY before calling here.
 * THR_ONCE_KEY and PTHREAD_ONCE_KEY_NP, defined in <thread.h>
 * and <pthread.h> respectively, must have the same value.
 * Example:
 *
 *	static pthread_key_t key = PTHREAD_ONCE_KEY_NP;
 *	...
 *	pthread_key_create_once_np(&key, destructor);
 */
#pragma weak pthread_key_create_once_np = _thr_keycreate_once
#pragma weak _pthread_key_create_once_np = _thr_keycreate_once
#pragma weak thr_keycreate_once = _thr_keycreate_once
int
_thr_keycreate_once(thread_key_t *keyp, void (*destructor)(void *))
{
	static mutex_t key_lock = DEFAULTMUTEX;
	thread_key_t key;
	int error;

	if (*keyp == THR_ONCE_KEY) {
		lmutex_lock(&key_lock);
		if (*keyp == THR_ONCE_KEY) {
			error = _thr_keycreate(&key, destructor);
			if (error) {
				lmutex_unlock(&key_lock);
				return (error);
			}
			_membar_producer();
			*keyp = key;
		}
		lmutex_unlock(&key_lock);
	}
	_membar_consumer();

	return (0);
}

#pragma weak pthread_key_delete = _thr_key_delete
#pragma weak _pthread_key_delete = _thr_key_delete
int
_thr_key_delete(thread_key_t key)
{
	tsd_metadata_t *tsdm = &curthread->ul_uberdata->tsd_metadata;

	lmutex_lock(&tsdm->tsdm_lock);

	if (key >= tsdm->tsdm_nused ||
	    tsdm->tsdm_destro[key] == TSD_UNALLOCATED) {
		lmutex_unlock(&tsdm->tsdm_lock);
		return (EINVAL);
	}

	tsdm->tsdm_destro[key] = TSD_UNALLOCATED;
	lmutex_unlock(&tsdm->tsdm_lock);

	return (0);
}

/*
 * Blessedly, the pthread_getspecific() interface is much better than the
 * thr_getspecific() interface in that it cannot return an error status.
 * Thus, if the key specified is bogus, pthread_getspecific()'s behavior
 * is undefined.  As an added bonus (and as an artificat of not returning
 * an error code), the requested datum is returned rather than stored
 * through a parameter -- thereby avoiding the unnecessary store/load pair
 * incurred by thr_getspecific().  Every once in a while, the Standards
 * get it right -- but usually by accident.
 */
#pragma weak	pthread_getspecific	= _pthread_getspecific
void *
_pthread_getspecific(pthread_key_t key)
{
	tsd_t *stsd;

	/*
	 * We are cycle-shaving in this function because some
	 * applications make heavy use of it and one machine cycle
	 * can make a measurable difference in performance.  This
	 * is why we waste a little memory and allocate a NULL value
	 * for the invalid key == 0 in curthread->ul_ftsd[0] rather
	 * than adjusting the key by subtracting one.
	 */
	if (key < TSD_NFAST)
		return (curthread->ul_ftsd[key]);

	if ((stsd = curthread->ul_stsd) != NULL && key < stsd->tsd_nalloc)
		return (stsd->tsd_data[key]);

	return (NULL);
}

#pragma weak thr_getspecific = _thr_getspecific
int
_thr_getspecific(thread_key_t key, void **valuep)
{
	tsd_t *stsd;

	/*
	 * Amazingly, some application code (and worse, some particularly
	 * fugly Solaris library code) _relies_ on the fact that 0 is always
	 * an invalid key.  To preserve this semantic, 0 is never returned
	 * as a key from thr_/pthread_key_create(); we explicitly check
	 * for it here and return EINVAL.
	 */
	if (key == 0)
		return (EINVAL);

	if (key < TSD_NFAST)
		*valuep = curthread->ul_ftsd[key];
	else if ((stsd = curthread->ul_stsd) != NULL && key < stsd->tsd_nalloc)
		*valuep = stsd->tsd_data[key];
	else
		*valuep = NULL;

	return (0);
}

/*
 * We call _thr_setspecific_slow() when the key specified
 * is beyond the current thread's currently allocated range.
 * This case is in a separate function because we want
 * the compiler to optimize for the common case.
 */
static int
_thr_setspecific_slow(thread_key_t key, void *value)
{
	ulwp_t *self = curthread;
	tsd_metadata_t *tsdm = &self->ul_uberdata->tsd_metadata;
	tsd_t *stsd;
	tsd_t *ntsd;
	uint_t nkeys;

	/*
	 * It isn't necessary to grab locks in this path;
	 * tsdm->tsdm_nused can only increase.
	 */
	if (key >= tsdm->tsdm_nused)
		return (EINVAL);

	/*
	 * We would like to test (tsdm->tsdm_destro[key] == TSD_UNALLOCATED)
	 * here but that would require acquiring tsdm->tsdm_lock and we
	 * want to avoid locks in this path.
	 *
	 * We have a key which is (or at least _was_) valid.  If this key
	 * is later deleted (or indeed, is deleted before we set the value),
	 * we don't care; such a condition would indicate an application
	 * race for which POSIX thankfully leaves the behavior unspecified.
	 *
	 * First, determine our new size.  To avoid allocating more than we
	 * have to, continue doubling our size only until the new key fits.
	 * stsd->tsd_nalloc must always be a power of two.
	 */
	nkeys = ((stsd = self->ul_stsd) != NULL)? stsd->tsd_nalloc : 8;
	for (; key >= nkeys; nkeys <<= 1)
		continue;

	/*
	 * Allocate the new TSD.
	 */
	if ((ntsd = lmalloc(nkeys * sizeof (void *))) == NULL)
		return (ENOMEM);

	if (stsd != NULL) {
		/*
		 * Copy the old TSD across to the new.
		 */
		(void) memcpy(ntsd, stsd, stsd->tsd_nalloc * sizeof (void *));
		lfree(stsd, stsd->tsd_nalloc * sizeof (void *));
	}

	ntsd->tsd_nalloc = nkeys;
	ntsd->tsd_data[key] = value;
	self->ul_stsd = ntsd;

	return (0);
}

#pragma weak thr_setspecific = _thr_setspecific
#pragma weak pthread_setspecific = _thr_setspecific
#pragma weak _pthread_setspecific = _thr_setspecific
int
_thr_setspecific(thread_key_t key, void *value)
{
	tsd_t *stsd;
	int ret;
	ulwp_t *self = curthread;

	/*
	 * See the comment in _thr_getspecific(), above.
	 */
	if (key == 0)
		return (EINVAL);

	if (key < TSD_NFAST) {
		curthread->ul_ftsd[key] = value;
		return (0);
	}

	if ((stsd = curthread->ul_stsd) != NULL && key < stsd->tsd_nalloc) {
		stsd->tsd_data[key] = value;
		return (0);
	}

	/*
	 * This is a critical region since we are dealing with memory
	 * allocation and free. Similar protection required in tsd_free().
	 */
	enter_critical(self);
	ret = _thr_setspecific_slow(key, value);
	exit_critical(self);
	return (ret);
}

/*
 * Contract-private interface for java.  See PSARC/2003/159
 *
 * If the key falls within the TSD_NFAST range, return a non-negative
 * offset that can be used by the caller to fetch the TSD data value
 * directly out of the thread structure using %g7 (sparc) or %gs (x86).
 * With the advent of TLS, %g7 and %gs are part of the ABI, even though
 * the definition of the thread structure itself (ulwp_t) is private.
 *
 * We guarantee that the offset returned on sparc will fit within
 * a SIMM13 field (that is, it is less than 2048).
 *
 * On failure (key is not in the TSD_NFAST range), return -1.
 */
ptrdiff_t
_thr_slot_offset(thread_key_t key)
{
	if (key != 0 && key < TSD_NFAST)
		return ((ptrdiff_t)offsetof(ulwp_t, ul_ftsd[key]));
	return (-1);
}

/*
 * This is called by _thrp_exit() to apply destructors to the thread's tsd.
 */
void
tsd_exit()
{
	ulwp_t *self = curthread;
	tsd_metadata_t *tsdm = &self->ul_uberdata->tsd_metadata;
	thread_key_t key;
	int recheck;
	void *val;
	void (*func)(void *);

	lmutex_lock(&tsdm->tsdm_lock);

	do {
		recheck = 0;

		for (key = 1; key < TSD_NFAST &&
		    key < tsdm->tsdm_nused; key++) {
			if ((func = tsdm->tsdm_destro[key]) != NULL &&
			    func != TSD_UNALLOCATED &&
			    (val = self->ul_ftsd[key]) != NULL) {
				self->ul_ftsd[key] = NULL;
				lmutex_unlock(&tsdm->tsdm_lock);
				(*func)(val);
				lmutex_lock(&tsdm->tsdm_lock);
				recheck = 1;
			}
		}

		if (self->ul_stsd == NULL)
			continue;

		/*
		 * Any of these destructors could cause us to grow the number
		 * TSD keys in the slow TSD; we cannot cache the slow TSD
		 * pointer through this loop.
		 */
		for (; key < self->ul_stsd->tsd_nalloc &&
		    key < tsdm->tsdm_nused; key++) {
			if ((func = tsdm->tsdm_destro[key]) != NULL &&
			    func != TSD_UNALLOCATED &&
			    (val = self->ul_stsd->tsd_data[key]) != NULL) {
				self->ul_stsd->tsd_data[key] = NULL;
				lmutex_unlock(&tsdm->tsdm_lock);
				(*func)(val);
				lmutex_lock(&tsdm->tsdm_lock);
				recheck = 1;
			}
		}
	} while (recheck);

	lmutex_unlock(&tsdm->tsdm_lock);

	/*
	 * We're done; if we have slow TSD, we need to free it.
	 */
	tsd_free(self);
}

void
tsd_free(ulwp_t *ulwp)
{
	tsd_t *stsd;
	ulwp_t *self = curthread;

	enter_critical(self);
	if ((stsd = ulwp->ul_stsd) != NULL)
		lfree(stsd, stsd->tsd_nalloc * sizeof (void *));
	ulwp->ul_stsd = NULL;
	exit_critical(self);
}
